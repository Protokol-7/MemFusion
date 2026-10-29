package memprocfs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"memforensics-gui/internal/debuglog"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Emitter reports a progress event with an arbitrary JSON-serializable
// payload, matching internal/volatility's Emitter type.
type Emitter func(event string, payload any)

// RunForensicScan runs MemProcFS in non-interactive forensic mode
// (-forensic 1, the standard in-memory database mode) against imagePath
// and reports progress via emit as "memprocfs:status" events. If
// onScanComplete is non-nil it is invoked once, when the forensic scan
// reaches 100% — used to chain a follow-up stage (the analyzer) while the
// mount stays alive.
//
// MemProcFS does not exit once the scan finishes — it keeps a live
// filesystem mounted (confirmed empirically) — so this function keeps
// running (and keeps the mount alive) until ctx is cancelled. Callers
// should treat a "memprocfs:status" event with state=="scan-complete" as
// the meaningful completion signal, not the return of this function.
//
// MemProcFS mounts a drive letter through Dokany, and the letter is chosen
// at run time — see pickWindowsMountDrive.
//
// With -forensic 1 the sqlite database is kept in memory, so unlike the
// old -forensic 4 mode there may be no on-disk database file to preserve.
// The copy into outputDir (via the path reported by forensic/database.txt)
// is therefore best-effort: if it fails, scan-complete is still reported
// and the findings remain browsable in the mounted forensic/ directory.
// DefaultMountDir is the drive MemProcFS itself falls back to when it is not
// told otherwise. It is exported so ListMounts (mounts_windows.go) has
// something to check when it cannot read a running process's command line.
//
// It is only ever a fallback: the drive for a run started by this app is
// picked from the free letters at the time (pickWindowsMountDrive), because
// M: is very often already taken by a mapped network share — MemProcFS then
// fails to mount, or worse, the app watches a drive belonging to something
// else.
const DefaultMountDir = `M:\`

// activeMount records the mount point of the run currently in progress, so
// App can refuse to "clean up" the live mount. Empty when no run is active.
var (
	activeMountMu  sync.Mutex
	activeMountDir string
)

// ActiveMountDir returns the mount point of the run in progress, or "" if no
// run is active.
func ActiveMountDir() string {
	activeMountMu.Lock()
	defer activeMountMu.Unlock()
	return activeMountDir
}

func setActiveMountDir(dir string) {
	activeMountMu.Lock()
	activeMountDir = dir
	activeMountMu.Unlock()
}

// windowsDriveSearchOrder is the order free drive letters are tried in.
//
// It runs backwards from Z on purpose. MemProcFS's own default, M:, is not
// preferred: it sits right in the middle of the range people map shares to,
// and a mapped drive is per-logon-session, so this process can believe M: is
// free while the user's Explorer session has a share on it. Starting at Z
// keeps the mount clear of that whole argument. M stays in the list as a
// late fallback rather than being excluded outright.
const windowsDriveSearchOrder = "ZYXWVUTSRQPONMLKJIHGFED"

// pickWindowsMountDrive returns a free drive letter for MemProcFS to mount
// on, as a bare letter ("Z") plus the corresponding root path ("Z:\").
//
// "Free" is decided by driveLetterInUse (drives_windows.go), which asks
// Windows what letters are actually spoken for rather than trying to open
// them — see that file for why stat'ing the root is not good enough.
//
// Returns ok=false when every letter is in use, which the caller reports
// rather than mounting over something.
func pickWindowsMountDrive() (letter, root string, ok bool) {
	for _, c := range windowsDriveSearchOrder {
		if !driveLetterInUse(byte(c)) {
			return string(c), string(c) + `:\`, true
		}
	}
	return "", "", false
}

func RunForensicScan(ctx context.Context, memprocfsPath, imagePath, outputDir string, emit Emitter, onScanComplete func()) error {
	args := []string{"-f", imagePath, "-forensic", "1", "-license-accept-elastic-license-2-0"}
	// MemProcFS's own default drive is M:, which collides with any mapped
	// share the user already has there, so pick a letter that is actually
	// free and tell MemProcFS to use that one. Killing the process on stop
	// unmounts the drive.
	letter, mountDir, ok := pickWindowsMountDrive()
	if !ok {
		err := fmt.Errorf("no free drive letter available to mount MemProcFS on")
		emit("memprocfs:status", map[string]any{"state": "error", "message": err.Error()})
		return err
	}
	args = append(args, "-mount", letter)
	emit("run:log", map[string]any{"source": "memprocfs", "line": "mounting at " + mountDir})
	setActiveMountDir(mountDir)
	defer setActiveMountDir("")

	cmd := exec.CommandContext(ctx, memprocfsPath, args...)
	proc.Configure(cmd)
	stdout, stdoutWriter := io.Pipe()
	stderr, stderrWriter := io.Pipe()
	defer stdout.Close()
	defer stderr.Close()
	defer stdoutWriter.Close()
	defer stderrWriter.Close()
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	diagnostics := debuglog.Attach(cmd, outputDir, "memprocfs", true, func(message string) {
		emit("run:log", map[string]any{"source": "memprocfs", "line": message})
	})
	if err := cmd.Start(); err != nil {
		diagnostics.Finish(cmd, err)
		emit("memprocfs:status", map[string]any{"state": "error", "message": fmt.Sprintf("starting memprocfs: %v", err)})
		return err
	}
	emit("memprocfs:status", map[string]any{"state": "running", "message": "scanning…"})

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		streamLines(stdout, func(line string) { emit("run:log", map[string]any{"source": "memprocfs", "line": line}) })
		io.Copy(io.Discard, stdout)
	}()
	go func() {
		defer readers.Done()
		streamLines(stderr, func(line string) { emit("run:log", map[string]any{"source": "memprocfs", "line": line}) })
		io.Copy(io.Discard, stderr)
	}()

	watchCtx, stopWatch := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() { defer close(watchDone); watchProgress(watchCtx, mountDir, outputDir, emit, onScanComplete) }()

	waitErr := cmd.Wait()
	stdoutWriter.Close()
	stderrWriter.Close()
	readers.Wait()
	diagnostics.Finish(cmd, waitErr)
	stopWatch()
	<-watchDone
	if waitErr != nil && ctx.Err() == nil {
		// Process exited on its own (not due to our cancellation) — surface as an error.
		emit("memprocfs:status", map[string]any{"state": "error", "message": fmt.Sprintf("memprocfs exited unexpectedly: %v", waitErr)})
		return waitErr
	}
	emit("memprocfs:status", map[string]any{"state": "stopped", "message": "stopped"})
	return nil
}

// watchProgress polls MemProcFS's forensic/progress_percent.txt virtual
// file (inside the FUSE mount) until it reports 100%, then attempts the
// best-effort database copy into outputDir, reports scan-complete, and
// fires onScanComplete. It exits once it has reported completion, or
// immediately if ctx is cancelled first (e.g. the scan was stopped early).
func watchProgress(ctx context.Context, mountDir, outputDir string, emit Emitter, onScanComplete func()) {
	progressFile := filepath.Join(mountDir, "forensic", "progress_percent.txt")
	dbPointerFile := filepath.Join(mountDir, "forensic", "database.txt")
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	lastPct := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		data, err := os.ReadFile(progressFile)
		if err != nil {
			continue // forensic subsystem not mounted/ready yet
		}
		pct, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pct == lastPct {
			continue
		}
		lastPct = pct

		if pct < 100 {
			emit("memprocfs:status", map[string]any{"state": "running", "message": fmt.Sprintf("scanning… %d%%", pct)})
			continue
		}

		dbPath, copyErr := copyDatabase(dbPointerFile, outputDir)
		if copyErr != nil {
			// Expected with -forensic 1: the database is in-memory, so there
			// is nothing on disk to copy. The scan itself still succeeded.
			emit("memprocfs:status", map[string]any{"state": "scan-complete", "message": "forensic scan complete (results in mounted forensic/ directory; no on-disk database to copy)"})
		} else {
			emit("memprocfs:status", map[string]any{"state": "scan-complete", "dbPath": dbPath, "message": "forensic scan complete"})
		}
		if onScanComplete != nil {
			onScanComplete()
		}
		return
	}
}

func copyDatabase(dbPointerFile, outputDir string) (string, error) {
	raw, err := os.ReadFile(dbPointerFile)
	if err != nil {
		return "", fmt.Errorf("reading database pointer: %w", err)
	}
	srcPath := strings.TrimSpace(string(raw))
	if srcPath == "" {
		return "", fmt.Errorf("empty database path reported by memprocfs")
	}

	dstPath := filepath.Join(outputDir, filepath.Base(srcPath))
	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("creating %s: %w", dstPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copying database: %w", err)
	}
	return dstPath, nil
}

func streamLines(r io.Reader, onLine func(string)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		onLine(line)
	}
}
