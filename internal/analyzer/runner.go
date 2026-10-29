package analyzer

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// Emitter reports a progress event with an arbitrary JSON-serializable
// payload, matching internal/volatility's Emitter type.
type Emitter func(event string, payload any)

// Run launches MemProcFS-Analyzer via its standard command line:
//
//	powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script>
//
// MemProcFS-Analyzer is a Windows PowerShell script (it drives Windows-only
// tooling and Excel/ImportExcel output), so on any other OS this reports an
//
// Progress is reported via "analyzer:status" events (state: "running",
// "done", "error") and its console output is streamed as "run:log" events
// with source "analyzer".
//
//go:embed mounted.ps1
var mountedScript string

func Run(ctx context.Context, scriptPath, memprocfsPath, imagePath, mountRoot, outputRoot string, emit Emitter) error {
	if err := CheckDependencies(scriptPath); err != nil {
		emit("analyzer:status", map[string]any{"state": "error", "message": err.Error()})
		return err
	}
	if info, err := os.Stat(paths.ZircolitePython()); err != nil || info.IsDir() {
		err := fmt.Errorf("Zircolite Python missing at %s. Run Install dependencies, then Install / update tools under this Windows account", paths.ZircolitePython())
		emit("analyzer:status", map[string]any{"state": "error", "message": err.Error()})
		return err
	}
	var err error
	outputRoot, err = freshOutputDir(outputRoot)
	if err != nil {
		return err
	}
	emit("run:log", map[string]any{"source": "analyzer", "line": "Analyzer output: " + outputRoot})
	wrapper := filepath.Join(outputRoot, "run-mounted.ps1")
	if err := os.WriteFile(wrapper, []byte(mountedScript), 0600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", wrapper,
		"-AnalyzerScript", scriptPath, "-MemProcFSPath", memprocfsPath, "-ImagePath", imagePath, "-MountRoot", mountRoot, "-OutputRoot", outputRoot)
	proc.Configure(cmd)
	// The script resolves its Config.json and bundled tools relative to its
	// own folder, so run it from there.
	cmd.Dir = filepath.Dir(scriptPath)
	cmd.Env = append(os.Environ(), "MEMFORENSICS_ANALYZER_PYTHON="+paths.ZircolitePython())

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		emit("analyzer:status", map[string]any{"state": "error", "message": fmt.Sprintf("starting analyzer: %v", err)})
		return err
	}
	emit("analyzer:status", map[string]any{"state": "running", "message": "MemProcFS-Analyzer running…"})

	var complete atomic.Bool
	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		streamLines(stdout, func(line string) {
			if strings.TrimSpace(line) == "MEMFORENSICS_ANALYZER_COMPLETE" {
				complete.Store(true)
			}
			emit("run:log", map[string]any{"source": "analyzer", "line": line})
		})
	}()
	go func() {
		defer readers.Done()
		streamLines(stderr, func(line string) { emit("run:log", map[string]any{"source": "analyzer", "line": line}) })
	}()

	waitErr := cmd.Wait()
	readers.Wait()
	if waitErr == nil && ctx.Err() == nil && !complete.Load() {
		waitErr = fmt.Errorf("Analyzer ended before completing its mounted analysis; inspect its transcript")
	}
	if waitErr != nil && ctx.Err() == nil {
		emit("analyzer:status", map[string]any{"state": "error", "message": fmt.Sprintf("analyzer exited with error: %v", waitErr)})
		return waitErr
	}
	if ctx.Err() != nil {
		emit("analyzer:status", map[string]any{"state": "error", "message": "analyzer stopped"})
		return ctx.Err()
	}
	emit("analyzer:status", map[string]any{"state": "done", "message": "analyzer finished"})
	return nil
}

// Upstream renames and expands files in place and cannot safely reuse output.
// Preserve earlier evidence instead of overwriting or deleting it on reruns.
func freshOutputDir(root string) (string, error) {
	dir := filepath.Join(root, "Analyzer")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return dir, nil
	}
	return os.MkdirTemp(dir, "run-")
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
