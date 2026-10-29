// Package memnixfs drives MemNixFS (github.com/MemNixFS/MemNixFS), an
// independent, Apache-2.0 tool that reads Linux memory dumps (AVML, LiME,
// raw, kdump) and presents them as a browsable filesystem — the MemProcFS
// idea, brought to Linux images, which MemProcFS itself cannot read.
//
// MemNixFS is not affiliated with or endorsed by MemProcFS or Volatility —
// see its README's "Acknowledgements" section — but is interoperable with
// both and independently useful for Linux triage.
package memnixfs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Emitter matches the Emitter type used elsewhere in the app.
type Emitter func(event string, payload any)

// ExportSubtrees are the parts of MemNixFS's virtual filesystem this app
// writes out, rather than exporting the whole tree.
//
// Exporting everything is not viable, and MemNixFS's own README says so —
// "Whole tree is huge; pass a subtree". Measured on a 4 GiB VMware image, a
// full export produced 19 GB and filled the disk. Essentially all of it was a
// single file: proc/347-systemd-udevd/proc.dmp, at 18.3 GB. That file is a
// process dump indexed by *virtual* address, and that process's mappings ran
// from 0x57f163927000 (heap) to 0x7ffe57bf2000 (stack) — a 41 TB span under
// ASLR — with the unmapped holes in between written out as zero bytes. Every
// 64-bit process has that shape, so the blow-up is a property of the format,
// not of one unusual process.
//
// The excluded subtrees are excluded for concrete reasons:
//
//   - /proc — the per-process dumps above.
//   - /mem  — holds phys.raw, a verbatim copy of the image already on disk.
//   - /fs   — recovered cached file contents; unbounded, and closer to file
//     carving than to the triage the rest of a run produces.
//   - /search — strings and entropy over the whole image, again unbounded.
//
// What is kept is what MemNixFS's README calls out as the integration
// surface ("indexes /sys and /forensic with zero new integration"): the
// system-wide triage (findevil, dmesg, modules, network, processes, shell
// history) and the timeline. Both are small and are the parts an analyst
// actually reads. Anything deliberately left out is still reachable by
// running MemNixFS directly against the same image.
var ExportSubtrees = []string{"/sys", "/forensic"}

// RunExport runs MemNixFS against a Linux memory image in its non-interactive
// "export" mode, which walks the whole reconstructed filesystem view
// (proc/, sys/, fs/, forensic/, search/) and writes it under
// outputDir/memnixfs. Export is used instead of "mount" deliberately: mount
// needs WinFsp on Windows (a kernel driver this app cannot silently install)
// and a live drive letter, while export needs neither and still produces
// everything as ordinary files the Results panel already knows how to
// summarise, matching how Volatility's plugin output already lands in
// outputDir.
//
// symbolsPath is an ISF file for this image's exact kernel, resolved up front
// by internal/linuxsymbols. It must be a single file matching this image's
// banner, never a directory of assorted ISFs, and "" when nothing matched.
//
// What is deliberately NOT passed here is as important as what is:
//
//   - --auto-fetch, which this used to send, is documented as running
//     tools/fetch_symbols.sh, and MemNixFS's Windows release ships no tools/
//     directory at all — so it could only ever fail on this platform, leaving
//     MemNixFS to report that the analyst should supply --vmlinux by hand.
//
//   - --symbol-cache is not passed either, even though pointing MemNixFS's
//     downloads at this app's symbol directory would look convenient for
//     sharing them with Volatility 3. Its help says that flag *overrides* the
//     default cache (%LOCALAPPDATA%\MemNixFS\symbols) rather than adding to
//     it. In practice, on an Ubuntu 6.5.0-41 image, MemNixFS still found that
//     default cache and loaded from it with the flag set — so this is not a
//     measured failure, only an unnecessary risk: the flag buys nothing here
//     (MemNixFS still saved to its own default) while documented as
//     displacing the cache its own symbol discovery depends on.
//
// So MemNixFS keeps its own symbol discovery intact and is only ever *given*
// an exact match when this app has one. Volatility 3 does not depend on this
// path at all: it resolves symbols through --remote-isf-url and --symbol-dirs
// independently.
//
// Unlike MemProcFS's forensic scan, MemNixFS's export command runs to
// completion and exits on its own — there is no persistent mount to keep
// alive afterwards, so this function returns once the process exits.
func RunExport(ctx context.Context, memnixfsPath, imagePath, outputDir, symbolsPath string, emit Emitter) error {
	exportDir := filepath.Join(outputDir, "memnixfs")
	if err := os.MkdirAll(exportDir, 0o755); err != nil {
		err = fmt.Errorf("creating %s: %w", exportDir, err)
		emit("memnixfs:status", map[string]any{"state": "error", "message": err.Error()})
		return err
	}

	var firstErr error
	for i, subtree := range ExportSubtrees {
		if ctx.Err() != nil {
			break
		}
		dest := filepath.Join(exportDir, strings.TrimPrefix(subtree, "/"))
		if err := os.MkdirAll(dest, 0o755); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		emit("memnixfs:status", map[string]any{"state": "running",
			"message": fmt.Sprintf("exporting %s (%d/%d)…", subtree, i+1, len(ExportSubtrees))})
		if err := exportSubtree(ctx, memnixfsPath, imagePath, symbolsPath, subtree, dest, emit); err != nil {
			if ctx.Err() != nil {
				emit("memnixfs:status", map[string]any{"state": "stopped", "message": "stopped"})
				return ctx.Err()
			}
			// One subtree failing should not cost the others — they are
			// separate invocations producing independent output.
			emit("run:log", map[string]any{"source": "memnixfs",
				"line": fmt.Sprintf("export of %s failed: %v", subtree, err)})
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if ctx.Err() != nil {
		emit("memnixfs:status", map[string]any{"state": "stopped", "message": "stopped"})
		return ctx.Err()
	}
	if firstErr != nil {
		emit("memnixfs:status", map[string]any{"state": "error",
			"message": "some exports failed: " + firstErr.Error()})
		return firstErr
	}
	emit("memnixfs:status", map[string]any{"state": "scan-complete",
		"message": "export complete", "exportDir": exportDir})
	return nil
}

// exportSubtree runs one `memnixfs … export <subtree> <dest>` invocation.
func exportSubtree(ctx context.Context, memnixfsPath, imagePath, symbolsPath, subtree, dest string, emit Emitter) error {
	args := []string{"--dump", imagePath}
	if strings.TrimSpace(symbolsPath) != "" {
		args = append(args, "--symbols", symbolsPath)
	}
	args = append(args, "export", subtree, dest)
	cmd := exec.CommandContext(ctx, memnixfsPath, args...)
	proc.Configure(cmd)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting memnixfs: %w", err)
	}

	go streamLines(stdout, func(line string) { emit("run:log", map[string]any{"source": "memnixfs", "line": line}) })
	go streamLines(stderr, func(line string) { emit("run:log", map[string]any{"source": "memnixfs", "line": line}) })

	return cmd.Wait()
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
