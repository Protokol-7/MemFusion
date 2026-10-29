package volatility

import (
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
	"time"
)

// Emitter reports a progress event with an arbitrary JSON-serializable
// payload. In the running app this wraps runtime.EventsEmit; kept as a
// plain function type here so this package stays importable and testable
// without pulling in Wails.
type Emitter func(event string, payload any)

// RunSummary is emitted once all plugins have finished (or the run was
// cancelled).
type RunSummary struct {
	Total     int     `json:"total"`
	Succeeded int     `json:"succeeded"`
	Failed    int     `json:"failed"`
	Seconds   float64 `json:"seconds"`
}

// RunPlugins runs each selected plugin against imagePath one at a time,
// writing one CSV per plugin to outputDir, and reports progress via emit.
//
// This was originally a direct port of vol_wrapper.go's goroutine-pool
// pattern (~/tools/VolGolangWrapper/vol_wrapper.go), running several
// plugins concurrently (first uncapped at NumCPU-1, then capped at a fixed
// 4). Both were abandoned after two separate real OOM-kills of a running
// `vol` process on an 8-core/7.7GB-RAM machine — a single plugin can use
// several GB scanning a large image on its own, so any concurrency here
// risks exhausting memory on smaller machines. Plugins now run strictly
// sequentially; ctx is still checked between each one so StopRun can skip
// any not yet started.
func RunPlugins(ctx context.Context, volPath, imagePath, outputDir string, plugins []string,
	autoFetchLinuxSymbols, pidEnabled bool, targetPID int, yaraRulesPath string, emit Emitter) RunSummary {
	summary := RunSummary{Total: len(plugins)}
	start := time.Now()

	for _, plugin := range plugins {
		if ctx.Err() != nil {
			break
		}

		if runOnePlugin(ctx, volPath, imagePath, outputDir, plugin, autoFetchLinuxSymbols,
			pidEnabled, targetPID, yaraRulesPath, emit) {
			summary.Succeeded++
		} else {
			summary.Failed++
		}
	}

	summary.Seconds = time.Since(start).Seconds()
	return summary
}

func runOnePlugin(ctx context.Context, volPath, imagePath, outputDir, plugin string,
	autoFetchLinuxSymbols, pidEnabled bool, targetPID int, yaraRulesPath string, emit Emitter) bool {
	start := time.Now()
	emit("vol3:plugin-start", map[string]any{"plugin": plugin})

	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s_%s.csv", filepath.Base(imagePath), plugin))
	f, err := os.Create(outputFile)
	if err != nil {
		emit("vol3:plugin-done", map[string]any{
			"plugin": plugin, "seconds": time.Since(start).Seconds(),
			"ok": false, "error": fmt.Sprintf("creating output file: %v", err),
		})
		return false
	}
	defer f.Close()

	args := append(pluginDirArgs(PluginDirs()), symbolDirArgs()...)
	// Online symbol lookup only makes sense (and only gets attempted) for
	// linux.* plugins — see remoteISFArgs and RemoteISFSources.
	if autoFetchLinuxSymbols && categorize(plugin) == "linux" {
		args = append(args, remoteISFArgs()...)
	}
	args = append(args, "-f", imagePath, "-r", "csv", plugin)
	if pidEnabled && SupportsPID(FrameworkVol3, plugin) {
		args = append(args, "--pid", strconv.Itoa(targetPID))
	}
	if RequiresYaraRules(plugin) && strings.TrimSpace(yaraRulesPath) != "" {
		args = append(args, "--yara-file", yaraRulesPath)
	}
	cmd := exec.CommandContext(ctx, volPath, args...)
	proc.Configure(cmd)
	cmd.Stdout = f
	// Captured (not discarded, unlike the original CLI tool) so failures are
	// diagnosable — but capped: vol continuously rewrites progress lines on
	// stderr, which over a multi-hour plugin run on a large image adds up to
	// serious memory held for nothing. Only the tail is ever shown anyway.
	//
	// It's also piped rather than buffered-only so vol's live progress can be
	// forwarded to the UI while the plugin runs; without this a slow plugin
	// looks indistinguishable from a hung one.
	stderrBuf := &tailBuffer{max: 8 * 1024}
	stderrPipe, stderrWriter := io.Pipe()
	defer stderrPipe.Close()
	defer stderrWriter.Close()
	cmd.Stderr = stderrWriter

	diagnostics := debuglog.Attach(cmd, outputDir, "vol3-"+plugin, false, func(message string) {
		emit("run:log", map[string]any{"source": "vol3", "line": message})
	})
	fmt.Fprintf(diagnostics, "Plugin output: %s\n", f.Name())
	if err := cmd.Start(); err != nil {
		diagnostics.Finish(cmd, err)
		emit("vol3:plugin-done", map[string]any{
			"plugin": plugin, "seconds": time.Since(start).Seconds(),
			"ok": false, "error": fmt.Sprintf("starting vol: %v", err),
		})
		return false
	}
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		streamProgress(stderrPipe, stderrBuf, progressInterval, func(text string) {
			emit("tool:progress", map[string]any{
				"tool": "vol3", "item": plugin, "text": text,
			})
		})
		io.Copy(io.Discard, stderrPipe)
	}()
	stopBeat := startHeartbeat("vol3", plugin, emit)

	runErr := cmd.Wait()
	stderrWriter.Close()
	<-streamDone
	defer diagnostics.Finish(cmd, runErr)
	stopBeat()
	seconds := time.Since(start).Seconds()

	if runErr != nil {
		emit("vol3:plugin-done", map[string]any{
			"plugin": plugin, "seconds": seconds,
			"ok": false, "error": errorDetail(runErr, stderrBuf.String()),
		})
		return false
	}

	// vol3 exits 0 even when it refuses to run a plugin whose declared
	// dependency versions don't match the installed framework — it writes the
	// refusal into the output file and calls it a day. Without this check the
	// run is reported as a success and the failure is only discovered later,
	// when someone opens a CSV containing an error message instead of data.
	if reason := unsatisfiedRequirement(outputFile); reason != "" {
		fmt.Fprintf(diagnostics, "Plugin refused execution: %s\n", reason)
		emit("vol3:plugin-done", map[string]any{
			"plugin": plugin, "seconds": seconds, "ok": false,
			"error": reason + "; the plugin needs updating for this Volatility 3 version " +
				"(run scripts/patch_plugins_for_vol3.py)",
		})
		return false
	}

	emit("vol3:plugin-done", map[string]any{
		"plugin": plugin, "seconds": seconds, "ok": true, "error": "",
	})
	return true
}

// unsatisfiedRequirement returns vol3's dependency-refusal message if the
// plugin's output turns out to be one, or "" for genuine output. Only the
// head of the file is read: the message is written at the very start, and
// real output can be hundreds of megabytes.
func unsatisfiedRequirement(outputFile string) string {
	f, err := os.Open(outputFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	head := string(buf[:n])
	if !strings.Contains(head, "Unsatisfied requirement") {
		return ""
	}
	for _, line := range strings.Split(head, "\n") {
		if strings.Contains(line, "Unsatisfied requirement") {
			return strings.TrimSpace(line)
		}
	}
	return "unsatisfied plugin requirement"
}

// maxErrorDetailLen caps how much of a plugin's stderr gets surfaced to the
// UI. Some vol3 errors (e.g. an invalid plugin name) dump argparse's full
// "choose from <all 181 plugins>" text as a single unwrapped line, which
// line-based truncation alone doesn't help with.
const maxErrorDetailLen = 300

func errorDetail(err error, stderr string) string {
	tail := trimToLastLines(stderr, 3)
	if tail == "" {
		return err.Error()
	}
	if len(tail) > maxErrorDetailLen {
		tail = tail[:maxErrorDetailLen] + "…"
	}
	return fmt.Sprintf("%v: %s", err, tail)
}

// tailBuffer is an io.Writer that keeps only the last max bytes written.
type tailBuffer struct {
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.buf) }

func trimToLastLines(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
