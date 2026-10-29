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
	"time"
)

// RunVol2Plugins runs the selected Volatility 2 plugins sequentially against
// imagePath, writing one .txt per plugin into outputDir.
//
// Output is plain text, not CSV: vol2's --output=csv is implemented per
// plugin (via its own renderer) rather than framework-wide, so requesting it
// makes any plugin lacking a CSV renderer fail outright. Text is the only
// format every vol2 plugin supports, so it's what we ask for.
//
// Plugins run one at a time for the same reason as the vol3 path — a single
// plugin scanning a large image can consume several GB, and this app has
// already been OOM-killed doing that concurrently.
func RunVol2Plugins(ctx context.Context, vol2Path, imagePath, outputDir, profile string, plugins []string,
	pidEnabled bool, targetPID int, yaraRulesPath string, emit Emitter) RunSummary {
	summary := RunSummary{Total: len(plugins)}
	start := time.Now()

	for _, plugin := range plugins {
		if ctx.Err() != nil {
			break
		}
		if runOneVol2Plugin(ctx, vol2Path, imagePath, outputDir, profile, plugin,
			pidEnabled, targetPID, yaraRulesPath, emit) {
			summary.Succeeded++
		} else {
			summary.Failed++
		}
	}

	summary.Seconds = time.Since(start).Seconds()
	return summary
}

func runOneVol2Plugin(ctx context.Context, vol2Path, imagePath, outputDir, profile, plugin string,
	pidEnabled bool, targetPID int, yaraRulesPath string, emit Emitter) bool {
	start := time.Now()
	// Prefixed so the UI can tell a vol2 row from a vol3 row with the same
	// plugin name (cmdscan, consoles, malfind… exist in both).
	label := "vol2:" + plugin
	emit("vol3:plugin-start", map[string]any{"plugin": label})

	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s_vol2_%s.txt", filepath.Base(imagePath), plugin))
	f, err := os.Create(outputFile)
	if err != nil {
		emit("vol3:plugin-done", map[string]any{
			"plugin": label, "seconds": time.Since(start).Seconds(),
			"ok": false, "error": fmt.Sprintf("creating output file: %v", err),
		})
		return false
	}
	defer f.Close()

	args := vol2PluginDirArgs(Vol2PluginDirs())
	args = append(args, "-f", imagePath)
	if profile != "" {
		args = append(args, "--profile="+profile)
	}
	args = append(args, plugin)
	if pidEnabled && SupportsPID(FrameworkVol2, plugin) {
		args = append(args, "--pid="+strconv.Itoa(targetPID))
	}
	if RequiresYaraRules(plugin) && yaraRulesPath != "" {
		args = append(args, "--yara-file="+yaraRulesPath)
	}

	cmd := exec.CommandContext(ctx, vol2Path, args...)
	proc.Configure(cmd)
	cmd.Stdout = f
	stderrBuf := &tailBuffer{max: 8 * 1024}
	stderrPipe, stderrWriter := io.Pipe()
	defer stderrPipe.Close()
	defer stderrWriter.Close()
	cmd.Stderr = stderrWriter

	diagnostics := debuglog.Attach(cmd, outputDir, "vol2-"+plugin, false, func(message string) {
		emit("run:log", map[string]any{"source": "vol2", "line": message})
	})
	fmt.Fprintf(diagnostics, "Plugin output: %s\n", f.Name())
	if err := cmd.Start(); err != nil {
		diagnostics.Finish(cmd, err)
		emit("vol3:plugin-done", map[string]any{
			"plugin": label, "seconds": time.Since(start).Seconds(),
			"ok": false, "error": fmt.Sprintf("starting vol2: %v", err),
		})
		return false
	}
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		streamProgress(stderrPipe, stderrBuf, progressInterval, func(text string) {
			emit("tool:progress", map[string]any{
				"tool": "vol2", "item": label, "text": text,
			})
		})
		io.Copy(io.Discard, stderrPipe)
	}()
	stopBeat := startHeartbeat("vol2", label, emit)

	runErr := cmd.Wait()
	stderrWriter.Close()
	<-streamDone
	defer diagnostics.Finish(cmd, runErr)
	stopBeat()
	seconds := time.Since(start).Seconds()

	if runErr != nil {
		emit("vol3:plugin-done", map[string]any{
			"plugin": label, "seconds": seconds,
			"ok": false, "error": errorDetail(runErr, stderrBuf.String()),
		})
		return false
	}
	emit("vol3:plugin-done", map[string]any{
		"plugin": label, "seconds": seconds, "ok": true, "error": "",
	})
	return true
}

// SplitByFramework partitions selected plugin names into vol2 and vol3 sets
// using the discovered catalog. Names not found in the catalog are treated as
// vol3, which is what the app produced before vol2 support existed.
func SplitByFramework(catalog []Plugin, selected []string) (vol2 []string, vol3 []string) {
	framework := make(map[string]string, len(catalog))
	for _, p := range catalog {
		framework[p.Name] = p.Framework
	}
	for _, name := range selected {
		if framework[name] == FrameworkVol2 {
			vol2 = append(vol2, name)
		} else {
			vol3 = append(vol3, name)
		}
	}
	return vol2, vol3
}
