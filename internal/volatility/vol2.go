package volatility

import (
	"bufio"
	"context"
	"fmt"
	"memforensics-gui/internal/proc"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Volatility 2 is a separate, Python-2-era program with its own plugin set
// and its own calling convention. This file keeps all of that isolated from
// the Volatility 3 paths: discovery parses `volatility --info` instead of
// `vol -h`, and running a plugin requires a --profile, which vol3 determines
// automatically but vol2 cannot.
//
// The install path used by this app is the official
// `volatility_2.6_lin64_standalone` build, which bundles its own Python 2
// interpreter — verified to run on a modern system with no python2 present.

// vol2PluginLine matches the "  name   - description" rows in the Plugins
// section of `volatility --info`.
var vol2PluginLine = regexp.MustCompile(`^([a-z0-9_]+)\s+-\s+(.*)$`)

// ListVol2Plugins parses `<vol2Path> --info` into the plugin catalog. Unlike
// vol3, vol2 reports no per-plugin load failures, so everything listed is
// marked Loadable.
func ListVol2Plugins(ctx context.Context, vol2Path string) ([]Plugin, error) {
	if strings.TrimSpace(vol2Path) == "" {
		return nil, nil // vol2 not configured — not an error, just no vol2 plugins
	}
	probeCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	pluginDirs := Vol2PluginDirs()
	args := append(vol2PluginDirArgs(pluginDirs), "--info")
	cmd := exec.CommandContext(probeCtx, vol2Path, args...)
	proc.Configure(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("running '%s --info': %w", vol2Path, err)
	}

	plugins := parseVol2Info(string(out))
	if len(plugins) == 0 {
		return nil, fmt.Errorf("no plugins found in '%s --info' output; is this a working Volatility 2 install?", vol2Path)
	}

	// Volatility 2 gives no indication of which plugins came from --plugins
	// dirs, and silently skips any whose imports fail (several community
	// plugins need modules the frozen standalone doesn't bundle). Matching
	// the discovered names against the .py files present is therefore the
	// only way to tag customs — and it self-corrects, since a plugin that
	// failed to import simply never appears in the output.
	customNames := vol2CustomNames(pluginDirs)
	for i := range plugins {
		if customNames[plugins[i].Name] {
			plugins[i].Category = "custom"
		}
	}
	sort.Slice(plugins, func(i, j int) bool { return plugins[i].Name < plugins[j].Name })
	return plugins, nil
}

// parseVol2Info reads only the "Plugins" section of --info. The same output
// also lists Profiles, Address Spaces and Scanner Checks in the identical
// "name - description" shape, so section tracking (not just line shape) is
// what keeps those out of the catalog.
func parseVol2Info(output string) []Plugin {
	var plugins []Plugin
	inPlugins := false
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		// Section headers are underlined with dashes; the header itself is
		// the line before. Track entry into "Plugins" and exit at the next
		// header.
		if trimmed == "Plugins" {
			inPlugins = true
			continue
		}
		if inPlugins && isVol2SectionHeader(trimmed) {
			break
		}
		if !inPlugins || trimmed == "" || strings.HasPrefix(trimmed, "---") {
			continue
		}
		m := vol2PluginLine.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		name := m[1]
		plugins = append(plugins, Plugin{
			Name:        name,
			Framework:   FrameworkVol2,
			Category:    categorizeVol2(name),
			Description: strings.TrimSpace(m[2]),
			Loadable:    true,
		})
	}
	return plugins
}

func isVol2SectionHeader(line string) bool {
	switch line {
	case "Profiles", "Address Spaces", "Scanner Checks":
		return true
	}
	return false
}

// categorizeVol2 buckets vol2 plugins by their name prefix: vol2 namespaces
// its Linux and Mac plugins as linux_*/mac_*, and everything else is either
// Windows-specific or image-format generic.
func categorizeVol2(name string) string {
	switch {
	case strings.HasPrefix(name, "linux_"):
		return "linux"
	case strings.HasPrefix(name, "mac_"):
		return "mac"
	}
	switch name {
	case "imageinfo", "kdbgscan", "kpcrscan", "crashinfo", "hpakinfo", "hpakextract",
		"imagecopy", "raw2dmp", "vboxinfo", "vmwareinfo", "hibinfo", "machoinfo",
		"limeinfo", "qemuinfo", "strings", "volshell", "patcher", "bioskbd":
		return "generic"
	}
	return "windows"
}

// profileLine matches imageinfo's "Suggested Profile(s) : A, B, C" row.
var profileLine = regexp.MustCompile(`Suggested Profile\(s\)\s*:\s*(.+)`)

// DetectVol2Profile runs vol2's imageinfo against the image and returns the
// first suggested profile. Volatility 2 cannot analyse an image without one,
// and unlike vol3 (which resolves symbols itself) there is no autodetection
// at plugin runtime — hence this separate, and slow, scanning pass.
//
// This only works for Windows images: vol2 Linux/Mac support requires a
// hand-built profile .zip that cannot be derived from the image, so callers
// should expect an error there and surface it rather than retrying.
func DetectVol2Profile(ctx context.Context, volPath, vol2Path, imagePath string, emit Emitter) (string, error) {
	// A previously detected profile for this exact image is reused: imageinfo
	// is a whole-image scan costing tens of minutes on a large dump, and its
	// answer never changes for a given image.
	if cached := CachedVol2Profile(imagePath); cached != "" {
		emit("vol2:status", map[string]any{"state": "profiled", "profile": cached,
			"message": "Volatility 2 profile: " + cached + " (cached from a previous run; skipping imageinfo)"})
		return cached, nil
	}

	// Fast path: ask Volatility 3 what the image is (sub-second, because it
	// identifies the kernel by PDB rather than scanning) and map that to a
	// vol2 profile. This also catches the common and otherwise very expensive
	// case where vol2 has no profile for the image at all — imageinfo would
	// scan for tens of minutes before failing to converge on such an image.
	if strings.TrimSpace(volPath) != "" {
		emit("vol2:status", map[string]any{"state": "profiling",
			"message": "identifying image with Volatility 3 (fast)…"})
		if info, err := DescribeImageWithVol3(ctx, volPath, imagePath); err == nil {
			emit("run:log", map[string]any{"source": "vol2", "line": "image identified as " + info.String()})
			profile, pickErr := PickVol2Profile(ctx, vol2Path, info)
			if pickErr != nil {
				// Not a failure to detect — a definite answer that vol2
				// cannot analyse this image. Report it instead of spending
				// tens of minutes in imageinfo to reach the same conclusion.
				return "", pickErr
			}
			if err := StoreVol2Profile(imagePath, profile); err != nil {
				emit("run:log", map[string]any{"source": "vol2", "line": "could not cache profile: " + err.Error()})
			}
			emit("vol2:status", map[string]any{"state": "profiled", "profile": profile,
				"message": fmt.Sprintf("Volatility 2 profile: %s (derived from %s in seconds, cached)", profile, info)})
			return profile, nil
		} else {
			emit("run:log", map[string]any{"source": "vol2",
				"line": "fast identification failed (" + err.Error() + "); falling back to imageinfo"})
		}
	}

	emit("vol2:status", map[string]any{"state": "profiling",
		"message": "detecting Volatility 2 profile (imageinfo); this scans the whole image and can take tens of minutes; set the profile manually in Configure to skip it"})

	args := append(vol2PluginDirArgs(Vol2PluginDirs()), "-f", imagePath, "imageinfo")
	cmd := exec.CommandContext(ctx, vol2Path, args...)
	proc.Configure(cmd)

	// imageinfo is the slowest opaque step in a run — it scans the whole
	// image for the KDBG and can take many minutes while printing only
	// carriage-return progress updates. Buffering it (CombinedOutput) meant
	// the UI showed a frozen "detecting profile…" for the entire time, so
	// stdout and stderr are streamed instead: stdout is captured for the
	// profile match, stderr is forwarded live as progress.
	var outBuf strings.Builder
	stdoutPipe, outErr := cmd.StdoutPipe()
	stderrPipe, errErr := cmd.StderrPipe()
	if outErr != nil || errErr != nil {
		return "", fmt.Errorf("preparing imageinfo pipes: %v %v", outErr, errErr)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("starting imageinfo: %w", err)
	}

	stopBeat := startHeartbeat("vol2", "imageinfo", emit)
	defer stopBeat()

	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			outBuf.WriteString(line)
			outBuf.WriteString("\n")
			if strings.TrimSpace(line) != "" {
				emit("run:log", map[string]any{"source": "vol2", "line": line})
			}
		}
	}()
	go streamProgress(stderrPipe, nil, progressInterval, func(text string) {
		emit("tool:progress", map[string]any{"tool": "vol2", "item": "imageinfo", "text": text})
	})

	err := cmd.Wait()
	<-done // let the stdout reader finish so outBuf is complete
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	out := outBuf.String()
	m := profileLine.FindStringSubmatch(out)
	if m == nil {
		if err != nil {
			return "", fmt.Errorf("imageinfo failed: %v: %s", err, trimToLastLines(out, 2))
		}
		return "", fmt.Errorf("imageinfo reported no suggested profile; for Linux/macOS images Volatility 2 needs a hand-built profile, which this app cannot generate")
	}
	// "Win10x64_19041, Win10x64_18362, ..." — the first is vol2's best guess.
	first := strings.TrimSpace(strings.Split(m[1], ",")[0])
	if first == "" {
		return "", fmt.Errorf("could not parse a profile from imageinfo output")
	}
	// Cache it so no future run of this image pays for imageinfo again.
	if err := StoreVol2Profile(imagePath, first); err != nil {
		emit("run:log", map[string]any{"source": "vol2", "line": "could not cache profile: " + err.Error()})
	}
	emit("vol2:status", map[string]any{"state": "profiled", "profile": first,
		"message": "Volatility 2 profile: " + first + " (cached for future runs)"})
	return first, nil
}
