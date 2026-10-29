package volatility

import (
	"context"
	"fmt"
	"memforensics-gui/internal/proc"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Framework identifies which Volatility major version runs a plugin. The two
// are separate programs with incompatible plugin sets, so every Plugin
// carries this and the runner dispatches on it.
const (
	FrameworkVol3 = "vol3"
	FrameworkVol2 = "vol2"
)

// Plugin describes one Volatility plugin as discovered from `vol -h`
// (Volatility 3) or `volatility --info` (Volatility 2).
type Plugin struct {
	Name        string `json:"name"`
	Framework   string `json:"framework"` // "vol3" | "vol2"
	Category    string `json:"category"`  // "windows" | "linux" | "mac" | "custom" | "generic"
	Description string `json:"description"`
	Loadable    bool   `json:"loadable"`
	// Redundant marks plugins whose output MemProcFS's forensic mount
	// already contains (see coverage.go); the UI hides these by default.
	Redundant       bool   `json:"redundant"`
	RedundantReason string `json:"redundantReason"`
	// AnalyzerRedundant marks plugins whose output MemProcFS-Analyzer
	// already produces; the UI hides these only when the analyzer is
	// enabled for the run.
	AnalyzerRedundant bool   `json:"analyzerRedundant"`
	AnalyzerReason    string `json:"analyzerReason"`
	// LowValue marks plugins that are utilities, framework introspection,
	// bulk dumpers or dead-malware scanners rather than triage signal. The
	// fields are retained for compatibility; the UI no longer hides these plugins.
	LowValue       bool   `json:"lowValue"`
	LowValueReason string `json:"lowValueReason"`
	// Note is a short caveat shown in the UI tooltip for plugins kept
	// despite partially overlapping MemProcFS (e.g. the pool-scan family).
	Note string `json:"note"`
	// SupportsPID means the plugin declares a PID/PIDs option. PID is an
	// optional narrowing filter in the current catalogs; no discovered plugin
	// requires it merely to start.
	SupportsPID bool `json:"supportsPID"`
	// RequiresYaraRules marks the generic YARA scanners that need a rule string
	// or file supplied by the user. Custom detection plugins embed their own
	// rules and are deliberately not marked.
	RequiresYaraRules bool `json:"requiresYaraRules"`
}

const unloadablePrefix = "volatility3.plugins."

// tail returns the last n non-empty lines of s, so a probe failure error can
// carry the actual crash/traceback instead of discarding it.
func tail(s string, n int) string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// lastLine returns the last non-empty line of s — for a crashing Python
// probe that is normally the exception type and message, which is a useful
// one-line summary without dumping the whole traceback into the UI.
func lastLine(s string) string {
	t := tail(s, 1)
	if t == "" {
		return "no output"
	}
	return strings.TrimSpace(t)
}

// ListPlugins shells out to `vol -h` and parses the full plugin catalog,
// including plugins that failed to load because of missing optional
// dependencies (e.g. yarascan needing yara-python). Those are returned with
// Loadable=false rather than silently omitted, so the UI can show why a
// plugin isn't selectable instead of just leaving it absent.
//
// The returned warning is non-empty when the custom plugin dirs (-p) made
// vol crash outright rather than just refusing individual plugins — some
// vendored community plugins deliberately share a package name with vol3's
// own ("windows/"), which occasionally provokes a namespace-package circular
// import in vol3's loader. That is a vol3/plugin-layout fragility, not
// something an empty or broken tool install caused, so it is worth retrying
// once without -p rather than failing the whole catalog over it.
func ListPlugins(ctx context.Context, volPath string) ([]Plugin, string, error) {
	pluginDirs := PluginDirs()

	plugins, out, err := probePlugins(ctx, volPath, pluginDirs)
	warning := ""
	if len(plugins) == 0 && len(pluginDirs) > 0 {
		firstOut := out
		plugins, out, err = probePlugins(ctx, volPath, nil)
		if len(plugins) > 0 {
			warning = fmt.Sprintf("custom plugin directories failed to load, continuing without them; %s",
				lastLine(firstOut))
		}
	}
	if err != nil && len(plugins) == 0 {
		return nil, "", err
	}
	if len(plugins) == 0 {
		return nil, "", fmt.Errorf("no plugins found in '%s -h' output; is this a working Volatility3 install?\n\n%s",
			volPath, tail(out, 40))
	}

	// Plugins loaded from the custom plugin dirs get their own category so
	// the picker can group them; they're recognized by their top-level
	// module name matching a .py file in one of those dirs.
	// A custom plugin's name is <module>.<Class> for a flat file, or
	// <subdir>.<module>.<Class> for one in a subdirectory — so both the
	// first and the first-two dotted segments have to be checked against
	// the known custom module names.
	customModules := customModuleNames(pluginDirs)
	for i := range plugins {
		parts := strings.Split(plugins[i].Name, ".")
		if len(parts) > 0 && customModules[parts[0]] {
			plugins[i].Category = "custom"
			continue
		}
		if len(parts) > 1 && customModules[parts[0]+"."+parts[1]] {
			plugins[i].Category = "custom"
		}
	}
	annotateCoverage(plugins)

	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].Category != plugins[j].Category {
			return plugins[i].Category < plugins[j].Category
		}
		return plugins[i].Name < plugins[j].Name
	})
	return plugins, warning, nil
}

// probePlugins runs `vol -h` (optionally with -p pluginDirs) and parses the
// plugin catalog from its output.
func probePlugins(ctx context.Context, volPath string, pluginDirs []string) ([]Plugin, string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	args := append(pluginDirArgs(pluginDirs), symbolDirArgs()...)
	args = append(args, "-h")
	cmd := exec.CommandContext(probeCtx, volPath, args...)
	proc.Configure(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, "", fmt.Errorf("running '%s -h': %w", volPath, err)
	}
	return parsePluginList(string(out)), string(out), nil
}

func parsePluginList(output string) []Plugin {
	lines := strings.Split(output, "\n")

	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == "PLUGIN" {
			start = i + 1
			break
		}
	}
	if start == -1 {
		return nil
	}

	var plugins []Plugin
	var current *Plugin
	unloadableIdx := -1

	for i := start; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(strings.TrimSpace(line), "The following plugins could not be loaded") {
			unloadableIdx = i
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		indent := leadingSpaces(line)
		switch {
		case indent == 4:
			name, rest := splitNameAndRest(trimmed)
			plugins = append(plugins, Plugin{
				Name:        name,
				Framework:   FrameworkVol3,
				Category:    categorize(name),
				Description: rest,
				Loadable:    true,
			})
			current = &plugins[len(plugins)-1]
		case indent >= 8 && current != nil:
			if current.Description != "" {
				current.Description += " "
			}
			current.Description += trimmed
		}
	}

	if unloadableIdx != -1 {
		plugins = append(plugins, parseUnloadable(lines[unloadableIdx:])...)
	}

	return plugins
}

// parseUnloadable reads the comma-separated dotted module paths listed after
// the "could not be loaded" header (no class name suffix, since the class
// itself failed to import) and turns them into disabled Plugin entries.
func parseUnloadable(lines []string) []Plugin {
	var joined strings.Builder
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		joined.WriteString(strings.TrimSpace(line))
		joined.WriteString(" ")
	}

	var plugins []Plugin
	seen := map[string]bool{}
	for _, raw := range strings.Split(joined.String(), ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		name = strings.TrimPrefix(name, unloadablePrefix)
		if seen[name] {
			continue
		}
		seen[name] = true
		plugins = append(plugins, Plugin{
			Name:        name,
			Framework:   FrameworkVol3,
			Category:    categorize(name),
			Description: "Not available on this system; missing an optional dependency (run 'vol -vv' for details).",
			Loadable:    false,
		})
	}
	return plugins
}

func splitNameAndRest(trimmed string) (name string, rest string) {
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", ""
	}
	name = fields[0]
	rest = strings.TrimSpace(strings.TrimPrefix(trimmed, name))
	return name, rest
}

func categorize(name string) string {
	switch {
	case strings.HasPrefix(name, "windows."):
		return "windows"
	case strings.HasPrefix(name, "linux."):
		return "linux"
	case strings.HasPrefix(name, "mac."):
		return "mac"
	default:
		return "generic"
	}
}

func leadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r != ' ' {
			break
		}
		n++
	}
	return n
}
