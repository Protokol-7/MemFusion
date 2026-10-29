package config

import (
	"context"
	"fmt"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToolStatus is the result of probing a single external tool executable.
type ToolStatus struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	Executable bool   `json:"executable"`
	ProbeOK    bool   `json:"probeOk"`
	Detail     string `json:"detail"`
	Error      string `json:"error"`
}

// ValidationResult bundles the probe results for every external tool.
type ValidationResult struct {
	Vol       ToolStatus `json:"vol"`
	Vol2      ToolStatus `json:"vol2"`
	MemProcfs ToolStatus `json:"memProcfs"`
	MemNixFs  ToolStatus `json:"memNixFs"`
	Analyzer  ToolStatus `json:"analyzer"`
}

// ToolPaths is the set of configured tool locations to validate. Optional
// tools may be empty, which is reported as "not configured" rather than as
// a failure.
type ToolPaths struct {
	VolPath       string `json:"volPath"`
	Vol2Path      string `json:"vol2Path"`
	MemProcfsPath string `json:"memProcfsPath"`
	MemNixFsPath  string `json:"memNixFsPath"`
	AnalyzerPath  string `json:"analyzerPath"`
}

// Validate probes every configured tool path and reports whether each looks
// like a working install. Each probe runs the tool and inspects its output,
// so a file that exists but is the wrong program, or one that cannot resolve
// its shared libraries, is reported as broken rather than as present.
func Validate(paths ToolPaths) ValidationResult {
	return ValidationResult{
		Vol:       probeVol(paths.VolPath),
		Vol2:      probeVol2(paths.Vol2Path),
		MemProcfs: probeMemProcfs(paths.MemProcfsPath),
		MemNixFs:  probeMemNixFs(paths.MemNixFsPath),
		Analyzer:  probeAnalyzer(paths.AnalyzerPath),
	}
}

// optionalNotConfigured builds the status for an optional tool the user has
// left blank — distinct from a configured-but-broken tool.
func optionalNotConfigured(note string) ToolStatus {
	return ToolStatus{Detail: note}
}

func probeVol2(path string) ToolStatus {
	if strings.TrimSpace(path) == "" {
		return optionalNotConfigured("not configured; Volatility 2 plugins will be unavailable")
	}
	status := ToolStatus{Path: path}
	exists, executable, err := statFile(path)
	status.Exists = exists
	status.Executable = executable
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !executable {
		status.Error = "file is not executable"
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--info")
	proc.Configure(cmd)
	out, runErr := cmd.CombinedOutput()
	text := string(out)
	if !strings.Contains(text, "Volatility Foundation Volatility Framework") {
		if runErr != nil {
			status.Error = fmt.Sprintf("probe failed: %v", runErr)
		} else {
			status.Error = "output did not look like Volatility 2"
		}
		return status
	}
	status.ProbeOK = true
	status.Detail = "Volatility 2 detected"
	if v := firstLineContaining(text, "Volatility Framework"); v != "" {
		status.Detail = v + " detected"
	}
	return status
}

// probeAnalyzer checks the MemProcFS-Analyzer script. It is a PowerShell
// script rather than an executable, so it is validated by inspecting the
// file rather than by running it — executing an analyst's script as a
// side effect of clicking "Validate" would be surprising and slow.
func probeAnalyzer(path string) ToolStatus {
	if strings.TrimSpace(path) == "" {
		return optionalNotConfigured("not configured; the analyzer stage will be unavailable")
	}
	status := ToolStatus{Path: path}
	info, err := os.Stat(path)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if info.IsDir() {
		status.Error = "path is a directory, not MemProcFS-Analyzer.ps1"
		return status
	}
	status.Exists = true
	if !strings.EqualFold(filepath.Ext(path), ".ps1") {
		status.Error = "expected a .ps1 script"
		return status
	}
	data, err := os.ReadFile(path)
	if err != nil {
		status.Error = fmt.Sprintf("cannot read script: %v", err)
		return status
	}
	if !strings.Contains(string(data), "MemProcFS") {
		status.Error = "script does not mention MemProcFS; is this the right file?"
		return status
	}
	status.Executable = true
	status.ProbeOK = true
	status.Detail = "MemProcFS-Analyzer script found"
	return status
}

func firstLineContaining(text, needle string) string {
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, needle) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

func statFile(path string) (exists, executable bool, err error) {
	if strings.TrimSpace(path) == "" {
		return false, false, fmt.Errorf("no path given")
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return false, false, statErr
	}
	if info.IsDir() {
		return true, false, fmt.Errorf("path is a directory, not a file")
	}
	// Windows has no POSIX exec bit — os.FileInfo.Mode() never reports one,
	// so whether a file runs is determined by its extension instead.
	return true, isWindowsExecutableExt(path), nil
}

// isWindowsExecutableExt reports whether path's extension is one Windows
// will actually launch, mirroring the default PATHEXT set.
func isWindowsExecutableExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".com", ".bat", ".cmd":
		return true
	default:
		return false
	}
}

func probeVol(path string) ToolStatus {
	status := ToolStatus{Path: path}
	exists, executable, err := statFile(path)
	status.Exists = exists
	status.Executable = executable
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !executable {
		status.Error = "file is not executable"
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-h")
	proc.Configure(cmd)
	out, runErr := cmd.CombinedOutput()
	text := string(out)
	if !strings.Contains(text, "memory forensics framework") {
		if runErr != nil {
			status.Error = fmt.Sprintf("probe failed: %v", runErr)
		} else {
			status.Error = "output did not look like Volatility 3"
		}
		return status
	}
	status.ProbeOK = true
	status.Detail = "Volatility 3 detected"
	return status
}

func probeMemProcfs(path string) ToolStatus {
	status := ToolStatus{Path: path}
	exists, executable, err := statFile(path)
	status.Exists = exists
	status.Executable = executable
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !executable {
		status.Error = "file is not executable"
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// MemProcFS's -h exits non-zero even on success, so the exit code can't
	// be used to detect failure here — only the output content can.
	cmd := exec.CommandContext(ctx, path, "-h")
	proc.Configure(cmd)
	out, runErr := cmd.CombinedOutput()
	text := string(out)
	if !strings.Contains(text, "MemProcFS") {
		if runErr != nil {
			status.Error = fmt.Sprintf("probe failed: %v", runErr)
		} else {
			status.Error = "output did not look like MemProcFS"
		}
		return status
	}
	status.ProbeOK = true
	if v := extractMemProcfsVersion(text); v != "" {
		status.Detail = "MemProcFS " + v + " detected"
	} else {
		status.Detail = "MemProcFS detected"
	}
	return status
}

// probeMemNixFs checks the MemNixFS executable. It is optional — only Linux
// images use it — so an unconfigured path is reported as "not configured"
// rather than as a failure, the same as Volatility 2 and the analyzer.
func probeMemNixFs(path string) ToolStatus {
	if strings.TrimSpace(path) == "" {
		return optionalNotConfigured("not configured; Linux memory images will be analyzed with Volatility only")
	}
	status := ToolStatus{Path: path}
	exists, executable, err := statFile(path)
	status.Exists = exists
	status.Executable = executable
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if !executable {
		status.Error = "file is not executable"
		return status
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-h")
	proc.Configure(cmd)
	out, runErr := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(out)), "memnixfs") {
		if runErr != nil {
			status.Error = fmt.Sprintf("probe failed: %v", runErr)
		} else {
			status.Error = "output did not look like MemNixFS"
		}
		return status
	}
	status.ProbeOK = true
	status.Detail = "MemNixFS detected"
	return status
}

func extractMemProcfsVersion(text string) string {
	const marker = "MemProcFS v"
	idx := strings.Index(text, marker)
	if idx == -1 {
		return ""
	}
	rest := text[idx+len(marker):]
	end := strings.IndexAny(rest, " \n\t")
	if end == -1 {
		return ""
	}
	return rest[:end]
}
