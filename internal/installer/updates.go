package installer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"memforensics-gui/internal/proc"
)

// UpdateRequest contains the configured paths for tools whose releases are
// tracked on GitHub. Volatility 2 is intentionally absent: it is archived and
// has no moving signature/plugin content.
type UpdateRequest struct {
	VolPath       string `json:"volPath"`
	MemProcfsPath string `json:"memProcfsPath"`
	MemNixFsPath  string `json:"memNixFsPath"`
	AnalyzerPath  string `json:"analyzerPath"`
}

// UpdateStatus compares one installed tool with its latest GitHub release.
type UpdateStatus struct {
	Tool             string `json:"tool"`
	Repository       string `json:"repository"`
	Installed        bool   `json:"installed"`
	InstalledVersion string `json:"installedVersion"`
	LatestVersion    string `json:"latestVersion"`
	UpdateAvailable  bool   `json:"updateAvailable"`
	Error            string `json:"error"`
}

// UpdateReport is returned by CheckUpdates in stable display order.
type UpdateReport struct {
	Tools []UpdateStatus `json:"tools"`
}

// CheckUpdates performs a read-only comparison against each project's latest
// GitHub release. Downloading remains an explicit Install / update tools action.
func CheckUpdates(ctx context.Context, req UpdateRequest) UpdateReport {
	specs := []struct {
		name, repo, path string
		version          func(string) string
	}{
		{"Volatility 3", "volatilityfoundation/volatility3", req.VolPath, volatility3Version},
		{"MemProcFS", "ufrisk/MemProcFS", req.MemProcfsPath, markerVersion},
		{"MemProcFS-Analyzer", "LETHAL-FORENSICS/MemProcFS-Analyzer", req.AnalyzerPath, markerVersion},
		{"MemNixFS", "MemNixFS/MemNixFS", req.MemNixFsPath, markerVersion},
	}

	report := UpdateReport{Tools: make([]UpdateStatus, 0, len(specs))}
	for _, spec := range specs {
		status := UpdateStatus{Tool: spec.name, Repository: spec.repo}
		if info, err := os.Stat(strings.TrimSpace(spec.path)); err == nil && !info.IsDir() {
			status.Installed = true
			status.InstalledVersion = spec.version(spec.path)
		}

		release, err := githubLatestRelease(ctx, spec.repo)
		if err != nil {
			status.Error = err.Error()
		} else {
			status.LatestVersion = release.TagName
			status.UpdateAvailable = status.InstalledVersion != "" &&
				normalizeVersion(status.InstalledVersion) != normalizeVersion(status.LatestVersion)
		}
		report.Tools = append(report.Tools, status)
	}
	return report
}

func normalizeVersion(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(strings.ToLower(version)), "v")
}

// markerVersion walks upward from an installed executable/script to the first
// app-owned release marker. This works with archives that contain an extra
// top-level directory without assuming a fixed release layout.
func markerVersion(path string) string {
	dir := filepath.Dir(path)
	toolsRoot := filepath.Clean(ToolsDir())
	for {
		if version := installedTag(dir); version != "" {
			return version
		}
		if filepath.Clean(dir) == toolsRoot {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(strings.ToLower(parent), strings.ToLower(toolsRoot)) {
			return ""
		}
		dir = parent
	}
}

var versionNumber = regexp.MustCompile(`\d+(?:\.\d+){1,3}`)

// volatility3Version asks the interpreter beside vol.exe for the installed
// distribution version. The CLI fallback covers a user-selected launcher
// outside an ordinary virtual environment.
func volatility3Version(volPath string) string {
	python := filepath.Join(filepath.Dir(volPath), "python.exe")
	if isFile(python) {
		cmd := exec.Command(python, "-c", "import importlib.metadata as m; print(m.version('volatility3'))")
		proc.Configure(cmd)
		if output, err := cmd.Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	cmd := exec.Command(volPath, "--version")
	proc.Configure(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	if match := versionNumber.FindString(string(output)); match != "" {
		return match
	}
	return ""
}
