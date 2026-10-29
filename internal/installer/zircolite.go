package installer

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

//go:embed sigma_update.py
var sigmaUpdateScript string

func ensureZircolite(ctx context.Context, analyzerPath string, emit Emitter) error {
	return prepareZircolite(ctx, analyzerPath, emit, true)
}

// PrepareAnalyzerRuntime repairs only an unusable runtime. A healthy install
// runs offline and does not refresh packages or detection rules during analysis.
func PrepareAnalyzerRuntime(ctx context.Context, analyzerPath string, emit Emitter) error {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	root := filepath.Join(filepath.Dir(analyzerPath), "Tools", "Zircolite")
	cmd := exec.CommandContext(probeCtx, paths.ZircolitePython(), filepath.Join(root, "zircolite.py"), "--help")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")
	proc.Configure(cmd)
	if err := cmd.Run(); err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	emit("install:log", logLine("Repairing missing or unusable Zircolite runtime: "+paths.ZircolitePython()))
	return prepareZircolite(ctx, analyzerPath, emit, false)
}

func prepareZircolite(ctx context.Context, analyzerPath string, emit Emitter, updateRules bool) error {
	root := filepath.Join(filepath.Dir(analyzerPath), "Tools", "Zircolite")
	packageArgs, err := zircolitePackageArgs(root)
	if err != nil {
		return err
	}
	python := paths.ZircolitePython()
	run := func(exe string, args ...string) error {
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "PYTHONIOENCODING=utf-8")
		proc.Configure(cmd)
		return runLoggedCmd(emit, cmd)
	}
	if !isFile(python) {
		base := paths.VenvPython()
		if base == "" {
			return fmt.Errorf("install Python dependencies first")
		}
		if err := run(base, "-m", "venv", filepath.Dir(filepath.Dir(python))); err != nil {
			return err
		}
	}
	emit("install:log", logLine("Installing/verifying isolated Zircolite dependencies..."))
	if err := run(python, append([]string{"-m", "pip", "install", "--timeout", "120", "--retries", "5"}, packageArgs...)...); err != nil {
		return fmt.Errorf("Zircolite dependencies: %w", err)
	}
	if err := run(python, "-m", "pip", "check"); err != nil {
		return fmt.Errorf("Zircolite dependency verification: %w", err)
	}
	if err := run(python, filepath.Join(root, "zircolite.py"), "--help"); err != nil {
		return err
	}
	if updateRules {
		emit("install:log", logLine("Downloading and verifying Sigma rules..."))
		if err := run(python, "-c", sigmaUpdateScript); err != nil {
			return fmt.Errorf("Sigma rule update failed (existing rules may be stale): %w", err)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "rules", "rules_windows_generic.json"))
	if err != nil {
		return fmt.Errorf("Sigma Windows rules missing: %w", err)
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(data, &rules); err != nil || len(rules) == 0 {
		return fmt.Errorf("Sigma Windows rules are empty or invalid")
	}
	emit("install:log", logLine(fmt.Sprintf("Zircolite verified with %d Windows Sigma rules", len(rules))))
	return nil
}

func zircolitePackageArgs(root string) ([]string, error) {
	// Current releases use PEP 517 project metadata. Let pip resolve the
	// project's declared dependencies rather than maintaining a second list.
	if isFile(filepath.Join(root, "pyproject.toml")) {
		return []string{root}, nil
	}
	if requirements := filepath.Join(root, "requirements.txt"); isFile(requirements) {
		return []string{"-r", requirements}, nil
	}
	return nil, fmt.Errorf("Zircolite dependency metadata missing (pyproject.toml or requirements.txt); complete Analyzer tool installation")
}
