package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"memforensics-gui/internal/analyzer"
	"memforensics-gui/internal/config"
	"memforensics-gui/internal/custody"
	"memforensics-gui/internal/imageid"
	"memforensics-gui/internal/installer"
	"memforensics-gui/internal/linuxsymbols"
	"memforensics-gui/internal/memnixfs"
	"memforensics-gui/internal/memprocfs"
	"memforensics-gui/internal/prereq"
	"memforensics-gui/internal/proc"
	"memforensics-gui/internal/results"
	"memforensics-gui/internal/volatility"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// vol3PoolPatchScript is scripts/patch_vol3_pool_circular_import.py,
// embedded so PatchVol3CircularImport can run it without depending on the
// scripts/ directory being shipped next to the built executable.
//
//go:embed scripts/patch_vol3_pool_circular_import.py
var vol3PoolPatchScript string

// App struct
type App struct {
	ctx context.Context

	runMu       sync.Mutex
	running     bool
	installing  bool
	cancelRun   context.CancelFunc
	mountCancel context.CancelFunc
	mountDone   chan struct{}

	// Each phase of a run (vol2, vol3, the mount) executes under its own
	// child context so a single phase can be abandoned without ending the
	// run — that is what the Skip button cancels. Stop cancels the parent
	// runCtx instead, which ends everything.
	phaseMu     sync.Mutex
	phaseName   string
	phaseCancel context.CancelFunc
	phaseSkiped bool

	catalogMu    sync.Mutex
	catalogKey   string
	catalogCache *PluginCatalog
}

// PluginCatalog bundles the discovered plugin list and the recommended
// subset, so the frontend gets both from a single (slow) `vol -h` probe.
type PluginCatalog struct {
	Plugins     []volatility.Plugin `json:"plugins"`
	Recommended []string            `json:"recommended"`
	// Vol2Warning is non-empty when a configured Volatility 2 path could
	// not be probed; the vol3 catalog is still returned.
	Vol2Warning string `json:"vol2Warning"`
	// Vol3Warning is non-empty when the custom plugin dirs made vol3 crash
	// and the catalog had to be re-probed without them.
	Vol3Warning string `json:"vol3Warning"`
	// Presets are the built-in, task-oriented bundles, resolved against this
	// catalog so they only ever name plugins actually present here.
	Presets []volatility.Preset `json:"presets"`
}

// RunRequest describes a run requested from the Run screen.
type RunRequest struct {
	CaseID          string   `json:"caseID"`
	Analyst         string   `json:"analyst"`
	VolPath         string   `json:"volPath"`
	Vol2Path        string   `json:"vol2Path"`
	MemProcfsPath   string   `json:"memProcfsPath"`
	MemNixFsPath    string   `json:"memNixFsPath"`
	AnalyzerPath    string   `json:"analyzerPath"`
	ImagePath       string   `json:"imagePath"`
	OutputDir       string   `json:"outputDir"`
	SelectedPlugins []string `json:"selectedPlugins"`
	IncludeAnalyzer bool     `json:"includeAnalyzer"`
	// Vol2Profile optionally pins the Volatility 2 profile; empty means
	// auto-detect via imageinfo (Windows images only).
	Vol2Profile string `json:"vol2Profile"`
	// ImageOS is "windows", "linux" or "" for auto-detect. It decides which
	// mount/export tool the run uses first: MemProcFS for a Windows image,
	// MemNixFS for a Linux one (MemProcFS cannot read those at all).
	ImageOS string `json:"imageOS"`
	// AutoFetchLinuxSymbols enables online kernel-symbol lookup for linux.*
	// plugins (see internal/volatility/remoteisf.go) — vol3's own
	// --remote-isf-url mechanism, pointed at the community sources this app
	// knows about. Has no effect on non-Linux plugins.
	AutoFetchLinuxSymbols bool `json:"autoFetchLinuxSymbols"`
	// PIDEnabled applies TargetPID only to plugins that expose a PID/PIDs
	// option. Other selected plugins still run normally.
	PIDEnabled bool `json:"pidEnabled"`
	TargetPID  int  `json:"targetPID"`
	// YaraRulesPath is passed only to generic YARA scanner plugins. Custom
	// YARA-based plugins carry their own embedded rules.
	YaraRulesPath string `json:"yaraRulesPath"`
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// InstallTools downloads and installs the external tools this app needs
// (Volatility 3, MemProcFS, and — on Windows only — MemProcFS-Analyzer)
// into per-user locations, and returns the detected executable paths so the
// frontend can auto-populate the config fields. Progress is reported via
// "install:progress" and "install:log" events. Only one install may run at
// a time, and not while a forensic run is in progress.
func (a *App) InstallTools() (installer.Result, error) {
	a.runMu.Lock()
	if a.running || a.mountDone != nil {
		a.runMu.Unlock()
		return installer.Result{}, fmt.Errorf("stop analysis and unmount MemProcFS before installing tools")
	}
	if a.installing {
		a.runMu.Unlock()
		return installer.Result{}, fmt.Errorf("an install is already in progress")
	}
	a.installing = true
	a.runMu.Unlock()
	defer func() {
		a.runMu.Lock()
		a.installing = false
		a.runMu.Unlock()
	}()

	emit := func(event string, payload any) { runtime.EventsEmit(a.ctx, event, payload) }
	res := installer.InstallTools(a.ctx, emit)
	if res.VolPath != "" && strings.EqualFold(filepath.Clean(res.VolPath), filepath.Clean(installer.VenvVol())) {
		if _, err := installer.PatchVol3CircularImport(a.ctx, emit, vol3PoolPatchScript); err != nil {
			res.Errors = append(res.Errors, "Volatility 3 compatibility fix: "+err.Error())
		}
	}
	// A fresh install changes what plugins are available, so drop the
	// cached catalog — the next GetPluginCatalog re-probes.
	a.catalogMu.Lock()
	a.catalogCache = nil
	a.catalogMu.Unlock()
	return res, nil
}

// InstallDependencies installs everything the tools need but are not: the
// system-level components (Dokany, WinFsp, .NET, ClamAV) and an app-owned
// Python environment holding Volatility 3 plus every package its built-in and
// custom plugins import. Kept separate from InstallTools because it is the
// slow, elevation-prompting half — and because a colleague setting the app up
// on a fresh machine needs it exactly once, while the tools half is pressed
// again on every update.
//
// Progress is reported over the same "install:progress" / "install:log"
// events as InstallTools, and it takes the same lock: neither may run
// alongside the other or alongside a forensic run.
//
// The Volatility 3 circular-import patch is applied at the end without
// prompting — unlike PatchVol3CircularImport's own doc note, the environment
// being patched here is one this function just created, and leaving it
// unpatched costs every custom plugin.
func (a *App) InstallDependencies() (installer.DepsResult, error) {
	a.runMu.Lock()
	if a.running || a.mountDone != nil {
		a.runMu.Unlock()
		return installer.DepsResult{}, fmt.Errorf("stop analysis and unmount MemProcFS before installing dependencies")
	}
	if a.installing {
		a.runMu.Unlock()
		return installer.DepsResult{}, fmt.Errorf("an install is already in progress")
	}
	a.installing = true
	a.runMu.Unlock()
	defer func() {
		a.runMu.Lock()
		a.installing = false
		a.runMu.Unlock()
	}()

	emit := func(event string, payload any) { runtime.EventsEmit(a.ctx, event, payload) }
	res := installer.InstallDependencies(a.ctx, emit, vol3PoolPatchScript)
	// New packages can make previously unloadable plugins load, so the
	// cached catalog is no longer trustworthy.
	a.catalogMu.Lock()
	a.catalogCache = nil
	a.catalogMu.Unlock()
	return res, nil
}

// PatchVol3CircularImport patches the installed Volatility 3 to fix a
// circular-import crash that this app's custom plugin dirs (-p) can
// provoke (AttributeError: partially initialized module
// 'volatility3...poolscanner' ... circular import) — see
// scripts/patch_vol3_pool_circular_import.py for the full explanation and
// internal/volatility/discover.go for the fallback this works around.
//
// The frontend should only call this after the user has explicitly agreed:
// it edits a file inside a third-party installed package, not anything
// this app owns, and needs re-running after every volatility3 upgrade.
func (a *App) PatchVol3CircularImport() (string, error) {
	emit := func(event string, payload any) { runtime.EventsEmit(a.ctx, event, payload) }
	out, err := installer.PatchVol3CircularImport(a.ctx, emit, vol3PoolPatchScript)
	if err == nil {
		// The patch only affects module import behaviour, not plugin
		// content, but dropping the cache means the next catalog fetch
		// re-probes with -p instead of serving the stale no-custom-plugins
		// result from before the patch.
		a.catalogMu.Lock()
		a.catalogCache = nil
		a.catalogMu.Unlock()
	}
	return out, err
}

// GenerateLinuxISF builds a Volatility3 ISF symbol file from a Linux kernel
// debuginfo package (.rpm, .ddeb, …) — the fallback for a kernel that none
// of the online community sources (internal/volatility/remoteisf.go) happen
// to have. It extracts the real vmlinux ELF out of the package with 7-Zip,
// runs dwarf2json against it, and drops the result into
// paths.SymbolsDir()/linux, where Volatility3 already looks for local symbol
// tables — no further configuration needed, it applies on the very next run.
//
// Progress is reported via "isfgen:log" events. This shares the same
// exclusive-operation lock as InstallTools/InstallDependencies: it is a slow
// foreground operation that shells out to other tools, same as those.
func (a *App) GenerateLinuxISF(packagePath string) (linuxsymbols.GenerateResult, error) {
	a.runMu.Lock()
	if a.running {
		a.runMu.Unlock()
		return linuxsymbols.GenerateResult{}, fmt.Errorf("a run is in progress; stop it before generating symbols")
	}
	if a.installing {
		a.runMu.Unlock()
		return linuxsymbols.GenerateResult{}, fmt.Errorf("an install is already in progress")
	}
	a.installing = true
	a.runMu.Unlock()
	defer func() {
		a.runMu.Lock()
		a.installing = false
		a.runMu.Unlock()
	}()

	emit := func(event string, payload any) { runtime.EventsEmit(a.ctx, event, payload) }
	return linuxsymbols.GenerateISFFromPackage(a.ctx, linuxsymbols.GenerateRequest{PackagePath: packagePath}, emit)
}

// DetectImageOS inspects a memory image and reports which OS it came from,
// so the UI can preselect the matching plugin category and skip the
// MemProcFS phase for a Linux image. Returns os "unknown" when it can't tell,
// which the UI should treat as "ask the user" rather than an error.
func (a *App) DetectImageOS(imagePath string) (imageid.Result, error) {
	imagePath = networkImagePath(imagePath)
	return imageid.Detect(imagePath)
}

// ValidateToolPaths probes every configured tool path and reports whether
// each looks like a working install.
func (a *App) ValidateToolPaths(paths config.ToolPaths) config.ValidationResult {
	return config.Validate(paths)
}

// CheckToolUpdates compares the configured tools with their latest GitHub
// releases. It is read-only; InstallTools performs the actual updates.
func (a *App) CheckToolUpdates(paths config.ToolPaths) installer.UpdateReport {
	return installer.CheckUpdates(a.ctx, installer.UpdateRequest{
		VolPath:       paths.VolPath,
		MemProcfsPath: paths.MemProcfsPath,
		MemNixFsPath:  paths.MemNixFsPath,
		AnalyzerPath:  paths.AnalyzerPath,
	})
}

// CheckPrerequisites reports third-party software the tools need but this
// app does not install itself (Dokany, WinFsp, .NET, Python 3…), so the UI
// can tell the user what is missing before a run fails.
func (a *App) CheckPrerequisites() prereq.Report {
	return prereq.Detect()
}

// BrowseForFile opens a native file picker and returns the selected path,
// or an empty string if the user cancelled.
func (a *App) BrowseForFile(title string) (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
	})
}

// BrowseForDirectory opens a native directory picker and returns the
// selected path, or an empty string if the user cancelled.
func (a *App) BrowseForDirectory(title string) (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: title,
	})
}

// GetPluginCatalog returns the full Volatility3 plugin catalog (discovered
// by parsing `<volPath> -h`, including custom plugin dirs) together with
// the recommended pre-checked subset — one backend call, one vol
// invocation. Starting vol is a full Python interpreter launch that can
// take many seconds, so the parsed catalog is cached and reused until the
// vol binary or a custom plugin file changes.
func (a *App) GetPluginCatalog(volPath string, vol2Path string) (*PluginCatalog, error) {
	key := catalogCacheKey(volPath) + "|v2:" + catalogCacheKey(vol2Path)

	a.catalogMu.Lock()
	defer a.catalogMu.Unlock()
	if a.catalogCache != nil && a.catalogKey == key {
		return a.catalogCache, nil
	}

	plugins, vol3Warning, err := volatility.ListPlugins(a.ctx, volPath)
	if err != nil {
		return nil, err
	}
	// Volatility 2 is optional: if it isn't configured or can't be probed,
	// the catalog is still perfectly usable as a vol3-only list, so a vol2
	// failure is surfaced as a warning rather than failing the whole call.
	var vol2Warning string
	if strings.TrimSpace(vol2Path) != "" {
		vol2Plugins, v2err := volatility.ListVol2Plugins(a.ctx, vol2Path)
		if v2err != nil {
			vol2Warning = v2err.Error()
		} else {
			plugins = append(plugins, vol2Plugins...)
		}
	}

	// Annotations that span both frameworks are applied once here, after the
	// vol2 and vol3 lists are merged.
	volatility.AnnotateAll(plugins)

	catalog := &PluginCatalog{
		Plugins:     plugins,
		Recommended: volatility.RecommendedNames(plugins),
		Vol2Warning: vol2Warning,
		Vol3Warning: vol3Warning,
		Presets:     volatility.BuiltInPresets(plugins),
	}
	a.catalogKey = key
	a.catalogCache = catalog
	return catalog, nil
}

// catalogCacheKey fingerprints everything the plugin catalog depends on:
// the vol binary itself and the contents of the custom plugin dirs.
func catalogCacheKey(volPath string) string {
	var b strings.Builder
	b.WriteString(volPath)
	if info, err := os.Stat(volPath); err == nil {
		fmt.Fprintf(&b, "|%d|%d", info.ModTime().UnixNano(), info.Size())
	}
	for _, dir := range volatility.PluginDirs() {
		b.WriteString("|" + dir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				fmt.Fprintf(&b, "|%s|%d|%d", e.Name(), info.ModTime().UnixNano(), info.Size())
			}
		}
	}
	return b.String()
}

// StartRun runs Volatility 2, then Volatility 3, then the image's filesystem
// tool. Windows analysis retains the MemProcFS mount after Analyzer finishes.
// Linux symbols are resolved before either consumer; MemNixFS still exports.
func (a *App) StartRun(req RunRequest) error {
	req.ImagePath = networkImagePath(req.ImagePath)
	a.runMu.Lock()
	if a.mountDone != nil {
		a.runMu.Unlock()
		return fmt.Errorf("a MemProcFS mount is still open; unmount it in Mounts before starting another run")
	}
	if a.installing {
		a.runMu.Unlock()
		return fmt.Errorf("tool installation is in progress")
	}
	if a.running {
		a.runMu.Unlock()
		return fmt.Errorf("a run is already in progress")
	}
	if req.PIDEnabled && req.TargetPID < 0 {
		a.runMu.Unlock()
		return fmt.Errorf("target PID must be zero or greater")
	}
	for _, plugin := range req.SelectedPlugins {
		if !volatility.RequiresYaraRules(plugin) {
			continue
		}
		if strings.TrimSpace(req.YaraRulesPath) == "" {
			a.runMu.Unlock()
			return fmt.Errorf("%s needs a YARA rules file", plugin)
		}
		info, err := os.Stat(req.YaraRulesPath)
		if err != nil || info.IsDir() {
			a.runMu.Unlock()
			return fmt.Errorf("YARA rules file is not readable: %s", req.YaraRulesPath)
		}
	}
	if req.IncludeAnalyzer {
		if !strings.EqualFold(req.ImageOS, imageid.OSLinux) {
			if err := analyzer.CheckDependencies(req.AnalyzerPath); err != nil {
				a.runMu.Unlock()
				return err
			}
		}
		if strings.TrimSpace(req.AnalyzerPath) == "" {
			a.runMu.Unlock()
			return fmt.Errorf("analyzer enabled but no MemProcFS-Analyzer.ps1 path configured")
		}
	}
	// Only checked when the user explicitly picked Linux — on Auto-detect,
	// which tool is needed isn't known until the image is sniffed inside the
	// run goroutine below, so an empty path there is instead reported as a
	// "memnixfs:status" error event once detection resolves to Linux.
	if strings.EqualFold(req.ImageOS, imageid.OSLinux) && strings.TrimSpace(req.MemNixFsPath) == "" {
		a.runMu.Unlock()
		return fmt.Errorf("image OS is set to Linux but no MemNixFS path configured")
	}
	if err := os.MkdirAll(req.OutputDir, 0o755); err != nil {
		a.runMu.Unlock()
		return fmt.Errorf("creating output directory: %w", err)
	}

	runCtx, cancel := context.WithCancel(a.ctx)
	a.cancelRun = cancel
	a.running = true
	a.runMu.Unlock()

	record := custody.New()
	emit := func(event string, payload any) {
		record.Event(event, payload)
		runtime.EventsEmit(a.ctx, event, payload)
	}

	go func() {
		defer cancel()
		defer func() {
			emit("run:log", map[string]any{"source": "app", "line": "Finalizing custody record, image SHA-256, and run log..."})
			if err := record.Finish(req.OutputDir, req.ImagePath, req.CaseID, req.Analyst, req, runCtx.Err() != nil); err != nil {
				emit("run:log", map[string]any{"source": "app", "line": "Custody record failed: " + err.Error()})
			}
			a.runMu.Lock()
			a.running = false
			a.cancelRun = nil
			a.runMu.Unlock()
			emit("run:finished", nil)
		}()

		if req.PIDEnabled {
			emit("run:log", map[string]any{"source": "app", "line": fmt.Sprintf(
				"PID filter enabled: %d (applied only to PID-capable plugins)", req.TargetPID)})
		}
		if strings.TrimSpace(req.YaraRulesPath) != "" {
			emit("run:log", map[string]any{"source": "app",
				"line": "YARA rules file: " + req.YaraRulesPath})
		}

		// Tools run sequentially to avoid concurrent memory pressure.
		var vol2Selected, vol3Selected []string
		if len(req.SelectedPlugins) > 0 {
			catalog, catErr := a.GetPluginCatalog(req.VolPath, req.Vol2Path)
			if catErr != nil {
				// Without a catalog we can't tell the frameworks apart; treat
				// everything as vol3, which is how the app behaved before vol2.
				vol3Selected = req.SelectedPlugins
				emit("run:log", map[string]any{"source": "app",
					"line": "could not load plugin catalog to split vol2/vol3 selections: " + catErr.Error()})
			} else {
				vol2Selected, vol3Selected = volatility.SplitByFramework(catalog.Plugins, req.SelectedPlugins)
			}
		}

		// Kernel symbols for a Linux image are resolved once, in phase 1, and
		// the path is kept here so the Volatility 3 phase can say what it is
		// actually working with rather than guessing. Empty means nothing
		// matched.
		var symbolsPath string

		// imageOS decides which mount tool runs: MemProcFS only understands
		// Windows images, MemNixFS only understands Linux ones. Resolved
		// once, up front, since it now gates the first phase rather than the
		// last.
		//
		// An empty ImageOS means the user left the selector on "Auto-detect",
		// so resolve it here. Detection failing is not fatal: it falls back
		// to the MemProcFS/Windows path, which is what the app did before
		// this check existed.
		imageOS := strings.TrimSpace(req.ImageOS)
		if imageOS == "" {
			if detected, derr := imageid.Detect(req.ImagePath); derr == nil {
				imageOS = detected.OS
				emit("run:log", map[string]any{"source": "app",
					"line": fmt.Sprintf("auto-detected image OS: %s (%s)", detected.OS, detected.Evidence)})
			} else {
				emit("run:log", map[string]any{"source": "app",
					"line": "image OS auto-detection failed, assuming Windows: " + derr.Error()})
			}
		}

		// Resolve Linux symbols before the analysis phases.
		if imageid.IsLinux(imageOS) {
			// Kernel symbols are resolved once, here, and shared by both
			// tools that need them. MemNixFS cannot fetch its own on Windows
			// (see memnixfs.RunExport), and doing it up front also means
			// Volatility 3 finds the ISF locally rather than re-resolving it
			// per plugin.
			if req.AutoFetchLinuxSymbols {
				emit("memnixfs:status", map[string]any{"state": "running", "message": "resolving kernel symbols…"})
				res, symErr := linuxsymbols.ResolveForImage(runCtx, req.ImagePath, emit)
				if symErr != nil {
					// Not fatal: both tools degrade to partial output without
					// symbols, and saying so beats silently producing less.
					emit("run:log", map[string]any{"source": "symbols",
						"line": "could not resolve kernel symbols: " + symErr.Error()})
				} else {
					symbolsPath = res.ISFPath
					emit("run:log", map[string]any{"source": "symbols", "line": fmt.Sprintf(
						"kernel symbols ready (%s): %s", map[bool]string{true: "already downloaded", false: "downloaded"}[res.Cached], res.ISFPath)})
				}
			}
			// Nothing is passed to MemNixFS when there is no exact match: it
			// has its own symbol discovery (and its own cache of previous
			// downloads), and handing it this app's directory of assorted
			// ISFs would suppress that in favour of files belonging to other
			// images. See memnixfs.RunExport.
			if symbolsPath == "" {
				emit("run:log", map[string]any{"source": "symbols",
					"line": "no exact match from the community sources; leaving MemNixFS to its own symbol discovery"})
			}

		}

		// Volatility 2 runs first when selected.
		if len(vol2Selected) > 0 {
			phaseCtx, endPhase := a.beginPhase(runCtx, "vol2", "Volatility 2")
			profile := strings.TrimSpace(req.Vol2Profile)
			var profErr error
			if profile == "" {
				profile, profErr = volatility.DetectVol2Profile(phaseCtx, req.VolPath, req.Vol2Path, req.ImagePath, emit)
			}
			if profErr != nil {
				// Every vol2 plugin needs a profile, so without one the
				// whole vol2 phase is skipped — but the vol3 phase still
				// runs.
				emit("vol2:status", map[string]any{"state": "error",
					"message": "skipping " + fmt.Sprint(len(vol2Selected)) + " Volatility 2 plugin(s): " + profErr.Error()})
			} else {
				v2summary := volatility.RunVol2Plugins(phaseCtx, req.Vol2Path, req.ImagePath, req.OutputDir, profile,
					vol2Selected, req.PIDEnabled, req.TargetPID, req.YaraRulesPath, emit)
				emit("vol2:all-done", v2summary)
			}
			if endPhase() {
				emit("vol2:status", map[string]any{"state": "error", "message": "skipped by user"})
			}
		}

		if runCtx.Err() != nil {
			return
		}

		// Volatility 3 follows Volatility 2.
		if len(vol3Selected) > 0 {
			// Report what the Volatility 3 phase will actually use. Phase 1
			// has normally already put the exact ISF on disk, in which case
			// vol3 finds it through --symbol-dirs and goes nowhere near the
			// network — so announcing an online lookup here (as this used to,
			// unconditionally) described something that does not happen.
			if imageid.IsLinux(imageOS) {
				switch {
				case symbolsPath != "":
					emit("run:log", map[string]any{"source": "symbols",
						"line": "Volatility 3 will use the kernel symbols resolved earlier: " + symbolsPath})
				case req.AutoFetchLinuxSymbols:
					emit("run:log", map[string]any{"source": "symbols", "line": fmt.Sprintf(
						"no local symbol match; Volatility 3 will try %d online community source(s) per plugin (disable in Config).",
						len(volatility.RemoteISFSources))})
				default:
					emit("run:log", map[string]any{"source": "symbols",
						"line": "no local symbol match and online symbol lookup is disabled in Config; linux.* plugins needing kernel symbols will fail."})
				}
			}
			phaseCtx, endPhase := a.beginPhase(runCtx, "vol3", "Volatility 3")
			summary := volatility.RunPlugins(phaseCtx, req.VolPath, req.ImagePath, req.OutputDir, vol3Selected,
				req.AutoFetchLinuxSymbols, req.PIDEnabled, req.TargetPID, req.YaraRulesPath, emit)
			emit("vol3:all-done", summary)
			if endPhase() {
				emit("run:log", map[string]any{"source": "app", "line": "Volatility 3 phase skipped by user"})
			}
		}
		if runCtx.Err() != nil {
			return
		}

		// Mount/export runs last.
		if imageid.IsLinux(imageOS) {
			phaseCtx, endPhase := a.beginPhase(runCtx, "memnixfs", "MemNixFS")
			_ = memnixfs.RunExport(phaseCtx, req.MemNixFsPath, req.ImagePath, req.OutputDir, symbolsPath, emit)
			if endPhase() {
				emit("memnixfs:status", map[string]any{"state": "stopped", "message": "skipped by user"})
			}
		} else {
			// Analyzer shares the live mount, which remains after the run.
			if req.IncludeAnalyzer {
				emit("analyzer:status", map[string]any{"state": "running", "message": "Checking Zircolite runtime..."})
				setupEmit := func(event string, payload any) {
					if event == "install:log" {
						if data, ok := payload.(map[string]any); ok {
							emit("run:log", map[string]any{"source": "analyzer", "line": data["line"]})
						}
					}
				}
				if err := installer.PrepareAnalyzerRuntime(runCtx, req.AnalyzerPath, setupEmit); err != nil {
					emit("analyzer:status", map[string]any{"state": "error", "message": "Zircolite setup failed: " + err.Error()})
					emit("run:log", map[string]any{"source": "analyzer", "line": "Zircolite setup failed: " + err.Error()})
					return
				}
			}
			phaseCtx, endPhase := a.beginPhase(runCtx, "memprocfs", "MemProcFS")
			a.runRetainedMount(phaseCtx, req, emit)
			if endPhase() {
				emit("memprocfs:status", map[string]any{"state": "stopped", "message": "skipped by user"})
			}

		}
	}()
	return nil
}

// StopRun cancels an in-progress run: kills any running/queued plugin
// processes and stops MemProcFS (unmounting it cleanly).
func (a *App) StopRun() error {
	a.runMu.Lock()
	defer a.runMu.Unlock()
	if !a.running || a.cancelRun == nil {
		return fmt.Errorf("no run in progress")
	}
	a.cancelRun()
	if a.mountCancel != nil {
		a.mountCancel()
	}

	// Cancelling the context should terminate every tool, but Stop promises
	// that nothing is left running, so it is enforced rather than assumed.
	// The sweep runs slightly later to give the context path its chance to
	// exit cleanly first; anything still alive after that is killed outright,
	// process group included (the vol2 standalone forks a worker that
	// survives a kill aimed only at its launcher).
	go func() {
		time.Sleep(2 * time.Second)
		if n := proc.KillAllChildren(); n > 0 {
			runtime.EventsEmit(a.ctx, "run:log", map[string]any{
				"source": "app",
				"line":   fmt.Sprintf("stop: force-killed %d leftover tool process group(s)", n),
			})
		}
	}()
	return nil
}

// beginPhase scopes one stage of a run to its own cancellable context and
// publishes which stage is active, so the UI can label the Skip button and
// so SkipPhase knows what it is skipping.
//
// The returned end function reports whether the phase was skipped, letting
// callers distinguish "this tool was abandoned, carry on" from "the whole run
// was stopped" — the two look identical from a cancelled context alone.
func (a *App) beginPhase(parent context.Context, name, label string) (context.Context, func() bool) {
	ctx, cancel := context.WithCancel(parent)

	a.phaseMu.Lock()
	a.phaseName = name
	a.phaseCancel = cancel
	a.phaseSkiped = false
	a.phaseMu.Unlock()

	runtime.EventsEmit(a.ctx, "run:phase", map[string]any{"phase": name, "label": label})

	return ctx, func() bool {
		a.phaseMu.Lock()
		skipped := a.phaseSkiped
		a.phaseName = ""
		a.phaseCancel = nil
		a.phaseSkiped = false
		a.phaseMu.Unlock()
		cancel()
		return skipped
	}
}

// SkipPhase abandons the tool currently running and moves the run on to the
// next one — for a tool that has crashed, hung, or is grinding pointlessly
// (vol2 on an image it has no profile for, say), without throwing away the
// stages that would follow it.
//
// Only the current phase's context is cancelled, so its processes are killed
// (their whole process group, via proc.Configure) while the run itself
// continues. Stop remains the way to end everything.
func (a *App) SkipPhase() error {
	a.runMu.Lock()
	running := a.running
	a.runMu.Unlock()
	if !running {
		return fmt.Errorf("no run in progress")
	}

	a.phaseMu.Lock()
	name := a.phaseName
	cancel := a.phaseCancel
	if cancel != nil {
		a.phaseSkiped = true
	}
	a.phaseMu.Unlock()

	if cancel == nil {
		return fmt.Errorf("nothing is running that can be skipped right now")
	}
	runtime.EventsEmit(a.ctx, "run:log", map[string]any{
		"source": "app", "line": "skipping " + name + "; moving on to the next tool",
	})
	cancel()
	return nil
}

// shutdown runs when the app window closes. Without it, a run in progress
// would be abandoned rather than stopped: the Go process exits, its
// context-cancel watchdogs die with it, and the tool processes are reparented
// to init and keep consuming CPU with nowhere to send their output.
func (a *App) shutdown(ctx context.Context) {
	a.runMu.Lock()
	cancel := a.cancelRun
	mountCancel := a.mountCancel
	a.runMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if mountCancel != nil {
		mountCancel()
	}
	proc.KillAllChildren()
}

// ListMemProcfsMounts returns MemProcFS-related mounts and leftover mount
// directories on this system, so the Mounts panel can offer per-entry
// cleanup of orphans from previous runs.
func (a *App) ListMemProcfsMounts() ([]memprocfs.MountInfo, error) {
	return memprocfs.ListMounts()
}

// CleanupMemProcfsMount terminates the memprocfs process owning the given
// mount point (if any), unmounts it, and removes the mount directory. The
// mount belonging to a run that is currently in progress is protected —
// that one is ended via StopRun instead.
func (a *App) CleanupMemProcfsMount(mountPoint string) error {
	if handled, err := a.unmountRetained(mountPoint); handled {
		return err
	}
	a.runMu.Lock()
	running := a.running
	a.runMu.Unlock()
	if active := memprocfs.ActiveMountDir(); running && active != "" &&
		strings.EqualFold(filepath.Clean(mountPoint), filepath.Clean(active)) {
		return fmt.Errorf("this mount belongs to the run currently in progress; use Stop instead")
	}
	return memprocfs.CleanupMount(mountPoint)
}

// ListRunResults summarises what a run produced: one entry per plugin output
// file, classified as findings / empty / error, so the UI can surface the few
// files that matter among the many that legitimately contain nothing.
func (a *App) ListRunResults(outputDir string) (results.Summary, error) {
	return results.Scan(outputDir)
}

// OpenResultFile opens a single output file in its default application.
func (a *App) OpenResultFile(path string) error {
	// The empty second argument is start's window title, which it would
	// otherwise take from a quoted path.
	return exec.Command("cmd", "/c", "start", "", path).Start()
}

// OpenOutputFolder opens the given directory in Explorer.
func (a *App) OpenOutputFolder(path string) error {
	return exec.Command("explorer", path).Start()
}
