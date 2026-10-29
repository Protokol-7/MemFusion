package installer

// Dependency installation — everything the tools need but that is not a tool
// itself: the system components (Dokany, .NET, ClamAV, Python) and the
// Python packages the Volatility 3 plugins import.
//
// This is deliberately separate from installing the tools. A colleague
// getting this app on a fresh Windows box has none of it; the "Install
// dependencies" button is what makes their machine look like the developer's
// without a page of manual setup steps.
//
// The Python side does not use whatever interpreter happens to be on PATH.
// It creates an app-owned virtualenv on a wheel-compatible interpreter,
// because the packages that matter most here ship as binary wheels only:
// yara-python — which yarascan and five custom plugins need — had no wheel
// for Python 3.14 at the time of writing, so a colleague on the newest
// Python silently loses those plugins. Pinning the venv to a known-good
// interpreter makes the plugin set identical on every machine.

import (
	"context"
	"fmt"
	"io"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/prereq"
	"memforensics-gui/internal/proc"
	"memforensics-gui/internal/pydeps"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// PackageResult is the outcome of installing one Python package.
type PackageResult struct {
	Name     string `json:"name"`     // pip requirement string
	OK       bool   `json:"ok"`       // installed (or already present)
	Skipped  bool   `json:"skipped"`  // not applicable to this platform
	Affects  string `json:"affects"`  // plugins that stop working without it
	Detail   string `json:"detail"`   // error text when OK is false
	Optional bool   `json:"optional"` // a failure only costs the listed plugins
}

// SystemDepResult is the outcome of one system-level dependency.
type SystemDepResult struct {
	Name          string `json:"name"`
	OK            bool   `json:"ok"`
	AlreadyThere  bool   `json:"alreadyThere"`
	Skipped       bool   `json:"skipped"`
	Detail        string `json:"detail"`
	Required      bool   `json:"required"`
	ManualCommand string `json:"manualCommand"` // what to run by hand if it failed
}

// DepsResult reports everything the dependency install did.
type DepsResult struct {
	Python      string             `json:"python"`  // the venv interpreter it settled on
	VolPath     string             `json:"volPath"` // the venv's vol launcher, if built
	Packages    []PackageResult    `json:"packages"`
	System      []SystemDepResult  `json:"system"`
	SymbolPacks []SymbolPackResult `json:"symbolPacks"`
	Errors      []string           `json:"errors"` // failures that leave something unusable
}

// SymbolPackResult is the outcome of fetching one bulk Volatility 3 ISF
// symbol pack (see installVolatilitySymbols).
type SymbolPackResult struct {
	OS      string `json:"os"`
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped"` // already downloaded and up to date
	Path    string `json:"path"`
	Detail  string `json:"detail"`
}

// --- Python interpreter selection ------------------------------------------

// wheelSafeMinMinor / wheelSafeMaxMinor bound the Python 3 versions the venv
// will be built on. The upper bound is the point of the exercise: a brand new
// Python release predates the binary wheels of the C-extension packages above
// by months, and pip's only fallback is an sdist build needing MSVC and
// libyara — which is not something a colleague's laptop has.
//
// Raise wheelSafeMaxMinor once yara-python publishes wheels for the next
// version.
const (
	wheelSafeMinMinor = 10
	wheelSafeMaxMinor = 13
)

// wingetPythonID is the package installed when no compatible interpreter
// exists. Kept in step with wheelSafeMaxMinor.
const wingetPythonID = "Python.Python.3.13"

// VenvDir, VenvPython and VenvVol re-export the shared location helpers, so
// callers already holding this package don't need internal/paths too.
func VenvDir() string { return paths.VenvDir() }

// VenvPython returns the app venv's interpreter, or "" if the venv has not
// been created yet.
func VenvPython() string { return paths.VenvPython() }

// VenvVol returns the app venv's vol launcher, or "" if it isn't there.
func VenvVol() string { return paths.VenvVol() }

var pyVersionRe = regexp.MustCompile(`Python (\d+)\.(\d+)`)

// pythonMinor reports the 3.x minor version of an interpreter, or -1 if it
// isn't a usable Python 3.
func pythonMinor(path string) int {
	cmd := exec.Command(path, "--version")
	proc.Configure(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return -1
	}
	m := pyVersionRe.FindStringSubmatch(string(out))
	if m == nil || m[1] != "3" {
		return -1
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return -1
	}
	return minor
}

// hostPythonCandidates lists interpreters worth testing as the venv base, in
// preference order: the py launcher's explicit versions first (those let us
// ask for a specific minor even when PATH points at a newer one), then the
// default per-user install locations, then PATH.
func hostPythonCandidates() []string {
	var out []string
	if py := firstOnPath("py"); py != "" {
		// "py -3.13" is resolved below via launcherPython.
		for minor := wheelSafeMaxMinor; minor >= wheelSafeMinMinor; minor-- {
			if p := launcherPython(py, minor); p != "" {
				out = append(out, p)
			}
		}
	}
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		matches, _ := filepath.Glob(filepath.Join(base, "Programs", "Python", "Python3*", "python.exe"))
		out = append(out, matches...)
		// pythoncore (the Store/py-manager layout) installs here.
		matches, _ = filepath.Glob(filepath.Join(base, "Python", "pythoncore-3.*", "python.exe"))
		out = append(out, matches...)
	}
	matches, _ := filepath.Glob(`C:\Python3*\python.exe`)
	out = append(out, matches...)
	out = append(out, firstOnPath("python3"), firstOnPath("python"))
	return out
}

// launcherPython asks the Windows py launcher where a specific 3.x lives.
func launcherPython(py string, minor int) string {
	cmd := exec.Command(py, fmt.Sprintf("-3.%d", minor), "-c", "import sys; print(sys.executable)")
	proc.Configure(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if isFile(p) {
		return p
	}
	return ""
}

// pickBasePython returns the best interpreter to build the venv on: a
// wheel-compatible one if any exists, otherwise "" (the caller then installs
// one). The second return is the newest Python 3 seen at all, used only to
// explain in the log why an otherwise fine interpreter was passed over.
func pickBasePython() (chosen string, newestSeen string, newestMinor int) {
	seen := map[string]bool{}
	newestMinor = -1
	for _, c := range hostPythonCandidates() {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		minor := pythonMinor(c)
		if minor < 0 {
			continue
		}
		if minor > newestMinor {
			newestMinor, newestSeen = minor, c
		}
		if chosen == "" && minor >= wheelSafeMinMinor && minor <= wheelSafeMaxMinor {
			chosen = c
		}
	}
	return chosen, newestSeen, newestMinor
}

// ensurePythonEnv makes sure the app venv exists on a wheel-compatible
// interpreter and returns its python. It reuses an existing venv when that
// venv's own version is still in range, so repeat runs are cheap.
func ensurePythonEnv(ctx context.Context, emit Emitter) (string, error) {
	if p := VenvPython(); p != "" {
		if minor := pythonMinor(p); minor >= wheelSafeMinMinor && minor <= wheelSafeMaxMinor {
			emit("install:log", logLine(fmt.Sprintf("Reusing existing Python environment (3.%d) at %s", minor, VenvDir())))
			return p, nil
		}
		emit("install:log", logLine("Existing Python environment is on an unsupported version; rebuilding it."))
		if err := os.RemoveAll(VenvDir()); err != nil {
			return "", fmt.Errorf("removing stale environment: %w", err)
		}
	}

	base, newest, newestMinor := pickBasePython()
	if base == "" {
		if newestMinor >= 0 {
			emit("install:log", logLine(fmt.Sprintf(
				"Found Python 3.%d at %s, but packages this app needs (yara-python among them) "+
					"have no wheels for it; installing Python 3.%d alongside it.",
				newestMinor, newest, wheelSafeMaxMinor)))
		} else {
			emit("install:log", logLine("No Python 3 found; installing one."))
		}
		if err := installPython(ctx, emit); err != nil {
			return "", err
		}
		base, _, _ = pickBasePython()
		if base == "" {
			return "", fmt.Errorf("installed Python, but still could not find a %d.%d–%d.%d interpreter "+
				"(a new terminal may be needed for PATH changes to apply)",
				3, wheelSafeMinMinor, 3, wheelSafeMaxMinor)
		}
	}

	emit("install:log", logLine("Creating Python environment at "+VenvDir()+" using "+base))
	if err := os.MkdirAll(filepath.Dir(VenvDir()), 0o755); err != nil {
		return "", err
	}
	if err := runLogged(ctx, emit, base, "-m", "venv", VenvDir()); err != nil {
		return "", fmt.Errorf("creating virtualenv with %s: %w", base, err)
	}
	python := VenvPython()
	if python == "" {
		return "", fmt.Errorf("virtualenv created at %s but no interpreter found inside it", VenvDir())
	}
	// An old pip in a fresh venv is the usual cause of "no matching
	// distribution" on packages that do have a wheel, so bring it current
	// before anything else.
	if err := runLogged(ctx, emit, python, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"); err != nil {
		emit("install:log", logLine("Warning: could not upgrade pip in the new environment; continuing anyway."))
	}
	return python, nil
}

// installPython installs a wheel-compatible Python, winget first and the
// python.org installer as the fallback.
func installPython(ctx context.Context, emit Emitter) error {
	if err := wingetInstall(ctx, emit, wingetPythonID); err == nil {
		return nil
	} else {
		emit("install:log", logLine("winget could not install Python ("+err.Error()+"); trying the python.org installer."))
	}
	// python.org's installer is a Windows Installer bootstrapper; these
	// switches give an unattended per-user install that also registers the
	// py launcher and puts python on PATH.
	url := fmt.Sprintf("https://www.python.org/ftp/python/3.%d.0/python-3.%d.0-amd64.exe",
		wheelSafeMaxMinor, wheelSafeMaxMinor)
	return runDownloadedInstaller(ctx, emit, url, "python-installer.exe",
		"/quiet", "InstallAllUsers=0", "PrependPath=1", "Include_launcher=1")
}

// --- pip install ------------------------------------------------------------

// installPythonPackages installs every applicable dependency into the venv.
// Each package is installed on its own so one failure (a package with no
// wheel for this interpreter, say) costs only the plugins that need it.
func installPythonPackages(ctx context.Context, emit Emitter, python string) []PackageResult {
	results := make([]PackageResult, 0, len(pydeps.All))
	total := len(pydeps.All)
	for i, dep := range pydeps.All {
		pct := (i * 100) / total
		emit("install:progress", stage("pydeps", "running", pct, fmt.Sprintf("installing %s (%d/%d)…", dep.Req, i+1, total)))
		emit("install:log", logLine("Installing "+dep.Req+"…"))
		err := runLogged(ctx, emit, python, "-m", "pip", "install", "--upgrade", dep.Req)
		if err == nil {
			err = runLogged(ctx, emit, python, "-c", "import importlib; importlib.import_module("+strconv.Quote(dep.Import)+")")
		}
		if err == nil {
			results = append(results, PackageResult{Name: dep.Req, OK: true, Affects: dep.Affects, Optional: dep.Optional})
			continue
		}
		results = append(results, PackageResult{Name: dep.Req, Affects: dep.Affects, Optional: dep.Optional,
			Detail: err.Error()})
		emit("install:log", logLine(fmt.Sprintf("  %s failed; unavailable: %s", dep.Req, dep.Affects)))
	}
	return results
}

// --- Volatility 3 bulk symbol packs ------------------------------------------

// volSymbolPacks lists the official Volatility 3 bulk ISF packs this app
// downloads automatically. windows.zip is deliberately excluded: at ~840 MB
// it would more than double the length of "Install dependencies" for a pack
// that mostly duplicates what vol3 already resolves on its own — given a
// Windows image, it looks up the exact PDB for that kernel from Microsoft's
// public symbol server per run, no bulk pack required. Linux and macOS have
// no equivalent always-available symbol server, which is the actual gap
// these packs close (the same gap MemNixFS's own --auto-fetch targets for
// the Linux images it reads directly).
var volSymbolPacks = []struct{ os, url string }{
	{"linux", "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip"},
	{"mac", "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip"},
}

// installVolatilitySymbols downloads the bulk packs into paths.SymbolsDir(),
// which every `vol` invocation is pointed at via --symbol-dirs (see
// internal/volatility/plugindirs.go's symbolDirArgs). A pack already on disk
// with the same size as the remote copy is left alone — these packs aren't
// versioned any more precisely than that upstream, and re-downloading tens
// of megabytes on every "Install dependencies" click would make the button
// expensive to press on a machine that is already current.
func installVolatilitySymbols(ctx context.Context, emit Emitter) []SymbolPackResult {
	dir := paths.SymbolsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []SymbolPackResult{{Detail: "creating " + dir + ": " + err.Error()}}
	}

	results := make([]SymbolPackResult, 0, len(volSymbolPacks))
	for _, pack := range volSymbolPacks {
		dest := filepath.Join(dir, pack.os+".zip")
		tool := "symbols-" + pack.os

		if remoteSize, err := remoteContentLength(ctx, pack.url); err == nil {
			if info, statErr := os.Stat(dest); statErr == nil && info.Size() == remoteSize {
				emit("install:log", logLine(pack.os+".zip already downloaded; skipping."))
				emit("install:progress", stage(tool, "done", 100, "already downloaded"))
				results = append(results, SymbolPackResult{OS: pack.os, OK: true, Skipped: true, Path: dest})
				continue
			}
		}

		emit("install:progress", stage(tool, "running", 0, "downloading "+pack.os+" symbol pack…"))
		emit("install:log", logLine("Downloading "+pack.url+"…"))
		tmpPath, err := downloadToTemp(ctx, pack.url, pack.os+".zip", tool, emit)
		if err != nil {
			emit("install:progress", stage(tool, "error", 0, err.Error()))
			results = append(results, SymbolPackResult{OS: pack.os, Detail: err.Error()})
			continue
		}
		if err := moveFile(tmpPath, dest); err != nil {
			os.Remove(tmpPath)
			emit("install:progress", stage(tool, "error", 0, err.Error()))
			results = append(results, SymbolPackResult{OS: pack.os, Detail: err.Error()})
			continue
		}
		emit("install:progress", stage(tool, "done", 100, "downloaded"))
		results = append(results, SymbolPackResult{OS: pack.os, OK: true, Path: dest})
	}
	return results
}

// remoteContentLength HEADs url and returns the server-reported size, used
// to decide whether an already-downloaded pack is still current.
func remoteContentLength(ctx context.Context, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
		return 0, fmt.Errorf("HEAD %s: HTTP %s", url, resp.Status)
	}
	return resp.ContentLength, nil
}

// --- system dependencies ----------------------------------------------------

// systemDep is one non-Python dependency, with both install routes.
type systemDep struct {
	name     string
	required bool
	present  func() bool
	wingetID string
	// fallback installs the dep without winget; nil means winget-only.
	fallback func(ctx context.Context, emit Emitter) error
	manual   string // what to tell the user if everything failed
	why      string
}

func windowsSystemDeps() []systemDep {
	return []systemDep{
		{
			name: "Dokany v2 (filesystem driver)", required: true, present: prereq.DokanyPresent,
			wingetID: "dokan-dev.Dokany",
			fallback: func(ctx context.Context, emit Emitter) error {
				// DokanSetupDbg.exe is the debug build and sits right
				// beside the real one in the release, so exclude it.
				return installFromGitHubRelease(ctx, emit, "dokan-dev/dokany", func(n string) bool {
					return strings.HasPrefix(n, "DokanSetup") && !strings.Contains(n, "Dbg") &&
						strings.HasSuffix(n, ".exe")
				}, innoSetupSilentArgs...)
			},
			manual: "https://github.com/dokan-dev/dokany/releases/latest → DokanSetup.exe",
			why:    "MemProcFS mounts its virtual filesystem through Dokany",
		},
		{
			name: ".NET 9 Desktop Runtime", required: true, present: prereq.DotnetPresent,
			wingetID: "Microsoft.DotNet.DesktopRuntime.9",
			fallback: func(ctx context.Context, emit Emitter) error {
				return runDownloadedInstaller(ctx, emit,
					"https://aka.ms/dotnet/9.0/windowsdesktop-runtime-win-x64.exe",
					"windowsdesktop-runtime.exe", "/install", "/quiet", "/norestart")
			},
			manual: "https://dotnet.microsoft.com/en-us/download/dotnet/9.0",
			why:    "the EZTools parsers MemProcFS-Analyzer drives (AmcacheParser, RECmd, EvtxECmd…)",
		},
		{
			name: "ClamAV", required: false, present: prereq.ClamAVPresent,
			wingetID: "Cisco.ClamAV",
			manual:   "https://www.clamav.net/downloads; then remove the 'Example' lines from freshclam.conf and clamd.conf",
			why:      "optional standalone antivirus; not used by the mounted Analyzer workflow",
		},
		{
			name: "7-Zip", required: false, present: prereq.SevenZipPresent,
			wingetID: "7zip.7zip",
			fallback: func(ctx context.Context, emit Emitter) error {
				return installFromGitHubRelease(ctx, emit, "ip7z/7zip", func(n string) bool {
					return strings.HasPrefix(n, "7z") && strings.HasSuffix(n, "-x64.exe")
				}, "/S")
			},
			manual: "https://www.7-zip.org/download.html",
			why:    "extracting the vmlinux ELF out of a kernel debuginfo package (.rpm/.ddeb) for the Linux symbol generator (internal/linuxsymbols); the automatic online lookup doesn't need it",
		},
	}
}

// innoSetupSilentArgs are the unattended switches for an Inno Setup
// installer, which is what Dokany ships.
var innoSetupSilentArgs = []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}

// installSystemDeps installs the platform's system-level dependencies,
// skipping anything already present so no needless UAC prompts appear.
func installSystemDeps(ctx context.Context, emit Emitter) []SystemDepResult {
	deps := windowsSystemDeps()
	results := make([]SystemDepResult, 0, len(deps))
	haveWinget := firstOnPath("winget") != ""
	if !haveWinget {
		emit("install:log", logLine("winget not found; falling back to direct vendor downloads."))
	}

	for i, dep := range deps {
		pct := (i * 100) / len(deps)
		if dep.present != nil && dep.present() {
			emit("install:log", logLine(dep.name+" already installed; skipping."))
			results = append(results, SystemDepResult{Name: dep.name, OK: true, AlreadyThere: true,
				Required: dep.required, Detail: "already installed"})
			continue
		}
		emit("install:progress", stage("sysdeps", "running", pct, "installing "+dep.name+"…"))
		emit("install:log", logLine("Installing "+dep.name+" ("+dep.why+")…"))

		var lastErr error
		installed := false
		if haveWinget && dep.wingetID != "" {
			if err := wingetInstall(ctx, emit, dep.wingetID); err == nil {
				installed = true
			} else {
				lastErr = err
				emit("install:log", logLine("  winget route failed: "+err.Error()))
			}
		}
		if !installed && dep.fallback != nil {
			emit("install:log", logLine("  trying direct download…"))
			if err := dep.fallback(ctx, emit); err == nil {
				installed = true
			} else {
				lastErr = err
			}
		}

		res := SystemDepResult{Name: dep.name, Required: dep.required, ManualCommand: dep.manual}
		switch {
		case installed && dep.present != nil && !dep.present():
			// Driver installs commonly need a reboot before their DLLs show
			// up; say so rather than reporting a false failure.
			res.OK = true
			res.Detail = "installer ran; a restart may be needed before it is detected"
		case installed:
			res.OK = true
			res.Detail = "installed"
		default:
			res.Detail = errText(lastErr)
		}
		results = append(results, res)
	}
	return results
}

// --- install helpers --------------------------------------------------------

// wingetInstall runs an unattended winget install. Exit code 0x8A150061
// ("already installed") is treated as success, since re-running the
// dependency button must not report an error for something already there.
func wingetInstall(ctx context.Context, emit Emitter, id string) error {
	winget := firstOnPath("winget")
	if winget == "" {
		return fmt.Errorf("winget not found")
	}
	cmd := exec.CommandContext(ctx, winget, "install", "--id", id, "--exact",
		"--silent", "--accept-source-agreements", "--accept-package-agreements",
		"--disable-interactivity")
	proc.Configure(cmd)
	err := runLoggedCmd(emit, cmd)
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if ok := asExitError(err, &exitErr); ok {
		switch uint32(exitErr.ExitCode()) {
		case 0x8A150061: // APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
			return nil
		case 0x8A15002B: // ...NO_APPLICABLE_UPGRADE
			return nil
		}
	}
	return err
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// installFromGitHubRelease downloads the matching asset from a repo's latest
// release and runs it unattended. .msi assets go through msiexec; anything
// else is executed directly with the supplied switches.
func installFromGitHubRelease(ctx context.Context, emit Emitter, repo string, match func(string) bool, args ...string) error {
	name, url, _, err := githubLatestAsset(ctx, repo, match)
	if err != nil {
		return err
	}
	return runDownloadedInstaller(ctx, emit, url, name, args...)
}

// runDownloadedInstaller fetches an installer to a temp file and runs it
// unattended, then deletes it.
func runDownloadedInstaller(ctx context.Context, emit Emitter, url, name string, args ...string) error {
	dir, err := os.MkdirTemp("", "memforensics-dep-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, filepath.Base(name))

	emit("install:log", logLine("Downloading "+name+"…"))
	if err := downloadFile(ctx, url, path); err != nil {
		return err
	}

	emit("install:log", logLine("Running "+filepath.Base(path)+" (a Windows elevation prompt may appear)…"))
	if strings.EqualFold(filepath.Ext(path), ".msi") {
		msiArgs := append([]string{"/i", path, "/qn", "/norestart"}, args...)
		return runLogged(ctx, emit, "msiexec", msiArgs...)
	}
	return runLogged(ctx, emit, path, args...)
}

// downloadFile streams url to path.
func downloadFile(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %s", url, resp.Status)
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func errText(err error) string {
	if err == nil {
		return "failed"
	}
	return err.Error()
}

// --- entry point ------------------------------------------------------------

// InstallDependencies installs everything the tools need but are not: the
// system components on this platform, then an app-owned Python environment
// with Volatility 3 and every package its plugins import.
//
// System dependencies come first because they are the ones that can prompt
// for elevation — better to get those out of the way while the user is still
// watching than halfway through a long pip run.
//
// patchScript is scripts/patch_vol3_pool_circular_import.py. It is applied to
// the environment this function creates, without asking: a fresh Volatility 3
// crashes on any -p plugin directory with
//
//	AttributeError: partially initialized module '…poolscanner' has no
//	attribute 'PoolConstraint' (most likely due to a circular import)
//
// which the catalog probe survives only by dropping every custom plugin — so
// an unpatched environment silently loses the ~60 vendored plugins that are
// the point of this app. The consent prompt that guards the same patch after
// a tools install exists because that one may be editing a Python
// installation the user owns; this environment is the app's own, created
// moments earlier, so there is nothing to ask about.
func InstallDependencies(ctx context.Context, emit Emitter, patchScript string) DepsResult {
	var res DepsResult
	emit("install:log", logLine("Installing dependencies…"))

	// --- system dependencies ---
	emit("install:progress", stage("sysdeps", "running", 0, "checking system dependencies…"))
	res.System = installSystemDeps(ctx, emit)
	var sysFailed []string
	for _, s := range res.System {
		if !s.OK && !s.Skipped {
			sysFailed = append(sysFailed, s.Name)
			res.Errors = append(res.Errors, s.Name+": "+s.Detail)
		}
	}
	if len(sysFailed) > 0 {
		emit("install:progress", stage("sysdeps", "error", 100,
			"could not install: "+strings.Join(sysFailed, ", ")))
	} else {
		emit("install:progress", stage("sysdeps", "done", 100, "all system dependencies present"))
	}

	// --- Python environment ---
	emit("install:progress", stage("pyenv", "running", 0, "preparing the Python environment…"))
	python, err := ensurePythonEnv(ctx, emit)
	if err != nil {
		res.Errors = append(res.Errors, "Python environment: "+err.Error())
		emit("install:progress", stage("pyenv", "error", 0, err.Error()))
		return res
	}
	res.Python = python
	emit("install:progress", stage("pyenv", "done", 100, "ready: "+python))

	// --- Python packages ---
	emit("install:progress", stage("pydeps", "running", 0, "installing Python packages…"))
	res.Packages = installPythonPackages(ctx, emit, python)
	if err := runLogged(ctx, emit, python, "-m", "pip", "check"); err != nil {
		res.Errors = append(res.Errors, "Python dependency conflicts: "+err.Error())
	}
	var failedRequired, failedOptional []string
	for _, p := range res.Packages {
		if p.OK || p.Skipped {
			continue
		}
		if p.Optional {
			failedOptional = append(failedOptional, p.Name)
			res.Errors = append(res.Errors, p.Name+" failed to install; affects: "+p.Affects)
		} else {
			failedRequired = append(failedRequired, p.Name)
			res.Errors = append(res.Errors, p.Name+" failed to install; affects: "+p.Affects)
		}
	}
	switch {
	case len(failedRequired) > 0:
		emit("install:progress", stage("pydeps", "error", 100, "failed: "+strings.Join(failedRequired, ", ")))
	case len(failedOptional) > 0:
		emit("install:progress", stage("pydeps", "done", 100,
			"installed, except "+strings.Join(failedOptional, ", ")+" (those plugins will show as unavailable)"))
	default:
		emit("install:progress", stage("pydeps", "done", 100, "all packages installed"))
	}

	// --- Volatility 3 bulk symbol packs (Linux, macOS) ---
	emit("install:progress", stage("symbols", "running", 0, "downloading Volatility 3 symbol packs…"))
	res.SymbolPacks = installVolatilitySymbols(ctx, emit)
	var symFailed []string
	for _, s := range res.SymbolPacks {
		if !s.OK {
			symFailed = append(symFailed, s.OS)
			res.Errors = append(res.Errors, s.OS+" symbol pack: "+s.Detail)
		}
	}
	if len(symFailed) > 0 {
		emit("install:progress", stage("symbols", "error", 100, "could not download: "+strings.Join(symFailed, ", ")))
	} else {
		emit("install:progress", stage("symbols", "done", 100, "symbol packs ready"))
	}

	res.VolPath = VenvVol()
	if res.VolPath == "" {
		res.Errors = append(res.Errors, "Volatility 3 installed, but no 'vol' launcher appeared in "+VenvDir())
		return res
	}
	emit("install:log", logLine("Volatility 3 launcher: "+res.VolPath))

	// --- circular-import patch ---
	// pip may have written a fresh (unpatched) pool.py, so this runs on every
	// dependency install, not just the first.
	if patchScript != "" {
		emit("install:progress", stage("vol3patch", "running", 0, "applying the Volatility 3 circular-import fix…"))
		if _, err := PatchVol3CircularImport(ctx, emit, patchScript); err != nil {
			// Not fatal: vol3 still runs, it just cannot load the custom
			// plugin directories, which the catalog probe already handles.
			res.Errors = append(res.Errors,
				"could not apply the Volatility 3 circular-import fix; custom plugins may not load: "+err.Error())
			emit("install:progress", stage("vol3patch", "error", 0, err.Error()))
		} else {
			emit("install:progress", stage("vol3patch", "done", 100, "custom plugin loading fixed"))
		}
	}
	return res
}
