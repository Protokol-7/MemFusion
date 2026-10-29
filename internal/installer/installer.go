// Package installer downloads and installs the external tools this app
// drives — Volatility 3, MemProcFS, MemNixFS, and (Windows only)
// MemProcFS-Analyzer — into predictable per-user locations, and reports back
// the resulting executable paths so the UI can auto-populate its config
// fields.
package installer

import (
	"archive/zip"
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"memforensics-gui/internal/analyzer"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/proc"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Emitter matches the Emitter type used elsewhere in the app.
type Emitter func(event string, payload any)

// Result reports the outcome of an install run: the detected tool paths
// (empty if that tool couldn't be installed/found) and any per-tool errors.
type Result struct {
	VolPath        string   `json:"volPath"`
	Vol2Path       string   `json:"vol2Path"`
	MemProcfsPath  string   `json:"memProcfsPath"`
	MemNixFsPath   string   `json:"memNixFsPath"`
	AnalyzerPath   string   `json:"analyzerPath"`
	Dwarf2JsonPath string   `json:"dwarf2JsonPath"`
	Errors         []string `json:"errors"`
}

// ToolsDir is the per-user directory the app installs downloaded tools into:
// %LOCALAPPDATA%\memforensics-gui\tools
func ToolsDir() string { return paths.ToolsDir() }

// InstallTools downloads and installs the external tools themselves, and
// returns the detected paths. Each tool is attempted independently; a failure
// in one is recorded in Result.Errors and does not stop the others.
// MemProcFS-Analyzer is a Windows-only PowerShell tool, so it is skipped
// entirely on other systems.
//
// Anything already at the latest release is left alone (see upToDate), so
// this doubles as the update button: pressing it on a current machine costs
// four GitHub API calls and nothing else.
//
// The dependencies those tools need — the Windows system components and the
// Python packages the plugins import — are installed separately by
// InstallDependencies.
func InstallTools(ctx context.Context, emit Emitter) Result {
	var res Result
	toolsDir := ToolsDir()
	_, vol2Exe := vol2AssetMatcher()
	res.Vol2Path = findExecutable(filepath.Join(toolsDir, "volatility2"), vol2Exe)
	res.MemProcfsPath = findExecutable(filepath.Join(toolsDir, "MemProcFS"), "MemProcFS.exe")
	res.MemNixFsPath = findExecutable(filepath.Join(toolsDir, "MemNixFS"), "memnixfs.exe")
	res.AnalyzerPath = findExecutable(filepath.Join(toolsDir, "MemProcFS-Analyzer"), "MemProcFS-Analyzer.ps1")
	res.Dwarf2JsonPath = findExecutable(filepath.Join(toolsDir, "dwarf2json"), "dwarf2json.exe")
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("creating tools dir %s: %v", toolsDir, err))
		emit("install:progress", stage("all", "error", 0, err.Error()))
		return res
	}
	emit("install:log", logLine("Installing into "+toolsDir))

	// --- Volatility 3 (via pip/pipx) ---
	emit("install:progress", stage("volatility3", "running", 0, "installing Volatility 3…"))
	if path, err := installVolatility(ctx, emit); err != nil {
		res.Errors = append(res.Errors, "Volatility 3: "+err.Error())
		emit("install:progress", stage("volatility3", "error", 0, err.Error()))
	} else {
		res.VolPath = path
		emit("install:progress", stage("volatility3", "done", 100, "installed: "+path))
	}

	// --- Volatility 2 (standalone build, bundles its own Python 2) ---
	emit("install:progress", stage("volatility2", "running", 0, "downloading Volatility 2…"))
	if path, err := installVolatility2(ctx, toolsDir, emit); err != nil {
		res.Errors = append(res.Errors, "Volatility 2: "+err.Error())
		emit("install:progress", stage("volatility2", "error", 0, err.Error()))
	} else {
		res.Vol2Path = path
		emit("install:progress", stage("volatility2", "done", 100, "installed: "+path))
	}

	// --- MemProcFS (release archive) ---
	emit("install:progress", stage("memprocfs", "running", 0, "downloading MemProcFS…"))
	if path, err := installMemProcfs(ctx, toolsDir, emit); err != nil {
		res.Errors = append(res.Errors, "MemProcFS: "+err.Error())
		emit("install:progress", stage("memprocfs", "error", 0, err.Error()))
	} else {
		res.MemProcfsPath = path
		emit("install:progress", stage("memprocfs", "done", 100, "installed: "+path))
	}

	// --- MemNixFS (Linux memory images, runs on Windows) ---
	emit("install:progress", stage("memnixfs", "running", 0, "downloading MemNixFS…"))
	if path, err := installMemNixFS(ctx, toolsDir, emit); err != nil {
		res.Errors = append(res.Errors, "MemNixFS: "+err.Error())
		emit("install:progress", stage("memnixfs", "error", 0, err.Error()))
	} else {
		res.MemNixFsPath = path
		emit("install:progress", stage("memnixfs", "done", 100, "installed: "+path))
	}

	// --- MemProcFS-Analyzer ---
	emit("install:progress", stage("analyzer", "running", 0, "downloading MemProcFS-Analyzer…"))
	if path, err := installAnalyzer(ctx, toolsDir, emit); err != nil {
		res.Errors = append(res.Errors, "MemProcFS-Analyzer: "+err.Error())
		emit("install:progress", stage("analyzer", "error", 0, err.Error()))
	} else {
		res.AnalyzerPath = path
		emit("install:progress", stage("analyzer", "done", 100, "installed: "+path))
	}
	if res.AnalyzerPath != "" {
		// Updater.ps1 fetches the smaller tools the analyzer drives
		// (EZTools, xsv, jq, Zircolite…) — see internal/prereq's note on the
		// analyzer's own prerequisites. Best-effort: the analyzer script
		// itself is already installed either way, and re-running Install
		// retries this on its own.
		emit("install:progress", stage("analyzer-updater", "running", 0, "running MemProcFS-Analyzer's Updater.ps1…"))
		if err := runAnalyzerUpdater(ctx, res.AnalyzerPath, emit); err != nil {
			res.Errors = append(res.Errors, "Analyzer dependencies: "+err.Error())
			emit("install:progress", stage("analyzer-updater", "error", 0, err.Error()))
		} else {
			emit("install:progress", stage("analyzer-updater", "done", 100, "analyzer tooling up to date"))
		}
	}

	// --- dwarf2json (Linux symbol generation fallback — internal/linuxsymbols) ---
	emit("install:progress", stage("dwarf2json", "running", 0, "downloading dwarf2json…"))
	if path, err := installDwarf2Json(ctx, toolsDir, emit); err != nil {
		res.Errors = append(res.Errors, "dwarf2json: "+err.Error())
		emit("install:progress", stage("dwarf2json", "error", 0, err.Error()))
	} else {
		res.Dwarf2JsonPath = path
		emit("install:progress", stage("dwarf2json", "done", 100, "installed: "+path))
	}

	return res
}

// PatchVol3CircularImport writes scriptSource (the contents of
// scripts/patch_vol3_pool_circular_import.py) to a temp file and runs it
// with whichever Python interpreter has volatility3 installed. It works
// around a circular-import crash in vol3's own pool.py that this app's
// custom plugin dirs can provoke (see internal/volatility/discover.go's
// fallback, and the script's own doc comment for the full explanation).
//
// This is opt-in — call it only after the user has confirmed — since it
// edits a file inside a third-party installed package rather than anything
// this app owns, and needs re-running after every volatility3 upgrade.
func PatchVol3CircularImport(ctx context.Context, emit Emitter, scriptSource string) (string, error) {
	python := DetectVolatility3Python()
	if python == "" {
		return "", fmt.Errorf("could not find a Python interpreter with volatility3 installed")
	}

	tmp, err := os.CreateTemp("", "memforensics-gui-vol3patch-*.py")
	if err != nil {
		return "", fmt.Errorf("writing temp patch script: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(scriptSource); err != nil {
		tmp.Close()
		return "", fmt.Errorf("writing temp patch script: %w", err)
	}
	tmp.Close()

	emit("install:log", logLine("Patching Volatility 3 (circular-import fix) using "+python+"…"))
	cmd := exec.CommandContext(ctx, python, tmp.Name())
	proc.Configure(cmd)
	out, runErr := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if text != "" {
		emit("install:log", logLine(text))
	}
	if runErr != nil {
		return text, fmt.Errorf("patch script failed: %w", runErr)
	}
	return text, nil
}

// DetectVolatility3Python finds a Python interpreter with volatility3
// importable, verified by actually importing it rather than assumed from
// the install method — a pipx install runs in an isolated venv interpreter,
// while a pip --user install uses the system one.
func DetectVolatility3Python() string {
	var candidates []string
	// The app's own environment first — it is the one guaranteed to have the
	// plugin dependencies installed alongside volatility3.
	candidates = append(candidates, VenvPython())
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "pipx", "venvs", "volatility3", "Scripts", "python.exe"))
	}
	candidates = append(candidates, firstOnPath("python3"), firstOnPath("python"))

	for _, c := range candidates {
		if c == "" {
			continue
		}
		cmd := exec.Command(c, "-c", "import volatility3")
		proc.Configure(cmd)
		if err := cmd.Run(); err == nil {
			return c
		}
	}
	return ""
}

// --- Volatility 3 -----------------------------------------------------------

// installVolatility installs Volatility 3 with pipx if available (cleanest —
// gives a predictable vol.exe launcher) or pip --user otherwise, then locates
// the resulting executable.
//
// Note this is the fallback path: InstallDependencies normally puts
// Volatility 3 in the app's own environment, and detectVol prefers that.
func installVolatility(ctx context.Context, emit Emitter) (string, error) {
	// The dependency installer owns this environment, so upgrade its Volatility
	// package in place. Merely finding vol.exe is not enough: that was the old
	// behavior and left the framework (including YARA scanner fixes) stale.
	if python := VenvPython(); python != "" {
		emit("install:log", logLine("Checking PyPI for a newer Volatility 3 release…"))
		if err := runLogged(ctx, emit, python, "-m", "pip", "install", "--upgrade", "volatility3[full]"); err != nil {
			return "", err
		}
		if vol := VenvVol(); vol != "" {
			return vol, nil
		}
		return "", fmt.Errorf("Volatility 3 upgraded, but vol.exe is missing from %s", VenvDir())
	}

	python := firstOnPath("python", "python3")
	if pipx := firstOnPath("pipx"); pipx != "" {
		emit("install:log", logLine("Installing or upgrading Volatility 3 via pipx…"))
		if err := runLogged(ctx, emit, pipx, "upgrade", "volatility3"); err != nil {
			// upgrade fails when the package is not installed yet.
			if err := runLogged(ctx, emit, pipx, "install", "volatility3"); err != nil {
				return "", err
			}
		}
	} else if python != "" {
		emit("install:log", logLine("pipx not found; installing Volatility 3 via pip --user…"))
		if err := runLogged(ctx, emit, python, "-m", "pip", "install", "--user", "--upgrade", "volatility3"); err != nil {
			return "", err
		}
	} else {
		return "", fmt.Errorf("neither pipx nor python found on PATH; install Python 3 first")
	}

	if p := detectVol(); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("installed, but could not locate vol.exe afterwards; check that the Scripts directory of your Python install is on PATH")
}

// detectVol looks for the vol launcher, preferring the app's own Python
// environment (what InstallDependencies builds) over anything the user
// happens to have, then the locations pipx/pip --user use on each platform,
// then PATH. The venv comes first because it is the one interpreter this app
// guarantees has every plugin dependency in it.
func detectVol() string {
	if v := VenvVol(); v != "" {
		return v
	}
	const name = "vol.exe"
	var candidates []string
	if home, err := os.UserHomeDir(); err == nil {
		// pipx, and newer pipx on Windows.
		candidates = append(candidates, filepath.Join(home, ".local", "bin", name))
	}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		// pip --user on Windows: %APPDATA%\Python\PythonXY\Scripts
		matches, _ := filepath.Glob(filepath.Join(appdata, "Python", "Python*", "Scripts", name))
		candidates = append(candidates, matches...)
	}
	for _, c := range candidates {
		if isFile(c) {
			return c
		}
	}
	if p := firstOnPath(name); p != "" {
		return p
	}
	return ""
}

// --- Volatility 2 -----------------------------------------------------------

// installVolatility2 fetches the official standalone Volatility 2.6 build.
// The standalone bundles its own Python 2 interpreter, which is why it is
// preferred over the source zip: Volatility 2 needs Python 2, which is EOL
// and absent from modern systems, and installing one just for this would be
// far more invasive than dropping in a self-contained binary.
func installVolatility2(ctx context.Context, toolsDir string, emit Emitter) (string, error) {
	matcher, exeName := vol2AssetMatcher()
	name, url, tag, err := githubLatestAsset(ctx, "volatilityfoundation/volatility", matcher)
	if err != nil {
		return "", err
	}
	dest := filepath.Join(toolsDir, "volatility2")
	if existing, ok := upToDate(dest, tag, exeName); ok {
		emit("install:log", logLine("Volatility 2 already at the latest release ("+tag+"); skipping download."))
		return existing, nil
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", fmt.Errorf("clearing old install: %w", err)
	}
	emit("install:log", logLine("Downloading "+name))
	if err := downloadAndExtract(ctx, url, name, dest, "volatility2", emit); err != nil {
		return "", err
	}
	writeInstalledTag(dest, tag)
	path := findExecutable(dest, exeName)
	if path == "" {
		return "", fmt.Errorf("extracted, but no %s found under %s", exeName, dest)
	}
	return path, nil
}

func vol2AssetMatcher() (func(string) bool, string) {
	return func(n string) bool { return strings.Contains(n, "win64_standalone") && strings.HasSuffix(n, ".zip") },
		"volatility_2.6_win64_standalone.exe"
}

// --- MemProcFS --------------------------------------------------------------

func installMemProcfs(ctx context.Context, toolsDir string, emit Emitter) (string, error) {
	name, url, tag, err := githubLatestAsset(ctx, "ufrisk/MemProcFS", memprocfsAssetMatcher())
	if err != nil {
		return "", err
	}
	dest := filepath.Join(toolsDir, "MemProcFS")
	const exe = "memprocfs.exe"
	if existing, ok := upToDate(dest, tag, exe); ok {
		emit("install:log", logLine("MemProcFS already at the latest release ("+tag+"); skipping download."))
		return existing, nil
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", fmt.Errorf("clearing old install: %w", err)
	}
	emit("install:log", logLine("Downloading "+name))
	if err := downloadAndExtract(ctx, url, name, dest, "memprocfs", emit); err != nil {
		return "", err
	}
	writeInstalledTag(dest, tag)
	path := findExecutable(dest, exe)
	if path == "" {
		return "", fmt.Errorf("extracted, but no %s found under %s", exe, dest)
	}
	return path, nil
}

// memprocfsAssetMatcher returns a predicate selecting the right MemProcFS
// release asset. Asset names look like
// MemProcFS_files_and_binaries_v5.18.5-win_x64-20260820.zip — note the
// "-latest" asset is deliberately avoided in favor of the version-stamped
// one.
func memprocfsAssetMatcher() func(string) bool {
	return func(n string) bool {
		return strings.Contains(n, "win_x64") && strings.HasSuffix(n, ".zip") && !strings.Contains(n, "latest")
	}
}

// --- MemNixFS (Linux memory images, runs on Windows) ------------------------

// installMemNixFS downloads the MemNixFS release for this platform.
// MemNixFS (github.com/MemNixFS/MemNixFS) is an independent, Apache-2.0
// project built by two developers unrelated to MemProcFS or Volatility — it
// does the same "memory as a filesystem" trick MemProcFS does, but for Linux
// dumps (AVML/LiME/raw/kdump), which MemProcFS itself cannot read. Its
// releases publish a SHA256SUMS.txt alongside the archives; this is verified
// against the download before extracting anything, which the other tools
// here don't do — worth the extra step for a smaller, newer project than
// Volatility or MemProcFS.
func installMemNixFS(ctx context.Context, toolsDir string, emit Emitter) (string, error) {
	const repo = "MemNixFS/MemNixFS"
	rel, err := githubLatestRelease(ctx, repo)
	if err != nil {
		return "", err
	}

	var assetName, assetURL, sumsURL string
	for _, a := range rel.Assets {
		switch {
		case strings.Contains(a.Name, "win64") && strings.HasSuffix(a.Name, ".zip"):
			assetName, assetURL = a.Name, a.URL
		case strings.EqualFold(a.Name, "SHA256SUMS.txt"):
			sumsURL = a.URL
		}
	}
	if assetName == "" {
		return "", fmt.Errorf("no win64 zip asset in %s release %s", repo, rel.TagName)
	}

	dest := filepath.Join(toolsDir, "MemNixFS")
	const exe = "memnixfs.exe"
	if existing, ok := upToDate(dest, rel.TagName, exe); ok {
		emit("install:log", logLine("MemNixFS already at the latest release ("+rel.TagName+"); skipping download."))
		return existing, nil
	}

	emit("install:log", logLine("Downloading "+assetName))
	archivePath, err := downloadToTemp(ctx, assetURL, assetName, "memnixfs", emit)
	if err != nil {
		return "", err
	}
	defer os.Remove(archivePath)

	if sumsURL != "" {
		if err := verifyChecksum(ctx, sumsURL, assetName, archivePath); err != nil {
			return "", fmt.Errorf("verifying MemNixFS download: %w", err)
		}
		emit("install:log", logLine("MemNixFS download verified against the release's SHA256SUMS.txt."))
	} else {
		emit("install:log", logLine("MemNixFS release has no SHA256SUMS.txt; installing without checksum verification."))
	}

	if err := os.RemoveAll(dest); err != nil {
		return "", fmt.Errorf("clearing old install: %w", err)
	}
	emit("install:log", logLine("Extracting "+assetName+"…"))
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	if err := extractZip(archivePath, dest); err != nil {
		return "", err
	}
	writeInstalledTag(dest, rel.TagName)
	path := findExecutable(dest, exe)
	if path == "" {
		return "", fmt.Errorf("extracted, but no %s found under %s", exe, dest)
	}
	return path, nil
}

// verifyChecksum fetches a SHA256SUMS.txt-style file (lines of
// "<hex sha256>␠␠<filename>") from sumsURL, finds the entry for assetName,
// and confirms it matches the file already downloaded to localPath. Returns
// an error on a mismatch — deliberately fatal, since a mismatch here means
// either a corrupted transfer or a tampered asset, and unpacking either into
// this app's tools directory is worse than failing the install.
func verifyChecksum(ctx context.Context, sumsURL, assetName, localPath string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("fetching checksums: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching checksums: HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading checksums: %w", err)
	}

	var want string
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			want = strings.ToLower(fields[0])
			break
		}
	}
	if want == "" {
		return fmt.Errorf("no checksum listed for %s", assetName)
	}

	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", want, got)
	}
	return nil
}

// --- MemProcFS-Analyzer (Windows only) -------------------------------------

func installAnalyzer(ctx context.Context, toolsDir string, emit Emitter) (string, error) {
	name, url, tag, err := githubLatestAsset(ctx, "LETHAL-FORENSICS/MemProcFS-Analyzer",
		func(n string) bool { return strings.HasSuffix(n, ".zip") })
	if err != nil {
		return "", err
	}
	dest := filepath.Join(toolsDir, "MemProcFS-Analyzer")
	if existing, ok := upToDate(dest, tag, "MemProcFS-Analyzer.ps1"); ok {
		emit("install:log", logLine("MemProcFS-Analyzer already at the latest release ("+tag+"); skipping download."))
		return existing, nil
	}
	if err := os.RemoveAll(dest); err != nil {
		return "", fmt.Errorf("clearing old install: %w", err)
	}
	emit("install:log", logLine("Downloading "+name))
	if err := downloadAndExtract(ctx, url, name, dest, "analyzer", emit); err != nil {
		return "", err
	}
	writeInstalledTag(dest, tag)
	path := findExecutable(dest, "MemProcFS-Analyzer.ps1")
	if path == "" {
		return "", fmt.Errorf("extracted, but MemProcFS-Analyzer.ps1 not found under %s", dest)
	}
	return path, nil
}

//go:embed analyzer_setup.ps1
var analyzerSetupScript string

// runAnalyzerUpdater runs MemProcFS-Analyzer's own Updater.ps1, which sits
// alongside MemProcFS-Analyzer.ps1 in the extracted release and fetches the
// smaller tools the analyzer drives (EZTools, xsv, jq, Zircolite…).
func runAnalyzerUpdater(ctx context.Context, analyzerScriptPath string, emit Emitter) error {
	if paths.VenvPython() == "" {
		return fmt.Errorf("click Install dependencies before Install / update tools")
	}
	dir := filepath.Dir(analyzerScriptPath)
	updaterPath := findExecutable(dir, "Updater.ps1")
	if updaterPath == "" {
		return fmt.Errorf("Updater.ps1 not found alongside %s", analyzerScriptPath)
	}

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", analyzerSetupScript)
	cmd.Env = append(os.Environ(), "MEMFORENSICS_UPDATER="+updaterPath,
		"MEMFORENSICS_ANALYZER_ROOT="+dir,
		"MEMFORENSICS_BASE_PYTHON="+paths.VenvPython(),
		"MEMFORENSICS_ZIRCOLITE_PYTHON="+paths.ZircolitePython())
	proc.Configure(cmd)
	// Updater.ps1 resolves its downloads relative to its own folder, same as
	// MemProcFS-Analyzer.ps1 itself (see internal/analyzer/runner.go).
	cmd.Dir = dir
	completed := false
	updaterEmit := func(event string, payload any) {
		if data, ok := payload.(map[string]any); ok && data["line"] == "MEMFORENSICS_UPDATER_COMPLETE" {
			completed = true
		}
		emit(event, payload)
	}
	updaterErr := runLoggedCmd(updaterEmit, cmd)
	if updaterErr == nil && !completed {
		updaterErr = fmt.Errorf("Analyzer setup exited early; inspect the install log")
	}
	// Always prepare Zircolite, even if an unrelated updater component failed.
	zircoliteErr := ensureZircolite(ctx, analyzerScriptPath, emit)
	return errors.Join(updaterErr, zircoliteErr, analyzer.CheckInstalledDependencies(analyzerScriptPath))
}

// --- dwarf2json --------------------------------------------------------------

// installDwarf2Json downloads the official dwarf2json build — used by
// internal/linuxsymbols to turn a kernel debuginfo package's extracted
// vmlinux into a Volatility3 ISF when no online community index (see
// internal/volatility/remoteisf.go) already has that exact kernel. Its
// release publishes a single bare executable per platform rather than an
// archive, so this is a plain download-and-place rather than
// downloadAndExtract.
func installDwarf2Json(ctx context.Context, toolsDir string, emit Emitter) (string, error) {
	const assetName = "dwarf2json-windows-amd64.exe"
	name, url, tag, err := githubLatestAsset(ctx, "volatilityfoundation/dwarf2json",
		func(n string) bool { return n == assetName })
	if err != nil {
		return "", err
	}
	dest := filepath.Join(toolsDir, "dwarf2json")
	const exe = "dwarf2json.exe"
	destFile := filepath.Join(dest, exe)
	if installedTag(dest) == tag && isFile(destFile) {
		emit("install:log", logLine("dwarf2json already at the latest release ("+tag+"); skipping download."))
		return destFile, nil
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return "", err
	}
	emit("install:log", logLine("Downloading "+name))
	tmpPath, err := downloadToTemp(ctx, url, name, "dwarf2json", emit)
	if err != nil {
		return "", err
	}
	if err := moveFile(tmpPath, destFile); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	writeInstalledTag(dest, tag)
	return destFile, nil
}

// --- GitHub / download helpers ---------------------------------------------

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

// githubLatestRelease fetches a repo's latest release metadata (tag plus
// every asset). Split out from githubLatestAsset for callers that need more
// than one asset from the same release — MemNixFS's checksum file alongside
// its archive — without querying the API twice.
func fetchLatestRelease(ctx context.Context, repo string) (ghRelease, error) {
	api := "https://api.github.com/repos/" + repo + "/releases/latest"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := httpClient().Do(req)
	if err != nil {
		return ghRelease{}, fmt.Errorf("querying %s: %w", repo, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == 429 || (resp.StatusCode == 403 && (resp.Header.Get("X-RateLimit-Remaining") == "0" || strings.Contains(strings.ToLower(string(body)), "rate limit"))) {
			releases.RetryAfter = time.Now().Add(time.Minute)
			if seconds, e := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); e == nil && time.Unix(seconds, 0).After(time.Now()) {
				releases.RetryAfter = time.Unix(seconds, 0).Add(time.Second)
			}
			if seconds, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && time.Now().Add(time.Duration(seconds)*time.Second).After(releases.RetryAfter) {
				releases.RetryAfter = time.Now().Add(time.Duration(seconds) * time.Second)
			}
			return ghRelease{}, fmt.Errorf("GitHub request limit reached; retry after %s. Installed tools are unchanged", releases.RetryAfter.Local().Format("15:04:05 MST"))
		}
		return ghRelease{}, fmt.Errorf("GitHub API returned %s for %s", resp.Status, repo)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return ghRelease{}, fmt.Errorf("decoding release JSON: %w", err)
	}
	return rel, nil
}

func githubLatestAsset(ctx context.Context, repo string, match func(string) bool) (name, url, tag string, err error) {
	rel, err := githubLatestRelease(ctx, repo)
	if err != nil {
		return "", "", "", err
	}
	for _, a := range rel.Assets {
		if match(a.Name) {
			return a.Name, a.URL, rel.TagName, nil
		}
	}
	return "", "", "", fmt.Errorf("no matching asset in %s release %s", repo, rel.TagName)
}

// downloadToTemp streams url to a new temp file, reporting progress under
// tool, and returns the temp file's path. The caller is responsible for
// removing it.
func downloadToTemp(ctx context.Context, url, name, tool string, emit Emitter) (string, error) {
	tmp, err := os.CreateTemp("", "memforensics-dl-*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer tmp.Close()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := httpClient().Do(req)
	if err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("downloading %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Remove(tmpPath)
		return "", fmt.Errorf("downloading %s: HTTP %s", name, resp.Status)
	}

	pr := &progressReader{r: resp.Body, total: resp.ContentLength, emit: emit, tool: tool}
	if _, err := io.Copy(tmp, pr); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("saving %s: %w", name, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// downloadAndExtract streams the archive at url to a temp file (emitting
// download progress under the tool id), then extracts it into dest based on
// its extension.
func downloadAndExtract(ctx context.Context, url, name, dest, tool string, emit Emitter) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	tmpPath, err := downloadToTemp(ctx, url, name, tool, emit)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	emit("install:log", logLine("Extracting "+name+"…"))
	if !strings.HasSuffix(name, ".zip") {
		return fmt.Errorf("don't know how to extract %s", name)
	}
	return extractZip(tmpPath, dest)
}

// extractZip unpacks a zip into dest, guarding against path traversal.
func extractZip(src, dest string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		mode := f.Mode()
		if mode == 0 {
			mode = 0o644
		}
		if err := writeFile(target, rc, mode); err != nil {
			rc.Close()
			return err
		}
		rc.Close()
	}
	return nil
}

// --- small utilities --------------------------------------------------------

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Minute} }

// safeJoin joins name onto base, rejecting entries that would escape base
// (a "zip slip" traversal).
func safeJoin(base, name string) (string, error) {
	target := filepath.Join(base, name)
	if !strings.HasPrefix(target, filepath.Clean(base)+string(os.PathSeparator)) && target != filepath.Clean(base) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return target, nil
}

func writeFile(path string, r io.Reader, mode os.FileMode) error {
	out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, r)
	return err
}

// findExecutable walks root for a file whose base name equals exe.
func findExecutable(root, exe string) string {
	var found string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(info.Name(), exe) {
			found = path
			return io.EOF // stop early
		}
		return nil
	})
	return found
}

// moveFile moves src to dst, falling back to copy+remove when they are on
// different volumes (os.Rename cannot cross those on Windows) — used for the
// symbol packs in deps.go, which are downloaded to a temp file and then
// placed directly (unextracted) into the symbols directory.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := writeFile(dst, in, 0o644); err != nil {
		return err
	}
	return os.Remove(src)
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func firstOnPath(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// runLogged runs a command, streaming its combined output to the UI log.
func runLogged(ctx context.Context, emit Emitter, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	proc.Configure(cmd)
	return runLoggedCmd(emit, cmd)
}

// runLoggedCmd runs a pre-built *exec.Cmd (for callers that need to set
// fields like Dir before running) and streams its combined output to the
// install log the same way runLogged does.
func runLoggedCmd(emit Emitter, cmd *exec.Cmd) error {
	reader, writer := io.Pipe()
	cmd.Stdout, cmd.Stderr = writer, writer
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 65536), 4*1024*1024)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) != "" {
				emit("install:log", logLine(scanner.Text()))
			}
		}
		if err := scanner.Err(); err != nil {
			emit("install:log", logLine("Log reader: "+err.Error()))
			_, _ = io.Copy(io.Discard, reader)
		}
	}()
	stop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	started := time.Now()
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				emit("install:log", logLine(fmt.Sprintf("%s still running (%s elapsed); waiting for tool output", filepath.Base(cmd.Path), time.Since(started).Round(time.Second))))
			}
		}
	}()
	err := cmd.Run()
	close(stop)
	<-heartbeatDone
	_ = writer.Close()
	<-done
	_ = reader.Close()
	return err
}

func stage(tool, state string, percent int, message string) map[string]any {
	return map[string]any{"tool": tool, "state": state, "percent": percent, "message": message}
}

func logLine(line string) map[string]any {
	return map[string]any{"source": "install", "line": line}
}

// progressReader wraps a download stream and emits percentage progress under
// a caller-chosen tool id, so each download (Volatility 2, MemProcFS, the
// analyzer, MemNixFS, a symbol pack…) repaints its own progress row instead
// of all of them colliding on one.
type progressReader struct {
	r        io.Reader
	total    int64
	read     int64
	lastPct  int
	tool     string
	emit     Emitter
	lastEmit time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if p.total > 0 {
		pct := int(p.read * 100 / p.total)
		// Throttle to whole-percent changes, at most ~5/sec.
		if pct != p.lastPct && time.Since(p.lastEmit) > 200*time.Millisecond {
			p.lastPct = pct
			p.lastEmit = time.Now()
			p.emit("install:progress", stage(p.tool+"-dl", "running", pct,
				fmt.Sprintf("downloading %s… %d%%", p.tool, pct)))
		}
	}
	return n, err
}

// --- installed-version tracking ---------------------------------------------
//
// Each downloaded tool gets a marker file recording the GitHub release tag it
// came from. "Install / update tools" then re-downloads only what is actually
// out of date, which is what makes the button safe to press repeatedly: on a
// machine that is already current it does nothing but four API calls.

const versionMarkerName = ".memforensics-version"

// installedTag reads the release tag recorded for an install directory, or ""
// if there is no marker (an install predating this, or none at all).
func installedTag(dest string) string {
	b, err := os.ReadFile(filepath.Join(dest, versionMarkerName))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// writeInstalledTag records the release tag an install directory holds.
func writeInstalledTag(dest, tag string) {
	if tag == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(dest, versionMarkerName), []byte(tag), 0o644)
}

// upToDate reports whether dest already holds release tag from a complete
// install — the marker matches and the executable it should contain is there.
// It returns that executable's path so the caller can report it.
func upToDate(dest, tag, exeName string) (string, bool) {
	if tag == "" || installedTag(dest) != tag {
		return "", false
	}
	path := findExecutable(dest, exeName)
	if path == "" {
		return "", false
	}
	return path, true
}
