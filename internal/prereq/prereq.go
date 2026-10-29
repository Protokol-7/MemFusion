// Package prereq reports the third-party software each tool needs before the
// install button can produce something that actually runs, and which of the
// Python packages the plugins import are actually importable.
//
// The install buttons do install all of this now (see internal/installer);
// this package is what tells the user what is still missing afterwards —
// including things that need a reboot before they show up, like a freshly
// installed filesystem driver.
package prereq

import (
	"context"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/proc"
	"memforensics-gui/internal/pydeps"
	"os/exec"
	"strconv"
	"strings"
)

// Check is one prerequisite and whether it is satisfied on this machine.
type Check struct {
	Tool     string `json:"tool"`     // which app feature needs it
	Name     string `json:"name"`     // human name of the prerequisite
	Present  bool   `json:"present"`  // detected on this system
	Required bool   `json:"required"` // true = the tool cannot work without it
	Detail   string `json:"detail"`   // version/path when found, or why it matters
	HowTo    string `json:"howTo"`    // what the user should do about it
}

// Report bundles the checks with the platform they were run on.
type Report struct {
	Platform string  `json:"platform"`
	Checks   []Check `json:"checks"`
}

// Detect runs every prerequisite check.
func Detect() Report {
	return Report{Platform: "windows", Checks: windowsChecks()}
}

func windowsChecks() []Check {
	checks := []Check{python3Check()}

	// Volatility 2 ships as a frozen standalone .exe with Python 2 baked in,
	// so it is the one tool with no runtime prerequisite at all. Stated
	// explicitly because "Volatility 2 needs Python 2" is the obvious
	// assumption and it is wrong here.
	checks = append(checks, Check{
		Tool: "Volatility 2", Name: "Python 2", Present: true, Required: false,
		Detail: "not needed; the standalone build bundles its own Python 2 interpreter",
		HowTo:  "nothing to do",
	})

	// MemNixFS's Windows release bundles every DLL it needs (fmt, snappy,
	// liblzma, libcrypto) and this app only ever drives its `export` command,
	// which — unlike `mount` — needs no WinFsp or any other kernel driver.
	// Stated explicitly since "another mount tool, another driver" is the
	// obvious assumption here and it's wrong.
	checks = append(checks, Check{
		Tool: "MemNixFS", Name: "System dependencies", Present: true, Required: false,
		Detail: "not needed; the Windows release is self-contained, and this app only uses its no-driver 'export' mode",
		HowTo:  "nothing to do",
	})

	// MemProcFS mounts via Dokany on Windows (FUSE has no Windows port).
	// Without the driver, memprocfs.exe runs but cannot mount, which is the
	// whole point of it.
	dokany := dokanyPresent()
	checks = append(checks, Check{
		Tool: "MemProcFS", Name: "Dokany v2 file system driver", Present: dokany, Required: true,
		Detail: "MemProcFS mounts its virtual filesystem through Dokany on Windows",
		HowTo:  "Install DokanSetup.exe from https://github.com/dokan-dev/dokany/releases/latest",
	})

	// MemProcFS-Analyzer's own documented prerequisites. Its Updater.ps1
	// installs the smaller tools (EZTools, xsv, jq, Zircolite…) itself, but
	// these four it expects to already be there.
	checks = append(checks,
		Check{
			Tool: "MemProcFS-Analyzer", Name: "PowerShell 5.1", Present: powershellPresent(), Required: true,
			Detail: "required to run the Analyzer adapter",
			HowTo:  "Built into Windows",
		},
		Check{
			Tool: "MemProcFS-Analyzer", Name: ".NET 9 Desktop Runtime", Present: dotnetPresent(), Required: true,
			Detail: "required by the EZTools parsers (AmcacheParser, RECmd, EvtxECmd…)",
			HowTo:  "https://dotnet.microsoft.com/en-us/download/dotnet/9.0",
		},
		Check{
			Tool: "MemProcFS-Analyzer", Name: "ClamAV", Present: clamavPresent(), Required: false,
			Detail: "not used by this app's mounted Analyzer workflow",
			HowTo:  "https://www.clamav.net/downloads; then remove the 'Example' lines from freshclam.conf and clamd.conf",
		},
		Check{
			Tool: "MemProcFS-Analyzer", Name: "Zircolite Python environment", Present: anyFileExists(paths.ZircolitePython()), Required: true,
			Detail: "needed by Zircolite (SIGMA detection over the event logs)",
			HowTo:  `Click Install dependencies, then Install / update tools`,
		},
	)

	// 7-Zip and dwarf2json are only needed for the manual "generate ISF from
	// a kernel debug package" fallback (internal/linuxsymbols) — the
	// automatic online lookup (internal/volatility's remoteISFArgs) needs
	// neither. Both are optional for that reason.
	checks = append(checks,
		Check{
			Tool: "Linux symbol generation", Name: "7-Zip", Present: SevenZipPresent(), Required: false,
			Detail: "extracts the vmlinux ELF out of a kernel debuginfo package (.rpm/.ddeb) before dwarf2json can read it",
			HowTo:  `Click "Install dependencies", or install manually from https://www.7-zip.org/download.html`,
		},
		Check{
			Tool: "Linux symbol generation", Name: "dwarf2json", Present: paths.Dwarf2Json() != "", Required: false,
			Detail: "builds a Volatility3 ISF symbol file from an extracted vmlinux",
			HowTo:  `Click "Install / update tools"`,
		},
	)
	checks = append(checks, pythonPackageChecks()...)
	return checks
}

// python3Check reports Python 3, which Volatility 3 needs (it is installed
// via pip/pipx rather than as a frozen binary).
func python3Check() Check {
	path, version := python3Info()
	detail := "required to install and run Volatility 3"
	if version != "" {
		detail = version + " at " + path
	}
	return Check{
		Tool: "Volatility 3", Name: "Python 3", Present: path != "", Required: true,
		Detail: detail,
		HowTo:  "Click Install dependencies to create the app Python environment",
	}
}

func python3Info() (path, version string) {
	for _, name := range []string{paths.VenvPython(), "python3", "python"} {
		if name == "" {
			continue
		}
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.CommandContext(context.Background(), p, "--version")
		proc.Configure(cmd)
		out, err := cmd.CombinedOutput()
		v := strings.TrimSpace(string(out))
		// A bare "python" on Windows can still be Python 2, which cannot run
		// Volatility 3 — so only accept it if it reports 3.x.
		if err == nil && strings.HasPrefix(v, "Python 3") {
			return p, v
		}
	}
	return "", ""
}

func python3Present() bool { p, _ := python3Info(); return p != "" }

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// dokanyPresent looks for the Dokany driver DLL that MemProcFS links against.
func dokanyPresent() bool {
	return anyFileExists(
		`C:\Windows\System32\dokan2.dll`,
		`C:\Windows\System32\dokan1.dll`,
		`C:\Program Files\Dokan\Dokan Library-2.0.6\dokan2.dll`,
	)
}

func dotnetPresent() bool {
	exe := firstExistingFile(`C:\Program Files\dotnet\dotnet.exe`)
	if exe == "" {
		exe, _ = exec.LookPath("dotnet")
	}
	if exe == "" {
		return false
	}
	cmd := exec.Command(exe, "--list-runtimes")
	proc.Configure(cmd)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Microsoft.NETCore.App 9.") {
			return true
		}
	}
	return false
}

func clamavPresent() bool {
	return commandExists("clamscan") || commandExists("clamd") ||
		anyFileExists(`C:\Program Files\ClamAV\clamscan.exe`)
}

func powershellPresent() bool {
	return commandExists("powershell") || commandExists("pwsh")
}

// --- exported presence checks -----------------------------------------------
//
// internal/installer reuses these so the "Install dependencies" button skips
// anything already on the machine, rather than re-running vendor installers
// that each want a UAC prompt.

// DokanyPresent reports whether the Dokany filesystem driver is installed.
func DokanyPresent() bool { return dokanyPresent() }

// DotnetPresent reports whether a .NET runtime is on PATH.
func DotnetPresent() bool { return dotnetPresent() }

// ClamAVPresent reports whether ClamAV is installed.
func ClamAVPresent() bool { return clamavPresent() }

// SevenZipPath returns the 7-Zip command-line executable's path, or "" if it
// isn't found — checked on PATH first, then the default per-machine install
// locations winget's "7zip.7zip" package and the official installer both use.
func SevenZipPath() string {
	if p, err := exec.LookPath("7z"); err == nil {
		return p
	}
	return firstExistingFile(
		`C:\Program Files\7-Zip\7z.exe`,
		`C:\Program Files (x86)\7-Zip\7z.exe`,
	)
}

// SevenZipPresent reports whether 7-Zip is installed.
func SevenZipPresent() bool { return SevenZipPath() != "" }

// --- Python package checks --------------------------------------------------

// pythonPackageChecks reports which of the Python packages the Volatility 3
// plugins import are actually importable from the interpreter that will run
// them. Without this the failure mode is silent: vol3 catches the ImportError
// and quietly lists the plugin as unloadable, so a colleague sees a shorter
// plugin list with no explanation of why.
//
// Everything importable collapses into a single satisfied check — the panel
// is for what is missing, not a package inventory.
func pythonPackageChecks() []Check {
	python := vol3Python()
	if python == "" {
		return []Check{{
			Tool: "Volatility 3", Name: "Plugin Python packages", Present: false, Required: false,
			Detail: "no Python environment with volatility3 found, so the plugin packages could not be checked",
			HowTo:  `Click "Install dependencies"`,
		}}
	}

	missing := missingPythonImports(python)
	if len(missing) == 0 {
		return []Check{{
			Tool: "Volatility 3", Name: "Plugin Python packages", Present: true, Required: false,
			Detail: "all " + itoa(len(pydeps.All)) + " packages importable from " + python,
			HowTo:  "nothing to do",
		}}
	}

	checks := make([]Check, 0, len(missing))
	for _, dep := range missing {
		checks = append(checks, Check{
			Tool:    "Volatility 3",
			Name:    dep.Req + " (Python package)",
			Present: false,
			// A non-optional package is one whose absence breaks a broad
			// swathe of plugins rather than a named few.
			Required: !dep.Optional,
			Detail:   "not importable from " + python + "; unavailable: " + dep.Affects,
			HowTo:    `Click "Install dependencies" (or: ` + python + ` -m pip install ` + dep.Req + `)`,
		})
	}
	return checks
}

// missingPythonImports returns the deps that python cannot import. The whole
// set is tested in one interpreter start-up, since spawning Python ~18 times
// is noticeably slow on Windows and this runs on every panel render.
func missingPythonImports(python string) []pydeps.Dep {
	names := make([]string, 0, len(pydeps.All))
	for _, d := range pydeps.All {
		names = append(names, d.Import)
	}

	script := `
import importlib.util, sys
for name in sys.argv[1:]:
    try:
        found = importlib.util.find_spec(name) is not None
    except Exception:
        found = False
    print(name if found else "")
`
	args := append([]string{"-c", script}, names...)
	cmd := exec.CommandContext(context.Background(), python, args...)
	proc.Configure(cmd)
	out, err := cmd.Output()
	if err != nil {
		// Can't tell — better to report nothing than to claim everything is
		// missing because the probe itself broke.
		return nil
	}

	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	var missing []pydeps.Dep
	for i, dep := range pydeps.All {
		if i >= len(lines) || strings.TrimSpace(lines[i]) == "" {
			missing = append(missing, dep)
		}
	}
	return missing
}

// vol3Python finds the interpreter the app's Volatility 3 runs under. The
// app's own environment wins; otherwise fall back to whatever on PATH can
// import volatility3.
func vol3Python() string {
	if p := paths.VenvPython(); p != "" {
		return p
	}
	for _, name := range []string{"python3", "python"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		cmd := exec.CommandContext(context.Background(), p, "-c", "import volatility3")
		proc.Configure(cmd)
		if cmd.Run() == nil {
			return p
		}
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }
