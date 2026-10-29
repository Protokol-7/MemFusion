// Package paths holds the per-user locations this app installs into.
//
// It exists so that both internal/installer (which creates them) and
// internal/prereq (which reports on what is missing from them) can agree on
// where things live without one importing the other — prereq is a leaf, and
// installer already depends on it.
//
// This build is Windows-only.
package paths

import (
	"os"
	"path/filepath"
)

// ToolsDir is the per-user directory the app installs downloaded tools into:
// %LOCALAPPDATA%\memforensics-gui\tools, falling back to a path under the
// home directory if LOCALAPPDATA is somehow unset.
func ToolsDir() string {
	if base := os.Getenv("LOCALAPPDATA"); base != "" {
		return filepath.Join(base, "memforensics-gui", "tools")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, "AppData", "Local", "memforensics-gui", "tools")
}

// VenvDir is the app-owned Python environment holding Volatility 3 and the
// packages its plugins import.
func VenvDir() string { return filepath.Join(ToolsDir(), "python-env") }

// Zircolite has its own dependency versions; keep them out of Volatility.
func ZircolitePython() string {
	return filepath.Join(ToolsDir(), "zircolite-env", "Scripts", "python.exe")
}

// SymbolsDir is where the app-downloaded Volatility 3 bulk symbol packs
// (linux.zip, mac.zip — see internal/installer's InstallDependencies) live.
// It is passed to every `vol` invocation via --symbol-dirs, in addition to
// whatever symbol cache vol3 itself already maintains, so plugins that need
// an exact-match ISF still work if vol3's own online per-banner lookup
// misses (the common case for less mainstream Linux kernels).
func SymbolsDir() string { return filepath.Join(ToolsDir(), "volatility3-symbols") }

// VenvBin returns the path to a program inside the venv's Scripts directory,
// with the .exe suffix applied. The file is not guaranteed to exist.
func VenvBin(name string) string {
	return filepath.Join(VenvDir(), "Scripts", name+".exe")
}

// VenvPython returns the app venv's interpreter, or "" if the venv has not
// been created yet.
func VenvPython() string { return existingFile(VenvBin("python")) }

// VenvVol returns the app venv's vol launcher, or "" if it isn't there.
func VenvVol() string { return existingFile(VenvBin("vol")) }

// RemoteISFIndexPath is a small local JSON file that internal/volatility
// writes, chaining together the community "banners-isf.json" remote-ISF
// sources it knows about (see internal/volatility/remoteisf.go) so a single
// -remote-isf-url can point vol3 at all of them at once.
//
// Deliberately outside SymbolsDir(): that whole directory is passed to vol3
// via -s/--symbol-dirs, and vol3 recursively globs every *.json under it
// looking for real ISFs (see intermed.py's file_symbol_url) — dropping this
// routing file in there would get it swept up as a bogus candidate symbol
// table on every run.
func RemoteISFIndexPath() string { return filepath.Join(ToolsDir(), "remote-isf-index.json") }

// Dwarf2JsonPath is where the app-downloaded dwarf2json build lives — see
// internal/installer's InstallTools.
func Dwarf2JsonPath() string { return filepath.Join(ToolsDir(), "dwarf2json", "dwarf2json.exe") }

// Dwarf2Json returns the app's dwarf2json path, or "" if it hasn't been
// installed yet.
func Dwarf2Json() string { return existingFile(Dwarf2JsonPath()) }

func existingFile(path string) string {
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path
	}
	return ""
}
