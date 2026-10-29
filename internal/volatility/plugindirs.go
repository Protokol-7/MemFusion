package volatility

import (
	"memforensics-gui/internal/paths"
	"os"
	"path/filepath"
	"strings"
)

// PluginDirs returns the directories of custom (non-bundled) Volatility3
// plugins to pass to vol via -p, in priority order, keeping only ones that
// actually exist:
//
//  1. $MEMFORENSICS_PLUGIN_DIRS — colon-separated override, for testing or
//     unusual layouts.
//  2. ~/.local/share/memforensics-gui/plugins — the installed location the
//     app owns; the repo's custom_plugins/ directory is copied here (see
//     custom_plugins/README.md).
//  3. <dir of the running executable>/custom_plugins — so a built app
//     carried around with its plugin folder still finds it.
func PluginDirs() []string {
	var candidates []string
	if env := os.Getenv("MEMFORENSICS_PLUGIN_DIRS"); env != "" {
		candidates = append(candidates, strings.Split(env, ":")...)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "share", "memforensics-gui", "plugins"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "custom_plugins"))
	}

	var dirs []string
	seen := map[string]bool{}
	for _, dir := range candidates {
		dir = filepath.Clean(dir)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// Vol2PluginDirs returns directories of custom Volatility 2 plugins. Vol2
// keeps its own plugin set in a separate tree from vol3 (different framework,
// different API, Python 2), so it gets its own directories and its own
// --plugins flag rather than sharing vol3's -p.
func Vol2PluginDirs() []string {
	var candidates []string
	if env := os.Getenv("MEMFORENSICS_VOL2_PLUGIN_DIRS"); env != "" {
		candidates = append(candidates, strings.Split(env, ":")...)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".local", "share", "memforensics-gui", "plugins-vol2"))
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "custom_plugins_vol2"))
	}

	var dirs []string
	seen := map[string]bool{}
	for _, dir := range candidates {
		dir = filepath.Clean(dir)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// vol2PluginDirArgs returns the CLI arguments that load custom vol2 plugins.
// Volatility 2 takes a comma-separated list via --plugins=, which is a
// different flag and separator from vol3's `-p a;b`.
func vol2PluginDirArgs(dirs []string) []string {
	if len(dirs) == 0 {
		return nil
	}
	return []string{"--plugins=" + strings.Join(dirs, ",")}
}

// vol2CustomNames returns the plugin module basenames present in the custom
// vol2 dirs, so discovered plugins can be tagged as "custom".
func vol2CustomNames(dirs []string) map[string]bool {
	names := map[string]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".py") {
				continue
			}
			names[strings.TrimSuffix(e.Name(), ".py")] = true
		}
	}
	return names
}

// pluginDirArgs returns the extra vol CLI arguments needed to load the
// custom plugin directories (vol expects one semicolon-separated value),
// or nil if there are none.
func pluginDirArgs(dirs []string) []string {
	if len(dirs) == 0 {
		return nil
	}
	return []string{"-p", strings.Join(dirs, ";")}
}

// symbolDirArgs returns the vol3 CLI arguments that point it at the app's
// downloaded bulk symbol packs (paths.SymbolsDir — see internal/installer's
// InstallDependencies), or nil if that directory doesn't exist yet or is
// empty (nothing downloaded, or InstallDependencies never ran). vol3 takes
// this as -s/--symbol-dirs, a directory containing OS-named symbol pack
// zips (windows.zip, mac.zip, linux.zip) or raw ISF json/json.xz files.
func symbolDirArgs() []string {
	dir := paths.SymbolsDir()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	return []string{"-s", dir}
}

// customModuleNames returns the module names of the plugins in dirs, used to
// categorize discovered plugins as "custom".
//
// Both layouts are covered. A .py directly in a plugin dir is loaded by vol3
// as `<name>`, so it's keyed by basename. A .py inside a subdirectory is
// loaded as `<subdir>.<name>` — needed by plugin families that import each
// other through a fixed package path (f-block's ptemalfind/imgmalfind/
// apisearch all do `from volatility3.plugins.windows.ptenum import …`, so
// they only work from a windows/ subfolder), so those are keyed that way too.
func customModuleNames(dirs []string) map[string]bool {
	names := map[string]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				subEntries, subErr := os.ReadDir(filepath.Join(dir, e.Name()))
				if subErr != nil {
					continue
				}
				for _, se := range subEntries {
					if se.IsDir() || !strings.HasSuffix(se.Name(), ".py") {
						continue
					}
					names[e.Name()+"."+strings.TrimSuffix(se.Name(), ".py")] = true
				}
				continue
			}
			if !strings.HasSuffix(e.Name(), ".py") {
				continue
			}
			names[strings.TrimSuffix(e.Name(), ".py")] = true
		}
	}
	return names
}
