package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckDependencies verifies helpers used throughout the mounted analysis.
func CheckDependencies(script string) error {
	return checkDependencyFiles(script, false)
}

// CheckInstalledDependencies also checks helpers that upstream silently skips
// when absent. Setup must report incomplete feature coverage as a failure.
func CheckInstalledDependencies(script string) error {
	return checkDependencyFiles(script, true)
}

func checkDependencyFiles(script string, complete bool) error {
	missing := []string{}
	files := []string{"Tools/xsv/xsv.exe", "Tools/jq/jq-win64.exe", "Tools/7-Zip/7za.exe", "Tools/AmcacheParser/AmcacheParser.exe", "Tools/AppCompatCacheParser/AppCompatCacheParser.exe", "Tools/EvtxECmd/EvtxECmd.exe", "Tools/RECmd/RECmd.exe", "Tools/SBECmd/SBECmd.exe", "Tools/Zircolite/zircolite.py", "Tools/Zircolite/rules/rules_windows_generic.json"}
	if complete {
		files = append(files, "Tools/entropy/entropy.exe", "Tools/IPinfo/ipinfo.exe", "Tools/lnk_parser/lnk_parser_x86_64.exe", "Tools/YARA/yara64.exe")
	}
	for _, rel := range files {
		path := filepath.Join(filepath.Dir(script), filepath.FromSlash(rel))
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Analyzer dependencies missing: %s. Click Install dependencies, then Install / update tools", strings.Join(missing, "; "))
	}
	return nil
}
