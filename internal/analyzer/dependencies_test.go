package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCheckReportsSkippedAnalyzerFeatures(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "Analyzer.ps1")
	// These are sufficient for the existing mounted run, but setup must also
	// detect missing helpers that upstream silently skips at runtime.
	for _, rel := range []string{"xsv/xsv.exe", "jq/jq-win64.exe", "7-Zip/7za.exe", "AmcacheParser/AmcacheParser.exe", "AppCompatCacheParser/AppCompatCacheParser.exe", "EvtxECmd/EvtxECmd.exe", "RECmd/RECmd.exe", "SBECmd/SBECmd.exe", "Zircolite/zircolite.py", "Zircolite/rules/rules_windows_generic.json"} {
		path := filepath.Join(root, "Tools", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := CheckDependencies(script); err != nil {
		t.Fatal(err)
	}
	err := CheckInstalledDependencies(script)
	if err == nil {
		t.Fatal("incomplete setup reported success")
	}
	for _, name := range []string{"entropy.exe", "ipinfo.exe", "lnk_parser_x86_64.exe", "yara64.exe"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("missing diagnostic for %s: %v", name, err)
		}
	}
}
