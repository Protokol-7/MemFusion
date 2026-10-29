package volatility

import "testing"

func TestPresetBoundariesAndFramework(t *testing.T) {
	catalog := []Plugin{
		{Name: "windows.mftscan.MFTScan", Framework: FrameworkVol3, Loadable: true},
		{Name: "windows.mftscan.ResidentData", Framework: FrameworkVol3, Loadable: true},
		{Name: "windows.mftscan.MFTScanExtra", Framework: FrameworkVol3, Loadable: true},
		{Name: "windows.filescan.FileScan", Framework: FrameworkVol3, Loadable: false},
		{Name: "pslist", Framework: FrameworkVol2, Loadable: true},
		{Name: "pslist_extra", Framework: FrameworkVol2, Loadable: true},
		{Name: "windows.pslist.PsList", Framework: FrameworkVol2, Loadable: true},
	}
	result := BuiltInPresets(catalog)
	if len(result) != 2 {
		t.Fatalf("unexpected presets: %+v", result)
	}
	for _, preset := range result {
		if len(preset.Plugins) != 1 {
			t.Fatalf("unexpected selection: %+v", preset)
		}
		switch preset.Name {
		case "Windows files and registry inventory":
			if preset.Plugins[0] != "windows.mftscan.MFTScan" {
				t.Fatal(preset)
			}
		case "Windows legacy triage (Volatility 2)":
			if preset.Plugins[0] != "pslist" {
				t.Fatal(preset)
			}
		default:
			t.Fatal(preset)
		}
	}
}

func TestPresetDefinitions(t *testing.T) {
	seen := map[string]bool{}
	for _, def := range builtInPresets {
		if seen[def.name] || def.name == "" || def.description == "" || len(def.prefixes) == 0 {
			t.Fatalf("invalid preset: %+v", def)
		}
		seen[def.name] = true
		if def.framework != FrameworkVol2 && def.framework != FrameworkVol3 {
			t.Fatal(def)
		}
		members := map[string]bool{}
		for _, p := range def.prefixes {
			if members[p] {
				t.Fatalf("duplicate %s in %s", p, def.name)
			}
			members[p] = true
		}
	}
	if len(BuiltInPresets(nil)) != 0 {
		t.Fatal("empty catalog must produce no presets")
	}
}
