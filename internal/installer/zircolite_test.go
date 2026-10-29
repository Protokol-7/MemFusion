package installer

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestZircoliteDependencyFormats(t *testing.T) {
	for _, tc := range []struct {
		name    string
		files   []string
		project bool
	}{
		{"legacy", []string{"requirements.txt"}, false},
		{"current", []string{"pyproject.toml"}, true},
		{"prefer project", []string{"pyproject.toml", "requirements.txt"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, file := range tc.files {
				if err := os.WriteFile(filepath.Join(root, file), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			want := []string{"-r", filepath.Join(root, "requirements.txt")}
			if tc.project {
				want = []string{root}
			}
			got, err := zircolitePackageArgs(root)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v, %v; want %v", got, err, want)
			}
		})
	}
	if _, err := zircolitePackageArgs(t.TempDir()); err == nil {
		t.Fatal("missing metadata accepted")
	}
}

func TestMissingAnalyzerRuntimeReportsRepairPrerequisite(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	analyzer := filepath.Join(root, "Analyzer", "Analyzer.ps1")
	source := filepath.Join(filepath.Dir(analyzer), "Tools", "Zircolite")
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "requirements.txt"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	announced := false
	err := PrepareAnalyzerRuntime(context.Background(), analyzer, func(event string, payload any) {
		if event == "install:log" {
			announced = true
		}
	})
	if err == nil || !strings.Contains(err.Error(), "install Python dependencies first") || !announced {
		t.Fatalf("expected actionable repair failure, got %v (announced=%v)", err, announced)
	}
}

func TestCancelledRuntimeCheckDoesNotInstall(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := PrepareAnalyzerRuntime(ctx, "missing.ps1", func(string, any) { t.Error("repair attempted after cancellation") })
	if err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}
