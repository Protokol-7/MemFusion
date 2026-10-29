package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepeatedAnalysisPreservesPreviousOutput(t *testing.T) {
	root := t.TempDir()
	first, err := freshOutputDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != filepath.Join(root, "Analyzer") {
		t.Fatal(first)
	}
	evidence := filepath.Join(first, "previous.txt")
	if err := os.WriteFile(evidence, []byte("previous result"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := freshOutputDir(root)
	if err != nil {
		t.Fatal(err)
	}
	third, err := freshOutputDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if second == first || second == third {
		t.Fatal("output reused")
	}
	entries, err := os.ReadDir(second)
	if err != nil || len(entries) != 0 {
		t.Fatalf("new output not empty: %v", err)
	}
	data, err := os.ReadFile(evidence)
	if err != nil || string(data) != "previous result" {
		t.Fatal("previous output changed")
	}
}
