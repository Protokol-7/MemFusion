package custody

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanRecordAndSeparateRunLog(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	if err := os.Mkdir(output, 0755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, "image.raw")
	os.WriteFile(image, []byte("abc"), 0600)
	os.WriteFile(filepath.Join(output, "result.txt"), []byte("finding"), 0600)
	r := New()
	r.Event("analyzer:status", map[string]string{"state": "error"})
	if err := r.Finish(output, image, "CASE-1", "Analyst", nil, true); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(output, "custody-*", "CHAIN_OF_CUSTODY.txt"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	data, _ := os.ReadFile(files[0])
	for _, want := range []string{"CASE-1", "Stopped; partial analysis", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s", want)
		}
	}
	for _, unwanted := range []string{"Run configuration:", "Recorded events:", "analyzer:status", "MANIFEST"} {
		if strings.Contains(string(data), unwanted) {
			t.Fatalf("custody includes %s", unwanted)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(files[0]), "MANIFEST_SHA256.csv")); !os.IsNotExist(err) {
		t.Fatal("manifest should not be generated")
	}
	log, err := os.ReadFile(filepath.Join(output, "debug-logs", filepath.Base(filepath.Dir(files[0]))+"-run.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Run configuration:", "Recorded events:", "analyzer:status"} {
		if !strings.Contains(string(log), want) {
			t.Fatalf("run log missing %s", want)
		}
	}
	if err := r.Finish(output, image, "CASE-2", "Analyst", nil, false); err != nil {
		t.Fatal(err)
	}
	files, _ = filepath.Glob(filepath.Join(output, "custody-*", "CHAIN_OF_CUSTODY.txt"))
	if len(files) != 2 {
		t.Fatal("previous record overwritten")
	}
}
