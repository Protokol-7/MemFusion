package debuglog

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLivePipesPreserveCompleteOutput(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "echo stdout-final & echo stderr-final 1>&2")
	out, outWriter := io.Pipe()
	errOut, errWriter := io.Pipe()
	defer out.Close()
	defer errOut.Close()
	defer outWriter.Close()
	defer errWriter.Close()
	cmd.Stdout, cmd.Stderr = outWriter, errWriter
	dir := t.TempDir()
	log := Attach(cmd, dir, "streamed", true, func(s string) { t.Error(s) })
	stdoutDone, stderrDone := make(chan string, 1), make(chan string, 1)
	go func() { b, _ := io.ReadAll(out); stdoutDone <- string(b) }()
	go func() { b, _ := io.ReadAll(errOut); stderrDone <- string(b) }()
	err := cmd.Run()
	outWriter.Close()
	errWriter.Close()
	if !strings.Contains(<-stdoutDone, "stdout-final") || !strings.Contains(<-stderrDone, "stderr-final") {
		t.Error("live output truncated")
	}
	log.Finish(cmd, err)
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "debug-logs", "*.log"))
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"stdout-final", "stderr-final", "Exit code: 0"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("log missing %s", want)
		}
	}
}

func TestProcessLogsKeepFinalErrorAndAreUnique(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 2; i++ {
		cmd := exec.Command("cmd.exe", "/c", "echo diagnostic-tail 1>&2 & exit /b 7")
		log := Attach(cmd, dir, "vol3-plugin", false, func(s string) { t.Error(s) })
		err := cmd.Run()
		log.Finish(cmd, err)
		if err == nil {
			t.Fatal("expected process failure")
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "debug-logs", "*.log"))
	if len(files) != 2 {
		t.Fatalf("got %d logs", len(files))
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"diagnostic-tail", "Exit code: 7", "Started (UTC):", "Finished (UTC):", "Arguments"} {
			if !strings.Contains(string(data), want) {
				t.Errorf("missing %q in %s", want, file)
			}
		}
	}
}

func TestUnwritableLogDoesNotFailProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	warned := false
	cmd := exec.Command("cmd.exe", "/c", "exit /b 0")
	log := Attach(cmd, path, "tool", true, func(string) { warned = true })
	err := cmd.Run()
	log.Finish(cmd, err)
	if err != nil || !warned {
		t.Fatalf("error=%v warning=%v", err, warned)
	}
}
