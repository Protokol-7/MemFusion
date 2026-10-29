package installer

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunLoggedCmdStreamsBeforeExit(t *testing.T) {
	lines := make(chan string, 10)
	done := make(chan error, 1)
	cmd := exec.Command("powershell.exe", "-NoProfile", "-Command", "Write-Output 'stream-start'; Start-Sleep -Seconds 2; Write-Output 'stream-end'")
	go func() {
		done <- runLoggedCmd(func(_ string, payload any) { lines <- payload.(map[string]any)["line"].(string) }, cmd)
	}()
	select {
	case line := <-lines:
		if !strings.Contains(line, "stream-start") {
			t.Fatal(line)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no output received")
	}
	select {
	case err := <-done:
		t.Fatalf("process finished before output was delivered: %v", err)
	default:
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
