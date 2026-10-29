package custody

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record preserves analysis provenance, not an acquisition or transfer history.
type Record struct {
	mu     sync.Mutex
	Start  time.Time
	Events []string
}

func New() *Record { return &Record{Start: time.Now().UTC()} }
func (r *Record) Event(name string, payload any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	data, _ := json.Marshal(payload)
	r.Events = append(r.Events, time.Now().UTC().Format(time.RFC3339Nano)+" "+name+" "+string(data))
}
func hash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
func (r *Record) Finish(output, image, caseID, analyst string, config any, stopped bool) error {
	end := time.Now().UTC()
	dir, err := os.MkdirTemp(output, "custody-")
	if err != nil {
		return err
	}
	imageHash, imageErr := hash(image)
	hashStatus := "SHA-256 computed at finalization"
	if imageErr != nil {
		hashStatus = "Unable to hash image: " + imageErr.Error()
	}
	host, _ := os.Hostname()
	cfg, _ := json.MarshalIndent(config, "", "  ")
	r.mu.Lock()
	events := append([]string(nil), r.Events...)
	r.mu.Unlock()
	status := "Analysis ended; inspect recorded tool outcomes for errors or skipped stages"
	if stopped {
		status = "Stopped; partial analysis"
	}
	text := fmt.Sprintf("=== CHAIN OF CUSTODY - MemFusion analysis record ===\nCase/Ticket : %s\nAnalyst     : %s\nAnalysis host: %s\nExecuted as : %s\\%s\nStart UTC   : %s\nEnd UTC     : %s\nDurationSec : %.0f\nStatus      : %s\nImage       : %s\nImage SHA256: %s\nHash status : %s\nMethod      : Analysis of an existing memory image using configured forensic tools.\nNote        : This record does not establish prior acquisition or custody transfers.\n", caseID, analyst, host, os.Getenv("USERDOMAIN"), os.Getenv("USERNAME"), r.Start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), end.Sub(r.Start).Seconds(), status, image, imageHash, hashStatus)
	if err := os.WriteFile(filepath.Join(dir, "CHAIN_OF_CUSTODY.txt"), []byte(text), 0600); err != nil {
		return err
	}
	logDir := filepath.Join(output, "debug-logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return fmt.Errorf("creating run log directory: %w", err)
	}
	details := fmt.Sprintf("Custody record: %s\n\nRun configuration:\n%s\n\nRecorded events:\n", filepath.Join(dir, "CHAIN_OF_CUSTODY.txt"), cfg)
	for _, event := range events {
		details += event + "\n"
	}
	return os.WriteFile(filepath.Join(logDir, filepath.Base(dir)+"-run.log"), []byte(details), 0600)
}
