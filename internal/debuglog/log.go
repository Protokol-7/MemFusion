// Package debuglog saves process diagnostics without buffering them in memory.
package debuglog

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Log struct {
	mu     sync.Mutex
	file   *os.File
	warn   func(string)
	failed bool
}

// Attach must run after output wiring and before Start. Files are unique even
// when an image/plugin is run again in the same output directory.
// Live consumers must use caller-owned pipes (for example io.Pipe), not
// Cmd.StdoutPipe/StderrPipe: Start closes the latter's original write handles.
func Attach(cmd *exec.Cmd, outputDir, name string, stdout bool, warn func(string)) *Log {
	l := &Log{warn: warn}
	dir := filepath.Join(outputDir, "debug-logs")
	err := os.MkdirAll(dir, 0700)
	if err == nil {
		name = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, name)
		l.file, err = os.CreateTemp(dir, name+"-"+time.Now().UTC().Format("20060102T150405Z")+"-*.log")
	}
	if err != nil {
		warn("Cannot save debug log: " + err.Error())
		return l
	}
	fmt.Fprintf(l, "Started (UTC): %s\nExecutable: %s\nArguments (quoted individually): %q\nWorking directory: %s\n\n", time.Now().UTC().Format(time.RFC3339Nano), cmd.Path, cmd.Args[1:], cmd.Dir)
	if stdout {
		cmd.Stdout = combine(l, cmd.Stdout)
	}
	cmd.Stderr = combine(l, cmd.Stderr)
	return l
}

func combine(log io.Writer, existing io.Writer) io.Writer {
	if existing == nil {
		return log
	}
	return io.MultiWriter(log, existing)
}

func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil && !l.failed {
		if _, err := l.file.Write(p); err != nil {
			l.failed = true
			l.warn("Debug log write failed: " + err.Error())
		}
	}
	// Logging failure must not interrupt the forensic process.
	return len(p), nil
}

func (l *Log) Finish(cmd *exec.Cmd, err error) {
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	fmt.Fprintf(l, "\nFinished (UTC): %s\nExit code: %d\nProcess error: %v\n", time.Now().UTC().Format(time.RFC3339Nano), code, err)
	if l.file != nil {
		if err := l.file.Close(); err != nil {
			l.warn("Debug log close failed: " + err.Error())
		}
	}
}
