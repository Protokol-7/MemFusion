package volatility

import (
	"bufio"
	"io"
	"strings"
	"sync"
	"time"
)

// Volatility reports progress on stderr by overwriting a single line with
// carriage returns ("Progress:  23.45\t\tScanning..\r"), never emitting a
// newline until the plugin finishes. A plain line scanner therefore shows
// nothing at all for the entire run, which is exactly why a long plugin —
// or vol2's imageinfo — looks frozen.
//
// splitLinesOrCR splits on \n *and* \r so those in-place updates surface as
// individual chunks.
func splitLinesOrCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i, b := range data {
		if b == '\n' || b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil // ask for more data
}

// streamProgress reads r to completion, appending everything to tail (so a
// failure is still diagnosable) and invoking onUpdate for each non-empty
// chunk, throttled to at most one call per interval. Throttling matters:
// vol repaints its progress line many times a second, and forwarding every
// repaint to the UI would flood the event bridge for no extra information.
func streamProgress(r io.Reader, tail *tailBuffer, interval time.Duration, onUpdate func(string)) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	scanner.Split(splitLinesOrCR)

	var lastEmit time.Time
	var lastText string
	for scanner.Scan() {
		chunk := scanner.Bytes()
		if tail != nil {
			tail.Write(chunk)
			tail.Write([]byte("\n"))
		}
		text := strings.TrimSpace(string(chunk))
		if text == "" || text == lastText {
			continue
		}
		lastText = text
		if time.Since(lastEmit) < interval {
			continue
		}
		lastEmit = time.Now()
		onUpdate(text)
	}
	// Always surface the final state, even if the throttle just skipped it —
	// otherwise a plugin can finish showing a stale "23%".
	if lastText != "" {
		onUpdate(lastText)
	}
}

// progressInterval is how often streamed tool output reaches the UI.
const progressInterval = 500 * time.Millisecond

// heartbeatInterval is how often a silent-but-running tool reports that it
// is still alive.
const heartbeatInterval = 3 * time.Second

// startHeartbeat emits an elapsed-time tick every heartbeatInterval until
// the returned stop function is called.
//
// Streaming output is not enough on its own: measured against a real 9 GB
// image, vol2's imageinfo prints "Determining profile based on KDBG search…"
// once and then emits *nothing* for minutes while it scans. With only
// streamed output the UI cannot distinguish that from a hung process — which
// is precisely the "is it running or not?" problem. This tick originates
// from the goroutine that is sitting in cmd.Wait(), so it is evidence the
// child process is still being waited on, not merely that the UI is alive.
func startHeartbeat(tool, item string, emit Emitter) (stop func()) {
	start := time.Now()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				emit("tool:heartbeat", map[string]any{
					"tool": tool, "item": item,
					"seconds": time.Since(start).Seconds(),
				})
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
