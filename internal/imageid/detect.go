// Package imageid identifies which operating system a memory image came
// from, so the app can offer the right tools for it — MemProcFS and
// Volatility's windows.* plugins for Windows images, the linux.* plugins for
// Linux ones (MemProcFS does not read Linux images, so those runs are
// Volatility-only).
package imageid

import (
	"bytes"
	"io"
	"os"
	"strings"
)

// OS values returned by Detect.
const (
	OSWindows = "windows"
	OSLinux   = "linux"
	OSMac     = "darwin"
	OSUnknown = "unknown"
)

// Result reports what Detect concluded and the evidence for it, so the UI
// can show why rather than just asserting.
type Result struct {
	OS       string `json:"os"`
	Evidence string `json:"evidence"`
}

// The scan deliberately has no byte cap.
//
// It used to stop after the first 3 GiB, on the reasoning that kernel banners
// live in low physical memory and that scanning tens of GB would be slow for
// a question answered in the first fraction of the file. That reasoning is
// wrong, and it produced a silent, damaging failure: on a 4 GiB VMware .vmem
// of an Ubuntu guest, every copy of the banner sits between 3.33 and 3.39 GiB
// — just past the old cap. Detect returned OSUnknown, and since callers treat
// anything that is not Linux as Windows, the run went down the MemProcFS path
// and MemNixFS (the only tool of the two that reads Linux images at all)
// never started. Where a guest's kernel lands in physical memory is not
// something this app gets to assume.
//
// Cost is bounded by the match, not the file: both scanners below return as
// soon as they have what they need, so a recognisable image is cheap however
// large it is. Only an image with nothing to find is read to the end, and
// both callers are already asynchronous (the config screen shows "detecting
// image OS…"; the run does this on its own goroutine).
const chunkSize = 8 << 20 // 8 MiB

// signatures are matched against raw image bytes. Order matters: the first
// match wins, so the most specific markers come first.
var signatures = []struct {
	needle   []byte
	os       string
	evidence string
}{
	{[]byte("Linux version "), OSLinux, `found kernel banner "Linux version "`},
	{[]byte("Darwin Kernel Version"), OSMac, `found "Darwin Kernel Version" banner`},
	{[]byte("Windows Boot Manager"), OSWindows, `found "Windows Boot Manager"`},
	{[]byte("\\SystemRoot\\System32\\ntoskrnl.exe"), OSWindows, "found ntoskrnl.exe path"},
	{[]byte("\\WINDOWS\\system32\\"), OSWindows, `found "\WINDOWS\system32\" path`},
}

// Detect scans a memory image for kernel banner strings and reports the OS it
// belongs to, returning as soon as one matches. It returns OSUnknown (not an
// error) when nothing matches anywhere in the file, since an unrecognised
// image is a normal outcome the caller should handle by asking rather than
// guessing.
func Detect(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{OS: OSUnknown}, err
	}
	defer f.Close()

	// Overlap successive chunks by the longest needle minus one byte so a
	// signature straddling a chunk boundary is still found.
	maxNeedle := 0
	for _, s := range signatures {
		if len(s.needle) > maxNeedle {
			maxNeedle = len(s.needle)
		}
	}
	overlap := maxNeedle - 1

	buf := make([]byte, chunkSize+overlap)
	var carry int

	for {
		n, readErr := io.ReadFull(f, buf[carry:carry+chunkSize])
		if n > 0 {
			window := buf[:carry+n]
			for _, s := range signatures {
				if bytes.Contains(window, s.needle) {
					return Result{OS: s.os, Evidence: s.evidence}, nil
				}
			}
			// Carry the tail forward as the overlap for the next chunk.
			if len(window) >= overlap {
				copy(buf, window[len(window)-overlap:])
				carry = overlap
			} else {
				carry = len(window)
			}
		}
		if readErr != nil {
			break // EOF or short read — nothing more to scan
		}
	}
	return Result{OS: OSUnknown, Evidence: "no kernel banner found anywhere in the image"}, nil
}

// IsLinux reports whether an OS string (from Detect or a user override)
// means the Linux toolchain applies.
func IsLinux(os string) bool { return strings.EqualFold(os, OSLinux) }

// linuxBannerPrefix is the start of the kernel's linux_banner string, the
// exact bytes Volatility3 and MemNixFS both key their Linux symbol lookups
// on.
var linuxBannerPrefix = []byte("Linux version ")

// maxBannerLen caps how much is taken after the prefix. A real banner runs
// ~120-200 bytes; the cap only bounds the damage from a prefix that turns
// out not to be a banner at all.
const maxBannerLen = 512

// LinuxBanners returns the distinct candidate kernel banner strings found in
// an image, in the order encountered, trimmed of the trailing NUL/newline
// the kernel stores them with.
//
// Several matches are normal and expected: the real linux_banner is not the
// only place that text appears in memory (a running process's own copy, log
// buffers, and — seen on a real CentOS image — a JSON blob embedding the
// banner with an escaped "\n" all match the same prefix). Rather than trying
// to guess which is authentic, every candidate is returned and the caller
// resolves them against a symbol index; a false positive simply fails to
// match anything, so correctness comes from the index rather than from this
// heuristic.
func LinuxBanners(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// A banner straddling a chunk boundary must still be found whole, so the
	// overlap carried between chunks covers a full maximum-length banner
	// rather than just the prefix.
	const overlap = maxBannerLen
	buf := make([]byte, chunkSize+overlap)
	var carry int

	var banners []string
	seen := map[string]bool{}

	// Read to the end rather than stopping early: unlike Detect, which only
	// needs one hit, symbol resolution wants every candidate — the genuine
	// linux_banner is not reliably the first one encountered.
	for {
		n, readErr := io.ReadFull(f, buf[carry:carry+chunkSize])
		if n > 0 {
			window := buf[:carry+n]
			for offset := 0; ; {
				idx := bytes.Index(window[offset:], linuxBannerPrefix)
				if idx == -1 {
					break
				}
				start := offset + idx
				if b := extractBanner(window[start:]); b != "" && !seen[b] {
					seen[b] = true
					banners = append(banners, b)
				}
				offset = start + len(linuxBannerPrefix)
			}
			if len(window) >= overlap {
				copy(buf, window[len(window)-overlap:])
				carry = overlap
			} else {
				carry = len(window)
			}
		}
		if readErr != nil {
			break // EOF or short read — nothing more to scan
		}
	}
	return banners, nil
}

// extractBanner reads one banner out of data, which begins at the
// "Linux version " prefix. The kernel stores linux_banner NUL-terminated
// with a trailing newline, so the string ends at whichever of those comes
// first; anything non-printable before then means this was not really a
// banner. Returns "" if it does not look like one.
func extractBanner(data []byte) string {
	if len(data) > maxBannerLen {
		data = data[:maxBannerLen]
	}
	end := -1
	for i, c := range data {
		if c == '\n' || c == 0x00 {
			end = i
			break
		}
		// Printable ASCII plus tab. A banner is entirely printable, so a
		// control byte or high byte means this match is not one.
		if c != '\t' && (c < 0x20 || c > 0x7e) {
			return ""
		}
	}
	if end <= len(linuxBannerPrefix) {
		return "" // no terminator found, or nothing after the prefix
	}
	return string(data[:end])
}

// NormalizeBanner trims the trailing NUL and newline the kernel stores
// linux_banner with, so a banner read out of an image and one read out of a
// symbol index compare equal. Volatility3's own remote-index loader does the
// same thing (see its symbol_cache.py), because a banner carrying "\n\x00"
// never matches one carrying only "\n".
func NormalizeBanner(banner string) string {
	return strings.TrimRight(banner, "\x00\n\r \t")
}
