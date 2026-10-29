package volatility

import (
	"encoding/json"
	"fmt"
	"memforensics-gui/internal/paths"
	"net/url"
	"os"
	"path/filepath"
)

// RemoteISFSources lists community-maintained Volatility3 "remote ISF"
// indexes this app chains together for Linux images. Each is a
// banners-isf.json mapping a base64-encoded exact kernel banner string to
// the URL of a ready-made ISF for that exact build.
//
// This isn't something built on top of Volatility3 — it's Volatility3's own
// built-in mechanism (see its framework/automagic/symbol_cache.py,
// RemoteIdentifierFormat's "version": 1 format, and the CLI's
// --remote-isf-url flag). Given that flag, vol3 downloads the index, scans
// the image for a matching banner, and — on a match — downloads and caches
// the ISF itself automatically, the same way it already resolves Windows PDBs
// from Microsoft's symbol server per run. This app just points vol at a small
// local file chaining every source below via that format's own "additional"
// field, so one --remote-isf-url covers all of them; see remoteISFArgs.
//
// Only sources that have actually been checked belong in this list: a source
// that returns malformed JSON (as opposed to a plain 404, which vol3 already
// tolerates via RemoteIdentifierFormat.process_v1's `except OSError`) throws
// inside vol3's automagic and can take down the whole Linux run, not just
// miss a lookup. Both entries below were confirmed to serve valid
// "version": 1 JSON at the time this was written.
//
// Other community indexes exist — an ISF server at
// isf-server.techanarchy.net was mentioned alongside these two, but wasn't
// reachable when checked — add it (or any other) here once you've confirmed
// it actually serves valid "version": 1 JSON.
var RemoteISFSources = []string{
	// leludo84/vol3-linux-profiles — mostly CentOS/RHEL/Ubuntu kernels.
	// https://github.com/leludo84/vol3-linux-profiles
	"https://raw.githubusercontent.com/leludo84/vol3-linux-profiles/main/banners-isf.json",
	// Abyss-W4tcher/volatility3-symbols — Ubuntu/Debian/Amazon Linux/CentOS
	// kernels, hosted on S3 per the project's own README.
	// https://github.com/Abyss-W4tcher/volatility3-symbols
	"https://volatility3-symbols.s3.eu-west-1.amazonaws.com/banners.json",
}

// remoteISFIndex mirrors the "version": 1 remote-identifier format vol3's
// RemoteIdentifierFormat.process_v1 understands: a real index maps
// operating-system name to {base64-banner: [isf-url, ...]}, but "additional"
// alone (a list of further indexes to chain, recursively) is enough on its
// own to just aggregate other sources without this app re-hosting their
// content.
type remoteISFIndex struct {
	Version    int      `json:"version"`
	Additional []string `json:"additional"`
}

// EnsureRemoteISFIndex (re)writes the local file that chains RemoteISFSources
// together for --remote-isf-url and returns its path. It is rewritten on
// every call — the content is a few hundred bytes — so a change to
// RemoteISFSources takes effect on the very next run without the user having
// to clear any cache.
func EnsureRemoteISFIndex() (string, error) {
	path := paths.RemoteISFIndexPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(remoteISFIndex{Version: 1, Additional: RemoteISFSources}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// remoteISFArgs returns the vol3 CLI arguments that turn on online Linux
// kernel-symbol lookup: --remote-isf-url pointed at a local file chaining
// every source in RemoteISFSources (see EnsureRemoteISFIndex). Returns nil if
// that file couldn't be written, in which case the run proceeds without it —
// falling back to whatever local symbol packs (or generated ISFs — see
// internal/linuxsymbols) are already installed.
func remoteISFArgs() []string {
	path, err := EnsureRemoteISFIndex()
	if err != nil {
		return nil
	}
	return []string{"--remote-isf-url", fileURL(path)}
}

// fileURL turns a local filesystem path into a file:// URL that vol3's
// resource accessor (urllib underneath) can open, including on Windows where
// the drive letter needs to land after an extra slash: file:///C:/....
func fileURL(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	u := url.URL{Scheme: "file", Path: "/" + filepath.ToSlash(abs)}
	return u.String()
}
