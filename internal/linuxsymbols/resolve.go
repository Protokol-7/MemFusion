package linuxsymbols

// Resolving a Linux image's kernel symbols up front, in this app, rather than
// leaving each tool to do its own lookup.
//
// Volatility3 can resolve them itself given --remote-isf-url (see
// internal/volatility/remoteisf.go) — verified working against a real CentOS
// 7 image. MemNixFS cannot, at least not on Windows: its --auto-fetch is
// documented as running tools/fetch_symbols.sh, and its Windows release ships
// no tools/ directory at all, so that flag can only fail. Its remaining
// escape hatch, --vmlinux, wants a vmlinux the analyst has already extracted
// by hand — which is exactly the dead end this package exists to avoid.
//
// So the banner is resolved once here and the resulting ISF handed to both
// tools as an ordinary local file: MemNixFS via --symbols, Volatility3 by
// dropping it in paths.SymbolsDir()/linux which is already passed as
// --symbol-dirs. That also means the second run on the same image needs no
// network at all.

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"memforensics-gui/internal/imageid"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/volatility"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Resolution reports what a symbol lookup settled on.
type Resolution struct {
	Banner    string `json:"banner"`    // the kernel banner matched in the image
	ISFPath   string `json:"isfPath"`   // local ISF file both tools can use
	SourceURL string `json:"sourceUrl"` // where it came from ("" if already local)
	Cached    bool   `json:"cached"`    // it was already on disk, nothing downloaded
}

// maxIndexDepth bounds how far the "additional" chaining in a remote index is
// followed, so a cyclic or malicious index cannot loop forever.
const maxIndexDepth = 3

// indexFetchTimeout bounds fetching one index file. The largest source in use
// is a few megabytes.
const indexFetchTimeout = 2 * time.Minute

// remoteIndexDoc is the "version": 1 remote-identifier format, as produced by
// the community banners-isf.json sources and consumed by Volatility3's own
// RemoteIdentifierFormat.
type remoteIndexDoc struct {
	Version    int                 `json:"version"`
	Linux      map[string][]string `json:"linux"`
	Additional []string            `json:"additional"`
}

// ResolveForImage finds the kernel banner in imagePath, looks it up across the
// community sources, and makes sure a matching ISF exists on disk, returning
// where it is.
//
// An unmatched banner is not an error the caller should treat as fatal: plenty
// of kernels are in no community index, and both tools still produce partial
// output without symbols (MemNixFS falls back to the BTF type information
// modern kernels embed). Callers should surface the miss and carry on, which
// is why this returns a zero Resolution and a descriptive error rather than
// aborting a run.
func ResolveForImage(ctx context.Context, imagePath string, emit Emitter) (Resolution, error) {
	log := func(format string, args ...any) {
		emit("symbols:log", map[string]any{"line": fmt.Sprintf(format, args...)})
	}

	banners, err := imageid.LinuxBanners(imagePath)
	if err != nil {
		return Resolution{}, fmt.Errorf("scanning the image for a kernel banner: %w", err)
	}
	if len(banners) == 0 {
		return Resolution{}, fmt.Errorf("no Linux kernel banner found in the scanned region of the image")
	}
	// Deliberately not naming a banner yet. More than one candidate is normal
	// (see imageid.LinuxBanners) and the first one found is often not the
	// real one — on the CentOS 7 image this was built against, it was the
	// banner embedded in an application's JSON status blob. Only a symbol
	// file can say which is genuine, so the naming waits until there is a
	// match.
	log("Found %d candidate kernel banner(s).", len(banners))

	// Local files win, before any network access. This is what makes an ISF
	// the analyst generated from a kernel debug package (see
	// GenerateISFFromPackage) take effect with no further configuration, and
	// it means a repeat run on the same image needs no network at all.
	if path := LocalISFForBanner(banners); path != "" {
		banner, _ := readISFBanner(path)
		log("Using symbols already on disk: %s", path)
		return Resolution{Banner: banner, ISFPath: path, Cached: true}, nil
	}

	log("Checking community symbol sources…")
	index, err := loadIndex(ctx, log)
	if err != nil {
		return Resolution{}, err
	}
	log("Checked %d kernel(s) across %d community source(s).", len(index), len(volatility.RemoteISFSources))

	// Several banner candidates can come out of one image (see
	// imageid.LinuxBanners); the index decides which is real.
	for _, banner := range banners {
		url, ok := index[imageid.NormalizeBanner(banner)]
		if !ok {
			continue
		}
		destDir := filepath.Join(paths.SymbolsDir(), "linux")
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return Resolution{}, fmt.Errorf("creating %s: %w", destDir, err)
		}
		dest := filepath.Join(destDir, filepath.Base(url))
		log("Matched kernel: %s", banner)

		if info, statErr := os.Stat(dest); statErr == nil && info.Size() > 0 {
			// Downloaded by an earlier run (or placed by hand) but not yet
			// labelled — record it now so the local-first check above catches
			// it next time without touching the network.
			writeBannerSidecar(dest, banner)
			log("Symbols already present: %s", dest)
			return Resolution{Banner: banner, ISFPath: dest, Cached: true}, nil
		}
		log("Downloading symbols from %s", url)
		if err := downloadTo(ctx, url, dest); err != nil {
			return Resolution{}, fmt.Errorf("downloading the matching ISF: %w", err)
		}
		// Record which kernel this file is for, so the next run on this image
		// recognises it locally without fetching the index again.
		writeBannerSidecar(dest, banner)
		log("Symbols ready: %s", dest)
		return Resolution{Banner: banner, ISFPath: dest, SourceURL: url}, nil
	}

	// No candidate matched. Report the candidates rather than a bare "not
	// found": which banner was actually read out of the image is the first
	// thing needed to go looking for that kernel's debuginfo package by hand.
	return Resolution{}, fmt.Errorf(
		"no community source has symbols for this kernel; "+
			"generate them from the distro's kernel debuginfo package in Config. Banner(s) seen: %s",
		strings.Join(truncateEach(banners, 160), " | "))
}

// truncateEach shortens each string to at most n characters, so a run-log
// line built from banner candidates stays readable when one of them is a
// false positive that ran on far past where a real banner would end.
func truncateEach(values []string, n int) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if len(v) > n {
			v = v[:n] + "…"
		}
		out = append(out, v)
	}
	return out
}

// loadIndex fetches every configured community source and flattens it into a
// normalized-banner -> ISF-URL map. A source that cannot be fetched or parsed
// is logged and skipped rather than failing the lookup: the whole point of
// having several is that one being down still leaves the others usable.
func loadIndex(ctx context.Context, log func(string, ...any)) (map[string]string, error) {
	index := map[string]string{}
	var fetched int
	for _, src := range volatility.RemoteISFSources {
		if err := addSource(ctx, src, index, 0); err != nil {
			log("Source unavailable, skipping: %s (%v)", src, err)
			continue
		}
		fetched++
	}
	if fetched == 0 {
		return nil, fmt.Errorf("no community symbol source could be reached; check network connectivity")
	}
	return index, nil
}

// addSource fetches one index and merges its linux entries into index,
// following any "additional" chaining up to maxIndexDepth.
func addSource(ctx context.Context, url string, index map[string]string, depth int) error {
	if depth > maxIndexDepth {
		return nil
	}
	fetchCtx, cancel := context.WithTimeout(ctx, indexFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "memforensics-gui")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	var doc remoteIndexDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("parsing index: %w", err)
	}
	if doc.Version != 1 {
		return fmt.Errorf("unsupported index version %d", doc.Version)
	}

	for encoded, locations := range doc.Linux {
		if len(locations) == 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			continue
		}
		key := imageid.NormalizeBanner(string(raw))
		// First source wins, matching the order of RemoteISFSources.
		if _, exists := index[key]; !exists {
			index[key] = locations[0]
		}
	}
	for _, next := range doc.Additional {
		_ = addSource(ctx, next, index, depth+1)
	}
	return nil
}

// downloadTo streams url to path, writing via a temporary file so an
// interrupted download never leaves a truncated ISF behind that later runs
// would treat as a valid cached copy.
func downloadTo(ctx context.Context, url, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "memforensics-gui")
	client := &http.Client{Timeout: 30 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %s", url, resp.Status)
	}

	tmp := path + ".partial"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// SymbolsSearchDir is the directory holding ISFs this app has downloaded or
// generated, in the layout Volatility3 expects under --symbol-dirs and that
// MemNixFS's --symbols accepts as a directory to search.
func SymbolsSearchDir() string { return filepath.Join(paths.SymbolsDir(), "linux") }

// LocalISFForBanner returns the path of an ISF already sitting in the app's
// symbol directory whose own recorded banner matches one of the image's
// candidate banners, or "" if there is none.
//
// This is what makes an ISF the analyst produced themselves usable without
// any network: one generated from a kernel debug package by
// GenerateISFFromPackage, or simply dropped into the directory by hand. Each
// candidate file is opened and its linux_banner read, rather than trusting
// the filename — a file named for one kernel can contain another, and giving
// a tool symbols for the wrong kernel is worse than giving it none.
func LocalISFForBanner(banners []string) string {
	dir := SymbolsSearchDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	want := map[string]bool{}
	for _, b := range banners {
		want[imageid.NormalizeBanner(b)] = true
	}
	for _, e := range entries {
		if e.IsDir() || !isISFName(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		banner, err := readISFBanner(path)
		if err != nil || banner == "" {
			continue
		}
		if want[imageid.NormalizeBanner(banner)] {
			return path
		}
	}
	return ""
}

// isISFName reports whether a filename is an ISF, matching the extensions
// Volatility 3 itself accepts.
func isISFName(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".json", ".json.xz", ".json.gz", ".json.bz2"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// bannerSidecarSuffix names the small text file written next to a downloaded
// ISF recording the banner it is for.
//
// It exists because the community sources serve ISFs as .json.xz, Go's
// standard library has no xz decoder, and this app carries no third-party
// one. Without the sidecar an already-downloaded .xz could not be recognised
// on a later run without re-fetching the multi-megabyte index just to map the
// banner back to a filename — which would mean a repeat run on the same image
// still needed the network. The suffix deliberately does not end in .json, so
// Volatility 3's own recursive glob over the symbol directory ignores it.
const bannerSidecarSuffix = ".banner"

// writeBannerSidecar records which kernel an ISF is for. Best-effort: a
// failure only costs the offline fast path on the next run, so it is not
// worth failing a download that otherwise succeeded.
func writeBannerSidecar(isfPath, banner string) {
	_ = os.WriteFile(isfPath+bannerSidecarSuffix, []byte(banner), 0o644)
}

// readISFBanner returns the kernel banner an ISF is for, preferring the
// sidecar written at download time and otherwise reading the banner out of
// the ISF itself. Returns "" for an .xz ISF with no sidecar, which cannot be
// inspected here.
func readISFBanner(path string) (string, error) {
	if data, err := os.ReadFile(path + bannerSidecarSuffix); err == nil {
		return string(data), nil
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	lower := strings.ToLower(path)
	var r io.Reader = f
	switch {
	case strings.HasSuffix(lower, ".xz"):
		return "", fmt.Errorf("xz ISF cannot be read without a %s sidecar", bannerSidecarSuffix)
	case strings.HasSuffix(lower, ".gz"):
		zr, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer zr.Close()
		r = zr
	case strings.HasSuffix(lower, ".bz2"):
		r = bzip2.NewReader(f)
	}

	var doc struct {
		Symbols struct {
			LinuxBanner struct {
				ConstantData string `json:"constant_data"`
			} `json:"linux_banner"`
		} `json:"symbols"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Symbols.LinuxBanner.ConstantData)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
