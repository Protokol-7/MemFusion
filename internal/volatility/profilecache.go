package volatility

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Volatility 2's imageinfo is by far the most expensive step in a run: it
// scans the whole image looking for the KDBG, which on an 8 GB image takes
// tens of minutes. Its answer, however, is a property of the image and never
// changes — so paying that cost on every run of the same image is pure waste.
//
// This caches the detected profile on disk, keyed by the image's path, size
// and modification time. Size+mtime mean a re-acquired or truncated image at
// the same path is correctly treated as a different image rather than reusing
// a stale profile.

var profileCacheMu sync.Mutex

type profileCacheEntry struct {
	Profile string `json:"profile"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
}

func profileCachePath() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir = filepath.Join(dir, "memforensics-gui")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(dir, "vol2-profiles.json"), nil
}

func imageKey(imagePath string) (string, profileCacheEntry, error) {
	abs, err := filepath.Abs(imagePath)
	if err != nil {
		abs = imagePath
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", profileCacheEntry{}, err
	}
	return abs, profileCacheEntry{Size: info.Size(), ModTime: info.ModTime().Unix()}, nil
}

func readProfileCache() map[string]profileCacheEntry {
	cache := map[string]profileCacheEntry{}
	path, err := profileCachePath()
	if err != nil {
		return cache
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cache
	}
	_ = json.Unmarshal(data, &cache) // a corrupt cache is simply ignored
	return cache
}

// CachedVol2Profile returns a previously detected profile for imagePath, or
// "" if there is no valid entry.
func CachedVol2Profile(imagePath string) string {
	key, want, err := imageKey(imagePath)
	if err != nil {
		return ""
	}
	profileCacheMu.Lock()
	defer profileCacheMu.Unlock()
	entry, ok := readProfileCache()[key]
	if !ok || entry.Size != want.Size || entry.ModTime != want.ModTime {
		return ""
	}
	return entry.Profile
}

// StoreVol2Profile records a detected profile for imagePath.
func StoreVol2Profile(imagePath, profile string) error {
	if profile == "" {
		return nil
	}
	key, entry, err := imageKey(imagePath)
	if err != nil {
		return err
	}
	entry.Profile = profile

	profileCacheMu.Lock()
	defer profileCacheMu.Unlock()
	cache := readProfileCache()
	cache[key] = entry
	path, err := profileCachePath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing profile cache: %w", err)
	}
	return nil
}
