package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type cachedRelease struct {
	Release ghRelease
	Checked time.Time
}
type releaseCache struct {
	Entries    map[string]cachedRelease
	RetryAfter time.Time
}

var releaseMu sync.Mutex
var releases releaseCache
var releaseCacheLoaded bool

func githubLatestRelease(ctx context.Context, repo string) (ghRelease, error) {
	releaseMu.Lock()
	defer releaseMu.Unlock()
	path := filepath.Join(ToolsDir(), "github-releases-cache.json")
	if !releaseCacheLoaded {
		data, err := os.ReadFile(path)
		if err == nil {
			_ = json.Unmarshal(data, &releases)
		}
		if releases.Entries == nil {
			releases.Entries = map[string]cachedRelease{}
		}
		releaseCacheLoaded = true
	}
	if entry, ok := releases.Entries[repo]; ok && time.Since(entry.Checked) < time.Hour {
		return entry.Release, nil
	}
	if time.Now().Before(releases.RetryAfter) {
		return ghRelease{}, fmt.Errorf("GitHub request limit reached; retry after %s. Installed tools are unchanged", releases.RetryAfter.Local().Format("15:04:05 MST"))
	}
	release, err := fetchLatestRelease(ctx, repo)
	if err == nil {
		releases.Entries[repo] = cachedRelease{release, time.Now()}
	}
	data, e := json.Marshal(releases)
	if e == nil {
		_ = os.WriteFile(path, data, 0600)
	}
	return release, err
}
