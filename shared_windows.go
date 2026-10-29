package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows/registry"
)

func networkImagePath(path string) string {
	if len(path) < 3 || path[1] != ':' || (path[2] != '\\' && path[2] != '/') {
		return path
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Network\`+strings.ToUpper(path[:1]), registry.QUERY_VALUE)
	if err != nil {
		return path
	}
	defer key.Close()
	remote, _, err := key.GetStringValue("RemotePath")
	if err != nil || !strings.HasPrefix(remote, `\\`) {
		return path
	}
	return filepath.Join(remote, path[3:])
}

// BrowseMemoryImage accesses saved mapped shares through their UNC path,
// which is not tied to the file picker's elevated drive namespace.
func (a *App) BrowseMemoryImage(current string, shared bool) (string, error) {
	dir := ""
	if shared {
		dir = networkImagePath(`Z:\`)
		if dir == `Z:\` {
			return "", fmt.Errorf("No saved Z: network mapping found. Enter the share's UNC path in Memory image")
		}
	} else if current != "" {
		dir = filepath.Dir(networkImagePath(current))
	}
	if dir != "" {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			dir = ""
		}
	}
	opts := runtime.OpenDialogOptions{Title: "Select the memory image", DefaultDirectory: dir}
	path, err := runtime.OpenFileDialog(a.ctx, opts)
	if err != nil && dir != "" {
		opts.DefaultDirectory = ""
		return runtime.OpenFileDialog(a.ctx, opts)
	}
	return path, err
}
