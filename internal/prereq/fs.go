package prereq

import (
	"os"
	"strings"
)

func anyFileExists(paths ...string) bool {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}

// firstExistingFile returns the first path in paths that exists and is a
// regular file, or "" if none do.
func firstExistingFile(paths ...string) string {
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func fileContains(path, needle string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), needle)
}
