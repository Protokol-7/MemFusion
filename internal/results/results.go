// Package results summarises what a run actually produced.
//
// A run writes one file per plugin into the output directory, and on a real
// image most of them are legitimately empty — detection plugins find nothing
// on a clean host. Left as a folder of 70+ files, the handful that matter are
// indistinguishable from the ones that don't without opening each in turn.
// This package classifies them so the UI can put findings first.
package results

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Outcome classifies one plugin's output file.
type Outcome string

const (
	// OutcomeFindings means the file has at least one data row.
	OutcomeFindings Outcome = "findings"
	// OutcomeEmpty means the plugin ran but reported nothing — a normal and
	// common result, not a failure.
	OutcomeEmpty Outcome = "empty"
	// OutcomeError means the file holds an error instead of results, most
	// often Volatility 3 refusing a plugin whose declared dependency versions
	// don't match the installed framework. vol3 exits 0 in that case, so the
	// error is only visible in the file.
	OutcomeError Outcome = "error"
)

// Result describes one plugin's output.
type Result struct {
	Plugin    string  `json:"plugin"`
	Framework string  `json:"framework"` // "vol2" | "vol3"
	File      string  `json:"file"`
	Rows      int     `json:"rows"`
	Bytes     int64   `json:"bytes"`
	Outcome   Outcome `json:"outcome"`
	Detail    string  `json:"detail"`
}

// Summary bundles the per-plugin results with counts for the panel header.
type Summary struct {
	OutputDir string   `json:"outputDir"`
	Results   []Result `json:"results"`
	Findings  int      `json:"findings"`
	Empty     int      `json:"empty"`
	Errors    int      `json:"errors"`
}

// maxScanRows bounds how much of a file is counted. A plugin like filescan can
// emit hundreds of thousands of rows, and the panel only needs to distinguish
// "nothing", "a little" and "a lot" — not an exact census of a huge file.
const maxScanRows = 100_000

// Scan reads outputDir and classifies every plugin output file in it.
func Scan(outputDir string) (Summary, error) {
	summary := Summary{OutputDir: outputDir, Results: []Result{}}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return summary, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".csv" && ext != ".txt" {
			continue
		}
		// Skip MemProcFS's own artefacts; this panel is about plugin output.
		if strings.HasSuffix(name, ".sqlite3") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}

		res := Result{
			Plugin:    pluginNameFromFile(name),
			Framework: frameworkFromFile(name),
			File:      filepath.Join(outputDir, name),
			Bytes:     info.Size(),
		}
		res.Rows, res.Outcome, res.Detail = classify(res.File, ext)
		summary.Results = append(summary.Results, res)

		switch res.Outcome {
		case OutcomeFindings:
			summary.Findings++
		case OutcomeEmpty:
			summary.Empty++
		case OutcomeError:
			summary.Errors++
		}
	}

	// Errors first (they need action), then findings by size, then the empties.
	rank := map[Outcome]int{OutcomeError: 0, OutcomeFindings: 1, OutcomeEmpty: 2}
	sort.Slice(summary.Results, func(i, j int) bool {
		a, b := summary.Results[i], summary.Results[j]
		if rank[a.Outcome] != rank[b.Outcome] {
			return rank[a.Outcome] < rank[b.Outcome]
		}
		if a.Rows != b.Rows {
			return a.Rows > b.Rows
		}
		return a.Plugin < b.Plugin
	})
	return summary, nil
}

// classify counts data rows and detects error files.
func classify(path, ext string) (rows int, outcome Outcome, detail string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, OutcomeError, "could not read output file"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNo++
		trimmed := strings.TrimSpace(line)

		// vol3 writes its dependency refusal into the output file and still
		// exits 0, so the file content is the only place it appears.
		if strings.Contains(trimmed, "Unsatisfied requirement") {
			return 0, OutcomeError, trimmed
		}
		if lineNo <= 5 && (strings.Contains(trimmed, "Traceback (most recent call last)") ||
			strings.HasPrefix(trimmed, "Volatility Foundation Volatility Framework") && lineNo == 1 && ext == ".txt") {
			// A traceback is an error; the vol2 banner alone is not, so keep
			// reading in that case rather than judging on line 1.
			if strings.Contains(trimmed, "Traceback") {
				return 0, OutcomeError, "plugin raised an exception"
			}
		}
		if trimmed == "" {
			continue
		}
		// CSV: the first non-empty line is the header, so data starts after it.
		if ext == ".csv" && rows == 0 && lineNo == 1 {
			continue
		}
		rows++
		if rows >= maxScanRows {
			break
		}
	}

	if rows == 0 {
		return 0, OutcomeEmpty, "ran, reported nothing"
	}
	return rows, OutcomeFindings, ""
}

// pluginNameFromFile recovers the plugin name from the runner's naming
// scheme: "<image>_<plugin>.csv" for vol3 and "<image>_vol2_<plugin>.txt" for
// vol2.
func pluginNameFromFile(name string) string {
	base := strings.TrimSuffix(name, filepath.Ext(name))
	if idx := strings.Index(base, "_vol2_"); idx != -1 {
		return base[idx+len("_vol2_"):]
	}
	if idx := strings.LastIndex(base, "_"); idx != -1 && idx+1 < len(base) {
		return base[idx+1:]
	}
	return base
}

func frameworkFromFile(name string) string {
	if strings.Contains(name, "_vol2_") {
		return "vol2"
	}
	return "vol3"
}
