// Package linuxsymbols builds a Volatility3 ISF symbol table for a Linux
// kernel from a distro's kernel debuginfo package, for kernels no online
// community index (see internal/volatility/remoteisf.go) happens to have.
//
// The chain: a package (.rpm, .ddeb, …) -> extract -> the real ELF vmlinux
// buried inside it -> `dwarf2json linux --elf vmlinux` -> an ISF json,
// dropped into paths.SymbolsDir()/linux where Volatility3 already looks for
// local symbol tables. Neither dwarf2json nor Volatility3 can read the
// package directly: dwarf2json's linux subcommand only takes --elf (or
// --elf-symbols/--elf-types/--system-map), all of which expect an actual ELF
// file already sitting on disk, and it has no archive-unpacking logic of its
// own.
//
// Extraction goes through 7-Zip rather than a hand-rolled rpm/cpio parser: a
// package's payload can be compressed with gzip, xz, lzma or zstd depending
// on the distro, and 7-Zip already handles all of those (plus the .rpm/.deb/
// .cpio containers themselves) rather than this app vendoring a decoder per
// format. The extraction is applied repeatedly (7-Zip's rpm handler itself
// only unwraps one layer — the compressed cpio payload — per call, so this
// mirrors what `rpm2cpio file.rpm | cpio -idv` does on Linux, minus the fixed
// two-hop assumption: it keeps unwrapping until it finds an ELF vmlinux or
// gives up) since exactly how many hops that takes varies by payload
// compression.
package linuxsymbols

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"memforensics-gui/internal/paths"
	"memforensics-gui/internal/prereq"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Emitter reports a progress line. Matches the shape used elsewhere in this
// app (internal/volatility.Emitter, internal/installer.Emitter) but kept as
// its own type so this package doesn't need to import either just for one
// function type.
type Emitter func(event string, payload any)

// GenerateRequest names the kernel debug package to extract symbols from.
type GenerateRequest struct {
	// PackagePath is a kernel debuginfo package — an .rpm on RHEL/CentOS/
	// Fedora/openSUSE, a .ddeb on Debian/Ubuntu. Anything 7-Zip's Ar/Rpm/Cpio
	// handlers can open is fair game, since the extraction loop below just
	// keeps unwrapping whatever it's given until it finds an ELF vmlinux.
	PackagePath string
}

// GenerateResult reports what generation produced.
type GenerateResult struct {
	VmlinuxPath  string `json:"vmlinuxPath"`  // the extracted ELF that was fed to dwarf2json
	ISFPath      string `json:"isfPath"`      // where the resulting ISF was placed
	KernelBanner string `json:"kernelBanner"` // decoded "Linux version ..." banner, if dwarf2json's output was readable
}

// maxExtractionDepth bounds the extract-and-look-again loop. A real package
// resolves in 2-3 hops (package -> compressed cpio -> unpacked tree); this
// just guards against looping forever on an unexpected layout.
const maxExtractionDepth = 6

// GenerateISFFromPackage runs the whole chain and returns the ISF's final
// location. Progress is reported via "isfgen:log" events (a single "line"
// string field), matching internal/installer's own "install:log".
func GenerateISFFromPackage(ctx context.Context, req GenerateRequest, emit Emitter) (GenerateResult, error) {
	sevenZip := prereq.SevenZipPath()
	if sevenZip == "" {
		return GenerateResult{}, fmt.Errorf(`7-Zip not found; click "Install dependencies" first, or install it from https://www.7-zip.org/download.html`)
	}
	dwarf2json := paths.Dwarf2Json()
	if dwarf2json == "" {
		return GenerateResult{}, fmt.Errorf(`dwarf2json not found; click "Install / update tools" first`)
	}
	if info, err := os.Stat(req.PackagePath); err != nil {
		return GenerateResult{}, fmt.Errorf("package not found: %w", err)
	} else if info.IsDir() {
		return GenerateResult{}, fmt.Errorf("%s is a directory, not a package file", req.PackagePath)
	}

	workDir, err := os.MkdirTemp("", "memforensics-isf-*")
	if err != nil {
		return GenerateResult{}, fmt.Errorf("creating a working directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	log := func(format string, args ...any) {
		emit("isfgen:log", map[string]any{"line": fmt.Sprintf(format, args...)})
	}

	log("Extracting %s with 7-Zip…", filepath.Base(req.PackagePath))
	vmlinuxPath, err := extractUntilVmlinux(ctx, sevenZip, req.PackagePath, workDir, log)
	if err != nil {
		return GenerateResult{}, err
	}
	log("Found vmlinux: %s", vmlinuxPath)

	isfTmp := filepath.Join(workDir, "output.json")
	log("Running dwarf2json; this can take a few minutes for a large kernel…")
	if err := runDwarf2Json(ctx, dwarf2json, vmlinuxPath, isfTmp, log); err != nil {
		return GenerateResult{}, err
	}

	banner := readLinuxBanner(isfTmp)
	if banner != "" {
		log("Kernel banner in the generated ISF: %s", banner)
	}

	destDir := filepath.Join(paths.SymbolsDir(), "linux")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return GenerateResult{}, fmt.Errorf("creating %s: %w", destDir, err)
	}
	destName := strings.TrimSuffix(filepath.Base(req.PackagePath), filepath.Ext(req.PackagePath)) + ".json"
	dest := filepath.Join(destDir, destName)
	if err := copyFile(isfTmp, dest); err != nil {
		return GenerateResult{}, fmt.Errorf("placing the generated ISF at %s: %w", dest, err)
	}
	// Label it with the kernel it is for, so a later run matches this file
	// against an image's banner directly — see readISFBanner. Without the
	// label the match still works, but costs a full JSON parse of a file that
	// is tens of megabytes uncompressed.
	if banner != "" {
		writeBannerSidecar(dest, banner)
	}
	log("ISF ready at %s; Volatility3 will pick it up automatically on the next run.", dest)

	return GenerateResult{VmlinuxPath: vmlinuxPath, ISFPath: dest, KernelBanner: banner}, nil
}

// extractUntilVmlinux repeatedly 7-Zip-extracts archivePath (and whatever it
// unwraps to) into fresh subdirectories of workDir until it finds a file that
// is an ELF named vmlinux, or gives up after maxExtractionDepth hops.
func extractUntilVmlinux(ctx context.Context, sevenZip, archivePath, workDir string, log func(string, ...any)) (string, error) {
	current := archivePath
	if isVmlinuxELF(current) {
		return current, nil
	}

	for depth := 0; depth < maxExtractionDepth; depth++ {
		outDir := filepath.Join(workDir, fmt.Sprintf("extract-%d", depth))
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return "", err
		}

		cmd := exec.CommandContext(ctx, sevenZip, "x", "-y", "-o"+outDir, current)
		proc.Configure(cmd)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("7-Zip could not extract %s: %w\n%s", filepath.Base(current), err, tailLines(string(out), 8))
		}

		vmlinux, onlyFile, fileCount, err := inspectExtraction(outDir)
		if err != nil {
			return "", err
		}
		if vmlinux != "" {
			return vmlinux, nil
		}
		if fileCount != 1 {
			return "", fmt.Errorf(
				"extracted %d file(s) from %s but none was a usr/lib/debug/lib/modules/*/vmlinux ELF; "+
					"this package may not include kernel debug symbols, or uses a layout this tool doesn't recognize",
				fileCount, filepath.Base(archivePath))
		}
		log("  %s -> %s, still compressed; extracting again…", filepath.Base(current), filepath.Base(onlyFile))
		current = onlyFile
	}
	return "", fmt.Errorf("gave up looking for vmlinux after %d extraction levels", maxExtractionDepth)
}

// inspectExtraction walks dir once and reports three things: the path to a
// vmlinux ELF if one was found anywhere in the tree, the path to the single
// file in the tree if there is exactly one (the "still a compressed blob,
// unwrap again" case), and the total count of regular files found.
func inspectExtraction(dir string) (vmlinux, onlyFile string, fileCount int, err error) {
	var lastFile string
	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() {
			return nil
		}
		fileCount++
		lastFile = path
		if vmlinux == "" && looksLikeVmlinuxPath(path) && isVmlinuxELF(path) {
			vmlinux = path
		}
		return nil
	})
	if walkErr != nil {
		return "", "", 0, fmt.Errorf("walking %s: %w", dir, walkErr)
	}
	if fileCount == 1 {
		onlyFile = lastFile
	}
	return vmlinux, onlyFile, fileCount, nil
}

// looksLikeVmlinuxPath reports whether path's name/layout matches the debug
// package convention (usr/lib/debug/lib/modules/<version>/vmlinux), falling
// back to any file simply named "vmlinux" for packages laid out differently.
func looksLikeVmlinuxPath(path string) bool {
	return strings.EqualFold(filepath.Base(path), "vmlinux")
}

// isVmlinuxELF reports whether path starts with the ELF magic number. A
// vmlinux extracted from a debug package is always an ELF; this guards
// against a same-named but unrelated file.
func isVmlinuxELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'})
}

// runDwarf2Json runs `dwarf2json linux --elf vmlinuxPath`, writing its stdout
// (the ISF json) to outPath.
func runDwarf2Json(ctx context.Context, dwarf2json, vmlinuxPath, outPath string, log func(string, ...any)) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	cmd := exec.CommandContext(ctx, dwarf2json, "linux", "--elf", vmlinuxPath)
	proc.Configure(cmd)
	cmd.Stdout = out
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("dwarf2json failed: %w\n%s", err, tailLines(stderrBuf.String(), 8))
	}
	info, statErr := os.Stat(outPath)
	if statErr != nil || info.Size() == 0 {
		return fmt.Errorf("dwarf2json produced no output\n%s", tailLines(stderrBuf.String(), 8))
	}
	return nil
}

// readLinuxBanner best-effort extracts the decoded "Linux version ..."
// banner from a generated ISF, purely for the user-facing confirmation
// message — a failure to parse it is not an error for the caller.
func readLinuxBanner(isfPath string) string {
	f, err := os.Open(isfPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	var doc struct {
		Symbols struct {
			LinuxBanner struct {
				ConstantData string `json:"constant_data"`
			} `json:"linux_banner"`
		} `json:"symbols"`
	}
	if err := json.NewDecoder(f).Decode(&doc); err != nil {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(doc.Symbols.LinuxBanner.ConstantData)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(raw), "\x00\n")
}

// tailLines returns the last n non-empty lines of s, so a tool failure keeps
// its most useful diagnostic detail instead of a wall of output.
func tailLines(s string, n int) string {
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// copyFile copies src to dst, overwriting dst if it exists — used to place
// the generated ISF from the (about-to-be-removed) work directory into
// paths.SymbolsDir(), which may be on a different volume than the temp dir.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
