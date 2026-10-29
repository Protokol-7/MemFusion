//go:build windows

package memprocfs

import (
	"encoding/json"
	"fmt"
	"memforensics-gui/internal/proc"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// On Windows MemProcFS mounts a drive letter via Dokany rather than a FUSE
// directory, and which letter it uses is decided per run (see runner.go's
// pickWindowsMountDrive) because M: is so often already taken. So the drive
// is read back from each memprocfs.exe process's -mount argument rather than
// assumed, with DefaultMountDir (M:\) as the fallback for a process started
// outside this app that did not pass one.

type winProcRef struct {
	pid   int
	image string
	// mount is the drive root ("T:\\") parsed from the process's -mount
	// argument, falling back to DefaultMountDir when it has none.
	mount string
}

// ListMounts reports each running memprocfs.exe process with the drive it
// mounted (from its -mount argument) and its source image (from -f). With no
// process found it falls back to reporting MemProcFS's default drive, but
// only if something is actually mounted there.
func ListMounts() ([]MountInfo, error) {
	procs := memprocfsProcesses()

	if len(procs) == 0 {
		// Mounted with no owning process found — e.g. the CIM query below
		// failed or was blocked. Still worth surfacing rather than leaving
		// the user staring at a locked drive with no explanation.
		if _, err := os.Stat(DefaultMountDir); err == nil {
			return []MountInfo{{MountPoint: DefaultMountDir, Mounted: true}}, nil
		}
		return nil, nil
	}

	out := make([]MountInfo, 0, len(procs))
	for _, p := range procs {
		_, err := os.Stat(p.mount)
		out = append(out, MountInfo{MountPoint: p.mount, Mounted: err == nil, PID: p.pid, Image: p.image})
	}
	return out, nil
}

// CleanupMount kills the memprocfs.exe process owning the given drive and
// waits for Dokany to release it. Unlike the Linux side there is no separate
// "unmount" call available — Dokany drops the mount when the owning process
// exits, which is the same recovery path the Stop button already relies on.
//
// Only a drive that a memprocfs.exe process actually holds (or MemProcFS's
// default drive) is accepted, so the frontend cannot be used to kill
// processes over an unrelated drive letter.
func CleanupMount(mountPoint string) error {
	want := driveRoot(mountPoint)
	if want == "" {
		return fmt.Errorf("%s is not a drive this app can clean up", mountPoint)
	}
	if want == `Z:\` {
		return fmt.Errorf("Z: is reserved for the shared folder and cannot be cleaned up")
	}

	var owners []winProcRef
	for _, p := range memprocfsProcesses() {
		if p.mount == want {
			owners = append(owners, p)
		}
	}
	if len(owners) == 0 {
		return fmt.Errorf("%s is not a MemProcFS mount managed by this app", mountPoint)
	}

	for _, p := range owners {
		ps, err := os.FindProcess(p.pid)
		if err != nil {
			continue
		}
		_ = ps.Kill()
	}

	for i := 0; i < 15; i++ {
		if _, err := os.Stat(want); err != nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	if _, err := os.Stat(want); err == nil {
		return fmt.Errorf("%s is still mounted after cleanup attempt", want)
	}
	return nil
}

// driveRoot normalises a drive reference ("T", "T:", "T:\\", "t:/") to the
// root path form "T:\\". It returns "" for anything that is not a single
// drive letter, which is what keeps CleanupMount from accepting a path.
func driveRoot(s string) string {
	t := strings.TrimSpace(s)
	t = strings.TrimRight(t, `\/`)
	t = strings.TrimSuffix(t, ":")
	if len(t) != 1 {
		return ""
	}
	c := t[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return ""
	}
	return strings.ToUpper(t) + `:\`
}

type cimProcess struct {
	ProcessId   int    `json:"ProcessId"`
	CommandLine string `json:"CommandLine"`
}

// memprocfsProcesses queries running memprocfs.exe processes via CIM
// (through PowerShell — Windows has no /proc to read a command line from
// directly) and extracts the image path passed via -f.
func memprocfsProcesses() []winProcRef {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-CimInstance Win32_Process -Filter "Name='memprocfs.exe'" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress`)
	proc.Configure(cmd)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}

	var raw []cimProcess
	if strings.HasPrefix(trimmed, "{") {
		// ConvertTo-Json emits a bare object, not a one-element array, when
		// there is exactly one match.
		var single cimProcess
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil
		}
		raw = []cimProcess{single}
	} else if err := json.Unmarshal([]byte(trimmed), &raw); err != nil {
		return nil
	}

	refs := make([]winProcRef, 0, len(raw))
	for _, p := range raw {
		mount := driveRoot(extractDashMount(p.CommandLine))
		if mount == "" {
			mount = DefaultMountDir
		}
		refs = append(refs, winProcRef{pid: p.ProcessId, image: extractDashF(p.CommandLine), mount: mount})
	}
	return refs
}

var dashMountArg = regexp.MustCompile(`-mount\s+"([^"]+)"|-mount\s+(\S+)`)

// extractDashMount pulls the mount drive out of a memprocfs.exe command
// line. Returns "" when the process was started without -mount, in which
// case MemProcFS used its own default.
func extractDashMount(cmdline string) string {
	m := dashMountArg.FindStringSubmatch(cmdline)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

var dashFArg = regexp.MustCompile(`-f\s+"([^"]+)"|-f\s+(\S+)`)

// extractDashF pulls the image path out of a memprocfs.exe command line,
// handling both the quoted form (spaces in the path) and the bare form.
func extractDashF(cmdline string) string {
	m := dashFArg.FindStringSubmatch(cmdline)
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}
