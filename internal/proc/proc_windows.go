//go:build windows

package proc

import (
	"os/exec"
	"syscall"
	"time"
)

// Configure has no Setpgid/Pdeathsig equivalent on Windows, and
// exec.CommandContext's own kill-on-cancel is what's available without
// pulling in Job Objects. Orphaned children after an abrupt exit remain
// possible here; the Mounts panel is the recovery path for MemProcFS, and a
// stray vol/vol2 process can be ended from Task Manager.
func Configure(cmd *exec.Cmd) {
	// WaitDelay is portable and still worth setting: it stops Wait blocking
	// forever on streaming pipe readers after the process has been killed.
	cmd.WaitDelay = 5 * time.Second
	// This app is a GUI (non-console) process, but the tools it shells out to
	// (vol, vol2, memprocfs.exe…) are console subsystem binaries, so Windows
	// pops up a console window for each one unless told not to.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

// KillGroup is unsupported on Windows without Job Objects.
func KillGroup(pid int) error { return nil }

// KillAllChildren is unsupported on Windows without Job Objects; the
// context-cancel kill in exec.CommandContext is what applies there.
func KillAllChildren() int { return 0 }
