//go:build windows

package memprocfs

import (
	"golang.org/x/sys/windows/registry"
	"syscall"
	"unsafe"
)

// Drive-letter availability on Windows, used to pick where MemProcFS mounts.
//
// os.Stat on a drive root is not a good enough test. It answers "can this
// process open that root right now", which is a different question from "is
// this letter spoken for":
//
//   - A mapped network drive belongs to a logon session and does not cross an
//     elevation boundary. An elevated process stat-ing M: gets "not found"
//     while Explorer in the same desktop is happily showing the share.
//   - A subst'd or disconnected drive can fail to stat while still being a
//     defined DOS device that a mount would collide with.
//
// So both of the APIs that answer the real question are consulted:
// GetLogicalDrives for the bitmask of drives the session has, and
// QueryDosDevice per letter, which reports any defined DOS device name
// regardless of whether it is currently reachable.

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetLogicalDrive = kernel32.NewProc("GetLogicalDrives")
	procQueryDosDeviceW = kernel32.NewProc("QueryDosDeviceW")
)

// logicalDriveMask returns the GetLogicalDrives bitmask (bit 0 = A:), or 0 if
// the call fails — in which case the per-letter check still applies.
func logicalDriveMask() uint32 {
	r, _, _ := procGetLogicalDrive.Call()
	return uint32(r)
}

// dosDeviceDefined reports whether letter (a single 'A'-'Z') names a defined
// DOS device. A QueryDosDevice failure means no such device, which is what
// "free" looks like.
func dosDeviceDefined(letter byte) bool {
	name, err := syscall.UTF16PtrFromString(string(letter) + ":")
	if err != nil {
		return false
	}
	// The target path is not needed, only whether the lookup succeeds, so a
	// small buffer is enough: a too-small buffer still fails with
	// ERROR_INSUFFICIENT_BUFFER rather than ERROR_FILE_NOT_FOUND, which is
	// the distinction being tested.
	var buf [16]uint16
	r, _, errno := procQueryDosDeviceW.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r != 0 {
		return true
	}
	return errno == syscall.ERROR_INSUFFICIENT_BUFFER
}

// driveLetterInUse reports whether a drive letter is spoken for, by either
// measure.
func driveLetterInUse(letter byte) bool {
	upper := letter
	if upper >= 'a' && upper <= 'z' {
		upper -= 'a' - 'A'
	}
	if upper < 'A' || upper > 'Z' {
		return true // not a letter; never hand it out
	}
	// Persistent network mappings survive elevation even when drive APIs
	// cannot see the user's unelevated mapped drive. Reserve Z explicitly
	// for the user's VMware shared-folder mapping, including transient maps.
	if upper == 'Z' {
		return true
	}
	key, err := registry.OpenKey(registry.CURRENT_USER, `Network\`+string(upper), registry.QUERY_VALUE)
	if err == nil {
		key.Close()
		return true
	}
	if err != registry.ErrNotExist {
		return true
	}
	if logicalDriveMask()&(1<<uint(upper-'A')) != 0 {
		return true
	}
	return dosDeviceDefined(upper)
}
