package memprocfs

// MountInfo describes one MemProcFS-related mount point — or a leftover
// mount directory that is no longer mounted — found on the system.
type MountInfo struct {
	MountPoint string `json:"mountPoint"`
	Mounted    bool   `json:"mounted"`
	PID        int    `json:"pid"`   // owning memprocfs process, 0 if none found
	Image      string `json:"image"` // memory image from the process cmdline, if known
}
