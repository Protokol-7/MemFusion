package volatility

import "strings"

// redundantPrefixes maps plugin name prefixes to a short reason describing
// where MemProcFS already provides the same data. Plugins matching these
// prefixes are flagged Redundant in the catalog so the UI can hide them by
// default — the plugin picker then only offers plugins that fill gaps in
// MemProcFS's output.
//
// This list was verified against a real mounted MemProcFS forensic run
// (/cases/memprocfs-mount, MemProcFS 5.x, -forensic mode) by inspecting the
// actual virtual filesystem — not the sqlite schema, which under-represents
// what the mount exposes. Key evidence per entry is cited in each reason.
//
// The guiding rule: walk-based enumeration that MemProcFS already exports is
// redundant; scan-based discovery of hidden/freed objects (psscan, modscan,
// driverscan, svcscan, netscan, thrdscan) and detection/decoding plugins
// with no MemProcFS equivalent are kept.
var redundantPrefixes = map[string]string{
	// Processes: forensic/csv/process.csv has PID/PPID/State/User/
	// IntegrityLevel/CreateTime/ExitTime/CommandLine (terminated processes
	// included); per-process dirs under pid/.
	"windows.pslist": "process.csv + pid/ tree in the MemProcFS mount",
	"windows.pstree": "process.csv has PID/PPID (tree is derivable); pid/ tree in the mount",

	// Command line & environment: pid/<pid>/win-cmdline.txt,
	// win-environment.txt, and process.csv's CommandLine column.
	"windows.cmdline": "process.csv CommandLine column + pid/*/win-cmdline.txt",
	"windows.envars":  "pid/*/win-environment.txt",

	// Handles: forensic/csv/handles.csv + pid/<pid>/handles/.
	"windows.handles": "handles.csv + pid/*/handles/",

	// Loaded modules: forensic/csv/modules.csv (incl. version info, PDB
	// paths) + pid/<pid>/modules/. Kernel drivers: sys/drivers +
	// forensic/csv/drivers.csv; unloaded: unloaded_modules.csv.
	"windows.dlllist":         "modules.csv + pid/*/modules/",
	"windows.modules":         "drivers.csv + sys/drivers",
	"windows.unloadedmodules": "unloaded_modules.csv",
	"windows.verinfo":         "modules.csv Ver* columns",

	// Services: forensic/csv/services.csv + sys/services (registry+SCM
	// walk, incl. PID, state, image path). The scan-based svcscan/svcdiff
	// are kept for hidden-service detection.
	"windows.svclist":        "services.csv + sys/services",
	"windows.getservicesids": "services.csv (service accounts/users listed per service)",

	// Tokens / account context: pid/<pid>/token/ has sid.txt, sid-all.txt,
	// privileges.txt, integrity.txt, user.txt.
	"windows.getsids":    "pid/*/token/sid-all.txt + process.csv User column",
	"windows.privileges": "pid/*/token/privileges.txt",

	// Network: forensic/csv/net.csv, netdns.csv + sys/net/netstat.txt.
	// netscan is kept: its pool scan also finds freed/closed sockets.
	"windows.netstat": "net.csv + sys/net/netstat.txt",

	// Files & NTFS: forensic/files (recovered file objects), files.csv,
	// forensic/ntfs (MFT scan) + ntfs_files.txt.
	"windows.filescan": "files.csv + forensic/files (recovered) + forensic/ntfs (MFT)",
	"windows.mftscan":  "forensic/ntfs MFT scan + ntfs_files.txt",

	// Kernel objects: sys/objects walks the object-manager namespace
	// (named mutants/symlinks) and timeline_kernelobject.csv records them.
	"windows.mutantscan":  "sys/objects + timeline_kernelobject.csv",
	"windows.symlinkscan": "sys/objects + timeline_kernelobject.csv",

	// Threads: forensic/csv/threads.csv + pid/<pid>/threads/. thrdscan
	// (pool scan for hidden/terminated threads) is kept.
	"windows.threads": "threads.csv + pid/*/threads/",

	// Devices / system info.
	"windows.devicetree": "devices.csv + sys/drivers",
	"windows.info":       "sys/ (version*, architecture, computername, time-*)",

	// Registry: the full hive set is mounted and browsable under
	// registry/, with raw hive files under registry/hive_files.
	"windows.registry.hivelist":        "registry/hive_files (hives mounted + exportable)",
	"windows.registry.hivescan":        "registry/hive_files",
	"windows.registry.printkey":        "registry/ tree is directly browsable in the mount",
	"windows.registry.scheduled_tasks": "tasks.csv + sys/tasks + timeline_task.csv",
	"windows.registry.amcache":         "forensic/csv/amcache_*.csv (7 decoded tables)",

	// Vendored community plugins that duplicate the mount. They're still
	// installed (they're useful when running vol3 standalone against an
	// image with no MemProcFS mount), just not offered by default here.
	"windows.prefetch": "forensic/prefetch + timeline_prefetch.csv",
	"windows.evtxlog":  "misc/eventlog/*.evtx (Analyzer parses them with EvtxECmd)",

	// Timeline: forensic/csv/timeline_all.csv merges 10 source categories
	// (process, registry, net, ntfs, task, thread, web, prefetch, amcache,
	// kernelobject).
	"timeliner": "timeline_all.csv + per-category timeline CSVs",
}

// analyzerRedundantPrefixes maps plugin prefixes to the MemProcFS-Analyzer
// stage that already produces the same artifact. These are hidden only when
// the analyzer is enabled for the run (Windows only). Verified against the
// MemProcFS-Analyzer feature set (EvtxECmd/Zircolite, RECmd, AmcacheParser,
// AppCompatCacheParser, ClamAV + 447 YARA rules, browser/LNK/Prefetch
// parsers). Only overlaps with *core* vol3 plugins are listed here — most of
// the Analyzer's registry/browser/LNK output has no core vol3 equivalent, so
// this list is intentionally short.
var analyzerRedundantPrefixes = map[string]string{
	// RECmd decodes UserAssist from the raw hives.
	"windows.registry.userassist": "UserAssist decoded by RECmd",
	// The Analyzer runs dedicated ClamAV + 447 bundled YARA rules over the
	// image, a superset of an ad-hoc vad/kernel yara sweep.
	"windows.vadyarascan": "ClamAV + 447 bundled YARA rules",
	"yarascan":            "ClamAV + 447 bundled YARA rules",
	// The Analyzer explicitly does process path/name masquerading detection.
	"windows.malware.pebmasquerade": "process name/path masquerade detection",
}

// notePrefixes attaches a "kept, but here's the overlap" caveat to plugins
// that partially duplicate MemProcFS yet earn their place. Chiefly the
// pool-scan family: MemProcFS lists active objects by walking the OS's own
// structures, so its rows will look ~identical to these — but these carve
// physical memory for the raw structures directly, which is what catches a
// rootkit that has unlinked itself from the walked lists (DKOM).
var notePrefixes = map[string]string{
	"windows.psscan":     "≈ MemProcFS process.csv, but carves raw _EPROCESS structs; catches DKOM-hidden/terminated processes a walk misses",
	"windows.modscan":    "≈ MemProcFS modules, but pool-scans; catches unlinked/hidden modules",
	"windows.driverscan": "≈ MemProcFS drivers, but pool-scans; catches unlinked/hidden drivers",
	"windows.svcscan":    "overlaps sys/services, but scans for hidden services (pair with malware.svcdiff)",
	"windows.thrdscan":   "≈ MemProcFS threads.csv, but pool-scans; catches hidden/terminated threads",
	"windows.netscan":    "overlaps net.csv, but pool-scans; also recovers freed/closed sockets",
}

// annotateCoverage flags plugins whose output MemProcFS's forensic mount (or
// MemProcFS-Analyzer) already contains, and attaches overlap notes to the
// scan family.
func annotateCoverage(plugins []Plugin) {
	for i := range plugins {
		for prefix, reason := range redundantPrefixes {
			if strings.HasPrefix(plugins[i].Name, prefix) {
				plugins[i].Redundant = true
				plugins[i].RedundantReason = "Covered by MemProcFS: " + reason
				break
			}
		}
		for prefix, reason := range analyzerRedundantPrefixes {
			if strings.HasPrefix(plugins[i].Name, prefix) {
				plugins[i].AnalyzerRedundant = true
				plugins[i].AnalyzerReason = "Covered by MemProcFS-Analyzer: " + reason
				break
			}
		}
		for prefix, note := range notePrefixes {
			if strings.HasPrefix(plugins[i].Name, prefix) {
				plugins[i].Note = note
				break
			}
		}
	}
}
