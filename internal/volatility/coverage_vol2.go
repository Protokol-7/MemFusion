package volatility

// vol2RedundantPrefixes maps Volatility 2 plugin names to where MemProcFS's
// forensic mount already provides the same data. Verified against the live
// mount at /cases/memprocfs-mount (see coverage.go for the evidence per
// path); vol2's plugin set is largely the vol3 set under older names, so the
// same walk-vs-scan rule applies:
//
//	walk-based enumeration that MemProcFS exports  -> redundant
//	pool/tag scanning that finds hidden objects    -> kept
var vol2RedundantPrefixes = map[string]string{
	"pslist":          "process.csv + pid/ tree",
	"pstree":          "process.csv has PID/PPID; pid/ tree",
	"psxview":         "process.csv (cross-view) + findevil.csv",
	"cmdline":         "process.csv CommandLine + pid/*/win-cmdline.txt",
	"envars":          "pid/*/win-environment.txt",
	"handles":         "handles.csv + pid/*/handles/",
	"dlllist":         "modules.csv + pid/*/modules/",
	"ldrmodules":      "modules.csv (use vol3 windows.malware.ldrmodules for the unlink cross-check)",
	"modules":         "drivers.csv + sys/drivers",
	"modscan":         "drivers.csv + sys/drivers",
	"unloadedmodules": "unloaded_modules.csv",
	"verinfo":         "modules.csv Ver* columns",
	"getsids":         "pid/*/token/sid-all.txt",
	"privs":           "pid/*/token/privileges.txt",
	"svcscan":         "services.csv + sys/services",
	"getservicesids":  "services.csv",
	"netscan":         "net.csv + netdns.csv",
	"connections":     "net.csv (and this is XP/2003-only anyway)",
	"connscan":        "net.csv",
	"sockets":         "net.csv (XP/2003-only)",
	"sockscan":        "net.csv",
	"filescan":        "files.csv + forensic/files + forensic/ntfs",
	"mftparser":       "forensic/ntfs MFT scan + ntfs_files.txt",
	"mutantscan":      "sys/objects + timeline_kernelobject.csv",
	"symlinkscan":     "sys/objects",
	"thrdscan":        "threads.csv + pid/*/threads/",
	"threads":         "threads.csv + pid/*/threads/",
	"devicetree":      "devices.csv + sys/drivers",
	"driverscan":      "drivers.csv + sys/drivers",
	"hivelist":        "registry/hive_files",
	"hivescan":        "registry/hive_files",
	"printkey":        "registry/ tree is browsable in the mount",
	"userassist":      "(vol3 windows.registry.userassist covers the decode; Analyzer's RECmd also does)",
	"shimcache":       "amcache_*.csv + Analyzer's AppCompatCacheParser",
	"amcache":         "forensic/csv/amcache_*.csv (7 decoded tables)",
	"timeliner":       "timeline_all.csv + per-category timeline CSVs",
	"iehistory":       "forensic/web + timeline_web.csv",
	"evtlogs":         "misc/eventlog/*.evtx (and Analyzer parses them with EvtxECmd)",
	"getsids_":        "pid/*/token/",
}

// AnnotateAll applies every cross-reference and curation pass to a merged
// vol2+vol3 catalog. Called once after both frameworks are discovered, since
// some annotations (noise filtering) apply to both.
func AnnotateAll(plugins []Plugin) {
	annotateVol2Coverage(plugins)
	annotateNoise(plugins)
	annotateTargeting(plugins)
}

// annotateVol2Coverage flags vol2 plugins covered by MemProcFS.
func annotateVol2Coverage(plugins []Plugin) {
	for i := range plugins {
		if plugins[i].Framework != FrameworkVol2 {
			continue
		}
		if reason, ok := vol2RedundantPrefixes[plugins[i].Name]; ok {
			plugins[i].Redundant = true
			plugins[i].RedundantReason = "Covered by MemProcFS: " + reason
		}
	}
}
