package volatility

import "strings"

// Both frameworks ship a large tail of plugins that are not analysis steps at
// all: framework introspection, image-format conversion, interactive shells,
// bulk dumpers that write artifacts rather than findings, and per-malware-family
// scanners for threats that are long dead. Showing ~470 entries by default
// buries the ~60 that matter, so these are marked LowValue and hidden behind
// the "show everything" toggle rather than deleted — a plugin someone
// deliberately wants is still one checkbox away.
//
// The bar for hiding something: it produces no triage signal on its own, OR it
// only works when the analyst supplies extra arguments this GUI does not pass,
// OR it targets a specific malware family from the early 2010s.

// noiseExact hides plugins by exact name.
var noiseExact = map[string]string{
	// --- vol3: framework/introspection, not analysis ---
	"frameworkinfo.FrameworkInfo": "framework introspection, not image analysis",
	"isfinfo.IsfInfo":             "symbol-file introspection, not image analysis",
	"configwriter.ConfigWriter":   "writes a config file, produces no findings",
	"layerwriter.LayerWriter":     "dumps a memory layer to disk; use only when you want the raw layer",
	"regexscan.RegExScan":         "needs a user-supplied pattern to do anything",
	"vmscan.Vmscan":               "hypervisor scan, rarely relevant to a single-guest triage image",

	// --- vol2: image conversion / acquisition utilities ---
	"imagecopy":      "converts image formats; not an analysis step",
	"raw2dmp":        "converts image formats; not an analysis step",
	"hpakextract":    "extracts an HPAK container; not an analysis step",
	"hpakinfo":       "HPAK container metadata",
	"vboxinfo":       "container metadata for VirtualBox dumps",
	"vmwareinfo":     "container metadata for VMware dumps",
	"hibinfo":        "hibernation-file metadata",
	"limeinfo":       "LiME container metadata",
	"qemuinfo":       "QEMU container metadata",
	"machoinfo":      "Mach-O container metadata",
	"crashinfo":      "crash-dump header metadata",
	"volshell":       "interactive shell; cannot run unattended",
	"linux_volshell": "interactive shell; cannot run unattended",
	"mac_volshell":   "interactive shell; cannot run unattended",
	"patcher":        "modifies the image; never appropriate in triage",
	"bioskbd":        "reads the real-mode BIOS keyboard buffer; almost never populated on modern images",
	"strings":        "needs a user-supplied strings file",
	"pagecheck":      "low-level paging diagnostic",
	"testsuite":      "framework self-test",
	"kpcrscan":       "low-level KPCR enumeration; imageinfo already reports what's needed",
	"kdbgscan":       "profile-detection helper; the app runs imageinfo for this",
	"bigpools":       "raw big-pool listing; use the targeted scanners instead",
	"pooltracker":    "pool-tag statistics, not findings",
	"multiscan":      "internal scanning harness",
	"vaddump":        "bulk-dumps every VAD to disk rather than reporting findings",
	"vadtree":        "raw VAD tree; malfind/ptemalfind report the interesting subset",
	"vadwalk":        "raw VAD walk; see vadtree",
	"vadinfo":        "raw VAD metadata; malfind/ptemalfind report the interesting subset",
	"memmap":         "raw page mapping table",
	"memdump":        "bulk process memory dump rather than a finding",
	"procdump":       "bulk executable dump rather than a finding",
	"dlldump":        "bulk DLL dump rather than a finding",
	"moddump":        "bulk driver dump rather than a finding",
	"dumpfiles":      "bulk file extraction; MemProcFS's forensic/files already recovers these",
	"dumpregistry":   "bulk hive export; the mount exposes registry/hive_files",
	"dumpcerts":      "bulk certificate export",
	"evtlogs":        "bulk .evtx export; the mount exposes misc/eventlog",
	"notepad":        "single-application curiosity",
	"iehistory":      "IE-only browser history; superseded by the mount's forensic/web",
	"screenshot":     "reconstructs GDI window layout; rarely load-bearing and often empty",
	"gahti":          "GUI object-type internals",
	"atoms":          "GUI atom tables; internals, not findings",
	"atomscan":       "GUI atom tables; internals, not findings",
	"clipboard":      "occasionally useful but usually empty; unhide if you want it",
	"deskscan":       "GUI desktop internals",
	"windows":        "GUI window enumeration",
	"wintree":        "GUI window tree",
	"wndscan":        "GUI window-station scan",
	"sessions":       "session internals",
	"eventhooks":     "GUI event hooks",
	"messagehooks":   "GUI message hooks",
	"userhandles":    "GUI handle internals",
	"editbox":        "experimental GUI control scraper",
}

// noisePrefixes hides whole families by name prefix.
var noisePrefixes = map[string]string{
	// Per-malware-family scanners for threats that are effectively extinct.
	// Keeping them costs list space every session; anyone chasing one of
	// these knows to unhide it.
	"zeusscan":  "scanner for a specific, long-dead malware family",
	"poisonivy": "scanner for a specific, long-dead malware family",
	"ghostrat":  "scanner for a specific, long-dead malware family",
	"dyrescan":  "scanner for a specific, long-dead malware family",
	"plugx":     "scanner for a specific, long-dead malware family",
	"apt17scan": "scanner for one specific APT toolkit",
	"redleaves": "scanner for a specific malware family",
	"zbotscan":  "scanner for a specific, long-dead malware family",
	"citadel":   "scanner for a specific, long-dead malware family",

	// vol2 mac plugins: this app's mac support is untested and MemProcFS
	// does not cover them, so they're hidden rather than recommended.
	"mac_": "macOS plugin; untested in this app; unhide if analysing a mac image",

	// vol2's Linux plugins cannot actually run from this app: Volatility 2
	// requires a per-kernel profile .zip built from the exact target kernel's
	// headers, and `imageinfo` only suggests profiles for Windows images.
	// With no profile there is no way to invoke them, so listing them as
	// selectable options would promise something the app cannot deliver —
	// use the vol3 linux.* equivalents instead.
	"linux_": "Volatility 2 Linux plugins need a hand-built per-kernel profile this app cannot generate; use the vol3 linux.* equivalents",
}

// annotateNoise marks low-value plugins so the UI can hide them by default.
func annotateNoise(plugins []Plugin) {
	for i := range plugins {
		// Never hide a custom plugin: they were deliberately installed.
		if plugins[i].Category == "custom" {
			continue
		}
		if reason, ok := noiseExact[plugins[i].Name]; ok {
			plugins[i].LowValue = true
			plugins[i].LowValueReason = reason
			continue
		}
		// vol3 names are "<namespace>.<module>.<ClassName>" (or
		// "<module>.<ClassName>" for top-level plugins), so the module is the
		// SECOND-TO-LAST segment.
		//
		// It must not be the first segment: that is the OS namespace, and
		// vol2 has a plugin literally named "windows" (GUI window
		// enumeration) in the list below. Matching on the first segment made
		// every single windows.* vol3 plugin — all 105 of them — collide with
		// it and vanish from the picker as "low value".
		parts := strings.Split(plugins[i].Name, ".")
		if len(parts) >= 2 {
			module := parts[len(parts)-2]
			if reason, ok := noiseExact[module]; ok {
				plugins[i].LowValue = true
				plugins[i].LowValueReason = reason
				continue
			}
		}
		for prefix, reason := range noisePrefixes {
			if strings.HasPrefix(plugins[i].Name, prefix) {
				plugins[i].LowValue = true
				plugins[i].LowValueReason = reason
				break
			}
		}
	}
}
