package volatility

import "strings"

// Built-in, task-oriented plugin selections.
//
// The recommended set is deliberately broad — it is "everything that fills a
// gap MemProcFS doesn't cover". These are the opposite: narrow bundles aimed
// at one question, so an analyst chasing a specific lead doesn't have to
// re-derive the selection from filters each time.
//
// Entries are name prefixes resolved against the live catalog, exactly like
// recommendedPrefixes, so a preset silently omits anything not installed in a
// given environment rather than failing.
//
// Plugins known to be broken in this app are deliberately absent — autorun
// (pre-3.x requirement style) and directsyscalls (own classmethod on the old
// signature). See custom_plugins/MANUAL_PATCHES.md.

// Preset is one named bundle, resolved to concrete plugin names.
type Preset struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Plugins     []string `json:"plugins"`
}

type presetDef struct {
	name        string
	description string
	framework   string
	prefixes    []string
}

var builtInPresets = []presetDef{
	{name: "Windows triage", description: "Process lists, hidden-process scans, command lines, network connections and services. Runtime depends on image size.", framework: "vol3", prefixes: []string{"windows.pslist", "windows.pstree", "windows.psscan", "windows.cmdline", "windows.netscan", "windows.svcscan"}},
	{name: "Windows injection and evasion", description: "Injected code, hollowing, process ghosting, masquerading and suspicious threads.", framework: "vol3", prefixes: []string{"windows.malware.malfind", "windows.malware.hollowprocesses", "windows.malware.processghosting", "windows.malware.pebmasquerade", "windows.malware.suspicious_threads", "windows.malware.ldrmodules", "windows.ptemalfind", "windows.imgmalfind", "windows.masqueradeprocess"}},
	{name: "Windows credentials and keys", description: "Account hashes, LSA secrets, cached credentials and supported key stores. Output may contain secrets.", framework: "vol3", prefixes: []string{"windows.registry.hashdump", "windows.registry.cachedump", "windows.registry.lsadump", "windows.pypykatz", "windows.symcrypt", "windows.truecrypt", "keepass.KeePass"}},
	{name: "Windows remote access indicators", description: "Network connections, command lines, Cobalt Strike configurations and AnyDesk artifacts.", framework: "vol3", prefixes: []string{"windows.netscan", "windows.netstat", "windows.cmdline", "cobaltstrike.CobaltStrike", "anydesk.AnyDesk"}},
	{name: "Windows kernel and hidden objects", description: "Compare listed and scanned processes, drivers and services; inspect callbacks and system calls.", framework: "vol3", prefixes: []string{"windows.pslist", "windows.psscan", "windows.malware.psxview", "windows.modules", "windows.modscan", "windows.driverscan", "windows.thrdscan", "windows.svclist", "windows.svcscan", "windows.malware.svcdiff", "windows.malware.drivermodule", "windows.callbacks", "windows.ssdt"}},
	{name: "Windows user activity", description: "Command history, application execution records, sessions and recovered application text.", framework: "vol3", prefixes: []string{"windows.cmdline", "windows.cmdscan", "windows.consoles", "windows.registry.userassist", "windows.registry.amcache", "windows.shimcachemem", "windows.sessions", "windows.notepad", "windows.sticky", "windows.zoneid3"}},
	{name: "Windows network investigation", description: "Connections, sockets, process ownership, process trees and command lines.", framework: "vol3", prefixes: []string{"windows.netscan", "windows.netstat", "windows.pslist", "windows.pstree", "windows.cmdline"}},
	{name: "Windows services and scheduled tasks", description: "Service enumeration, hidden-service checks and registry scheduled-task records.", framework: "vol3", prefixes: []string{"windows.svclist", "windows.svcscan", "windows.malware.svcdiff", "windows.registry.scheduled_tasks", "windows.registry.hivelist", "windows.cmdline"}},
	{name: "Windows files and registry inventory", description: "File objects, MFT metadata and registry hive discovery. Does not bulk-dump file contents.", framework: "vol3", prefixes: []string{"windows.filescan", "windows.mftscan.MFTScan", "windows.registry.hivelist", "windows.registry.hivescan", "windows.handles"}},
	{name: "Windows process inspection", description: "Process trees, command lines, DLLs, handles, privileges and virtual memory mappings. Supports PID filtering where available.", framework: "vol3", prefixes: []string{"windows.pslist", "windows.pstree", "windows.cmdline", "windows.dlllist", "windows.handles", "windows.privileges", "windows.envars", "windows.vadinfo", "windows.memmap"}},
	{name: "Linux triage", description: "Processes, command history, open files, sockets and kernel modules. Requires matching Linux symbols.", framework: "vol3", prefixes: []string{"linux.pslist", "linux.pstree", "linux.bash", "linux.lsof", "linux.sockstat", "linux.lsmod", "linux.kmsg"}},
	{name: "Linux rootkit hunt", description: "Hidden modules, syscall and tracing hooks, fileless processes, injected code and eBPF objects.", framework: "vol3", prefixes: []string{"linux.check_ftrace", "linux.check_tracepoints", "linux.check_unlinked_modules", "linux.check_seqops", "linux.fileless", "linux.bpf_listprogs", "linux.bpf_listmaps", "linux.bpf_listlinks", "linux.bpf_listprocs", "linux.bpf_lsm", "linux.malware.hidden_modules", "linux.malware.check_syscall", "linux.malware.check_modules", "linux.malware.malfind", "linux.malware.netfilter"}},
	{name: "Linux process and network investigation", description: "Process ancestry, executable mappings, open files, sockets and network interfaces.", framework: "vol3", prefixes: []string{"linux.pslist", "linux.pstree", "linux.psaux", "linux.elfs", "linux.library_list", "linux.lsof", "linux.sockstat", "linux.ip.Addr", "linux.ip.Link"}},
	{name: "Linux user activity", description: "Shell history, process arguments, environment variables and open files.", framework: "vol3", prefixes: []string{"linux.bash", "linux.psaux", "linux.envars", "linux.lsof"}},
	{name: "Linux GPG credentials", description: "Recover supported gpg-agent cache entries and passphrases. Output may contain secrets.", framework: "vol3", prefixes: []string{"linux.gpg_full", "linux.gpg_partial"}},
	{name: "Utilities and diagnostics", description: "Inspect framework components, symbol files and image banners. No bulk exports or interactive shells.", framework: "vol3", prefixes: []string{"frameworkinfo.FrameworkInfo", "isfinfo.IsfInfo", "banners.Banners"}},
	{name: "Windows legacy triage (Volatility 2)", description: "Legacy process, network and service checks. Requires a supported Volatility 2 profile.", framework: "vol2", prefixes: []string{"pslist", "pstree", "psscan", "cmdline", "netscan", "svcscan"}},
}

// BuiltInPresets resolves the built-in bundles against the discovered
// catalog, dropping any that resolve to nothing in this environment (there is
// no point offering "Linux rootkit hunt" when no linux plugins are present).
func BuiltInPresets(plugins []Plugin) []Preset {
	out := make([]Preset, 0, len(builtInPresets))
	for _, def := range builtInPresets {
		var names []string
		for _, p := range plugins {
			if !p.Loadable || p.Framework != def.framework {
				continue
			}
			for _, prefix := range def.prefixes {
				if p.Name == prefix || strings.HasPrefix(p.Name, prefix+".") {
					names = append(names, p.Name)
					break
				}
			}
		}
		if len(names) == 0 {
			continue
		}
		out = append(out, Preset{Name: def.name, Description: def.description, Plugins: names})
	}
	return out
}
