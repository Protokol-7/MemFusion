package volatility

import "strings"

// recommendedPrefixes lists plugin name prefixes (dotted module path, with
// or without the trailing .ClassName) that are pre-checked by default in
// the plugin picker.
//
// This list was re-curated (2026-08) against a real mounted MemProcFS
// forensic run by inspecting the live virtual filesystem at
// /cases/memprocfs-mount — which exposes considerably more than the
// vmm.sqlite3 schema the first revision of this list was based on. Several
// plugins previously believed to be gaps turned out to be fully covered by
// the mount and were moved to coverage.go's redundant list instead:
// cmdline (win-cmdline.txt), envars (win-environment.txt), handles
// (handles.csv), dlllist (modules.csv), svclist/getservicesids
// (services.csv), getsids/privileges (pid/*/token/), netstat
// (sys/net/netstat.txt), filescan/mftscan (forensic/files + forensic/ntfs),
// and mutantscan/symlinkscan (sys/objects + kernel-object timeline).
//
// What remains, and why it survives the cross-reference:
//
//   - The *scan family (psscan, modscan, driverscan, svcscan, netscan,
//     thrdscan) discovers hidden, unlinked, or freed objects by pool/tag
//     scanning. MemProcFS's exports are built from structured walks, so a
//     rootkit that unlinks itself evades them; these plugins are the
//     cross-check. netscan additionally recovers freed/closed sockets that
//     sys/net's active-state walk misses.
//   - The windows.malware.* family does scan-vs-walk cross-referencing and
//     injection/rootkit detection with different heuristics than
//     MemProcFS's FindEvil (which is deliberately conservative, 64-bit
//     Win10+ only, and caps findings per process). Overlap exists
//     (e.g. malfind vs FindEvil's PE_INJECT/private-executable checks) but
//     the two catch different things, so both are worth running on a
//     suspect image.
//   - Console/command history (cmdscan, consoles) has no MemProcFS
//     equivalent at all — conhost scraping is a pure gap.
//   - Credential material (hashdump, cachedump, lsadump, truecrypt) is
//     never part of MemProcFS's automated export by design. Matched by
//     prefix so they light up wherever pycryptodome is present.
//   - windows.registry.userassist decodes an artifact the raw mounted
//     registry does not decode.
//   - Custom vendored plugins (see custom_plugins/): cobaltstrike (C2
//     config extraction), anydesk (RMM trace-log recovery), and
//     openssh_sessionkeys (SSH session key recovery, Linux) fill gaps
//     MemProcFS has no module for. keepass and richheader are shipped but
//     not pre-checked: keepass is a slow full-memory pattern sweep only
//     worth running when KeePass was in use, and richheader is
//     attribution-support info rather than triage signal.
//
// Linux/mac coverage below is a lower-confidence starting point based on
// general DFIR practice, not an empirical MemProcFS comparison — MemProcFS's
// Linux/mac support is known to be much thinner than its Windows support,
// so more of vol3's catalog there likely adds unique value, but this
// hasn't been verified against a real Linux/mac image the way the Windows
// list above was.
var recommendedPrefixes = []string{
	// --- Windows: hidden-object / rootkit pool-scanning ---
	"windows.psscan",
	"windows.modscan",
	"windows.driverscan",
	"windows.svcscan",
	"windows.thrdscan",

	// --- Windows: process injection / anti-evasion detection ---
	"windows.malware.malfind",
	"windows.malware.hollowprocesses",
	"windows.malware.processghosting",
	"windows.malware.pebmasquerade",
	"windows.malware.skeleton_key_check",
	"windows.malware.unhooked_system_calls",
	"windows.malware.suspicious_threads",
	"windows.malware.svcdiff",
	"windows.malware.ldrmodules",
	"windows.malware.drivermodule",

	// --- Windows: console/command history (no MemProcFS equivalent) ---
	"windows.cmdscan",
	"windows.consoles",

	// --- Windows: network (pool scan also finds freed/closed sockets) ---
	"windows.netscan",

	// --- Windows: credentials (never in an automated triage export) ---
	"windows.hashdump",
	"windows.cachedump",
	"windows.lsadump",
	"windows.registry.hashdump",
	"windows.registry.cachedump",
	"windows.registry.lsadump",
	"windows.truecrypt",

	// --- Windows: decoded registry artifact not covered by the mount ---
	"windows.registry.userassist",

	// --- Custom vendored plugins (custom_plugins/) ---
	"cobaltstrike", // Cobalt Strike beacon config extraction (Immersive Labs)
	"anydesk",      // AnyDesk RMM trace-log recovery (forensicxlab)
	// SSH session key recovery, Linux images (Fox-IT). Not recommended by
	// default: it additionally requires a hand-built `openssh64` symbol file
	// for the target sshd binary, without which it fails outright — so it is
	// installed and selectable, but only worth enabling deliberately.
	// "openssh_sessionkeys",
	// Frank Block's PTE-based detection (custom_plugins/windows/). These
	// examine page-table entries rather than VAD metadata, so they find
	// injected/modified executable memory that malfind's VAD-permission
	// heuristic misses, and flag in-place patches to mapped DLLs (EtwEventWrite
	// / AmsiScanBuffer style hooks) that no MemProcFS export covers.
	"windows.ptemalfind",
	"windows.imgmalfind",
	// Credential and secret extraction — like the built-in hashdump family,
	// this is never part of an automated triage export, so it's pure gap.
	"windows.pypykatz", // lsass credential extraction (pypykatz)
	"windows.symcrypt", // RSA keys from Windows' SymCrypt library
	"windows.notepad",  // unsaved Notepad text; cheap, and nothing else recovers it
	"linux.gpg_full",   // gpg-agent cached passphrases (Linux images)
	"linux.gpg_partial",
	// Persistence: nothing in MemProcFS's export decodes Auto-Start
	// Extensibility Points, and the Analyzer's RECmd pass is Windows-host
	// only — so this is a gap on both fronts.
	// "windows.autorun" // disabled: pre-3.x requirement style; needs a real port (see custom_plugins/MANUAL_PATCHES.md)
	// Modern evasion detection (memoryforensics1 PE-Shellcode suite). These
	// look for techniques MemProcFS's FindEvil does not model: direct
	// syscall stubs bypassing hooked ntdll, PEB name masquerading and packed
	// sections.
	// "windows.directsyscalls" // disabled: own classmethod still on the pre-3.x signature; needs a port
	"windows.masqueradeprocess",
	"windows.listpackers",
	// Linux rootkit detection (Abyss-W4tcher's 2023 contest plugins +
	// AsafEitani). Nothing else in this app reads a Linux image, so these
	// are the only source of ftrace hooks, tracepoint hooks, seq_ops hooks
	// and fileless processes.
	"linux.check_ftrace",
	"linux.check_tracepoints",
	"linux.check_unlinked_modules",
	"linux.check_seqops",
	"linux.fileless",
	"linux.ebpf_programs",
	// BPFVol3 eBPF suite. eBPF is now a mainstream Linux implant technique
	// and vol3's own linux.ebpf does not give this depth (loaded programs
	// with disassembly, maps, links, LSM hooks, and which processes own
	// them).
	"linux.bpf_listprogs",
	"linux.bpf_listmaps",
	"linux.bpf_listlinks",
	"linux.bpf_listprocs",
	"linux.bpf_lsm",

	// --- Linux: baseline + rootkit/hidden-object detection (lower confidence, see note above) ---
	"linux.malware.malfind",
	"linux.malware.hidden_modules",
	"linux.malware.check_afinfo",
	"linux.malware.check_creds",
	"linux.malware.check_idt",
	"linux.malware.check_modules",
	"linux.malware.check_syscall",
	"linux.malware.process_spoofing",
	"linux.malware.tty_check",
	"linux.psscan",
	"linux.bash",
	"linux.lsof",
	"linux.sockstat",

	// --- Mac: baseline + rootkit/hidden-object detection (lower confidence, see note above) ---
	"mac.malfind",
	"mac.check_syscall",
	"mac.check_sysctl",
	"mac.check_trap_table",
	"mac.kauth_listeners",
	"mac.kauth_scopes",
	"mac.trustedbsd",
	"mac.bash",
	"mac.lsof",
	"mac.netstat",
}

// RecommendedNames returns the subset of the given (already-discovered)
// plugins that match the curated recommended list, matched by name prefix
// so it's robust to a plugin's exact .ClassName suffix and simply matches
// nothing for plugins that aren't loadable in a given environment.
func RecommendedNames(plugins []Plugin) []string {
	var out []string
	for _, p := range plugins {
		if !p.Loadable {
			continue
		}
		for _, prefix := range recommendedPrefixes {
			if strings.HasPrefix(p.Name, prefix) {
				out = append(out, p.Name)
				break
			}
		}
	}
	return out
}
