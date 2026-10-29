# Built-in presets

Presets are task-based selections. They select loadable plugins from the installed catalog; a plugin can still fail on a particular image. Each preset uses one framework. Missing plugins are omitted, and empty presets are not shown.

Choosing a preset previews its scope without changing the selection. Use Add to selection to merge it, or Replace selection to use only that preset. Undo restores the previous selection. The selected list remains visible; Review selected shows the complete selection in the catalog, independent of catalog filters.

Utility is no longer a label or visibility filter. Utilities are visible subject to the remaining filters. The Utilities and diagnostics preset selects informational plugins only.

## Preset contents

### Windows triage

Process lists, hidden-process scans, command lines, network connections and services. Runtime depends on image size.

Framework: Volatility 3.

- `windows.pslist`
- `windows.pstree`
- `windows.psscan`
- `windows.cmdline`
- `windows.netscan`
- `windows.svcscan`

### Windows injection and evasion

Injected code, hollowing, process ghosting, masquerading and suspicious threads.

Framework: Volatility 3.

- `windows.malware.malfind`
- `windows.malware.hollowprocesses`
- `windows.malware.processghosting`
- `windows.malware.pebmasquerade`
- `windows.malware.suspicious_threads`
- `windows.malware.ldrmodules`
- `windows.ptemalfind`
- `windows.imgmalfind`
- `windows.masqueradeprocess`

### Windows credentials and keys

Account hashes, LSA secrets, cached credentials and supported key stores. Output may contain secrets.

Framework: Volatility 3.

- `windows.registry.hashdump`
- `windows.registry.cachedump`
- `windows.registry.lsadump`
- `windows.pypykatz`
- `windows.symcrypt`
- `windows.truecrypt`
- `keepass.KeePass`

### Windows remote access indicators

Network connections, command lines, Cobalt Strike configurations and AnyDesk artifacts.

Framework: Volatility 3.

- `windows.netscan`
- `windows.netstat`
- `windows.cmdline`
- `cobaltstrike.CobaltStrike`
- `anydesk.AnyDesk`

### Windows kernel and hidden objects

Compare listed and scanned processes, drivers and services; inspect callbacks and system calls.

Framework: Volatility 3.

- `windows.pslist`
- `windows.psscan`
- `windows.malware.psxview`
- `windows.modules`
- `windows.modscan`
- `windows.driverscan`
- `windows.thrdscan`
- `windows.svclist`
- `windows.svcscan`
- `windows.malware.svcdiff`
- `windows.malware.drivermodule`
- `windows.callbacks`
- `windows.ssdt`

### Windows user activity

Command history, application execution records, sessions and recovered application text.

Framework: Volatility 3.

- `windows.cmdline`
- `windows.cmdscan`
- `windows.consoles`
- `windows.registry.userassist`
- `windows.registry.amcache`
- `windows.shimcachemem`
- `windows.sessions`
- `windows.notepad`
- `windows.sticky`
- `windows.zoneid3`

### Windows network investigation

Connections, sockets, process ownership, process trees and command lines.

Framework: Volatility 3.

- `windows.netscan`
- `windows.netstat`
- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`

### Windows services and scheduled tasks

Service enumeration, hidden-service checks and registry scheduled-task records.

Framework: Volatility 3.

- `windows.svclist`
- `windows.svcscan`
- `windows.malware.svcdiff`
- `windows.registry.scheduled_tasks`
- `windows.registry.hivelist`
- `windows.cmdline`

### Windows files and registry inventory

File objects, MFT metadata and registry hive discovery. Does not bulk-dump file contents.

Framework: Volatility 3.

- `windows.filescan`
- `windows.mftscan.MFTScan`
- `windows.registry.hivelist`
- `windows.registry.hivescan`
- `windows.handles`

### Windows process inspection

Process trees, command lines, DLLs, handles, privileges and virtual memory mappings. Supports PID filtering where available.

Framework: Volatility 3.

- `windows.pslist`
- `windows.pstree`
- `windows.cmdline`
- `windows.dlllist`
- `windows.handles`
- `windows.privileges`
- `windows.envars`
- `windows.vadinfo`
- `windows.memmap`

### Linux triage

Processes, command history, open files, sockets and kernel modules. Requires matching Linux symbols.

Framework: Volatility 3.

- `linux.pslist`
- `linux.pstree`
- `linux.bash`
- `linux.lsof`
- `linux.sockstat`
- `linux.lsmod`
- `linux.kmsg`

### Linux rootkit hunt

Hidden modules, syscall and tracing hooks, fileless processes, injected code and eBPF objects.

Framework: Volatility 3.

- `linux.check_ftrace`
- `linux.check_tracepoints`
- `linux.check_unlinked_modules`
- `linux.check_seqops`
- `linux.fileless`
- `linux.bpf_listprogs`
- `linux.bpf_listmaps`
- `linux.bpf_listlinks`
- `linux.bpf_listprocs`
- `linux.bpf_lsm`
- `linux.malware.hidden_modules`
- `linux.malware.check_syscall`
- `linux.malware.check_modules`
- `linux.malware.malfind`
- `linux.malware.netfilter`

### Linux process and network investigation

Process ancestry, executable mappings, open files, sockets and network interfaces.

Framework: Volatility 3.

- `linux.pslist`
- `linux.pstree`
- `linux.psaux`
- `linux.elfs`
- `linux.library_list`
- `linux.lsof`
- `linux.sockstat`
- `linux.ip.Addr`
- `linux.ip.Link`

### Linux user activity

Shell history, process arguments, environment variables and open files.

Framework: Volatility 3.

- `linux.bash`
- `linux.psaux`
- `linux.envars`
- `linux.lsof`

### Linux GPG credentials

Recover supported gpg-agent cache entries and passphrases. Output may contain secrets.

Framework: Volatility 3.

- `linux.gpg_full`
- `linux.gpg_partial`

### Utilities and diagnostics

Inspect framework components, symbol files and image banners. No bulk exports or interactive shells.

Framework: Volatility 3.

- `frameworkinfo.FrameworkInfo`
- `isfinfo.IsfInfo`
- `banners.Banners`

### Windows legacy triage (Volatility 2)

Requires a supported Volatility 2 profile.
- `pslist`, `pstree`, `psscan`, `cmdline`, `netscan`, `svcscan`

## Curation decisions

- Split mixed Windows/Linux activity and credential selections.
- Replace Quick triage with Windows triage; runtime is not guaranteed to be short.
- Replace C2 & implants with remote access indicators; the selected plugins do not cover every implant or C2 system.
- Add list-based baselines alongside scan-based discovery for comparison.
- Use current registry credential names rather than selecting both current and deprecated aliases.
- Match whole modules or exact classes within one framework. For example, MFTScan does not implicitly select ResidentData.
- Exclude interactive shells, image modification, converters, and bulk dumpers from automatic presets. These remain in the catalog when installed.
- Exclude generic YARA/regex scanners from these presets because they require extra input. Select them explicitly after configuring the needed arguments.
- The app currently passes PID and YARA file arguments, not every specialized plugin option. Catalog visibility does not guarantee unattended compatibility.

## Validation

All module/class entries in the Volatility 3 presets resolved against the installed catalog during this review. Declared requirements were inspected; no additional mandatory scalar or list arguments were found for these entries. This does not verify plugin execution against every image or guarantee that all version dependencies are satisfied. Volatility 2 selections use exact legacy command names and are tested separately from Volatility 3 matching.
