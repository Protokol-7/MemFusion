package volatility

import "strings"

// PID-capable plugin names were generated from the installed Volatility
// 3.2.28 requirement objects (scripts/audit_vol3_pid.py) and from each
// Volatility 2.6 plugin's -h output. Every entry currently exposes PID as an
// optional filter rather than a mandatory argument.
var pidCapableVol3 = nameSet(`
cobaltstrike.CobaltStrike docker.mount.Mount docker.pslist.PsList docker.pstree.PsTree
keepass.KeePass linux.bash.Bash linux.capabilities.Capabilities linux.elfs.Elfs
linux.envars.Envars linux.gpg_full.GPGItem linux.gpg_partial.GPGPassphrase linux.inodes.Inodes
linux.library_list.LibraryList linux.lsof.Lsof linux.malfind.Malfind linux.malware.malfind.Malfind
linux.malware.process_spoofing.ProcessSpoofing linux.mountinfo.MountInfo linux.proc.Maps
linux.psaux.PsAux linux.pscallstack.PsCallStack linux.pslist.PsList linux.pstree.PsTree
linux.sockstat.Sockstat linux.vmaregexscan.VmaRegExScan linux.vmayarascan.VmaYaraScan
mac.bash.Bash mac.kevents.Kevents mac.lsof.Lsof mac.malfind.Malfind mac.netstat.Netstat
mac.proc_maps.Maps mac.psaux.Psaux mac.pslist.PsList openssh_sessionkeys.SSHKeys
richheader.RichHeader windows.apisearch.ApiSearch windows.cmdline.CmdLine
windows.directsyscalls.DirectSyscalls windows.dlllist.DllList windows.dumpcerts.Dumpcerts
windows.dumpfiles.DumpFiles windows.envars.Envars windows.etwpatch.EtwPatch
windows.getsids.GetSIDs windows.handles.Handles windows.hollowprocesses.HollowProcesses
windows.iat.IAT windows.imgmalfind.ImageMalfind windows.ldrmodules.LdrModules
windows.listpackers.ListPackers windows.malfind.Malfind windows.malware.hollowprocesses.HollowProcesses
windows.malware.ldrmodules.LdrModules windows.malware.malfind.Malfind
windows.malware.pebmasquerade.PebMasquerade windows.malware.suspicious_threads.SuspiciousThreads
windows.masqueradeprocess.MasqueradeProcess windows.memmap.Memmap windows.notepad.Notepad
windows.passwordmanagers.PasswordManager windows.pedump.PEDump windows.privileges.Privs
windows.pslist.PsList windows.psscan.PsScan windows.pstree.PsTree windows.pte_resolve.PteResolve
windows.ptemalfind.PteMalfind windows.sessions.Sessions windows.simple_pteenum.SimplePteEnumerator
windows.strings.Strings windows.suspicious_threads.SuspiciousThreads windows.swap_enum.SwapEnumerator
windows.symcrypt.Symcrypt windows.vadinfo.VadInfo windows.vadregexscan.VadRegExScan
windows.vadwalk.VadWalk windows.vadyarascan.VadYaraScan
`)

var pidCapableVol2 = nameSet(`
agtidconfig apihooks apt17scan cmdline derusbiconfig dlldump dlllist dumpcerts dumpfiles
editbox envars getsids handles hikitconfig hollowfind iehistory impscan joblinks ldrmodules
linux_apihooks linux_bash linux_bash_env linux_bash_hash linux_check_creds linux_dump_map
linux_dynamic_env linux_elfs linux_getcwd linux_info_regs linux_ldrmodules linux_library_list
linux_librarydump linux_lsof linux_malfind linux_memmap linux_netstat linux_pidhashtable
linux_pkt_queues linux_plthook linux_proc_maps linux_proc_maps_rb linux_procdump
linux_process_hollow linux_psaux linux_psenv linux_pslist linux_pslist_cache linux_pstree
linux_strings linux_threads linux_truecrypt_passphrase linux_volshell linux_yarascan
mac_adium mac_apihooks mac_bash mac_bash_env mac_bash_hash mac_calendar mac_contacts
mac_dead_procs mac_dead_sockets mac_dead_vnodes mac_dump_maps mac_dyld_maps mac_keychaindump
mac_ldrmodules mac_librarydump mac_list_sessions mac_lsof mac_malfind mac_memdump mac_netstat
mac_notesapp mac_orphan_threads mac_pgrp_hash_table mac_pid_hash_table mac_proc_maps
mac_procdump mac_psaux mac_psenv mac_pslist mac_pstree mac_strings mac_tasks mac_threads
mac_threads_simple mac_volshell mac_yarascan malfind memdump memmap notepad powersh privs
procdump psempire psinfo pslist strings threadmap threads userhandles vaddump vadinfo
vadtree vadwalk volshell yarascan
`)

var yaraRulePlugins = nameSet(`
yarascan.YaraScan windows.vadyarascan.VadYaraScan linux.vmayarascan.VmaYaraScan
yarascan linux_yarascan mac_yarascan
`)

func nameSet(names string) map[string]bool {
	set := make(map[string]bool)
	for _, name := range strings.Fields(names) {
		set[name] = true
	}
	return set
}

func annotateTargeting(plugins []Plugin) {
	for i := range plugins {
		if plugins[i].Framework == FrameworkVol2 {
			plugins[i].SupportsPID = pidCapableVol2[plugins[i].Name]
		} else {
			plugins[i].SupportsPID = pidCapableVol3[plugins[i].Name]
		}
		plugins[i].RequiresYaraRules = yaraRulePlugins[plugins[i].Name]
	}
}

// SupportsPID and RequiresYaraRules are also used by runners, where only the
// plugin name/framework is available.
func SupportsPID(framework, name string) bool {
	if framework == FrameworkVol2 {
		return pidCapableVol2[name]
	}
	return pidCapableVol3[name]
}

func RequiresYaraRules(name string) bool { return yaraRulePlugins[name] }
