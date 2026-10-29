# Custom Volatility 3 plugins

> ### ⚠ After upgrading Volatility 3, run `scripts/patch_plugins_for_vol3.py`
>
> Most of these plugins were written against vol3 ~2.0–2.5. Core plugins get **major** version
> bumps, and vol3 treats the major component as a hard compatibility barrier — the plugin is then
> refused outright:
>
> ```
> Unsatisfied requirement plugins.CobaltStrike.pslist:
> Version 2.0.0 dependency on volatility3.plugins.windows.pslist.PsList unmet
> ```
>
> Worse, **vol3 exits 0 when this happens** and writes the refusal into the output file, so an
> unpatched plugin looks like it succeeded until you open the CSV. (The app now detects this and
> reports the plugin as failed.)
>
> The bumps are not cosmetic — signatures change with them, e.g.
> `list_processes(context, layer_name, symbol_table, filter_func)` →
> `list_processes(context, kernel_module_name, filter_func)`. Fixing the version without the call
> site converts a clean refusal into a `TypeError`, so the script does both.
>
> ```bash
> # dry run — exits 1 if anything needs changing
> <vol3-python> scripts/patch_plugins_for_vol3.py --check
> # apply, then re-copy to ~/.local/share/memforensics-gui/plugins/
> <vol3-python> scripts/patch_plugins_for_vol3.py
> ```
>
> Run it with the interpreter that has volatility3 installed (for a pipx install:
> `~/.local/share/pipx/venvs/volatility3/bin/python`), since it reads the *installed* versions
> rather than hardcoding them.


Community plugins vendored into this app because they fill gaps MemProcFS's
forensic mount has no module for. The app passes these directories to vol
via `-p` (see `internal/volatility/plugindirs.go`); at runtime it looks in
`~/.local/share/memforensics-gui/plugins` first, then in `custom_plugins/`
next to the executable. To install/update: copy this directory's `.py`
files into `~/.local/share/memforensics-gui/plugins/`.

Every file was source-reviewed before vendoring (small, single-file, pure
memory-parsing code; no network, exec, or filesystem access beyond
vol-managed output) and load-tested against Volatility 3 Framework 2.28.0
on Python 3.14. Pinned at the commit fetched 2026-08-24.

| Plugin | What it does / gap it fills | Author / source | License |
|---|---|---|---|
| `cobaltstrike.py` | Scans process memory for Cobalt Strike beacon config blocks and decodes them (C2 server, ports, pipe names, sleep/jitter, spawnto…). Needs `yara-python` in the vol environment. | Kevin Breen, [Immersive-Labs-Sec/volatility_plugins](https://github.com/Immersive-Labs-Sec/volatility_plugins) | MIT |
| `richheader.py` | Recovers PE Rich headers from running processes and computes the Rich Header Hash (malware attribution/pivoting). | Kevin Breen, [Immersive-Labs-Sec/volatility_plugins](https://github.com/Immersive-Labs-Sec/volatility_plugins) | MIT |
| `anydesk.py` | Recovers and parses AnyDesk `ad.trace` / `ad_svc.trace` logs from memory — RMM-abuse evidence MemProcFS doesn't decode. | Félix Guyard (forensicxlab, VolWeb author), [forensicxlab/volatility3_plugins](https://github.com/forensicxlab/volatility3_plugins) | none stated (personal/local use) |
| `keepass.py` | Sweeps a KeePass process for the master-password composition left in memory. **Patched locally**: `--pid` is now optional (defaults to processes named like KeePass) so it can run from this GUI. Slow; not pre-checked by default. | Félix Guyard (forensicxlab), [forensicxlab/volatility3_plugins](https://github.com/forensicxlab/volatility3_plugins) | none stated (personal/local use) |
| `openssh_sessionkeys.py` | Recovers OpenSSH session keys from sshd processes (Linux images) for decrypting captured SSH traffic. Featured in the official [community3](https://github.com/volatilityfoundation/community3) repo (Vergeer_OpenSSH). | Fox-IT / NCC Group, [fox-it/OpenSSH-Session-Key-Recovery](https://github.com/fox-it/OpenSSH-Session-Key-Recovery) | Apache-2.0 |

## `windows/` subfolder — Frank Block's PTE plugins (vol3)

Source: [f-block/volatility-plugins](https://github.com/f-block/volatility-plugins) (ERNW), added
2026-08-24. **They must stay in the `windows/` subfolder**: they import each other as
`from volatility3.plugins.windows.ptenum import …`, so a flat layout breaks them. Needs `pefile`
and `future` in the vol3 environment (both injected via pipx).

| Plugin | What it does |
|---|---|
| `ptemalfind.py` | Injection detection via **page-table entries** rather than VAD permissions — finds executable private memory that `malfind` misses. **Recommended by default.** |
| `imgmalfind.py` | Finds in-place patches to mapped image files (DLL/EXE) — i.e. `EtwEventWrite`/`AmsiScanBuffer`-style inline hooks. Has an allow-listing mechanism for legitimate AV/EDR hooks. **Recommended by default.** |
| `apisearch.py` | Locates API functions in process memory (needs `pefile`). |
| `pte_resolve.py`, `simple_pteenum.py`, `swap_enum.py` | PTE/swap enumeration helpers. |
| `ptenum.py`, `pe_parser.py` | Library modules, not plugins — imported by the above, so they register no command of their own. |

## Additional Volatility 3 community plugins (added 2026-08-24)

Sourced from [daddycocoaman/volplugins](https://github.com/daddycocoaman/volplugins),
[spitfirerxf/vol3-plugins](https://github.com/spitfirerxf/vol3-plugins),
[its5Q/volatility3-plugins](https://github.com/its5Q/volatility3-plugins),
[kudelskisecurity/volatility-gpg](https://github.com/kudelskisecurity/volatility-gpg) and
[forensicxlab](https://github.com/forensicxlab/volatility3_plugins). All were scanned for
network/exec/eval before vendoring and verified to register in vol3 2.28.0.

### `windows/` — credential & secret extraction (recommended by default)
| Plugin | What it does |
|---|---|
| `pypykatz.py` | lsass credential extraction via pypykatz — the memory equivalent of mimikatz. Needs the `pypykatz` module. |
| `symcrypt.py` + `dumpcerts.py` | RSA keys/certificates from Windows' SymCrypt library. **`dumpcerts.py` is patched locally**: `cryptography` ≥40 renamed `PRIVATE_KEY_TYPES` to `PrivateKeyTypes`, so it is imported under an alias — without this both plugins fail to load. |
| `notepad.py` | Recovers displayed text from open Notepad processes — unsaved content nothing else recovers. |

### `windows/` — other artifacts (installed, not recommended by default)
| Plugin | Why not default |
|---|---|
| `prefetch.py` | Flagged **covered by MemProcFS** (`forensic/prefetch` + `timeline_prefetch.csv`). Useful when running vol3 without a mount. |
| `evtxlog.py` | Flagged **covered by MemProcFS** (`misc/eventlog/*.evtx`, which the Analyzer parses with EvtxECmd). |
| `sticky.py` | Sticky Notes recovery. Registers under the unhelpful upstream class name `MyFirstPlugin`. |
| `kusertime.py` | Parses KUSER_SHARED_DATA timestamps — narrow. |

### `linux/`
| Plugin | What it does |
|---|---|
| `gpg_full.py`, `gpg_partial.py` | Recover full/partial GPG passphrases from gpg-agent's cache (Kudelski Security). Recommended — MemNixFS has no equivalent. |
| `inodes.py` | Inode metadata for all processes (forensicxlab). |

## From awesome-volatility's index (added 2026-08-24, round 7)

[ZarKyo/awesome-volatility](https://github.com/ZarKyo/awesome-volatility) is a link index rather
than a plugin repo; working through its Volatility 3 section surfaced these. All scanned and
load-verified as above.

### `windows/` — persistence & modern evasion detection (recommended by default)
| Plugin | What it does |
|---|---|
| `autorun.py` | Auto-Start Extensibility Points (ASEPs) mapped to running processes ([Telindus-CSIRT](https://github.com/Telindus-CSIRT/volatility3-autoruns)). Nothing in MemProcFS's export decodes persistence, and the Analyzer's RECmd pass is Windows-host-only — a gap on both fronts. |
| `directsyscalls.py` | Detects direct syscall stubs used to bypass a hooked ntdll ([memoryforensics1](https://github.com/memoryforensics1/Volatility.PE-Shellcode)). |
| `masqueradeprocess.py` | Processes whose PE original-name disagrees with their image name. |
| `listpackers.py` | Identifies packed executables in memory. |

### `windows/` — other (installed, not default)
`passwordmanagers.py` (password-manager secrets, kevthehermit), `zoneid3.py` (Zone.Identifier ADS
streams — mark-of-the-web provenance).

### `linux/` — rootkit detection (recommended by default)
MemNixFS's `/sys/findevil` covers psscan / malfind / hidden modules, but **not** these techniques,
so they are complementary rather than duplicates:

| Plugin | What it does |
|---|---|
| `check_ftrace.py`, `check_tracepoints.py`, `check_unlinked_modules.py` | ftrace hooks, tracepoint hooks and unlinked kernel modules ([Abyss-W4tcher](https://github.com/Abyss-W4tcher/volatility-scripts), Volatility 2023 contest). |
| `check_seqops.py`, `fileless.py` | seq_ops hooking and fileless (memfd-backed) processes ([AsafEitani](https://github.com/AsafEitani/rootkit_plugins)). |
| `ebpf_programs.py` | Enumerates loaded eBPF programs ([AsafEitani](https://github.com/AsafEitani/ebpf_programs_plugin)) — MemNixFS's `ebpf.txt` is findevil-filtered, this lists all. |

### `linux/bpf_*.py` + `linux/bpfutil/` — BPFVol3 eBPF suite (recommended by default)

[vobst/BPFVol3](https://github.com/vobst/BPFVol3) (MIT, Valentin Obst). eBPF is now a mainstream
Linux implant technique, and neither MemNixFS's findevil pass nor vol3's built-in `linux.ebpf`
gives this depth: `bpf_listprogs` (loaded programs, with disassembly), `bpf_listmaps`,
`bpf_listlinks`, `bpf_listprocs` (which processes own them) and `bpf_lsm` (LSM hooks).
Extra deps: `capstone`, `networkx` (for `bpf_graph`).

**Locally restructured — do not "tidy" this away.** Upstream expects you to copy its `src/utility`
into `${VOLHOME}/volatility3/utility/` *and* `git apply` a patch to vol3's own source. Neither is
acceptable here: the patch targets vol3 v2.4.2/v2.5.0 and **fails on all three hunks against 2.28.0**
(verified), and injecting a package into the vol3 install would be silently erased by any vol3
upgrade. Instead the helper package is vendored as `linux/bpfutil/` and every
`volatility3.utility.*` import was rewritten to `volatility3.plugins.linux.bpfutil.*` — which works
because plugin directories *are* importable as `volatility3.plugins.*`. 22 references across 12 files.

Two plugins from that repo are **not** shipped: `bpf_netdev` and `ifconfig` need a `net_device`
extension that only the source patch adds.

### `docker/` — container forensics
`pslist.py`, `pstree.py`, `mount.py` from
[amir9339/volatility-docker](https://github.com/amir9339/volatility-docker) — container-aware
process/mount/network views, registering as `docker.*`.
**Not shipped from that repo**: `docker.py` and `file.py` (plus AsafEitani's `check_fops.py`) import
`volatility3.plugins.linux.file`/`.mount`, modules that exist only if you apply that project's
patches to vol3's own source tree. This app loads plugins via `-p` and does not patch vol3, so
those three cannot work here. **`ifconfig.py` removed for the same reason** (2026-08-24): it
references `symbols.linux.extensions.net_device`, a type this project's own patch adds — without
it the reference is a plain `AttributeError` at import time. Unlike a missing dependency
(`ImportError`, which vol3's plugin loader catches and reports as "could not be loaded"),
`AttributeError` is not caught there, so this one file crashed vol3's *entire* `-h` scan and
silently took every other custom plugin down with it.

### Rejected from these repos
- **`multiyara.py`** (community3, Silva) — calls `pygit2.clone_repository()` at runtime to fetch YARA
  rules from five remote GitHub repos. The sources are reputable, but a plugin that performs network
  fetches during evidence analysis is wrong for a tool that auto-runs plugins, and it fails outright
  on an air-gapped workstation. Not shipped.
- **`evtx.py`** (community3, Stelte) — imports the pre-release `volatility.framework` namespace
  (does not exist in vol3 2.x) **and** `requests`. Dead on arrival and network-capable; use
  `evtxlog.py` instead.
- **Hyper-V set** (community3, Gerhart: `hyperv.py`/`hvlib.py`/`stacker.py`) — needs `hvlib`
  importable as a **top-level** module plus registration as a layer stacker, which means installing
  into site-packages rather than a plugin dir. Too invasive for this app's `-p` mechanism.

Considered and rejected:

- **check_spoof** (community3, Chechik/Weber) — written against the pre-1.0
  `volatility.framework` API; does not import on vol3 2.28. PEB spoofing is
  covered by core `windows.malware.pebmasquerade` anyway.
- **forensicxlab `prefetch.py`**, **Stelte_Evtx**, browser-history plugins —
  their output is already covered by the MemProcFS mount (forensic/prefetch,
  misc/eventlog, forensic/web).
