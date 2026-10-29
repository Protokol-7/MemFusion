# Custom Volatility 2 plugins

Community plugins for **Volatility 2**, loaded by passing this directory to vol2 via
`--plugins=<dir>` (a different flag and separator from vol3's `-p a;b`). The app looks in
`~/.local/share/memforensics-gui/plugins-vol2` first, then `custom_plugins_vol2/` next to the
executable; override with `$MEMFORENSICS_VOL2_PLUGIN_DIRS`.

To install/update: copy these `.py` files into `~/.local/share/memforensics-gui/plugins-vol2/`.

All sourced from [volatilityfoundation/community](https://github.com/volatilityfoundation/community),
fetched 2026-08-24. Every file was scanned for network access, process execution, `eval`/`exec`,
and file deletion before being vendored, then **verified to actually register** in the frozen
`volatility_2.6_lin64_standalone` build — Volatility 2 silently skips plugins whose imports fail,
so "it's in the folder" does not mean "it works".

## Injection / malicious-process detection
| Plugin | What it does |
|---|---|
| `hollowfind.py` | Detects several process-hollowing variants (Monnappa K A). |
| `malfofind.py` | Finds hollowing / RunPE injection indicators (Dima Pshoul). |
| `malprocfind.py` | Flags processes deviating from known-good Windows behaviour — path, parent, priority, session, SID (Csaba Barta). |
| `psinfo.py` | Process detail plus suspicious memory regions (Monnappa K A). |
| `threadmap.py` | Correlates thread properties against their VAD properties (KSL Group). |

## Execution, persistence, and host artifacts
| Plugin | What it does |
|---|---|
| `psempire.py` | Detects PowerShell Empire — directly relevant to Empire-infected images. |
| `powersh.py` | Identifies PowerShell processes and extracts interesting strings. |
| `autoruns.py` | ASEP persistence points mapped to running processes (Thomas Chopitea). |
| `shimcachemem.py` | AppCompat Shim Cache parsed from **kernel memory** (not the hive). |
| `prefetch.py` | Scans for and parses Prefetch files (registers as `prefetchparser`). |
| `schtasks.py` | Parses scheduled task `.JOB` files (Bartosz Inglot). |
| `usnparser.py` | USN journal records. |
| `usbstor.py` | USB device history from the registry. |
| `trustrecords.py` | MS Office TrustRecords ("Enable Content" clicks) — useful for maldoc entry points. |
| `uninstallinfo.py` | Installed software from the Uninstall registry key. |
| `idxparser.py` | Java IDX files. |
| `ndispktscan.py` | Extracts network packets from memory. |
| `bitlocker.py` | Extracts BitLocker FVEK (Windows 7–10). |
| `sqlite_help.py` | Helper library imported by other plugins; registers no command of its own. |

## Deliberately excluded

- **`openioc_scan.py` — rejected on security grounds.** It calls `eval()` on strings built from
  user-supplied IOC XML documents (lines ~1655/1664/1784 upstream). A malicious `.ioc` file would
  therefore execute arbitrary Python. In a tool that runs plugins automatically that is an
  unacceptable default, regardless of the plugin's otherwise good reputation.
- **`mimikatz.py`** — needs `construct`, which the frozen standalone does not bundle; never registers.
- **`chromehistory.py`** — needs `Crypto.Protocol.KDF`; not bundled.
- **`firefoxhistory.py`, `filevault2.py`, `indx.py`** — verified not to register in the standalone build.

If you install Volatility 2 from source (rather than the standalone) and add the missing Python
modules, these become usable — drop them into the plugins directory and they'll appear automatically.

## Note on Linux

Volatility 2's `linux_*` plugins are hidden by the app. Vol2 needs a per-kernel profile `.zip`
built from the target kernel's headers, and `imageinfo` only suggests profiles for Windows images —
so this app cannot invoke them at all. Use the Volatility 3 `linux.*` plugins or MemNixFS instead.
