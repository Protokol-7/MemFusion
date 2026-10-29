# MemFusion

Memory forensics toolkit for Windows and Linux memory images, running on Windows.

MemFusion brings Volatility 3, Volatility 2, MemProcFS, MemNixFS, and MemProcFS-Analyzer into one desktop application. It installs the tools, helps analysts select plugins, runs analysis in sequence, and saves results and diagnostic logs to a chosen output folder. The external tools perform the memory analysis; MemFusion coordinates them.

## Features

- Install dependencies and update tools from the interface.
- Analyze Windows and Linux memory images with automatic OS detection and a manual override.
- Search and filter Volatility plugins, use investigation presets, and save custom selections.
- Apply a PID filter to plugins that support it.
- Find matching Linux symbols or generate them from a kernel debug package.
- Run Windows YARA scanning and Analyzer's Sigma detection through Zircolite.
- Follow progress and inspect per-tool diagnostic logs.
- Keep the Windows memory filesystem mounted after analysis for browsing and copying artifacts.
- Save an analysis record containing case details and the image SHA-256.

## Requirements

- Windows x64 and Microsoft Edge WebView2 Runtime.
- Internet access for tool installation, updates, and online symbol downloads.
- Sufficient RAM and disk space for the image and selected analysis tools.
- Permission to install system dependencies when Windows requests elevation.

MemFusion analyzes existing memory images. It does not acquire memory. Linux images can be analyzed from Windows; the GUI itself is Windows-only.

## Getting started

Use a packaged Windows build if one is available under this repository's **Releases**, or [build from source](#building-from-source).

1. Extract the package. Keep `custom_plugins` and `custom_plugins_vol2` beside `MemFusion.exe`.
2. Start `MemFusion.exe` and open **Evidence & tools**.
3. Click **Install dependencies**, then **Install / update tools**. Wait for each to finish and review any errors.
4. Select the memory image and a new output folder. Enter the case and analyst details if required.
5. Choose Volatility plugins or a preset. Leave the selection empty to run the filesystem tool only, with Analyzer if enabled.
6. Open **Run analysis** and click **Start run**.
7. Use **Open output folder** to inspect the saved files.

Tools are installed per Windows user under `%LOCALAPPDATA%\memforensics-gui\tools`. The legacy folder name is retained for compatibility. Tools, symbol downloads, and Sigma rules are installed separately from the application executable.

## Analysis order

Main stages and individual Volatility plugins run sequentially to limit memory pressure. Unselected Volatility stages are skipped.

| Image | Order |
| --- | --- |
| Windows | Volatility 2 → Volatility 3 → MemProcFS → MemProcFS-Analyzer, if enabled |
| Linux | Symbol resolution → selected Volatility stages → MemNixFS export |

For Windows, the mount stays open after analysis until you unmount it or close MemFusion, provided the MemProcFS process remains running. Copy required files before unmounting. Analyzer does not export the entire mount. Release the mount before another run or tool update.

Linux uses export mode and saves the `/sys` and `/forensic` subtrees. It does not retain a Linux mount. Volatility 3 is the recommended framework for Linux; legacy Volatility 2 requires a compatible profile.

## Tools and detections

| Tool | Purpose |
| --- | --- |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Memory-analysis plugins for supported operating systems |
| [Volatility 2](https://github.com/volatilityfoundation/volatility) | Optional legacy plugins |
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Windows memory filesystem and forensic scan |
| [MemNixFS](https://github.com/MemNixFS/MemNixFS) | Linux system and forensic exports |
| [MemProcFS-Analyzer](https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer) | Additional analysis of the Windows mount |
| [Zircolite](https://github.com/wagga40/Zircolite) | Sigma detection against recovered Windows event logs |
| [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) | Linux kernel symbol generation |

Generic Volatility YARA plugins use the rules file selected in the interface. MemProcFS is started with `-license-accept-elastic-license-2-0` to enable its built-in Elastic rules under that license.

Analyzer uses Zircolite's `rules_windows_generic.json`, downloaded during setup and refreshed by **Install / update tools**. The compiled rules come from [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), which derives rules from [SigmaHQ](https://github.com/SigmaHQ/sigma). Sigma detection depends on recoverable event logs; it is not a direct scan of raw memory.

## Symbols, results, and logs

Place matching Linux ISF files in:

```text
%LOCALAPPDATA%\memforensics-gui\tools\volatility3-symbols\linux\
```

Symbols must match the image's exact kernel build. Automatic lookup cannot cover every kernel. The [user guide](docs/USER_GUIDE.md#symbols) describes symbol downloads and generation.

The selected output folder contains plugin reports, nested tool output, `debug-logs`, and a `custody-<id>\CHAIN_OF_CUSTODY.txt` record. The Results page summarizes top-level output; use the output folder for nested artifacts. Debug logs are generated by packaged builds too, without source code or development tools.

The custody record documents the analysis session and image hash. It does not replace acquisition records or custody-transfer documentation. No output manifest is generated.

## Building from source

Build on Windows with Go 1.25 or a compatible later version, Node.js compatible with Vite 7, npm, and Wails v2.15.0.

```powershell
git clone https://github.com/Protokol-7/MemFusion.git
Set-Location MemFusion
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
wails doctor
wails build -platform windows/amd64
```

The executable is written to `build/bin/MemFusion.exe`. Wails builds the frontend and regenerates the Go/TypeScript bindings. `go build ./...` alone does not produce the packaged desktop application.

Development checks:

```powershell
go build ./...
go vet ./...
go test ./...
Push-Location frontend
npm ci
npm run build
Pop-Location
```

For a distributable ZIP, include the executable and both custom plugin folders, preserving their directory structure and attribution. Do not include memory images, case output, installed tool environments, or private logs. See [publishing instructions](docs/PUBLISHING.md).

## Documentation

- [User guide](docs/USER_GUIDE.md): setup, workflow, symbols, detections, logs, and troubleshooting
- [Plugin presets](docs/PRESETS.md)
- [Interface reference](docs/INTERFACE.md)
- [Custom plugin maintenance](custom_plugins/README.md)
- [GitHub publishing and releases](docs/PUBLISHING.md)

## Reporting problems

Include the app and affected tool versions, image OS, selected plugins, failure stage, and relevant excerpts from `<output folder>\debug-logs`. For Analyzer failures, include its transcript. Remove case identifiers, recovered data, and credentials before sharing logs. Do not upload memory images to public issues.

Tool support, symbol availability, and recoverable artifacts vary by image. Empty output or no detection matches does not establish that an image is clean.

## Licensing

External tools, detection rules, and vendored plugins retain their respective licenses. Preserve their notices and review their redistribution terms.

No top-level application license has been selected yet. This README does not grant a license or override third-party terms.
