# MemFusion

A Windows desktop application for analyzing memory images with Volatility 3, Volatility 2, MemProcFS, MemNixFS, and MemProcFS-Analyzer.

MemFusion installs and coordinates external forensic tools. It helps select plugins, resolves Linux symbols, runs analysis in sequence, and collects results and debugging information. The underlying tools perform the memory analysis.

## Contents

- [Features](#features)
- [Supported tools](#supported-tools)
- [Requirements](#requirements)
- [Installation](#installation)
- [Analysis workflow](#analysis-workflow)
- [Plugin selection](#plugin-selection)
- [Symbols](#symbols)
- [YARA and Sigma](#yara-and-sigma)
- [Results and logs](#results-and-logs)
- [Updating tools](#updating-tools)
- [Troubleshooting](#troubleshooting)
- [Building from source](#building-from-source)
- [Sharing a build](#sharing-a-build)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Licensing](#licensing)

## Features

- Install dependencies and tools from the GUI.
- Analyze Windows and Linux memory images from a Windows host.
- Detect the image OS, with a manual override.
- Run tools and plugins sequentially to limit concurrent memory use.
- Select plugins by operating system, framework, preset, or search.
- Filter plugins that overlap with MemProcFS output.
- Apply a process ID to plugins that support PID filtering.
- Resolve Linux symbols locally or through community indexes.
- Generate Linux symbols from supported kernel debug packages.
- Run Analyzer's event-log detection using Zircolite and Sigma rules.
- Show live activity, tool status, plugin outcomes, and console output.
- Save debugging logs and a separate chain-of-custody analysis record.
- Use Classic, Midnight, Black, or Light themes.

## Supported tools

| Tool | Role in the application |
| --- | --- |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Plugin-based memory analysis, including Windows and Linux plugins |
| [Volatility 2](https://github.com/volatilityfoundation/volatility) | Optional legacy plugins and profile-based analysis |
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Windows memory reconstruction, forensic scanning, and a temporary virtual filesystem |
| [MemNixFS](https://github.com/MemNixFS/MemNixFS) | Linux memory reconstruction and export of system and forensic data |
| [MemProcFS-Analyzer](https://github.com/LETHAL-FORENSICS/MemProcFS-Analyzer) | Optional Windows analysis using the live MemProcFS mount and supporting tools |
| [Zircolite](https://github.com/wagga40/Zircolite) | Sigma-based detection over event logs recovered by Analyzer |
| [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) | Linux symbol generation from a debug kernel ELF |

The application does not acquire memory. Supply an existing memory image supported by the tools you intend to use. Support for a filename extension alone does not guarantee that its contents can be analyzed.

## Requirements

- A Windows x64 host. This build does not support running the GUI on Linux or macOS.
- Microsoft Edge WebView2 Runtime for the Wails desktop interface.
- Enough RAM and free disk space for the image, tool installations, and extracted output. Requirements vary with image size and selected plugins.
- Internet access for initial setup and updates. Online symbol resolution also requires internet access.
- Permission to install system components when Windows requests elevation.

The dependency installer prepares an application-owned Python environment and attempts to install system components such as Dokany and the .NET runtime. Dokany is used by MemProcFS. Analyzer's supporting parsers require .NET. The installer also offers optional components; 7-Zip is needed for the Linux debug-package extraction workflow.

The installer also lists ClamAV as optional. The mounted Analyzer workflow used by this application does not run the upstream ClamAV scan stage.

The current MemNixFS integration uses export mode, not a mounted Linux filesystem. It does not require a filesystem driver for that mode.

## Installation

1. Extract the application package into a writable folder.
2. Keep `custom_plugins` and `custom_plugins_vol2` beside `MemFusion.exe` if supplied with the package.
3. Launch `MemFusion.exe`.
4. In **Tool setup**, click **Install dependencies** and wait for completion.
5. Click **Install / update tools** and wait for completion.
6. Review any installation errors before starting analysis. Installed executable paths are filled in automatically.

These two buttons are the normal setup route. A manual Python or Zircolite installation is not required when automatic setup succeeds. Downloads can fail because of network restrictions, upstream service limits, or Windows permissions. An installer may also require a restart.

| Button | Installs or verifies |
| --- | --- |
| Install dependencies | Compatible Python and the app environment, Volatility plugin packages, Dokany, .NET Desktop Runtime, 7-Zip, optional ClamAV, and bulk symbol packs |
| Install / update tools | Volatility 2/3, MemProcFS, MemNixFS, Analyzer and its helper tools, ImportExcel, the separate Zircolite environment, compiled Sigma rules, YARA rules, and dwarf2json |

Setup verifies Python imports and package compatibility. Analyzer setup checks its helper files, including standalone YARA and the LNK parser. Missing optional packages and failed symbol downloads are included in the installation summary. An existing Analyzer installation can still be repaired when its release check fails, although the update failure remains visible.

Exact Linux kernel symbols depend on the memory image. The app searches for matching symbols during analysis; kernels absent from the available indexes require a matching ISF or debug package. Custom YARA rules and plugin-specific inputs must also be supplied by the analyst. ClamAV is optional and is not used by the mounted Analyzer workflow.

### Installed locations

Tools are installed per user under the existing directory name for compatibility:

```text
%LOCALAPPDATA%\memforensics-gui\tools\
```

Important directories include:

```text
tools\
  python-env\                 Volatility 3 and plugin Python packages
  zircolite-env\              Separate Python environment for Zircolite
  volatility3-symbols\       Application-managed symbols
    linux\
  volatility2\
  MemProcFS\
  MemNixFS\
  MemProcFS-Analyzer\
  dwarf2json\
```

Archive extraction can introduce another directory level inside a tool folder. Use the executable paths shown in the GUI to locate the installed version.

Selections and configuration are remembered locally. MemFusion retains the legacy settings keys and WebView profile (`%APPDATA%\memforensics-gui.exe`) so existing installations keep their configuration. Tool installations belong to the current Windows account; another account normally needs its own setup.

## Analysis workflow

### 1. Evidence and configuration

- Enter the **Case / ticket** and **Analyst** fields for the final record.
- Select the **Memory image**.
- Select the image OS or use automatic detection. If detection fails, select the correct OS manually.
- Choose a dedicated **Output directory** for the run.
- Enable **MemProcFS-Analyzer** if you want its additional Windows analysis.
- Leave the Volatility 2 profile blank for automatic resolution, or supply a compatible profile.
- Set a YARA rules file if the selected generic YARA plugins require one.
- Click **Check tools and continue**.

Use a new output directory for each case or rerun. Some plugin output filenames are reused and can overwrite results from an earlier run in the same folder.

For shared memory images, use **Browse shared folder** or a UNC path such as `\\server\share\image.vmem`. Mapped drives can differ between normal and elevated Windows sessions.

### 2. Choose plugins

Open **Volatility plugins**. Start with **Use recommended** or preview a task-specific preset, then choose **Add to selection** or **Replace selection**. The selected list remains visible beside the catalog. An empty selection runs only MemProcFS or MemNixFS, with Analyzer when enabled. Selecting every available plugin can produce large output and substantially increase runtime.

### 3. Run analysis

Click **Start run**. The run order and progress area reflect the selected frameworks and image OS.

**Windows images:**

```text
Volatility 2, if plugins are selected
  -> Volatility 3, if plugins are selected
  -> MemProcFS scan
  -> MemProcFS-Analyzer, if enabled
  -> Mount remains open for browsing and copying files
```

**Linux images:**

```text
Linux symbol resolution
  -> Volatility 2, if selected and a usable profile is available
  -> Volatility 3, if plugins are selected
  -> MemNixFS export
```

MemProcFS and Analyzer are Windows-image stages. MemNixFS is the Linux-image stage. Volatility 3 is the practical default for Linux; the application does not generate legacy Volatility 2 Linux profiles.

Plugins within a framework run one at a time. The application avoids overlapping its main analysis phases to reduce memory pressure.

After Windows analysis, MemProcFS stays mounted until you click **Unmount** in Run analysis or Mounts, or close the app. **Open mount** opens it in Explorer. Copy minidumps and other required virtual files before unmounting; Analyzer does not export the entire mount. Results and the custody record finalize while the mount remains open. Unmount before starting another run or updating tools. Stop or Skip during the MemProcFS phase still closes that mount. Linux analysis uses export mode and does not retain a mount.

- **Skip current tool** stops the active phase and continues to the next phase.
- **Stop entire run** cancels the run. Existing output may be partial.
- The live console shows messages as tools produce them.
- Finalization computes the image SHA-256 and writes the analysis record. Hashing a large image can take time after the tools finish.

### 4. Results

Use **Results** to review output summaries and filter for findings or errors. Use **Open output folder** to inspect files in your preferred application. Clicking a result does not open the file.

The Results panel scans top-level CSV and text files. Nested Analyzer and MemNixFS output must be inspected in the output folder.

## Plugin selection

The catalog is discovered from the installed tools. Available plugins and counts can change after updates or dependency installation.

| Control | Purpose |
| --- | --- |
| Search | Match plugin names and descriptions |
| Category / Framework | Filter by OS category or Volatility version |
| Use recommended | Replace the selection with the curated starting set for the image OS |
| Select shown / Deselect shown | Change selection for visible plugins |
| Review selected | Show selected plugins, independent of catalog filters |
| Reset filters | Reset the view without clearing the selection |
| Clear selection | Deselect plugins |
| Preset | Preview a built-in or saved selection without applying it |
| Add to selection / Replace selection | Apply the previewed preset |
| Save selection / Delete preset | Manage named user selections |
| Undo | Restore the previous selection change |
| Supports PID | Show plugins that support process filtering |
| Plugin name | Show its description, inputs, availability, and overlap information |

The catalog shows available plugins for the image OS by default. Coverage is an explicit filter; plugins overlapping MemProcFS or Analyzer are not hidden by default. Use Availability to inspect unavailable plugins. Reset filters preserves your selection. Shift-click a checkbox to select a range of available rows. The selected list always shows the complete selection, including plugins outside the current filters. Empty selections, saved presets, and PID settings survive restart.

The workspace has separate Evidence & tools, Volatility plugins, Run analysis, Results, and Mounts pages. Switching pages preserves their state. Configuration and plugin editing are locked during a run; progress and logs remain active. Both installation buttons stay visible in Evidence & tools. Executable paths are under the expandable section in Tool setup.

Built-in presets cover Windows and Linux triage, injection, kernel checks, credentials, user activity, network investigation, process inspection, services, files, and diagnostics. See [Preset reference](PRESETS.md) for all 17 presets, their plugin selections, and curation decisions. A preset only includes matching loadable plugins.

### PID filtering

Enable **Target one process** and enter its PID. The PID applies only to selected plugins that support it. Other selected plugins still run without a PID filter. This is not a global restriction on every tool's analysis.

## Symbols

### Windows

Volatility 3 resolves Windows symbols through its own symbol mechanisms, including online retrieval when required. MemProcFS manages its own Windows symbol needs. Initial analysis of an unfamiliar build can require internet access.

### Linux

Linux symbols must match the kernel banner and build in the memory image. Matching only the distribution name or a similar kernel version is insufficient.

Place a Linux Intermediate Symbol Format (ISF) file in:

```text
%LOCALAPPDATA%\memforensics-gui\tools\volatility3-symbols\linux\
```

The application supports local JSON ISFs and compressed `.json.xz` files. Automatically downloaded compressed files can have a `.banner` sidecar used for later matching. Keep associated sidecars with their symbol files.

Use the application-managed symbols folder rather than the `volatility3\symbols` directory inside Python `site-packages`. The app passes its symbol directory to Volatility 3 and the resolved symbol file to MemNixFS.

When **Download missing Linux symbols** is enabled, local symbols are checked first, followed by community indexes configured in `internal/volatility/remoteisf.go`. These currently include the leludo84 Linux profiles index and the Abyss-W4tcher symbol collection. Coverage is not complete.

### Generate symbols from a debug package

If automatic lookup finds no exact match:

1. Obtain the debug package for the exact kernel build.
2. Expand **Generate Linux symbols (advanced)**.
3. Select the `.rpm` or `.ddeb` package.
4. Click **Extract & generate ISF**.
5. Review the generation log before rerunning analysis.

The application uses 7-Zip to extract the debug kernel ELF and `dwarf2json` to create the ISF. A package without the required debug information will not work.

## YARA and Sigma

These are separate detection systems.

### YARA

Generic Volatility YARA scanner plugins use the **YARA rules file** selected in configuration. Some custom plugins include their own rules and do not use that field.

MemProcFS is launched with:

```text
-license-accept-elastic-license-2-0
```

This enables its built-in Elastic YARA rules under the applicable Elastic license. Setting the GUI's Volatility YARA file does not automatically configure that file as a MemProcFS ruleset.

### Sigma

Sigma detection runs through Zircolite as part of MemProcFS-Analyzer on Windows images:

```text
Recovered Windows event logs -> Zircolite -> Sigma matches
```

The application uses `rules_windows_generic.json`. Rules are downloaded separately from the executable and refreshed through **Install / update tools**. Analysis uses the locally installed rules.

The source is [Zircolite-Rules-v2](https://github.com/wagga40/Zircolite-Rules-v2), which converts rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) into Zircolite-compatible JSON. The selected ruleset is not the entire SigmaHQ collection and does not imply coverage of every log source.

The typical rules location is:

```text
%LOCALAPPDATA%\memforensics-gui\tools\MemProcFS-Analyzer\
  MemProcFS-Analyzer-main\Tools\Zircolite\rules\
```

Sigma results depend on the event logs recoverable from the image. No matches does not establish that an image is clean. This integration does not apply Sigma directly to raw memory or to MemNixFS output.

## Results and logs

Typical output layout:

```text
<output folder>\
  <image>_<vol3-plugin>.csv
  <image>_vol2_<plugin>.txt
  Analyzer\
    Analyzer-transcript.txt
    ... recovered artifacts and reports ...
  memnixfs\
    ... exported system and forensic data ...
  debug-logs\
    vol3-<plugin>-<unique suffix>.log
    vol2-<plugin>-<unique suffix>.log
    memprocfs-<unique suffix>.log
    custody-<id>-run.log
  custody-<id>\
    CHAIN_OF_CUSTODY.txt
```

Files and directories depend on the tools selected and whether each stage succeeds.

### Debug logs

Volatility logs retain standard-error output, command arguments, timestamps, and exit codes. Normal plugin output is stored separately in CSV or text files. MemProcFS logs retain console output. Log filenames are unique to preserve previous diagnostics.

The final run log contains configuration and recorded events. Analyzer also writes its own transcript. Logs can contain paths, case information, and forensic findings; review them before attaching them to a public issue.

### Chain of custody

The final record includes case details, analyst, execution host/account, timestamps, run status, image path, and image SHA-256. Configuration and event details are kept in `debug-logs`.

The application does not generate an output manifest or hash every extracted result. The record documents this analysis session; it does not replace acquisition documentation or a custody-transfer history. An interrupted or crashed application may not complete finalization.

### MemNixFS export scope

The application exports `/sys` and `/forensic`. It does not export the entire virtual filesystem. Large process dumps and other unrestricted exports can greatly exceed the source image size.

## Updating tools

- **Check updates** compares installed versions with upstream release information.
- **Install / update tools** performs installation or updates and refreshes Analyzer's supporting tools and rules.
- **Install dependencies** repairs or installs the Python packages and system components.

Release checks are cached. A failed update check does not necessarily mean an installed tool is unusable. Review the install log for the component that failed.

The Analyzer integration uses an application-owned adapter. It does not rely on permanent edits to the installed upstream Analyzer script. Upstream API or script changes can still require an application update.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| GitHub returns 403 or an update check is unavailable | Read the install log. Rate limits or network policy may block requests. Wait for a reported reset before retrying. |
| A mapped drive is absent from Browse | Try Browse shared folder or its UNC path. Check the Windows account and elevation context. |
| A plugin is unavailable | Run Install dependencies and inspect failed packages. Some plugins require optional dependencies or a compatible framework version. |
| A plugin fails or creates an empty result | Read its file in debug-logs and its CSV/text output. Check symbol, argument, and version requirements. |
| Linux symbols are not recognized | Verify the exact kernel build, ISF contents, and application-managed symbol location. |
| Analyzer cannot find a helper or Zircolite | Run Install dependencies, then Install / update tools. Inspect installation errors and Analyzer's transcript. |
| Sigma updates fail | Check network access and the update log. A previously installed ruleset can remain usable but stale. |
| A tool appears inactive | Check live activity, elapsed time, console output, and process resource use. Some stages produce little output. |
| Analysis finishes but the app is still busy | The final image hash may still be running. |
| Output is missing from Results | Inspect nested Analyzer and MemNixFS directories through Open output folder. |
| A mount remains after a run | Expected for Windows analysis. Use Open mount to copy files, then Unmount to release it. Closing the app also stops its retained mount. |

For a bug report, include the affected tool and version, image OS, selected plugins, failure stage, and relevant logs. Do not publish memory images, recovered credentials, or private case data.

## Building from source

Build on Windows. The repository currently declares Go 1.25.0 and Wails v2.15.0. Install Go, Node.js 20.19+ or 22.12+ (as required by the installed Vite package), npm, and the Wails CLI. End users of the compiled application do not need these development tools.

```powershell
go install github.com/wailsapp/wails/v2/cmd/wails@v2.15.0
wails doctor
wails build -platform windows/amd64
```

The production executable is written to:

```text
build\bin\MemFusion.exe
```

For development:

```powershell
wails dev
```

For checks:

```powershell
go build ./...
go vet ./...
go test ./...

Push-Location frontend
npm ci
npm run build
Pop-Location

python internal/installer/sigma_update_test.py
```

The Python command runs offline regression tests for Sigma update handling. It does not update installed rules.

`go build ./...` is a compilation check. It does not create the packaged desktop application. Use `wails build` for the Windows executable; it builds the frontend and regenerates the Go/TypeScript bindings.

## Sharing a build

Distribute the executable together with the vendored plugin directories:

```text
MemFusion\
  MemFusion.exe
  custom_plugins\
  custom_plugins_vol2\
  README.md
```

Copy the current plugin directories from the repository when preparing a package. The custom plugins are not embedded in the executable. Preserve their directory structure and included attribution/license files.

Do not package your installed tools, memory images, case output, local configuration, or debugging logs with a public release. Colleagues install their own tool dependencies using the two setup buttons.

## Project structure

| Path | Purpose |
| --- | --- |
| `app.go` | Wails API, run lifecycle, and phase sequencing |
| `frontend/src/views/` | Configuration, plugins, run progress, results, mounts, and themes |
| `frontend/src/style.css`, `app.css`, `desktop.css` | Theme tokens and desktop layout |
| `internal/installer/` | Tool/dependency installation and Sigma updates |
| `internal/volatility/` | Catalog discovery, curation, plugin runners, and profiles |
| `internal/memprocfs/`, `internal/memnixfs/` | Memory filesystem tool runners |
| `internal/analyzer/` | Mounted Analyzer adapter and dependency checks |
| `internal/linuxsymbols/`, `internal/imageid/` | Image detection and Linux symbol resolution |
| `internal/debuglog/`, `internal/custody/` | Process diagnostics and final analysis records |
| `custom_plugins/`, `custom_plugins_vol2/` | Vendored plugins |
| `scripts/` | Plugin compatibility and maintenance scripts |

Consult [custom_plugins/README.md](../custom_plugins/README.md) before changing vendored plugins. Exported Go methods or models used by the frontend require regenerated bindings. Event names and payload keys must stay consistent between Go and TypeScript.

## Limitations

- This is a Windows-only desktop build.
- Analysis depends on upstream tool support for the image, kernel, and requested plugins.
- Automatic setup requires reachable package sources and sufficient Windows permissions; it is not an offline installer.
- Linux symbol indexes do not cover every kernel.
- Legacy Volatility 2 profiles do not cover all Windows versions or Linux builds.
- The Results panel is a summary, not a complete browser of nested output.
- Empty output or no detection matches is not proof that no relevant artifacts exist.
- Build and regression-test success does not establish compatibility with every image or a clean Windows installation.

## Licensing

Each external tool, detection ruleset, and vendored plugin retains its own license. MemProcFS's Elastic rule flag accepts Elastic License 2.0 for that feature. Review upstream terms before redistribution or use in your environment.

This repository currently has no top-level `LICENSE` file. A project license should be selected and added before publishing a release with stated redistribution rights. This README does not assign a license to the application or replace third-party terms.

