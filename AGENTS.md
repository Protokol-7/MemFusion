# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What this is

A Wails v2 desktop app (Go backend, vanilla-TypeScript frontend) that orchestrates external
memory-forensics tools against one memory image: Volatility 3, Volatility 2, MemProcFS (Windows
images), MemNixFS (Linux images) and MemProcFS-Analyzer. The app does not analyze memory itself —
its value is installing those tools, deciding which of ~470 plugins are worth running, sequencing
the run, and resolving Linux kernel symbols. The root `README.md` is the untouched Wails template
and describes nothing project-specific.

This build targets **Windows only** (`internal/paths`, `internal/proc/proc_windows.go`,
`internal/prereq` are all Windows-specific), even though `main.go` still carries a Linux options
block.

## Commands

```bash
wails build          # production build -> build/bin/MemFusion.exe (regenerates bindings + frontend)
wails dev            # live dev with hot-reloaded frontend; Go methods callable from http://localhost:34115
wails generate module # regenerate frontend/wailsjs bindings only

go build ./...       # compile check only — does NOT produce the app
go vet ./...
gofmt -l .           # must print nothing (exclude frontend/node_modules)

cd frontend && npx tsc --noEmit   # type-check
cd frontend && npm run build      # tsc + vite build
```

`go build` and `vite build` verify compilation but never produce the executable — only
`wails build` does. There are currently **no Go test files**; `go test ./...` passes vacuously.

After changing an exported `App` method or a struct crossing the Go/TS boundary, the bindings in
`frontend/wailsjs/` must be regenerated (`wails build` does it; `wails generate module` alone also
works) or the frontend silently calls a stale signature.

### Vendored plugin maintenance

```bash
<vol3-python> scripts/patch_plugins_for_vol3.py --check   # dry run, exits 1 if changes needed
<vol3-python> scripts/patch_plugins_for_vol3.py           # apply after a Volatility 3 upgrade
```

Run with the interpreter that has volatility3 installed (normally
`%LOCALAPPDATA%\memforensics-gui\tools\python-env\Scripts\python.exe`) — it reads *installed*
plugin versions rather than hardcoding them. See `custom_plugins/README.md`, which is the
authoritative record of every vendored plugin, why it was included or rejected, and which files
were patched locally.

## Architecture

### Run pipeline (`app.go`)

`StartRun` returns immediately and does the work in one goroutine, in three strictly sequential
phases:

1. **Volatility 2** — needs a `--profile`, obtained via `volatility.DetectVol2Profile`.
2. **Volatility 3**.
3. **Mount/export** — MemProcFS and optional Analyzer for Windows, MemNixFS export for Linux.
   OS detection and Linux symbol resolution happen before the analysis phases.

The user explicitly changed the order to Volatility first on 2026-09-28. `retained_mount.go`
keeps the Windows mount alive after analysis under an app-owned context. Run finalization
does not cancel it. Unmount, Stop during analysis, and app shutdown cancel it. A retained
mount blocks new runs and tool updates until released. Linux remains export-only.

Phases never overlap. This is deliberate and load-bearing: two of these tools running at once
against a large image caused real OOM kills, which is also why plugins within a framework run one
at a time rather than in a pool. `beginPhase` scopes each phase to its own cancellable context so
**Skip** abandons one tool while **Stop** cancels the whole run.

### Event contract

The Go side pushes progress through `runtime.EventsEmit` via an `Emitter func(event string, payload any)`
(each package declares its own identical type to avoid importing Wails). The frontend subscribes by
exact event-name string in `frontend/src/views/*.ts`. **Renaming an event or changing a payload key
breaks the UI silently** — nothing type-checks across that boundary. Current names include
`vol3:plugin-start|plugin-done|all-done`, `vol2:status|all-done`, `memprocfs:status`,
`memnixfs:status`, `analyzer:status`, `run:log|phase|finished`, `tool:progress|heartbeat`,
`install:progress|log`, `symbols:log`, `isfgen:log`.

`tool:heartbeat` exists because stages like vol2's `imageinfo` print nothing for minutes; without a
tick from the goroutine sitting in `cmd.Wait()`, a working run and a hung one look identical.

### Plugin catalog and its filtering layers

`volatility.ListPlugins` parses `vol -h`; `ListVol2Plugins` parses `volatility --info`. Both
frameworks' results merge into one catalog, then four separate files annotate it:

- `coverage.go` / `coverage_vol2.go` — plugins whose output MemProcFS's mount already provides
  (`Redundant`). Rule: walk-based enumeration MemProcFS exports is redundant; scan-based discovery
  of hidden/freed objects is kept.
- `recommended.go` — the pre-checked default set ("fills a gap MemProcFS doesn't cover").
- `noise.go` — introspection, converters, bulk dumpers, dead-malware scanners (`LowValue`, hidden
  behind "show everything").
- `presets.go` — narrow, task-oriented bundles.

All four match on **name prefixes resolved against the live catalog**, so an entry naming a plugin
that isn't installed is silently ignored rather than an error. The curation in `coverage.go` and
`recommended.go` was derived from inspecting a real mounted MemProcFS filesystem, not its sqlite
schema — don't "correct" those lists from the schema.

Starting `vol` is a full Python interpreter launch, so the catalog is cached in `App.catalogCache`,
keyed by `catalogCacheKey` (vol binary mtime/size + every custom-plugin file's mtime/size). Any
install or patch operation clears it.

### Two quirks the runners exist to work around

- **vol3 exits 0 when it refuses a plugin** whose declared dependency version doesn't match, writing
  the refusal into the output file. `runner.go`'s `unsatisfiedRequirement` reads the head of each
  output file so this is reported as a failure instead of a silent empty CSV.
- **vol2's `imageinfo` is unusably slow** (40+ min on an 8 GB image, `kdbgscan` produced nothing at
  all). `vol2profile.go` derives the vol2 profile from Volatility 3 instead, and
  `profilecache.go` caches it on disk keyed by path+size+mtime.

vol2 output is plain text, not CSV: its `--output=csv` is implemented per plugin, so requesting it
makes any plugin lacking a CSV renderer fail outright.

### Linux kernel symbol resolution

The chain, resolved once per run and shared by both tools that need it:

```
imageid.LinuxBanners(image)          -> candidate banner strings
linuxsymbols.ResolveForImage         -> local ISF first, then community indexes
  -> paths.SymbolsDir()/linux/*.json[.xz]
     MemNixFS  <- --symbols <exact file>
     Volatility 3 <- --symbol-dirs (already points at SymbolsDir)
```

Points that are easy to get wrong, each learned from a real failure:

- **`imageid` scans the whole file, with no byte cap.** A previous 3 GiB cap made a 4 GiB VMware
  `.vmem` (banner at 3.33 GiB) report `unknown`; since callers treat non-Linux as Windows, the run
  silently went down the MemProcFS path and MemNixFS never started. Both scanners exit early on a
  match, so cost is bounded by the match, not the file.
- **Multiple banner candidates per image are normal** and the first is often not genuine (on one
  CentOS image it was a banner embedded in an application's JSON blob). Never pick one heuristically
  — hand all candidates to the index and let a symbol file decide.
- **MemNixFS is given `--symbols <exact file>` only, never a directory, and never `--auto-fetch` or
  `--symbol-cache`.** `--auto-fetch` runs `tools/fetch_symbols.sh`, and the Windows release ships no
  `tools/` directory, so it can only fail (this is what makes MemNixFS suggest `--vmlinux`).
  `--symbol-cache` is documented as *overriding* MemNixFS's own cache. Passing a directory of other
  images' ISFs would suppress its own working discovery. See `memnixfs.RunExport`'s comment.
- **MemNixFS exports only the subtrees in `memnixfs.ExportSubtrees`** (`/sys`, `/forensic` — 18 MB
  measured). A whole-tree export produced **19 GB from a 4 GiB image**, essentially all of it one
  `proc/<pid>/proc.dmp`: those are indexed by *virtual* address, and a 64-bit process under ASLR
  spans ~41 TB of VA with the holes written out as zeros.
- Go's stdlib has no xz decoder and this project adds no dependency for one. Downloaded ISFs are
  `.json.xz`, so a `.banner` sidecar file is written next to each one to make offline re-matching
  possible.
- `paths.RemoteISFIndexPath()` deliberately lives **outside** `SymbolsDir()`: that whole directory is
  passed to vol3 as `--symbol-dirs` and vol3 recursively globs every `*.json` under it looking for
  real ISFs.

`volatility.RemoteISFSources` lists the community banner indexes. Only add a source verified to
serve valid `"version": 1` JSON — a malformed one throws inside vol3's automagic and can take down a
whole Linux run, whereas a 404 is tolerated.

The manual fallback for kernels no index carries is `linuxsymbols.GenerateISFFromPackage`:
`.rpm`/`.ddeb` → 7-Zip extract (looped, since payload compression varies) → real ELF `vmlinux` →
`dwarf2json linux --elf` → ISF. Neither dwarf2json nor Volatility 3 can read the package directly.

### Installed locations (`internal/paths`)

Everything the app installs lives under `%LOCALAPPDATA%\memforensics-gui\tools`: `python-env`
(app-owned venv holding Volatility 3 and every package the plugins import), `volatility3-symbols`,
`dwarf2json`, and one directory per downloaded tool. Each tool directory carries a
`.memforensics-version` marker so "Install / update tools" re-downloads only what is stale.

The venv is pinned to a wheel-compatible Python (`wheelSafeMinMinor`..`wheelSafeMaxMinor` in
`installer/deps.go`) rather than whatever is on PATH, because `yara-python` and friends ship as
binary wheels only — on a too-new interpreter those plugins silently disappear. Raise the max only
when wheels exist.

`internal/pydeps` is the single source of truth for Python requirements, shared by `installer`
(installs them) and `prereq` (reports what is missing) so the two can never disagree.

### Custom plugin loading

`volatility.PluginDirs()` resolves `$MEMFORENSICS_PLUGIN_DIRS` → `~/.local/share/memforensics-gui/plugins`
→ `<exe dir>/custom_plugins`, and passes them to vol via `-p` (semicolon-separated; vol2 uses
`--plugins=` comma-separated instead).

Constraints that look like tidy-able mess but are not:

- Plugins in `custom_plugins/windows/` **must stay in that subfolder** — they import each other as
  `volatility3.plugins.windows.ptenum`, so a flat layout breaks them.
- `custom_plugins/linux/bpfutil/` is a locally restructured vendor package; upstream expects you to
  patch vol3's own source tree, which fails against 2.28 and would be erased by any vol3 upgrade.
- A fresh vol3 raises a circular-import `AttributeError` in `pool.py` on any `-p` directory, which
  makes the catalog probe drop *every* custom plugin. `scripts/patch_vol3_pool_circular_import.py`
  fixes it; it is embedded in `app.go` via `go:embed` and applied automatically after
  `InstallDependencies` (which owns that venv) but only with user consent after `InstallTools`
  (which may be editing a Python the user owns). `discover.go` retries without `-p` as a fallback.

### Frontend

`frontend/src/main.ts` builds the whole DOM and delegates to `views/*.ts`; there is no framework and
no router — panels are shown/hidden by CSS class. Config is persisted to `localStorage` under
`memforensics-gui.config.v1`, merged over defaults on load, so adding a field to `RunConfig` needs a
default in `config.ts` or existing users get `undefined`.

`results.Scan` reads only the **top level** of the output directory, so nested tool output (the
MemNixFS export tree) never appears in the Results panel.
