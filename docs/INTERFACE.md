# Desktop interface

The September 2026 redesign replaces the scrolling workflow with five pages:

- **Evidence & tools:** case information, image, output, symbols, YARA input, Analyzer option, installation, and executable paths.
- **Volatility plugins:** catalog, preset preview, selected plugins, plugin details, and PID filtering.
- **Run analysis:** tool sequence, progress, skip/stop, and console output.
- **Results:** output summaries, filters, and the output-folder action.
- **Mounts:** inspect and clean up MemProcFS mounts.

The interface uses standard controls, solid backgrounds, square edges, and the system font. Classic, Light, Midnight, and Black appearances remain available. Midnight uses gray inputs. All controls remain available at the minimum 800-pixel window width; narrow windows stack the selection pane below the catalog.

## Plugin selection

Selecting a preset previews its description. **Add to selection** merges it; **Replace selection** replaces the existing selection. **Undo** restores the previous selection change. Saved presets remain compatible with the earlier version.

The right-hand list always displays the full selection. **Review selected** displays those plugins in the table without applying catalog filters. Search still works in this view. Choosing a plugin name shows its description, input information, and coverage notes. Checkboxes control whether it runs.

Catalog filters cover category, framework, overlap, availability, image OS, and PID support. Overlapping plugins remain visible by default. Unavailable plugins cannot be selected, including through bulk and range actions. **Select shown** and **Deselect shown** affect only visible, available plugins. Shift-click selects a range.

An empty selection is saved as an empty selection, rather than reverting to recommended plugins. This permits filesystem-tool-only runs. Invalid PID values continue to be rejected by run validation. Configuration and selection editing are locked while analysis is active; navigation, progress, logs, and run controls remain available.

## Compatibility and verification

Tool installation locations, stored configuration keys, and saved presets are unchanged. Volatility now runs first; the Windows mount stays open after analysis until Unmount or app shutdown. The previous project and executable were copied to `../MemFusion-before-redesign-20260928` before editing; executable SHA-256 values matched. Both versions share the same installed tools and user settings.

`scripts/ui-redesign-check.cjs` exercises the built frontend in headless Edge with mock Wails methods and a catalog of more than 480 plugins. It checks navigation, image-picker wiring, preset preview/add/replace, details, selection undo, saved empty selections, PID arguments, zero-plugin runs, unavailable plugins, catalog recovery, configuration locking, and Linux-only run plans. It captures all four themes and a narrow layout under `build/ui-review`.

Run `npm run build` in `frontend` before running the check. The script requires Playwright; set `MEMFUSION_PLAYWRIGHT` to its module path if it is not locally installed. Browser checks use fixture data and do not run forensic tools. They do not verify native file dialogs or replace an end-to-end memory-image analysis.

