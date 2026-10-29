import {GetPluginCatalog} from '../../wailsjs/go/main/App';
import type {main, volatility} from '../../wailsjs/go/models';
import {deletePreset, hasLastSelection, loadLastSelection, loadPresets, savePreset, saveLastSelection} from './presets';

let selected = new Set<string>();
let frameworks = new Map<string, string>();
let pidEnabled = false;
let targetPID = 0;
let generation = 0;
const PID_KEY = 'memforensics-gui.pid-target.v1';
const labels: Record<string, string> = {windows: 'Windows', linux: 'Linux', mac: 'macOS', custom: 'Custom', generic: 'Generic'};
const esc = (s: string) => s.replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]!));
export const getSelectedPlugins = () => [...selected];
export const getPIDOptions = () => ({enabled: pidEnabled, pid: targetPID});
export function selectedFrameworkCounts() {
    return {vol2: [...selected].filter(n => frameworks.get(n) === 'vol2').length,
        vol3: [...selected].filter(n => frameworks.get(n) === 'vol3').length};
}

export async function renderPluginsView(container: HTMLElement, volPath: string, includeAnalyzer = false, vol2Path = '', imageOS = '') {
    const current = ++generation;
    selected.clear(); frameworks.clear();
    document.dispatchEvent(new Event('run-plan-changed'));
    try {
        const pid = JSON.parse(localStorage.getItem(PID_KEY) || '{}');
        pidEnabled = pid.enabled === true;
        targetPID = Number.isInteger(pid.pid) && pid.pid >= 0 ? pid.pid : 0;
    } catch { pidEnabled = false; targetPID = 0; }
    container.innerHTML = '<section class="panel"><h2>Volatility plugins</h2><p role="status">Loading catalog...</p></section>';
    let catalog: main.PluginCatalog;
    try { catalog = await GetPluginCatalog(volPath, vol2Path); }
    catch (err) {
        if (current !== generation) return;
        container.innerHTML = `<section class="panel"><h2>Volatility plugins</h2><p class="status-error">${esc(String(err))}</p><p>No Volatility plugins selected. The memory filesystem tools can still run.</p><button class="btn-secondary" id="retryCatalog">Retry catalog</button></section>`;
        container.querySelector('#retryCatalog')!.addEventListener('click', () => renderPluginsView(container, volPath, includeAnalyzer, vol2Path, imageOS));
        return;
    }
    if (current !== generation) return;
    const plugins = [...(catalog.plugins || [])].sort((a, b) => a.name.localeCompare(b.name));
    const byName = new Map(plugins.map(p => [p.name, p]));
    frameworks = new Map(plugins.map(p => [p.name, p.framework]));
    const loadable = (names: string[]) => names.filter(n => byName.get(n)?.loadable);
    const wrongOS = (p: volatility.Plugin) => {
        const os = p.category === 'custom' ? p.name.split('.')[0] : p.category;
        return !!imageOS && ['windows', 'linux', 'docker', 'mac'].includes(os) && (os === 'docker' ? 'linux' : os) !== imageOS;
    };
    const covered = (p: volatility.Plugin) => imageOS !== 'linux' && (p.redundant || (includeAnalyzer && p.analyzerRedundant));
    const recommended = loadable(catalog.recommended || []).filter(n => !wrongOS(byName.get(n)!));
    selected = new Set(loadable(hasLastSelection() ? loadLastSelection() : recommended));
    let undo: string[] | null = null;
    let selectedView = false;
    let lastClicked = '';
    const presets = catalog.presets || [];
    container.innerHTML = `
      <section class="panel plugin-workspace">
        <div class="page-heading"><h2>Volatility plugins</h2><span class="hint">Optional. An empty selection runs only the memory filesystem tools.</span></div>
        ${[catalog.vol2Warning, catalog.vol3Warning].filter(Boolean).map(w => `<p class="status-error">${esc(w!)}</p>`).join('')}
        <div class="preset-toolbar">
          <label for="presetSelect">Preset</label><select id="presetSelect"></select>
          <button id="addPreset" class="btn-secondary">Add to selection</button>
          <button id="replacePreset" class="btn-secondary">Replace selection</button>
          <button id="selectRecommendedBtn" class="btn-secondary">Use recommended</button>
          <button id="savePresetBtn" class="btn-secondary">Save selection</button>
          <button id="deletePresetBtn" class="btn-secondary">Delete preset</button>
        </div>
        <p id="presetDescription" class="hint"></p>
        <form id="savePresetForm" class="preset-save" hidden><label for="presetName">Preset name</label><input id="presetName" required maxlength="100"><button class="btn-secondary" type="submit">Save</button><button class="btn-secondary" type="button" id="cancelSave">Cancel</button></form>
        <div class="plugin-columns">
          <div class="catalog-pane">
            <div class="catalog-filters">
              <label class="search-field" for="pluginSearch">Search<input id="pluginSearch" type="search" placeholder="Plugin name or description"></label>
              <label for="categoryFilter">Category<select id="categoryFilter"><option value="">All categories</option>${Object.entries(labels).map(([k,v]) => `<option value="${k}">${v}</option>`).join('')}</select></label>
              <label for="frameworkFilter">Framework<select id="frameworkFilter"><option value="">All versions</option><option value="vol3">Volatility 3</option><option value="vol2">Volatility 2</option></select></label>
              <label for="coverageFilter">Coverage<select id="coverageFilter"><option value="all">All plugins</option><option value="additional">Additional coverage</option><option value="covered">Overlaps other tools</option></select></label>
              <label for="availabilityFilter">Availability<select id="availabilityFilter"><option value="ready">Available</option><option value="all">All</option><option value="unavailable">Unavailable</option></select></label>
            </div>
            <div class="catalog-options">
              <label><input id="matchingOS" type="checkbox" ${imageOS ? 'checked' : ''}> Image OS only${imageOS ? ` (${esc(imageOS)})` : ''}</label>
              <label><input id="pidOnly" type="checkbox"> Supports PID</label>
              <button id="resetFiltersBtn" class="btn-secondary">Reset filters</button>
            </div>
            <div class="catalog-actions"><button id="catalogView" class="btn-secondary" aria-pressed="true">Catalog</button><button id="selectedView" class="btn-secondary" aria-pressed="false">Review selected</button><span id="visibleCount" role="status"></span><button id="selectShownBtn" class="btn-secondary">Select shown</button><button id="deselectShownBtn" class="btn-secondary">Deselect shown</button></div>
            <div class="catalog-scroll"><table class="catalog-table"><thead><tr><th class="check-col"><input id="toggleShown" type="checkbox" aria-label="Select all shown plugins"></th><th>Plugin</th><th>Version</th><th>Inputs / coverage</th></tr></thead><tbody id="pluginList"></tbody></table><p id="noMatches" hidden>No plugins match these filters.</p></div>
            <section id="pluginDetails" class="plugin-details" aria-label="Plugin details"><h3>Plugin details</h3><p>Select a plugin name to read its description and requirements.</p></section>
          </div>
          <aside class="selection-pane" aria-label="Selected plugins">
            <h3>Selected for this run <span id="selectedCount">0</span></h3><p id="frameworkCounts" class="hint"></p>
            <div class="selection-actions"><button id="clearSelectionBtn" class="btn-secondary">Clear selection</button><button id="undoSelection" class="btn-secondary">Undo</button></div>
            <p id="selectionWarning" class="status-warn" hidden></p>
            <div id="selectionList" class="selection-list"></div>
            <fieldset class="pid-settings"><legend>Process filter</legend><label><input id="pidEnabled" type="checkbox" ${pidEnabled ? 'checked' : ''}> Filter by PID</label><label for="targetPID">Process ID<input id="targetPID" type="number" min="0" step="1" value="${targetPID}" ${pidEnabled ? '' : 'disabled'}></label><p class="hint">Applied only to plugins that support PID.</p></fieldset>
            <button id="reviewRun" class="btn-primary">Continue to run</button>
          </aside>
        </div>
      </section>`;
    const el = <T extends HTMLElement = HTMLElement>(id: string) => container.querySelector<T>('#' + id)!;
    const input = (id: string) => el<HTMLInputElement>(id);
    const select = (id: string) => el<HTMLSelectElement>(id);
    const search = input('pluginSearch');
    const preset = select('presetSelect');
    const requirements = (p: volatility.Plugin) => [p.supportsPID ? 'PID' : '', p.requiresYaraRules ? 'YARA file required' : '', covered(p) ? (p.redundant ? 'MemProcFS overlap' : 'Analyzer overlap') : '', !p.loadable ? 'Unavailable' : ''].filter(Boolean).join('; ');
    const rows = plugins.map(p => {
        const row = document.createElement('tr');
        row.innerHTML = `<td><input type="checkbox" aria-label="Select ${esc(p.name)}" ${p.loadable ? '' : 'disabled'}></td><td><button class="plugin-link" title="${esc(p.name)}">${esc(p.name)}</button></td><td>${p.framework === 'vol2' ? 'Vol 2' : 'Vol 3'}</td><td class="plugin-inputs">${esc(requirements(p))}</td>`;
        el('pluginList').appendChild(row);
        const checkbox = row.querySelector('input')!;
        row.querySelector('button')!.addEventListener('click', () => showDetails(p));
        checkbox.addEventListener('click', event => {
            const visible = rows.filter(r => !r.row.hidden && r.p.loadable);
            const from = visible.findIndex(r => r.p.name === lastClicked), to = visible.findIndex(r => r.p.name === p.name);
            change(() => {
                const affected = event.shiftKey && from >= 0 && to >= 0 ? visible.slice(Math.min(from,to), Math.max(from,to) + 1) : [{p}];
                for (const item of affected) checkbox.checked ? selected.add(item.p.name) : selected.delete(item.p.name);
            });
            lastClicked = p.name; showDetails(p);
        });
        return {p, row, checkbox, search: `${p.name} ${p.description}`.toLowerCase()};
    });
    function showDetails(p: volatility.Plugin) {
        rows.forEach(r => r.row.classList.toggle('inspected', r.p.name === p.name));
        el('pluginDetails').innerHTML = `<h3>${esc(p.name)}</h3><p>${esc(p.description || 'No description supplied.')}</p><dl><dt>Framework</dt><dd>${p.framework === 'vol2' ? 'Volatility 2' : 'Volatility 3'}</dd><dt>Category</dt><dd>${esc(labels[p.category] || p.category)}</dd><dt>Inputs</dt><dd>${p.requiresYaraRules ? 'YARA file required. Set it in Evidence.' : 'No YARA file required.'} ${p.supportsPID ? 'Supports PID filtering.' : 'No PID filter.'}</dd><dt>Availability</dt><dd>${p.loadable ? 'Available' : 'Unavailable. Check tool dependencies.'}</dd>${covered(p) ? `<dt>Coverage</dt><dd>${esc(p.redundant ? p.redundantReason : p.analyzerReason)}</dd>` : ''}${p.note ? `<dt>Note</dt><dd>${esc(p.note)}</dd>` : ''}</dl>`;
    }
    function filter() {
        const q = search.value.trim().toLowerCase();
        let visible = 0, enabled = 0, checked = 0;
        for (const r of rows) {
            const p = r.p;
            const match = selectedView ? selected.has(p.name) :
                (!select('categoryFilter').value || p.category === select('categoryFilter').value) &&
                (!select('frameworkFilter').value || p.framework === select('frameworkFilter').value) &&
                (!input('matchingOS').checked || !wrongOS(p)) && (!input('pidOnly').checked || p.supportsPID) &&
                (select('coverageFilter').value === 'all' || covered(p) === (select('coverageFilter').value === 'covered')) &&
                (select('availabilityFilter').value === 'all' || p.loadable === (select('availabilityFilter').value === 'ready'));
            r.row.hidden = !(match && (!q || r.search.includes(q)));
            r.checkbox.checked = selected.has(p.name); r.row.classList.toggle('is-selected', r.checkbox.checked);
            if (!r.row.hidden) { visible++; if (p.loadable) { enabled++; if (r.checkbox.checked) checked++; } }
        }
        el('visibleCount').textContent = `${visible} shown`; el('noMatches').hidden = visible !== 0;
        input('toggleShown').checked = enabled > 0 && checked === enabled;
        input('toggleShown').indeterminate = checked > 0 && checked < enabled; input('toggleShown').disabled = enabled === 0;
        el<HTMLButtonElement>('selectShownBtn').disabled = enabled === 0; el<HTMLButtonElement>('deselectShownBtn').disabled = checked === 0;
        el('catalogView').setAttribute('aria-pressed', String(!selectedView)); el('selectedView').setAttribute('aria-pressed', String(selectedView));
        container.querySelectorAll<HTMLSelectElement | HTMLInputElement>('.catalog-filters select, .catalog-options input').forEach(c => c.disabled = selectedView);
    }
    function refresh() {
        filter(); el('selectedCount').textContent = String(selected.size);
        const counts = selectedFrameworkCounts();
        el('frameworkCounts').textContent = `Volatility 3: ${counts.vol3} | Volatility 2: ${counts.vol2}`;
        el('selectionList').innerHTML = selected.size ? [...selected].sort().map(n => `<div class="selection-item"><button class="plugin-link" data-inspect="${esc(n)}" title="${esc(n)}">${esc(n)}</button><button class="remove-plugin" data-remove="${esc(n)}" aria-label="Remove ${esc(n)}">Remove</button></div>`).join('') : '<p class="hint">No Volatility plugins selected.</p>';
        const mismatched = [...selected].filter(n => wrongOS(byName.get(n)!)).length;
        el('selectionWarning').hidden = mismatched === 0; el('selectionWarning').textContent = `${mismatched} selected plugins target a different OS.`;
        el<HTMLButtonElement>('undoSelection').disabled = undo === null;
        saveLastSelection([...selected]); document.dispatchEvent(new Event('run-plan-changed'));
    }
    function change(action: () => void) { undo = [...selected]; action(); refresh(); }
    function resetFilters() {
        search.value = ''; select('categoryFilter').value = ''; select('frameworkFilter').value = '';
        select('coverageFilter').value = 'all'; select('availabilityFilter').value = 'ready';
        input('matchingOS').checked = !!imageOS; input('pidOnly').checked = false; selectedView = false; filter();
    }
    container.querySelectorAll('.catalog-filters input, .catalog-filters select, .catalog-options input').forEach(c => c.addEventListener('input', filter));
    el('resetFiltersBtn').addEventListener('click', resetFilters);
    el('catalogView').addEventListener('click', () => { selectedView = false; filter(); });
    el('selectedView').addEventListener('click', () => { selectedView = true; search.value = ''; filter(); });
    const setShown = (checked: boolean) => change(() => rows.filter(r => !r.row.hidden && r.p.loadable).forEach(r => checked ? selected.add(r.p.name) : selected.delete(r.p.name)));
    el('selectShownBtn').addEventListener('click', () => setShown(true)); el('deselectShownBtn').addEventListener('click', () => setShown(false));
    input('toggleShown').addEventListener('change', () => setShown(input('toggleShown').checked));
    el('clearSelectionBtn').addEventListener('click', () => change(() => selected.clear()));
    el('selectRecommendedBtn').addEventListener('click', () => change(() => { selected = new Set(recommended); }));
    el('undoSelection').addEventListener('click', () => { if (undo !== null) { const old = [...selected]; selected = new Set(undo); undo = old; refresh(); } });
    el('selectionList').addEventListener('click', event => {
        const button = (event.target as HTMLElement).closest<HTMLButtonElement>('button');
        if (button?.dataset.remove) change(() => selected.delete(button.dataset.remove!));
        if (button?.dataset.inspect) showDetails(byName.get(button.dataset.inspect)!);
    });
    function updatePresets(value = '') {
        preset.innerHTML = '<option value="">Choose a preset</option><optgroup label="Built-in">' + presets.map(p => `<option value="builtin:${esc(p.name)}">${esc(p.name)} (${p.plugins.length})</option>`).join('') + '</optgroup><optgroup label="Saved">' + Object.keys(loadPresets()).sort().map(n => `<option value="saved:${esc(n)}">${esc(n)}</option>`).join('') + '</optgroup>';
        preset.value = value; previewPreset();
    }
    function presetNames() { return preset.value.startsWith('builtin:') ? presets.find(p => p.name === preset.value.slice(8))?.plugins || [] : loadPresets()[preset.value.slice(6)] || []; }
    function previewPreset() {
        el<HTMLButtonElement>('addPreset').disabled = !preset.value; el<HTMLButtonElement>('replacePreset').disabled = !preset.value;
        el<HTMLButtonElement>('deletePresetBtn').disabled = !preset.value.startsWith('saved:');
        const description = presets.find(p => `builtin:${p.name}` === preset.value)?.description;
        el('presetDescription').textContent = preset.value ? `${loadable(presetNames()).length} available plugins. ${description || 'Saved selection.'}` : 'Choose a preset to preview it.';
    }
    preset.addEventListener('change', previewPreset);
    el('addPreset').addEventListener('click', () => change(() => loadable(presetNames()).forEach(n => selected.add(n))));
    el('replacePreset').addEventListener('click', () => change(() => { selected = new Set(loadable(presetNames())); }));
    el('savePresetBtn').addEventListener('click', () => { el('savePresetForm').hidden = false; input('presetName').value = preset.value.startsWith('saved:') ? preset.value.slice(6) : ''; input('presetName').focus(); });
    el('cancelSave').addEventListener('click', () => { el('savePresetForm').hidden = true; });
    el('savePresetForm').addEventListener('submit', event => {
        event.preventDefault(); const name = input('presetName').value.trim(); if (!name) return;
        if (Object.prototype.hasOwnProperty.call(loadPresets(), name) && !window.confirm(`Replace saved preset "${name}"?`)) return;
        savePreset(name, [...selected]); updatePresets(`saved:${name}`); el('savePresetForm').hidden = true;
    });
    el('deletePresetBtn').addEventListener('click', () => {
        if (!preset.value.startsWith('saved:')) return;
        const name = preset.value.slice(6); if (window.confirm(`Delete preset "${name}"?`)) { deletePreset(name); updatePresets(); }
    });
    const savePID = () => {
        pidEnabled = input('pidEnabled').checked; input('targetPID').disabled = !pidEnabled;
        const value = Number(input('targetPID').value);
        targetPID = Number.isInteger(value) && value >= 0 && input('targetPID').value !== '' ? value : -1;
        input('targetPID').setCustomValidity(targetPID >= 0 ? '' : 'Enter a whole PID of zero or greater.');
        try { localStorage.setItem(PID_KEY, JSON.stringify({enabled: pidEnabled, pid: targetPID})); } catch { /* Optional persistence. */ }
    };
    input('pidEnabled').addEventListener('change', savePID); input('targetPID').addEventListener('input', savePID);
    el('reviewRun').addEventListener('click', () => document.dispatchEvent(new CustomEvent('navigate-section', {detail: 'runContainer'})));
    updatePresets(); refresh();
}

