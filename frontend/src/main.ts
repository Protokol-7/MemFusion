import './style.css';
import './app.css';
import './desktop.css';
import {applyStoredTheme, renderThemeSwitcher} from './views/theme';
import {renderConfigView, loadConfig} from './views/config';
import {renderPluginsView, getPIDOptions, getSelectedPlugins} from './views/plugin-workspace';
import {renderRunView} from './views/run';
import {renderMountsView} from './views/mounts';
import {renderResultsView} from './views/results';
import {EventsOn} from '../wailsjs/runtime/runtime';

applyStoredTheme();
const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
  <header class="desktop-header"><div><strong>MemFusion</strong><span>Memory forensics</span></div><div class="theme-switcher" id="themeSwitcher"></div></header>
  <nav class="workflow-nav" aria-label="Workspace">
    <button data-section="configContainer" aria-current="page">Evidence &amp; tools</button>
    <button data-section="pluginsContainer" disabled>Volatility plugins</button>
    <button data-section="runContainer" disabled>Run analysis</button>
    <button data-section="resultsContainer" disabled>Results</button>
    <button data-section="mountsContainer">Mounts</button>
    <span id="workspaceStatus" role="status">Configure tools to begin</span>
  </nav>
  <main id="main">
    <div id="configContainer" class="workspace-page"></div>
    <div id="pluginsContainer" class="workspace-page" hidden></div>
    <div id="runContainer" class="workspace-page" hidden></div>
    <div id="resultsContainer" class="workspace-page" hidden></div>
    <div id="mountsContainer" class="workspace-page" hidden></div>
  </main>`;
const get = (id: string) => document.getElementById(id)!;
let active = 'configContainer';
function navigate(id: string) {
    const button = document.querySelector<HTMLButtonElement>(`.workflow-nav button[data-section="${id}"]`);
    if (!button || button.disabled) return;
    active = id;
    document.querySelectorAll<HTMLElement>('.workspace-page').forEach(page => page.hidden = page.id !== id);
    document.querySelectorAll('.workflow-nav button').forEach(b => b.setAttribute('aria-current', b === button ? 'page' : 'false'));
    const heading = get(id).querySelector<HTMLElement>('h2');
    if (heading) { heading.tabIndex = -1; heading.focus({preventScroll: true}); }
    window.scrollTo(0, 0);
}
document.querySelector('.workflow-nav')!.addEventListener('click', event => {
    const b = (event.target as HTMLElement).closest<HTMLButtonElement>('button[data-section]');
    if (b) navigate(b.dataset.section!);
});
document.addEventListener('navigate-section', event => navigate((event as CustomEvent<string>).detail));
renderThemeSwitcher(get('themeSwitcher'));
renderMountsView(get('mountsContainer'));
let cleanupResults: (() => void) | undefined;
function lockConfiguration(running: boolean) {
    get('configContainer').inert = running;
    get('pluginsContainer').inert = running;
    if (running) get('workspaceStatus').textContent = 'Analysis running. Configuration is locked.';
    else get('workspaceStatus').textContent = 'Ready';
}
document.addEventListener('run-state-changed', event => lockConfiguration((event as CustomEvent<boolean>).detail));
renderConfigView(get('configContainer'), (ok, cfg) => {
    for (const id of ['pluginsContainer', 'runContainer', 'resultsContainer']) {
        document.querySelector<HTMLButtonElement>(`button[data-section="${id}"]`)!.disabled = !ok;
    }
    if (!ok) {
        get('workspaceStatus').textContent = 'Check tool configuration';
        if (!['configContainer', 'mountsContainer'].includes(active)) navigate('configContainer');
        return;
    }
    const detected = document.getElementById('imageOSDetected')?.dataset.os;
    const imageOS = cfg.imageOS || (detected === 'linux' || detected === 'windows' ? detected : '');
    void renderPluginsView(get('pluginsContainer'), cfg.volPath, cfg.includeAnalyzer, cfg.vol2Path, imageOS);
    renderRunView(get('runContainer'), {getConfig: loadConfig, getSelectedPlugins, getPIDOptions});
    const results = renderResultsView(get('resultsContainer'), () => loadConfig().outputDir);
    cleanupResults?.();
    cleanupResults = EventsOn('run:finished', () => results?.refresh());
    get('workspaceStatus').textContent = 'Ready';
    navigate('pluginsContainer');
});
EventsOn('run:phase', (p: {label?: string; phase?: string}) => { get('workspaceStatus').textContent = `Running: ${p.label || p.phase || 'analysis'}`; });
EventsOn('run:finished', () => { lockConfiguration(false); get('workspaceStatus').textContent = 'Run ended. Review results.'; });
