import {selectedFrameworkCounts} from './plugin-workspace';
import {StartRun, StopRun, SkipPhase, OpenOutputFolder, GetRetainedMountPath, CleanupMemProcfsMount} from '../../wailsjs/go/main/App';
import {EventsOn} from '../../wailsjs/runtime/runtime';
import type {RunConfig} from './config';

interface RunViewDeps {
    getConfig: () => RunConfig;
    getSelectedPlugins: () => string[];
    getPIDOptions: () => {enabled: boolean; pid: number};
}

interface PluginStartPayload {
    plugin: string;
}

interface PluginDonePayload {
    plugin: string;
    ok: boolean;
    seconds: number;
    error: string;
}

interface RunSummaryPayload {
    total: number;
    succeeded: number;
    failed: number;
    seconds: number;
}

interface MemProcfsStatusPayload {
    state: 'running' | 'scan-complete' | 'mounted' | 'stopped' | 'error';
    dbPath?: string;
    message: string;
}

interface MemNixFsStatusPayload {
    state: 'running' | 'scan-complete' | 'stopped' | 'error';
    exportDir?: string;
    message: string;
}

interface AnalyzerStatusPayload {
    state: 'running' | 'done' | 'error';
    message: string;
}

interface RunLogPayload {
    source: string;
    line: string;
}

const MAX_LOG_LINES = 500;

let unsubscribers: Array<() => void> = [];

function clearListeners() {
    unsubscribers.forEach((u) => u());
    unsubscribers = [];
}

function escapeHtml(s: string): string {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

let removePlanListener: (() => void) | undefined;
let removeMountListener: (() => void) | undefined;

export function renderRunView(container: HTMLElement, deps: RunViewDeps) {
    container.innerHTML = `
        <section class="panel">
            <h2>Run analysis</h2>
            <div class="run-toolbar">
                <button id="startBtn" class="btn-primary">Start run</button>
                <button id="skipBtn" class="btn-secondary" style="display:none;" title="Stop this tool and continue with the next.">Skip current tool</button>
                <button id="stopBtn" class="btn-secondary" style="display:none;" title="Stop all analysis">Stop entire run</button>
            </div>
            <div id="retainedMount" class="retained-mount" hidden>
                <span id="retainedMountLabel"></span>
                <button id="openRetainedMount" class="btn-secondary">Open mount</button>
                <button id="unmountRetained" class="btn-secondary">Unmount</button>
            </div>
            <p class="run-order">Select a memory image in Evidence.</p>
            <div class="overall-banner hint" id="overallBanner">Idle</div>
            <div class="progress-wrap" id="progressWrap" style="display:none;">
                <div class="progress-track"><div class="progress-fill" id="progressFill"></div></div>
                <span class="progress-text" id="progressText"></span>
            </div>
            <div class="activity-box" id="activityBox" style="display:none;">
                <div class="activity-line">
                    <span class="activity-spinner" id="activitySpinner" aria-hidden="true"></span>
                    <span class="activity-what" id="activityWhat">starting…</span>
                    <span class="activity-elapsed" id="activityElapsed"></span>
                </div>
                <div class="activity-detail" id="activityDetail"></div>
            </div>
            <div class="tool-status-row" id="memprocfsStatusRow">
                <span class="tool-status-label">MemProcFS:</span>
                <span id="memprocfsStatus" class="hint">not started</span>
            </div>
            <div class="tool-status-row" id="memnixfsStatusRow" style="display:none;">
                <span class="tool-status-label">MemNixFS:</span>
                <span id="memnixfsStatus" class="hint">not started</span>
            </div>
            <div class="tool-status-row" id="analyzerStatusRow" style="display:none;">
                <span class="tool-status-label">Analyzer:</span>
                <span id="analyzerStatus" class="hint">not started</span>
            </div>
            <div class="tool-status-row" id="vol2StatusRow" style="display:none;">
                <span class="tool-status-label">Volatility 2:</span>
                <span id="vol2Status" class="hint">not started</span>
            </div>
            <div class="run-list" id="runList"></div>
            <div id="runFooter"></div>
            <details class="log-details" open>
                <summary>Live console</summary>
                <p class="hint">Debug logs: output folder > debug-logs.</p>
                <pre class="log-pane" id="logPane"></pre>
            </details>
        </section>
    `;

    const startBtn = container.querySelector<HTMLButtonElement>('#startBtn')!;
    const stopBtn = container.querySelector<HTMLButtonElement>('#stopBtn')!;
    const skipBtn = container.querySelector<HTMLButtonElement>('#skipBtn')!;
    const bannerEl = container.querySelector<HTMLDivElement>('#overallBanner')!;
    const progressWrap = container.querySelector<HTMLDivElement>('#progressWrap')!;
    const progressFill = container.querySelector<HTMLDivElement>('#progressFill')!;
    const progressText = container.querySelector<HTMLSpanElement>('#progressText')!;
    const memprocfsStatusRow = container.querySelector<HTMLDivElement>('#memprocfsStatusRow')!;
    const memprocfsStatusEl = container.querySelector<HTMLSpanElement>('#memprocfsStatus')!;
    const memnixfsStatusRow = container.querySelector<HTMLDivElement>('#memnixfsStatusRow')!;
    const memnixfsStatusEl = container.querySelector<HTMLSpanElement>('#memnixfsStatus')!;
    const vol2StatusRow = container.querySelector<HTMLDivElement>('#vol2StatusRow')!;
    const vol2StatusEl = container.querySelector<HTMLSpanElement>('#vol2Status')!;
    const analyzerStatusRow = container.querySelector<HTMLDivElement>('#analyzerStatusRow')!;
    const analyzerStatusEl = container.querySelector<HTMLSpanElement>('#analyzerStatus')!;
    const activityBox = container.querySelector<HTMLDivElement>('#activityBox')!;
    const activityWhat = container.querySelector<HTMLSpanElement>('#activityWhat')!;
    const activityElapsed = container.querySelector<HTMLSpanElement>('#activityElapsed')!;
    const activityDetail = container.querySelector<HTMLDivElement>('#activityDetail')!;
    const activitySpinner = container.querySelector<HTMLSpanElement>('#activitySpinner')!;
    const listEl = container.querySelector<HTMLDivElement>('#runList')!;
    const footerEl = container.querySelector<HTMLDivElement>('#runFooter')!;
    const logPane = container.querySelector<HTMLPreElement>('#logPane')!;
    let retainedPath = '';
    const mountBox = container.querySelector<HTMLElement>('#retainedMount')!;
    async function refreshRetainedMount() {
        try {
            retainedPath = await GetRetainedMountPath();
            mountBox.hidden = !retainedPath;
            startBtn.disabled = !!retainedPath;
            container.querySelector('#retainedMountLabel')!.textContent = `Mount open: ${retainedPath}. Copy required files before unmounting. Unmount to start another run.`;
        } catch (err) { bannerEl.textContent = String(err); }
    }
    container.querySelector('#openRetainedMount')!.addEventListener('click', async () => {
        try { if (retainedPath) await OpenOutputFolder(retainedPath); }
        catch (err) { bannerEl.textContent = String(err); }
    });
    container.querySelector<HTMLButtonElement>('#unmountRetained')!.addEventListener('click', async event => {
        const button = event.currentTarget as HTMLButtonElement;
        button.disabled = true;
        try { if (retainedPath) await CleanupMemProcfsMount(retainedPath); await refreshRetainedMount(); }
        catch (err) { bannerEl.textContent = String(err); }
        finally { button.disabled = false; }
    });
    void refreshRetainedMount();
    removeMountListener?.();
    removeMountListener = EventsOn('mounts:changed', refreshRetainedMount);

    const rows = new Map<string, HTMLElement>();
    let vol3Failed = 0;
    let memprocfsMessage = 'not started';
    let memnixfsMessage = 'not started';
    // Which mount tool this run actually uses — decides which of the two
    // messages above updateBanner shows. Set once, when Start is pressed.
    let isLinuxRun = false;
    let activeOS = '';
    let hasVol2 = false;
    let hasVol3 = false;
    let analyzerEnabled = false;
    function refreshPlan(os?: string) {
        const cfg = deps.getConfig();
        const detected = document.getElementById('imageOSDetected');
        activeOS = os || (stopBtn.style.display !== 'none' ? activeOS : '') || (!cfg.imageOS ? (detected?.dataset.path === cfg.imagePath.trim() ? detected.dataset.os || '' : '') : cfg.imageOS);
        isLinuxRun = activeOS === 'linux';
        const counts = selectedFrameworkCounts();
        if (stopBtn.style.display === 'none') {
            hasVol2 = counts.vol2 > 0;
            hasVol3 = counts.vol3 > 0;
            analyzerEnabled = cfg.includeAnalyzer;
        }
        memprocfsStatusRow.style.display = activeOS === 'windows' ? '' : 'none';
        memnixfsStatusRow.style.display = isLinuxRun ? '' : 'none';
        analyzerStatusRow.style.display = activeOS === 'windows' && analyzerEnabled ? '' : 'none';
        vol2StatusRow.style.display = hasVol2 ? '' : 'none';
        const tools = [hasVol2 ? 'Volatility 2' : '', hasVol3 ? 'Volatility 3' : '',
            activeOS === 'windows' ? 'MemProcFS' : isLinuxRun ? 'MemNixFS' : '',
            activeOS === 'windows' && analyzerEnabled ? 'Analyzer' : ''].filter(Boolean);
        container.querySelector('.run-order')!.textContent = tools.length ? `Run order: ${tools.join(' → ')}` : 'Select a memory image in Evidence.';
    }
    removePlanListener?.();
    const planChanged = () => { if (stopBtn.style.display === 'none') refreshPlan(); };
    document.addEventListener('run-plan-changed', planChanged);
    removePlanListener = () => document.removeEventListener('run-plan-changed', planChanged);
    refreshPlan();

    // --- live activity tracking -------------------------------------------
    // The core problem this solves: several stages (vol2's imageinfo above
    // all) produce no output for minutes at a time, so a working run and a
    // hung one looked identical. Three things now distinguish them: a
    // client-side elapsed clock that ticks every second, the latest streamed
    // line from the tool, and a backend heartbeat proving the child process
    // is still being waited on.
    let activityLabel = '';
    let activityStart = 0;
    let lastHeartbeat = 0;
    let runStart = 0;
    let ticker: number | undefined;
    let currentPhaseLabel = '';

    function fmtDuration(seconds: number): string {
        if (seconds < 60) return `${seconds.toFixed(0)}s`;
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        if (m < 60) return `${m}m ${String(s).padStart(2, '0')}s`;
        return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, '0')}m`;
    }

    const SPINNER = ['.', '..', '...'];
    let spinnerIdx = 0;

    function tick() {
        if (!activityLabel) return;
        const elapsed = (Date.now() - activityStart) / 1000;
        const total = runStart ? (Date.now() - runStart) / 1000 : 0;
        activityElapsed.textContent = `${fmtDuration(elapsed)} (run total ${fmtDuration(total)})`;
        spinnerIdx = (spinnerIdx + 1) % SPINNER.length;
        activitySpinner.textContent = SPINNER[spinnerIdx];

        // If a tool has gone quiet for a long stretch, say so explicitly
        // rather than leaving the user to guess.
        const sinceBeat = lastHeartbeat ? (Date.now() - lastHeartbeat) / 1000 : 0;
        if (lastHeartbeat && sinceBeat > 12) {
            activityDetail.innerHTML =
                `<span class="status-error">No response for ${fmtDuration(sinceBeat)}. The tool may be stuck.</span>`;
        }

        // Keep the elapsed time on every still-running row current too.
        for (const [name, el] of rows) {
            const startedAt = Number(el.dataset.startedAt || 0);
            if (!startedAt) continue;
            const detail = el.querySelector<HTMLElement>('.run-row-detail')!;
            if (el.dataset.finished === '1') continue;
            const secs = (Date.now() - startedAt) / 1000;
            detail.textContent = `running… ${fmtDuration(secs)}${el.dataset.progress ? `; ${el.dataset.progress}` : ''}`;
            void name;
        }
    }

    function startActivity(label: string) {
        activityLabel = label;
        activityStart = Date.now();
        lastHeartbeat = 0;
        activityWhat.textContent = label;
        activityDetail.textContent = '';
        activityBox.style.display = '';
        if (ticker === undefined) ticker = window.setInterval(tick, 1000);
        tick();
    }

    function stopActivity() {
        activityLabel = '';
        if (ticker !== undefined) {
            window.clearInterval(ticker);
            ticker = undefined;
        }
        activityBox.style.display = 'none';
    }

    // Plugin progress spans both frameworks: vol2 runs first, then vol3, and
    // the bar covers the pair so it doesn't reset to 0% halfway through a run.
    let pluginsTotal = 0;
    let pluginsDone = 0;

    function updateProgress() {
        if (pluginsTotal === 0) {
            progressWrap.style.display = 'none';
            return;
        }
        progressWrap.style.display = '';
        const pct = Math.min(100, Math.round((pluginsDone / pluginsTotal) * 100));
        progressFill.style.width = `${pct}%`;
        progressFill.classList.toggle('progress-error', vol3Failed > 0);

        let eta = '';
        // Only estimate once a few plugins have finished — extrapolating from
        // one sample on a run where plugin durations vary by orders of
        // magnitude produces a number worse than none at all.
        if (pluginsDone >= 3 && pluginsDone < pluginsTotal && runStart) {
            const perPlugin = (Date.now() - runStart) / 1000 / pluginsDone;
            eta = ` · ~${fmtDuration(perPlugin * (pluginsTotal - pluginsDone))} left`;
        }
        progressText.textContent = `${pluginsDone}/${pluginsTotal} plugins${vol3Failed ? ` · ${vol3Failed} failed` : ''}${eta}`;
    }

    function updateBanner() {
        const parts = [];
        if (activeOS === 'linux') parts.push(`MemNixFS: ${memnixfsMessage}`);
        if (activeOS === 'windows') parts.push(`MemProcFS: ${memprocfsMessage}`);
        if (hasVol2 || hasVol3) parts.push(`${hasVol2 && hasVol3 ? 'Volatility 2/3' : hasVol2 ? 'Volatility 2' : 'Volatility 3'}: ${pluginsDone}/${pluginsTotal} plugins done`);
        bannerEl.textContent = parts.join(' · ') || 'Preparing analysis';
        bannerEl.className = `overall-banner ${vol3Failed > 0 ? 'status-error' : 'hint'}`;
    }

    function addRow(plugin: string) {
        const wrapper = document.createElement('div');
        wrapper.innerHTML = `
            <div class="run-row" data-plugin="${escapeHtml(plugin)}">
                <span class="run-row-icon run-row-running">Running</span>
                <span class="run-row-name">${escapeHtml(plugin)}</span>
                <span class="run-row-detail hint">running&hellip;</span>
            </div>
        `.trim();
        const el = wrapper.firstElementChild as HTMLElement;
        el.dataset.startedAt = String(Date.now());
        listEl.prepend(el);
        rows.set(plugin, el);
    }

    function updateRow(plugin: string, ok: boolean, seconds: number, error: string) {
        const el = rows.get(plugin);
        if (!el) return;
        el.dataset.finished = '1';
        const icon = el.querySelector<HTMLElement>('.run-row-icon')!;
        const detail = el.querySelector<HTMLElement>('.run-row-detail')!;
        icon.textContent = ok ? 'OK' : 'Error';
        icon.className = `run-row-icon ${ok ? 'run-row-ok' : 'run-row-error'}`;
        detail.textContent = ok ? `done in ${seconds.toFixed(1)}s` : error || 'failed';
        detail.className = `run-row-detail ${ok ? '' : 'status-error'}`;
    }

    // Ring buffer of log lines: rebuilding the pane from a bounded array
    // beats the old approach (append to textContent, then split the whole
    // pane on '\n' every line), which was O(pane size) per line and forced
    // a full re-layout of an ever-growing string. MemProcFS alone can emit
    // thousands of lines over a long run.
    const logLines: string[] = [];
    function appendLog(source: string, line: string) {
        const atBottom = logPane.scrollTop + logPane.clientHeight >= logPane.scrollHeight - 4;
        logLines.push(`[${source}] ${line}`);
        if (logLines.length > MAX_LOG_LINES) logLines.splice(0, logLines.length - MAX_LOG_LINES);
        logPane.textContent = logLines.join('\n') + '\n';
        if (atBottom) logPane.scrollTop = logPane.scrollHeight;
    }

    startBtn.addEventListener('click', async () => {
        const cfg = deps.getConfig();
        const selected = deps.getSelectedPlugins();
        const pid = deps.getPIDOptions();

        rows.clear();
        listEl.innerHTML = '';
        logLines.length = 0;
        logPane.textContent = '';
        runStart = Date.now();
        startActivity('starting run…');
        pluginsTotal = selected.length;
        pluginsDone = 0;
        vol3Failed = 0;
        memprocfsMessage = 'not started';
        memnixfsMessage = 'not started';
        updateBanner();
        refreshPlan();
        memnixfsStatusEl.textContent = 'Queued';
        memprocfsStatusEl.textContent = 'Queued';
        analyzerStatusEl.textContent = 'Queued';
        vol2StatusEl.textContent = 'Queued';
        updateBanner();
        startBtn.style.display = 'none';
        stopBtn.style.display = '';
        stopBtn.disabled = false;
        footerEl.innerHTML = `<button id="openOutputBtn" class="btn-secondary">Open output folder</button>`;
        footerEl.querySelector<HTMLButtonElement>('#openOutputBtn')!.addEventListener('click', () => {
            OpenOutputFolder(cfg.outputDir);
        });

        clearListeners();
        unsubscribers.push(
            EventsOn('vol3:plugin-start', (payload: PluginStartPayload) => {
                addRow(payload.plugin);
                startActivity(payload.plugin);
            }),
        );
        // Streamed tool output: vol repaints a progress line with carriage
        // returns, so this is where "34.12% Scanning…" style updates arrive.
        unsubscribers.push(
            EventsOn('tool:progress', (p: {tool: string; item: string; text: string}) => {
                if (activityLabel) activityDetail.textContent = p.text;
                const el = rows.get(p.item);
                if (el) el.dataset.progress = p.text;
            }),
        );
        // Heartbeat from the goroutine waiting on the child process — proof
        // of life for stages that print nothing at all.
        unsubscribers.push(
            EventsOn('tool:heartbeat', (p: {tool: string; item: string; seconds: number}) => {
                lastHeartbeat = Date.now();
                if (activityLabel && !activityDetail.textContent) {
                    activityDetail.textContent = `${p.tool} running. No output yet.`;
                }
            }),
        );
        unsubscribers.push(
            EventsOn('vol3:plugin-done', (payload: PluginDonePayload) => {
                updateRow(payload.plugin, payload.ok, payload.seconds, payload.error);
                pluginsDone++;
                updateProgress();
                if (!payload.ok) vol3Failed++;
                updateBanner();
            }),
        );
        unsubscribers.push(
            EventsOn('vol3:all-done', (_summary: RunSummaryPayload) => {
                updateBanner();
            }),
        );
        unsubscribers.push(
            EventsOn('memprocfs:status', (payload: MemProcfsStatusPayload) => {
                refreshPlan('windows');
                memprocfsMessage = payload.message;
                if (payload.state === 'running') startActivity('MemProcFS forensic scan');
                if (payload.state === 'scan-complete' || payload.state === 'error') stopActivity();
                if (payload.state === 'stopped' || payload.state === 'error') void refreshRetainedMount();
                memprocfsStatusEl.textContent = payload.message;
                memprocfsStatusEl.className = payload.state === 'error' ? 'status-error' : payload.state === 'scan-complete' ? 'status-ok' : 'hint';
                updateBanner();
            }),
        );
        unsubscribers.push(
            EventsOn('memnixfs:status', (payload: MemNixFsStatusPayload) => {
                refreshPlan('linux');
                memnixfsMessage = payload.message;
                if (payload.state === 'running') startActivity('MemNixFS analysis');
                if (payload.state === 'scan-complete' || payload.state === 'error') stopActivity();
                memnixfsStatusEl.textContent = payload.message;
                memnixfsStatusEl.className = payload.state === 'error' ? 'status-error' : payload.state === 'scan-complete' ? 'status-ok' : 'hint';
                updateBanner();
            }),
        );
        unsubscribers.push(
            EventsOn('analyzer:status', (payload: AnalyzerStatusPayload) => {
                analyzerStatusEl.textContent = payload.message;
                analyzerStatusEl.className = payload.state === 'error' ? 'status-error' : payload.state === 'done' ? 'status-ok' : 'hint';
            }),
        );
        unsubscribers.push(
            EventsOn('vol2:status', (payload: {state: string; message: string}) => {
                vol2StatusRow.style.display = hasVol2 ? '' : 'none';
                vol2StatusEl.textContent = payload.message;
                vol2StatusEl.className = payload.state === 'error' ? 'status-error' : payload.state === 'profiled' ? 'status-ok' : 'hint';
                // imageinfo is the stage that most looks hung; give it its
                // own activity entry so the clock is visibly running.
                if (payload.state === 'profiling') startActivity('Volatility 2: imageinfo (profile detection)');
            }),
        );
        unsubscribers.push(
            EventsOn('vol2:all-done', (summary: RunSummaryPayload) => {
                vol2StatusRow.style.display = hasVol2 ? '' : 'none';
                vol2StatusEl.textContent = `${summary.succeeded}/${summary.total} plugins done${summary.failed ? ` (${summary.failed} failed)` : ''} in ${summary.seconds.toFixed(1)}s`;
                vol2StatusEl.className = summary.failed ? 'status-error' : 'status-ok';
            }),
        );
        unsubscribers.push(
            EventsOn('run:log', (payload: RunLogPayload) => {
                appendLog(payload.source, payload.line);
            }),
        );
        // Kernel-symbol resolution runs before MemNixFS on a Linux image and
        // reports on its own channel; without this its progress (which banner
        // matched, what was downloaded) would never reach the log pane.
        unsubscribers.push(
            EventsOn('symbols:log', (payload: {line: string}) => {
                appendLog('symbols', payload.line);
            }),
        );
        // The backend announces which tool is active; the Skip button names
        // it so it is unambiguous what pressing it abandons.
        unsubscribers.push(
            EventsOn('run:phase', (p: {phase: string; label: string}) => {
                if (p.phase === 'memprocfs') refreshPlan('windows');
                if (p.phase === 'memnixfs') refreshPlan('linux');
                currentPhaseLabel = p.label;
                skipBtn.textContent = `Skip ${p.label}`;
                skipBtn.disabled = false;
                skipBtn.style.display = '';
            }),
        );
        unsubscribers.push(
            EventsOn('run:finished', () => {
                stopActivity();
                skipBtn.style.display = 'none';
                bannerEl.textContent = `${bannerEl.textContent} · finished in ${fmtDuration((Date.now() - runStart) / 1000)}`;
                startBtn.style.display = '';
                stopBtn.style.display = 'none';
                void refreshRetainedMount();
            }),
        );

        try {
            document.dispatchEvent(new CustomEvent('run-state-changed', {detail: true}));
            await StartRun({
                volPath: cfg.volPath,
                vol2Path: cfg.vol2Path,
                memProcfsPath: cfg.memProcfsPath,
                memNixFsPath: cfg.memNixFsPath,
                analyzerPath: cfg.analyzerPath,
                imagePath: cfg.imagePath,
                outputDir: cfg.outputDir,
                selectedPlugins: selected,
                includeAnalyzer: cfg.includeAnalyzer,
                vol2Profile: cfg.vol2Profile,
                imageOS: cfg.imageOS,
                autoFetchLinuxSymbols: cfg.autoFetchLinuxSymbols,
                pidEnabled: pid.enabled,
                targetPID: pid.pid,
                yaraRulesPath: cfg.yaraRulesPath,
                caseID: cfg.caseID,
                analyst: cfg.analyst,
            });
        } catch (err) {
            document.dispatchEvent(new CustomEvent('run-state-changed', {detail: false}));
            stopActivity();
            bannerEl.textContent = `Failed to start: ${String(err)}`;
            bannerEl.className = 'overall-banner status-error';
            startBtn.style.display = '';
            stopBtn.style.display = 'none';
            skipBtn.style.display = 'none';
        }
    });

    skipBtn.addEventListener('click', async () => {
        const label = currentPhaseLabel || 'this tool';
        skipBtn.disabled = true;
        skipBtn.textContent = `Skipping ${label}…`;
        appendLog('app', `skip requested for ${label}`);
        try {
            await SkipPhase();
        } catch (err) {
            appendLog('app', `skip failed: ${String(err)}`);
            skipBtn.disabled = false;
            skipBtn.textContent = `Skip ${label}`;
        }
    });

    stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true;
        skipBtn.style.display = 'none';
        memprocfsMessage = 'stopping…';
        updateBanner();
        try {
            await StopRun();
        } catch (err) {
            console.error(err);
        }
    });
}

