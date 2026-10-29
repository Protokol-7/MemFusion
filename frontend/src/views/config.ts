import {BrowseForDirectory, BrowseForFile, CheckPrerequisites, CheckToolUpdates, DetectImageOS, GenerateLinuxISF, InstallDependencies, InstallTools, ValidateToolPaths} from '../../wailsjs/go/main/App';
import {EventsOn} from '../../wailsjs/runtime/runtime';
import {BrowseMemoryImage} from '../../wailsjs/go/main/App';
import type {config, installer} from '../../wailsjs/go/models';

interface InstallProgressPayload {
    tool: string;
    state: 'running' | 'done' | 'error' | 'skipped';
    percent: number;
    message: string;
}

const STORAGE_KEY = 'memforensics-gui.config.v1';

export interface RunConfig {
    caseID: string;
    analyst: string;
    volPath: string;
    vol2Path: string;
    memProcfsPath: string;
    memNixFsPath: string;
    analyzerPath: string;
    imagePath: string;
    outputDir: string;
    includeAnalyzer: boolean;
    vol2Profile: string;
    // '' = auto-detect from the image, otherwise 'windows' | 'linux'.
    imageOS: string;
    // Whether linux.* plugins may try vol3's --remote-isf-url mechanism
    // against the community sources in internal/volatility/remoteisf.go when
    // no local symbol pack matches the image's exact kernel.
    autoFetchLinuxSymbols: boolean;
    // Used by the generic Volatility YARA scanners. Custom YARA plugins ship
    // their own rules and do not consume this file.
    yaraRulesPath: string;
}

const defaults: RunConfig = {
    caseID: '',
    analyst: '',
    volPath: '',
    vol2Path: '',
    memProcfsPath: '',
    memNixFsPath: '',
    analyzerPath: '',
    imagePath: '',
    outputDir: '',
    includeAnalyzer: false,
    vol2Profile: '',
    imageOS: '',
    autoFetchLinuxSymbols: true,
    yaraRulesPath: '',
};

export function loadConfig(): RunConfig {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return {...defaults};
        return {...defaults, ...JSON.parse(raw)};
    } catch {
        return {...defaults};
    }
}

function saveConfig(cfg: RunConfig) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(cfg));
    } catch {
        // best-effort only — a per-viewer convenience, not critical state
    }
}

// Renders the prerequisite report — third-party software the tools need but
// this app deliberately does not install (kernel drivers, runtimes, AV).
async function prerequisiteHtml(): Promise<string> {
    let report;
    try {
        report = await CheckPrerequisites();
    } catch {
        return '';
    }
    const problems = report.checks.filter((c) => !c.present);
    if (problems.length === 0) {
        return '<div class="status-row status-ok"><span class="status-icon">OK</span>' +
            `<span class="status-label">Prerequisites</span><span class="status-message">all satisfied on ${escapeHtml(report.platform)}</span></div>`;
    }
    const rows = problems.map((c) => {
        const cls = c.required ? 'status-error' : 'status-empty';
        const tag = c.required ? 'required' : 'optional';
        return `<div class="status-row ${cls}">
            <span class="status-icon">${c.required ? 'Error' : '!'}</span>
            <span class="status-label">${escapeHtml(c.tool)}</span>
            <span class="status-message"><strong>${escapeHtml(c.name)}</strong> missing (${tag}); ${escapeHtml(c.detail)}<br><span class="hint">${escapeHtml(c.howTo)}</span></span>
        </div>`;
    });
    return `<div class="prereq-block"><p class="hint">Missing components. Try Install dependencies.</p>${rows.join('')}</div>`;
}

function statusRow(label: string, status: config.ToolStatus): string {
    const ok = status.probeOk;
    const icon = ok ? 'OK' : (status.path ? 'Error' : '-');
    const cls = ok ? 'status-ok' : (status.path ? 'status-error' : 'status-empty');
    const message = ok ? status.detail : (status.error || status.detail || 'not checked yet');
    return `
        <div class="status-row ${cls}">
            <span class="status-icon">${icon}</span>
            <span class="status-label">${label}</span>
            <span class="status-message">${escapeHtml(message)}</span>
        </div>
    `;
}

function escapeHtml(s: string): string {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

// renderDepsSummary turns a dependency install into something actionable:
// what went in, what is still missing, and — for the plugins a failed package
// costs — exactly which ones stop working. Anything that succeeded is
// collapsed into a count, since the useful signal is the failures.
function renderDepsSummary(res: installer.DepsResult): string {
    const parts: string[] = [];

    const sysFailed = (res.system || []).filter(d => !d.ok && !d.skipped);
    const sysOk = (res.system || []).filter(d => d.ok);
    if (sysOk.length) {
        const already = sysOk.filter(d => d.alreadyThere).length;
        parts.push(`<p class="hint">System components: ${sysOk.length} ready${already ? ` (${already} already installed)` : ''}.</p>`);
    }
    if (sysFailed.length) {
        const rows = sysFailed.map(d => `<li><strong>${escapeHtml(d.name)}</strong>${d.required ? ' <span class="status-error">(required)</span>' : ' (optional)'}; ${escapeHtml(d.detail)}${d.manualCommand ? `<br><span class="hint">Install manually: ${escapeHtml(d.manualCommand)}</span>` : ''}</li>`).join('');
        parts.push(`<p class="status-error">Could not install automatically:</p><ul class="deps-list">${rows}</ul>`);
    }

    const pkgs = res.packages || [];
    const pkgOk = pkgs.filter(p => p.ok).length;
    const pkgFailed = pkgs.filter(p => !p.ok && !p.skipped);
    parts.push(`<p class="hint">Python packages: ${pkgOk}/${pkgs.length} installed into ${escapeHtml(res.python || 'the app environment')}.</p>`);
    if (pkgFailed.length) {
        const rows = pkgFailed.map(p => `<li><strong>${escapeHtml(p.name)}</strong> failed; unavailable: ${escapeHtml(p.affects)}</li>`).join('');
        parts.push(`<p class="status-error">These packages did not install:</p><ul class="deps-list">${rows}</ul>`);
    }

    const packs = res.symbolPacks || [];
    const packsFailed = packs.filter(p => !p.ok);
    if (packs.length) {
        const already = packs.filter(p => p.skipped).length;
        parts.push(`<p class="hint">Volatility 3 symbol packs: ${packs.length - packsFailed.length}/${packs.length} ready${already ? ` (${already} already downloaded)` : ''}.</p>`);
    }
    if (packsFailed.length) {
        const rows = packsFailed.map(p => `<li><strong>${escapeHtml(p.os)}</strong> failed; ${escapeHtml(p.detail)}</li>`).join('');
        parts.push(`<p class="status-error">Symbol download failed. Some plugins may not run:</p><ul class="deps-list">${rows}</ul>`);
    }
    return parts.join('');
}

function renderUpdateReport(report: installer.UpdateReport): string {
    return (report.tools || []).map((tool) => {
        let icon = '-';
        let cls = 'status-empty';
        let message = 'not installed';
        if (tool.error) {
            icon = '!';
            cls = 'status-empty';
            message = `${tool.installed ? `Installed${tool.installedVersion ? ' '+tool.installedVersion : ''}. ` : ''}Update check unavailable: ${tool.error}`;
        } else if (tool.updateAvailable) {
            icon = '↑';
            cls = 'status-update';
            message = `${tool.installedVersion} installed · ${tool.latestVersion} available`;
        } else if (tool.installed) {
            icon = 'OK';
            cls = 'status-ok';
            message = tool.installedVersion
                ? `${tool.installedVersion} · current`
                : `installed · latest release is ${tool.latestVersion}`;
        }
        return `<div class="status-row ${cls}">
            <span class="status-icon">${icon}</span>
            <span class="status-label">${escapeHtml(tool.tool)}</span>
            <span class="status-message">${escapeHtml(message)}</span>
        </div>`;
    }).join('');
}

export function renderConfigView(container: HTMLElement, onValidated: (ok: boolean, cfg: RunConfig) => void) {
    const cfg = loadConfig();

    container.innerHTML = `
        <section class="panel">
            <h2>Evidence &amp; tools</h2>
            <div class="setup-details" id="toolSetup">
                <h3>Tool setup</h3>
                <p class="hint">Install dependencies first, then tools.</p>
            <div class="install-box">
                <div class="install-heading">
                    <div>
                        <strong>Tool maintenance</strong>
                        <div class="hint">Checks official GitHub releases.</div>
                    </div>
                    <button id="checkUpdatesBtn" class="btn-secondary">Check updates</button>
                </div>
                <div id="updateStatus" class="update-status hint">Checking installed versions…</div>
                <div class="install-row">
                    <button id="installDepsBtn" class="btn-primary">Install dependencies</button>
                    <span id="installDepsHint" class="hint">Installs required software and Python packages.</span>
                </div>
                <div class="install-row install-row-second">
                    <button id="installToolsBtn" class="btn-primary">Install / update tools</button>
                    <span id="installHint" class="hint">Installs or updates tools and detection rules.</span>
                </div>
                <div id="installProgress" class="install-progress" style="display:none;"></div>
                <div id="depsSummary" class="deps-summary" style="display:none;"></div>
                <details class="log-details" id="installLogDetails" style="display:none;">
                    <summary>Install log</summary>
                    <pre class="log-pane" id="installLog"></pre>
                </details>
            </div>
            <h3 class="section-title">Tool paths</h3>
            <div class="field-row">
                <label for="volPath">Volatility 3</label>
                <div class="input-with-button">
                    <input id="volPath" type="text" placeholder="Select vol.exe or use Install / update tools" value="${escapeHtml(cfg.volPath)}" />
                    <button id="browseVol" class="btn-secondary">Browse</button>
                </div>
            </div>
            <div class="field-row">
                <label for="vol2Path">Volatility 2 executable <span class="hint">(optional)</span></label>
                <div class="input-with-button">
                    <input id="vol2Path" type="text" placeholder="Select the Volatility 2 Windows executable" value="${escapeHtml(cfg.vol2Path)}" />
                    <button id="browseVol2" class="btn-secondary">Browse</button>
                </div>
            </div>
            <div class="field-row">
                <label for="memProcfsPath">MemProcFS executable <span class="hint">(Windows images)</span></label>
                <div class="input-with-button">
                    <input id="memProcfsPath" type="text" placeholder="Select MemProcFS.exe or use Install / update tools" value="${escapeHtml(cfg.memProcfsPath)}" />
                    <button id="browseMemProcfs" class="btn-secondary">Browse</button>
                </div>
            </div>
            <div class="field-row">
                <label for="memNixFsPath">MemNixFS executable <span class="hint">(Linux images)</span></label>
                <div class="input-with-button">
                    <input id="memNixFsPath" type="text" placeholder="C:\\Tools\\MemNixFS\\memnixfs.exe" value="${escapeHtml(cfg.memNixFsPath)}" />
                    <button id="browseMemNixFs" class="btn-secondary">Browse</button>
                </div>
            </div>
            <div class="field-row">
                <label for="includeAnalyzer">MemProcFS-Analyzer</label>
                <div class="checkbox-row">
                    <input id="includeAnalyzer" type="checkbox" ${cfg.includeAnalyzer ? 'checked' : ''} />
                    <label for="includeAnalyzer" id="includeAnalyzerLabel">Run after MemProcFS</label>
                </div>
            </div>
            <div class="field-row" id="analyzerPathRow">
                <label for="analyzerPath">MemProcFS-Analyzer.ps1</label>
                <div class="input-with-button">
                    <input id="analyzerPath" type="text" placeholder="C:\\Tools\\MemProcFS-Analyzer\\MemProcFS-Analyzer.ps1" value="${escapeHtml(cfg.analyzerPath)}" />
                    <button id="browseAnalyzer" class="btn-secondary">Browse</button>
                </div>
            </div>
            </div>

            <h3 class="section-title">Case</h3>
            <div class="field-row">
                <label for="caseID">Case / ticket</label>
                <div class="input-with-button">
                    <input id="caseID" type="text" value="${escapeHtml(cfg.caseID)}" />
                </div>
            </div>
            <div class="field-row">
                <label for="analyst">Analyst</label>
                <div class="input-with-button">
                    <input id="analyst" type="text" value="${escapeHtml(cfg.analyst)}" />
                </div>
            </div>
            <div class="field-row">
                <label for="imagePath">Memory image</label>
                <div class="input-with-button">
                    <input id="imagePath" type="text" placeholder="Select a memory image" value="${escapeHtml(cfg.imagePath)}" />
                    <button id="browseImage" class="btn-secondary">Browse</button>
                    <button id="browseShare" class="btn-secondary">Browse shared folder</button>
                </div>
            </div>
            <div class="field-row">
                <label for="imageOS">Image OS</label>
                <div class="input-with-button">
                    <select id="imageOS">
                        <option value="">Auto-detect</option>
                        <option value="windows">Windows (MemProcFS)</option>
                        <option value="linux">Linux (MemNixFS)</option>
                    </select>
                    <span id="imageOSDetected" class="hint"></span>
                </div>
            </div>
            <div class="field-row">
                <label for="autoFetchLinuxSymbols">Linux kernel symbols</label>
                <div class="checkbox-row">
                    <input id="autoFetchLinuxSymbols" type="checkbox" ${cfg.autoFetchLinuxSymbols ? 'checked' : ''} />
                    <label for="autoFetchLinuxSymbols" id="autoFetchLinuxSymbolsLabel">Download missing Linux symbols</label>
                </div>
                <span class="hint">Requires internet. Local symbols are checked first.</span>
            </div>
            <div class="field-row">
                <label for="vol2Profile">Volatility 2 profile <span class="hint">(automatic if blank)</span></label>
                <div class="input-with-button">
                    <input id="vol2Profile" type="text" placeholder="e.g. Win10x64_19041" value="${escapeHtml(cfg.vol2Profile)}" />
                </div>
            </div>
            <div class="field-row">
                <label for="yaraRulesPath">YARA rules file</label>
                <div class="input-with-button">
                    <input id="yaraRulesPath" type="text" placeholder="C:\\Rules\\triage.yar" value="${escapeHtml(cfg.yaraRulesPath)}" />
                    <button id="browseYaraRules" class="btn-secondary">Browse</button>
                </div>
                <span class="hint">Required for generic YARA scanner plugins.</span>
            </div>
            <div class="field-row">
                <label for="outputDir">Output directory</label>
                <div class="input-with-button">
                    <input id="outputDir" type="text" placeholder="Select a folder for results and debug logs" value="${escapeHtml(cfg.outputDir)}" />
                    <button id="browseOutput" class="btn-secondary">Browse</button>
                </div>
            </div>
            <details class="log-details">
                <summary>Generate Linux symbols</summary>
                <p class="hint">Use a kernel debug package (.rpm or .ddeb) when automatic symbol lookup fails. Requires 7-Zip and dwarf2json.</p>
                <div class="field-row">
                    <label for="isfPackagePath">Kernel debug package</label>
                    <div class="input-with-button">
                        <input id="isfPackagePath" type="text" placeholder="C:\\Downloads\\kernel-debuginfo-5.14.0-70.13.1.el9_0.x86_64.rpm" />
                        <button id="browseIsfPackage" class="btn-secondary">Browse</button>
                    </div>
                </div>
            <div class="actions">
                    <button id="generateIsfBtn" class="btn-secondary">Extract &amp; generate ISF</button>
                </div>
                <div id="isfGenStatus" class="hint"></div>
                <pre class="log-pane" id="isfGenLog" style="display:none;"></pre>
            </details>
            <div class="actions">
                <button id="validateBtn" class="btn-primary">Check tools and continue</button>
            </div>
            <div id="statusArea"></div>
        </section>
    `;

    // Keep every control in this container so existing setup and validation
    // handlers continue to work, while separating evidence from maintenance.
    const panel = container.querySelector<HTMLElement>('.panel')!;
    const setup = container.querySelector<HTMLElement>('#toolSetup')!;
    const grid = document.createElement('div');
    grid.className = 'config-grid';
    const evidence = document.createElement('div');
    evidence.className = 'evidence-column';
    for (const child of Array.from(panel.children)) {
        if (child !== setup && child.tagName !== 'H2') evidence.appendChild(child);
    }
    const pathsTitle = setup.querySelector<HTMLElement>('.section-title')!;
    const pathDetails = document.createElement('details');
    pathDetails.className = 'tool-paths';
    pathDetails.innerHTML = '<summary>Executable paths</summary>';
    while (pathsTitle.nextElementSibling) pathDetails.appendChild(pathsTitle.nextElementSibling);
    pathsTitle.remove();
    setup.appendChild(pathDetails);
    // Analyzer is an analysis option, not an executable-path setting.
    const analyzerOption = pathDetails.querySelector('#includeAnalyzer')!.closest('.field-row')!;
    const actions = evidence.querySelector('#validateBtn')!.closest('.actions')!;
    evidence.insertBefore(analyzerOption, actions);
    grid.append(evidence, setup);
    panel.appendChild(grid);

    const volInput = container.querySelector<HTMLInputElement>('#volPath')!;
    const vol2Input = container.querySelector<HTMLInputElement>('#vol2Path')!;
    const vol2ProfileInput = container.querySelector<HTMLInputElement>('#vol2Profile')!;
    const imageOSSelect = container.querySelector<HTMLSelectElement>('#imageOS')!;
    const imageOSDetected = container.querySelector<HTMLSpanElement>('#imageOSDetected')!;
    const autoFetchLinuxSymbolsCheckbox = container.querySelector<HTMLInputElement>('#autoFetchLinuxSymbols')!;
    const memProcfsInput = container.querySelector<HTMLInputElement>('#memProcfsPath')!;
    const memNixFsInput = container.querySelector<HTMLInputElement>('#memNixFsPath')!;
    const analyzerInput = container.querySelector<HTMLInputElement>('#analyzerPath')!;
    const analyzerCheckbox = container.querySelector<HTMLInputElement>('#includeAnalyzer')!;
    const browseAnalyzerBtn = container.querySelector<HTMLButtonElement>('#browseAnalyzer')!;
    const imageInput = container.querySelector<HTMLInputElement>('#imagePath')!;
    const outputInput = container.querySelector<HTMLInputElement>('#outputDir')!;
    const yaraRulesInput = container.querySelector<HTMLInputElement>('#yaraRulesPath')!;
    const statusArea = container.querySelector<HTMLDivElement>('#statusArea')!;
    const validateBtn = container.querySelector<HTMLButtonElement>('#validateBtn')!;

    const currentConfig = (): RunConfig => ({
        volPath: volInput.value.trim(),
        vol2Path: vol2Input.value.trim(),
        memProcfsPath: memProcfsInput.value.trim(),
        memNixFsPath: memNixFsInput.value.trim(),
        analyzerPath: analyzerInput.value.trim(),
        imagePath: imageInput.value.trim(),
        outputDir: outputInput.value.trim(),
        includeAnalyzer: analyzerCheckbox.checked,
        vol2Profile: vol2ProfileInput.value.trim(),
        imageOS: imageOSSelect.value,
        autoFetchLinuxSymbols: autoFetchLinuxSymbolsCheckbox.checked,
        yaraRulesPath: yaraRulesInput.value.trim(),
        caseID: container.querySelector<HTMLInputElement>('#caseID')!.value.trim(),
        analyst: container.querySelector<HTMLInputElement>('#analyst')!.value.trim(),
    });

    imageOSSelect.value = cfg.imageOS;

    const persist = () => { saveConfig(currentConfig()); document.dispatchEvent(new Event('run-plan-changed')); };
    container.querySelector('#caseID')!.addEventListener('change', persist);
    container.querySelector('#analyst')!.addEventListener('change', persist);
    [volInput, vol2Input, memProcfsInput, memNixFsInput, analyzerInput, imageInput, outputInput, yaraRulesInput,
     analyzerCheckbox, vol2ProfileInput, imageOSSelect, autoFetchLinuxSymbolsCheckbox].forEach((el) => {
        el.addEventListener('change', persist);
    });

    // Scanning the image for a kernel banner takes a moment, so it runs when
    // the path changes rather than on every keystroke. The result only fills
    // in the "Auto-detect" label — an explicit user choice is never
    // overwritten.
    async function refreshDetectedOS() {
        const path = imageInput.value.trim();
        imageOSDetected.dataset.os = '';
        imageOSDetected.dataset.path = path;
        if (!path) { imageOSDetected.textContent = ''; return; }
        imageOSDetected.textContent = 'detecting image OS…';
        try {
            const result = await DetectImageOS(path);
            if (imageInput.value.trim() !== path) return;
            imageOSDetected.dataset.os = result.os;
            document.dispatchEvent(new Event('run-plan-changed'));
            if (result.os === 'unknown') {
                imageOSDetected.innerHTML = `<span class="status-error">could not identify; choose manually</span>`;
            } else {
                imageOSDetected.textContent = `Detected: ${result.os}${result.evidence ? ` (${result.evidence})` : ''}`;
            }
        } catch (err) {
            imageOSDetected.innerHTML = `<span class="status-error">${escapeHtml(String(err))}</span>`;
        }
    }
    imageInput.addEventListener('change', refreshDetectedOS);
    if (cfg.imagePath) refreshDetectedOS();

    // --- Install / update tools + Install dependencies ---
    const installBtn = container.querySelector<HTMLButtonElement>('#installToolsBtn')!;
    const installHint = container.querySelector<HTMLSpanElement>('#installHint')!;
    const depsBtn = container.querySelector<HTMLButtonElement>('#installDepsBtn')!;
    const depsHint = container.querySelector<HTMLSpanElement>('#installDepsHint')!;
    const depsSummary = container.querySelector<HTMLDivElement>('#depsSummary')!;
    const installProgress = container.querySelector<HTMLDivElement>('#installProgress')!;
    const installLogDetails = container.querySelector<HTMLDetailsElement>('#installLogDetails')!;
    const installLog = container.querySelector<HTMLPreElement>('#installLog')!;
    const checkUpdatesBtn = container.querySelector<HTMLButtonElement>('#checkUpdatesBtn')!;
    const updateStatus = container.querySelector<HTMLDivElement>('#updateStatus')!;

    const TOOL_LABELS: Record<string, string> = {
        sysdeps: 'System components',
        pyenv: 'Python environment',
        pydeps: 'Python packages',
        symbols: 'Volatility 3 symbol packs',
        'symbols-linux': 'Volatility 3 symbol pack (Linux)',
        'symbols-mac': 'Volatility 3 symbol pack (macOS)',
        vol3patch: 'Volatility 3 custom-plugin fix',
        dwarf2json: 'dwarf2json (Linux symbol generation)',
        volatility3: 'Volatility 3',
        volatility2: 'Volatility 2',
        memprocfs: 'MemProcFS',
        memnixfs: 'MemNixFS',
        analyzer: 'MemProcFS-Analyzer',
        'analyzer-updater': 'MemProcFS-Analyzer tooling (Updater.ps1)',
    };
    const progressRows = new Map<string, HTMLDivElement>();
    function installRow(tool: string): HTMLDivElement {
        let row = progressRows.get(tool);
        if (!row) {
            row = document.createElement('div');
            row.className = 'install-progress-row';
            installProgress.appendChild(row);
            progressRows.set(tool, row);
        }
        return row;
    }
    const installLogLines: string[] = [];

    async function refreshToolUpdates() {
        checkUpdatesBtn.disabled = true;
        checkUpdatesBtn.textContent = 'Checking…';
        updateStatus.className = 'update-status hint';
        updateStatus.textContent = 'Checking GitHub releases…';
        const cur = currentConfig();
        try {
            const report = await CheckToolUpdates({
                volPath: cur.volPath,
                vol2Path: cur.vol2Path,
                memProcfsPath: cur.memProcfsPath,
                memNixFsPath: cur.memNixFsPath,
                analyzerPath: cur.analyzerPath,
            });
            updateStatus.className = 'update-status';
            updateStatus.innerHTML = renderUpdateReport(report);
        } catch (err) {
            updateStatus.className = 'update-status status-error';
            updateStatus.textContent = `Could not check updates: ${String(err)}`;
        } finally {
            checkUpdatesBtn.disabled = false;
            checkUpdatesBtn.textContent = 'Check updates';
        }
    }
    checkUpdatesBtn.addEventListener('click', refreshToolUpdates);

    const unsubProgress = EventsOn('install:progress', (p: InstallProgressPayload) => {
        // Per-byte download progress is reported under "<tool>-dl" so it
        // repaints the same row as that tool's own done/error state rather
        // than adding a separate, noisier one.
        const tool = p.tool.endsWith('-dl') ? p.tool.slice(0, -3) : p.tool;
        const label = TOOL_LABELS[tool] || tool;
        const icon = p.state === 'done' ? 'OK' : p.state === 'error' ? 'Error' : p.state === 'skipped' ? '-' : '...';
        const cls = p.state === 'error' ? 'status-error' : p.state === 'done' ? 'status-ok' : 'hint';
        installRow(tool).innerHTML = `<span class="install-progress-icon ${cls}">${icon}</span> <strong>${label}:</strong> <span class="${cls}">${escapeHtml(p.message)}</span>`;
    });
    const unsubLog = EventsOn('install:log', (l: {line: string}) => {
        installLogLines.push(l.line);
        if (installLogLines.length > 500) installLogLines.splice(0, installLogLines.length - 500);
        installLog.textContent = installLogLines.join('\n');
        installLog.scrollTop = installLog.scrollHeight;
    });
    // EventsOn subscriptions outlive a re-render of this view; drop them if
    // the view is torn down and rebuilt.
    (container as any).__installCleanup?.();
    (container as any).__installCleanup = () => { unsubProgress(); unsubLog(); };

    // Both buttons drive the same backend lock, so the UI mirrors it: while
    // either install runs, neither can be started.
    function beginInstall(active: HTMLButtonElement, busyLabel: string) {
        installBtn.disabled = true;
        depsBtn.disabled = true;
        checkUpdatesBtn.disabled = true;
        active.textContent = busyLabel;
        installProgress.style.display = '';
        installLogDetails.style.display = '';
        depsSummary.style.display = 'none';
        depsSummary.innerHTML = '';
        progressRows.clear();
        installProgress.innerHTML = '';
        installLogLines.length = 0;
        installLog.textContent = '';
    }
    function endInstall() {
        installBtn.disabled = false;
        depsBtn.disabled = false;
        checkUpdatesBtn.disabled = false;
        installBtn.textContent = 'Install / update tools';
        depsBtn.textContent = 'Install dependencies';
    }

    depsBtn.addEventListener('click', async () => {
        beginInstall(depsBtn, 'Installing…');
        depsHint.textContent = 'Installing dependencies. Windows may request administrator approval.';
        try {
            const result: installer.DepsResult = await InstallDependencies();
            // The dependency install builds its own Python environment, so
            // the vol it produces is the one the app should use.
            if (result.volPath) { volInput.value = result.volPath; persist(); }
            depsSummary.innerHTML = renderDepsSummary(result);
            depsSummary.style.display = '';
            if (result.errors && result.errors.length) {
                depsHint.innerHTML = `<span class="status-error">Some installs failed. See details below.</span>`;
            } else {
                depsHint.innerHTML = '<span class="status-ok">Dependencies ready. Now click “Install / update tools”.</span>';
            }
        } catch (err) {
            depsHint.innerHTML = `<span class="status-error">Dependency install failed: ${escapeHtml(String(err))}</span>`;
        } finally {
            endInstall();
        }
    });

    installBtn.addEventListener('click', async () => {
        beginInstall(installBtn, 'Installing…');
        installHint.textContent = 'Downloading and installing tools...';
        try {
            const result: installer.Result = await InstallTools();
            // Auto-populate whatever was found.
            if (result.volPath) volInput.value = result.volPath;
            if (result.vol2Path) vol2Input.value = result.vol2Path;
            if (result.memProcfsPath) memProcfsInput.value = result.memProcfsPath;
            if (result.memNixFsPath) memNixFsInput.value = result.memNixFsPath;
            if (result.analyzerPath) analyzerInput.value = result.analyzerPath;
            persist();
            if (result.errors && result.errors.length) {
                installHint.innerHTML = `<span class="status-error">Finished with issues: ${escapeHtml(result.errors.join('; '))}</span>`;
            } else {
                installHint.innerHTML = '<span class="status-ok">Tools ready. Paths filled in.</span>';
            }
            await refreshToolUpdates();


        } catch (err) {
            installHint.innerHTML = `<span class="status-error">Install failed: ${escapeHtml(String(err))}</span>`;
        } finally {
            endInstall();
        }
    });

    container.querySelector<HTMLButtonElement>('#browseVol')!.addEventListener('click', async () => {
        const path = await BrowseForFile('Select the Volatility3 executable');
        if (path) { volInput.value = path; persist(); }
    });
    container.querySelector<HTMLButtonElement>('#browseVol2')!.addEventListener('click', async () => {
        const path = await BrowseForFile('Select the Volatility 2 executable');
        if (path) { vol2Input.value = path; persist(); }
    });
    container.querySelector<HTMLButtonElement>('#browseMemProcfs')!.addEventListener('click', async () => {
        const path = await BrowseForFile('Select the MemProcFS executable');
        if (path) { memProcfsInput.value = path; persist(); }
    });
    container.querySelector<HTMLButtonElement>('#browseMemNixFs')!.addEventListener('click', async () => {
        const path = await BrowseForFile('Select the MemNixFS executable');
        if (path) { memNixFsInput.value = path; persist(); }
    });
    browseAnalyzerBtn.addEventListener('click', async () => {
        const path = await BrowseForFile('Select MemProcFS-Analyzer.ps1');
        if (path) { analyzerInput.value = path; persist(); }
    });
    container.querySelector<HTMLButtonElement>('#browseImage')!.addEventListener('click', async () => {
        try {
        const path = await BrowseMemoryImage(imageInput.value.trim(), false);
        if (path) { imageInput.value = path; persist(); refreshDetectedOS(); }
        } catch (err) { alert(`Could not open the memory image picker: ${String(err)}`); }
    });
    container.querySelector<HTMLButtonElement>('#browseOutput')!.addEventListener('click', async () => {
        const path = await BrowseForDirectory('Select the output directory');
        if (path) { outputInput.value = path; persist(); }
    });
    container.querySelector<HTMLButtonElement>('#browseShare')!.addEventListener('click', async () => {
        try {
            const path = await BrowseMemoryImage(imageInput.value.trim(), true);
            if (path) { imageInput.value = path; persist(); refreshDetectedOS(); }
        } catch (err) { alert(String(err)); }
    });
    container.querySelector<HTMLButtonElement>('#browseYaraRules')!.addEventListener('click', async () => {
        const path = await BrowseForFile('Select a YARA rules file');
        if (path) { yaraRulesInput.value = path; persist(); }
    });

    // --- Generate Linux symbols (advanced) ---
    const isfPackageInput = container.querySelector<HTMLInputElement>('#isfPackagePath')!;
    const browseIsfBtn = container.querySelector<HTMLButtonElement>('#browseIsfPackage')!;
    const generateIsfBtn = container.querySelector<HTMLButtonElement>('#generateIsfBtn')!;
    const isfGenStatus = container.querySelector<HTMLDivElement>('#isfGenStatus')!;
    const isfGenLog = container.querySelector<HTMLPreElement>('#isfGenLog')!;

    browseIsfBtn.addEventListener('click', async () => {
        const path = await BrowseForFile('Select the kernel debug package (.rpm, .ddeb, …)');
        if (path) isfPackageInput.value = path;
    });

    const isfGenLogLines: string[] = [];
    const unsubIsfGenLog = EventsOn('isfgen:log', (p: {line: string}) => {
        isfGenLogLines.push(p.line);
        isfGenLog.style.display = '';
        isfGenLog.textContent = isfGenLogLines.join('\n');
        isfGenLog.scrollTop = isfGenLog.scrollHeight;
    });
    (container as any).__isfGenCleanup?.();
    (container as any).__isfGenCleanup = () => { unsubIsfGenLog(); };

    generateIsfBtn.addEventListener('click', async () => {
        const path = isfPackageInput.value.trim();
        if (!path) {
            isfGenStatus.innerHTML = '<span class="status-error">Pick a kernel debug package first.</span>';
            return;
        }
        generateIsfBtn.disabled = true;
        generateIsfBtn.textContent = 'Generating…';
        isfGenLogLines.length = 0;
        isfGenLog.textContent = '';
        isfGenLog.style.display = 'none';
        isfGenStatus.innerHTML = '<span class="hint">Generating symbols. This may take a few minutes...</span>';
        try {
            const result = await GenerateLinuxISF(path);
            const bannerLine = result.kernelBanner ? `<br><span class="hint">Kernel: ${escapeHtml(result.kernelBanner)}</span>` : '';
            isfGenStatus.innerHTML = `<span class="status-ok">ISF ready at ${escapeHtml(result.isfPath)}.</span>${bannerLine}`;
        } catch (err) {
            isfGenStatus.innerHTML = `<span class="status-error">${escapeHtml(String(err))}</span>`;
        } finally {
            generateIsfBtn.disabled = false;
            generateIsfBtn.textContent = 'Extract & generate ISF';
        }
    });

    validateBtn.addEventListener('click', async () => {
        persist();
        validateBtn.disabled = true;
        validateBtn.textContent = 'Validating…';
        statusArea.innerHTML = '<p class="hint">Checking configured tools...</p>';
        try {
            const cur = currentConfig();
            const result = await ValidateToolPaths({
                volPath: cur.volPath,
                vol2Path: cur.vol2Path,
                memProcfsPath: cur.memProcfsPath,
                memNixFsPath: cur.memNixFsPath,
                analyzerPath: cur.analyzerPath,
            });
            statusArea.innerHTML =
                statusRow('Volatility 3', result.vol) +
                statusRow('Volatility 2', result.vol2) +
                statusRow('MemProcFS', result.memProcfs) +
                statusRow('MemNixFS', result.memNixFs) +
                statusRow('MemProcFS-Analyzer', result.analyzer) +
                await prerequisiteHtml();
            // Volatility 3 is always required. Which mount tool is required
            // depends on the image: MemProcFS for an explicit Windows
            // choice, MemNixFS for an explicit Linux one; on Auto-detect
            // (the image isn't sniffed until the run starts) either one
            // being ready is enough to proceed. The other optional tools
            // report "not configured" without blocking a run.
            const needsWindows = cur.imageOS === 'windows';
            const needsLinux = cur.imageOS === 'linux';
            const mountOk = needsLinux ? result.memNixFs.probeOk
                : needsWindows ? result.memProcfs.probeOk
                : (result.memProcfs.probeOk || result.memNixFs.probeOk);
            onValidated(result.vol.probeOk && mountOk, cur);
        } catch (err) {
            statusArea.innerHTML = `<p class="status-error">Validation failed: ${escapeHtml(String(err))}</p>`;
            onValidated(false, currentConfig());
        } finally {
            validateBtn.disabled = false;
            validateBtn.textContent = 'Check tools and continue';
        }
    });

    // A read-only check on view load makes stale tools visible without making
    // the user remember to press the maintenance button.
    refreshToolUpdates();
}
