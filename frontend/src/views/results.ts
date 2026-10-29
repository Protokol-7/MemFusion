import {ListRunResults, OpenOutputFolder} from '../../wailsjs/go/main/App';
import type {results} from '../../wailsjs/go/models';

// Results panel: what the run actually produced.
//
// A run leaves 70+ files in the output directory and, on a real image, most
// are legitimately empty — detection plugins usually find nothing. Listing
// them by outcome (errors first, then findings by size, then the empties)
// turns a folder dump into something you can triage at a glance.

const HTML_ESCAPES: Record<string, string> = {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'};
function escapeHtml(s: string): string {
    return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

type Filter = 'all' | 'findings' | 'error';

export function renderResultsView(container: HTMLElement, getOutputDir: () => string) {
    container.innerHTML = `
        <section class="panel">
            <h2>Results</h2>
            <div class="filter-bar">
                <button id="refreshResultsBtn" class="btn-secondary">Refresh</button>
                <button id="openFolderBtn" class="btn-secondary">Open output folder</button>
                <span class="filter-sep"></span>
                <div class="chip-row" id="resultFilter">
                    <button class="chip chip-active" data-filter="all">All</button>
                    <button class="chip" data-filter="findings">With findings</button>
                    <button class="chip" data-filter="error">Errors</button>
                </div>
            </div>
            <div id="resultsSummary" class="hint"></div>
            <div class="result-list" id="resultList"></div>
        </section>
    `;

    const listEl = container.querySelector<HTMLDivElement>('#resultList')!;
    const summaryEl = container.querySelector<HTMLDivElement>('#resultsSummary')!;
    const filterRow = container.querySelector<HTMLDivElement>('#resultFilter')!;

    let current: results.Summary | null = null;
    let filter: Filter = 'all';

    function fmtRows(n: number): string {
        if (n >= 100000) return '100k+';
        if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
        return String(n);
    }

    function render() {
        if (!current) return;
        const shown = current.results.filter((r) =>
            filter === 'all' ? true : filter === 'findings' ? r.outcome === 'findings' : r.outcome === 'error',
        );

        summaryEl.innerHTML =
            `<strong>${current.results.length}</strong> output files · ` +
            `<span class="status-ok">${current.findings} with findings</span> · ` +
            `${current.empty} empty · ` +
            `<span class="${current.errors ? 'status-error' : ''}">${current.errors} errors</span>` +
            `<br><span class="hint">${escapeHtml(current.outputDir)}</span>`;

        if (shown.length === 0) {
            listEl.innerHTML = '<p class="hint">Nothing matches this filter.</p>';
            return;
        }

        listEl.innerHTML = shown
            .map((r) => {
                const icon = r.outcome === 'findings' ? 'Findings' : r.outcome === 'error' ? 'Error' : 'Empty';
                const cls = r.outcome === 'findings' ? 'result-findings'
                    : r.outcome === 'error' ? 'result-error' : 'result-empty';
                const right = r.outcome === 'findings'
                    ? `<span class="result-rows">${fmtRows(r.rows)} rows</span>`
                    : `<span class="result-detail">${escapeHtml(r.detail)}</span>`;
                return `
                    <div class="result-row ${cls}">
                        <span class="result-icon">${icon}</span>
                        <span class="result-name"><span class="fw-badge fw-${r.framework}">${r.framework === 'vol2' ? 'v2' : 'v3'}</span>${escapeHtml(r.plugin)}</span>
                        ${right}
                    </div>`;
            })
            .join('');
    }

    async function refresh() {
        const dir = getOutputDir();
        if (!dir) {
            summaryEl.innerHTML = '<span class="hint">No output directory configured yet.</span>';
            listEl.innerHTML = '';
            return;
        }
        listEl.innerHTML = '<p class="hint">Scanning output directory…</p>';
        try {
            current = await ListRunResults(dir);
            render();
        } catch (err) {
            summaryEl.innerHTML = '';
            listEl.innerHTML = `<p class="status-error">Could not read results: ${escapeHtml(String(err))}</p>`;
        }
    }

    filterRow.addEventListener('click', (ev) => {
        const chip = (ev.target as HTMLElement).closest<HTMLButtonElement>('.chip');
        if (!chip?.dataset.filter) return;
        filter = chip.dataset.filter as Filter;
        filterRow.querySelectorAll('.chip').forEach((c) => c.classList.toggle('chip-active', c === chip));
        render();
    });

    container.querySelector<HTMLButtonElement>('#refreshResultsBtn')!.addEventListener('click', refresh);
    container.querySelector<HTMLButtonElement>('#openFolderBtn')!.addEventListener('click', () => {
        const dir = getOutputDir();
        if (dir) OpenOutputFolder(dir);
    });

    refresh();
    return {refresh};
}
