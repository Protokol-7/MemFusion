import {CleanupMemProcfsMount, ListMemProcfsMounts, OpenOutputFolder} from '../../wailsjs/go/main/App';
import {EventsOn} from '../../wailsjs/runtime/runtime';
import type {memprocfs} from '../../wailsjs/go/models';

function escapeHtml(s: string): string {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

// The Mounts panel lists MemProcFS mounts and leftover mount folders
// (typically orphans from runs where the app was closed without Stop) and
// lets the user delete them individually — kill the owning process,
// unmount, remove the folder.
export function renderMountsView(container: HTMLElement) {
    container.innerHTML = `
        <section class="panel">
            <h2>Mounts</h2>
            <p class="hint">MemProcFS stays mounted after analysis. Copy required files before unmounting or closing the app.</p>
            <div class="run-toolbar">
                <button id="refreshMountsBtn" class="btn-secondary">Refresh</button>
            </div>
            <div id="mountsList"></div>
            <div id="mountsError"></div>
        </section>
    `;

    const listEl = container.querySelector<HTMLDivElement>('#mountsList')!;
    const errorEl = container.querySelector<HTMLDivElement>('#mountsError')!;
    const refreshBtn = container.querySelector<HTMLButtonElement>('#refreshMountsBtn')!;

    function describe(m: memprocfs.MountInfo): string {
        const parts: string[] = [];
        parts.push(m.mounted ? 'mounted' : 'not mounted (leftover)');
        if (m.pid) parts.push(`memprocfs PID ${m.pid}`);
        if (m.image) parts.push(m.image);
        return parts.join(' · ');
    }

    async function refresh() {
        errorEl.innerHTML = '';
        try {
            const mounts = await ListMemProcfsMounts();
            if (!mounts || mounts.length === 0) {
                listEl.innerHTML = '<p class="hint">No MemProcFS mounts found.</p>';
                return;
            }
            listEl.innerHTML = mounts.map((m, i) => `
                <div class="mount-row">
                    <span class="mount-row-icon" aria-hidden="true"></span>
                    <span class="mount-row-info">
                        <span class="mount-row-path">${escapeHtml(m.mountPoint)}</span>
                        <span class="mount-row-detail hint">${escapeHtml(describe(m))}</span>
                    </span>
                    <button class="btn-secondary mount-open-btn" data-idx="${i}" ${m.mounted ? '' : 'disabled'}>Open mount</button>
                    <button class="btn-secondary mount-delete-btn" data-idx="${i}">Unmount</button>
                </div>
            `).join('');
            listEl.querySelectorAll<HTMLButtonElement>('.mount-delete-btn').forEach((btn) => {
                btn.addEventListener('click', async () => {
                    const mount = mounts[Number(btn.dataset.idx)];
                    btn.disabled = true;
                    btn.textContent = 'Unmounting...';
                    try {
                        await CleanupMemProcfsMount(mount.mountPoint);
                        await refresh();
                    } catch (err) {
                        errorEl.innerHTML = `<p class="status-error">${escapeHtml(String(err))}</p>`;
                        btn.disabled = false;
                        btn.textContent = 'Unmount';
                    }
                });
            });
            listEl.querySelectorAll<HTMLButtonElement>('.mount-open-btn').forEach(btn => btn.addEventListener('click', async () => {
                try { await OpenOutputFolder(mounts[Number(btn.dataset.idx)].mountPoint); }
                catch (err) { errorEl.textContent = String(err); }
            }));
        } catch (err) {
            listEl.innerHTML = '';
            errorEl.innerHTML = `<p class="status-error">Failed to list mounts: ${escapeHtml(String(err))}</p>`;
        }
    }

    refreshBtn.addEventListener('click', refresh);
    EventsOn('run:finished', refresh);
    EventsOn('mounts:changed', refresh);
    EventsOn('memprocfs:status', (p: {state: string}) => { if (['mounted', 'stopped', 'error'].includes(p.state)) void refresh(); });
    refresh();
}
