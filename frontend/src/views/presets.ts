// Named plugin selections, saved locally.
//
// Selections are also persisted unnamed, so the last one survives a restart —
// re-picking from 500+ plugins on every launch was the single most repetitive
// part of using the app.

const PRESET_KEY = 'memforensics-gui.presets.v1';
const LAST_SELECTION_KEY = 'memforensics-gui.selection.v1';

export type Presets = Record<string, string[]>;

function read<T>(key: string, fallback: T): T {
    try {
        const raw = localStorage.getItem(key);
        if (!raw) return fallback;
        return JSON.parse(raw) as T;
    } catch {
        return fallback; // corrupt or blocked storage is not worth failing over
    }
}

function write(key: string, value: unknown) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch {
        // Best-effort convenience only.
    }
}

export function loadPresets(): Presets {
    const presets = read<Presets>(PRESET_KEY, {});
    // Guard against a hand-edited or partially written store.
    return Object.fromEntries(
        Object.entries(presets).filter(([, v]) => Array.isArray(v)),
    );
}

export function savePreset(name: string, plugins: string[]) {
    const presets = loadPresets();
    presets[name] = plugins;
    write(PRESET_KEY, presets);
}

export function deletePreset(name: string) {
    const presets = loadPresets();
    delete presets[name];
    write(PRESET_KEY, presets);
}

export function loadLastSelection(): string[] {
    const saved = read<string[]>(LAST_SELECTION_KEY, []);
    return Array.isArray(saved) ? saved : [];
}

export function hasLastSelection(): boolean {
    try { return Array.isArray(JSON.parse(localStorage.getItem(LAST_SELECTION_KEY) || 'null')); }
    catch { return false; }
}

export function saveLastSelection(plugins: string[]) {
    write(LAST_SELECTION_KEY, plugins);
}
