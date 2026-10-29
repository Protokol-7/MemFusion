// Theme selection. The chosen theme is applied as data-theme on <html>,
// which every colour token in style.css keys off, and remembered in
// localStorage so it survives a restart.

const STORAGE_KEY = 'memforensics-gui.theme.v1';

export type ThemeName = 'classic' | 'midnight' | 'dark' | 'light';

const THEMES: Array<{id: ThemeName; label: string; title: string}> = [
    {id: 'classic', label: 'Classic', title: 'Gray background'},
    {id: 'midnight', label: 'Midnight', title: 'Navy background'},
    {id: 'dark', label: 'Black', title: 'Black background'},
    {id: 'light', label: 'Light', title: 'Light background'},
];

const DEFAULT_THEME: ThemeName = 'classic';

function isTheme(value: string | null): value is ThemeName {
    return value === 'classic' || value === 'midnight' || value === 'dark' || value === 'light';
}

export function loadTheme(): ThemeName {
    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (isTheme(stored)) return stored;
    } catch {
        // Private mode or blocked storage — fall through to the default.
    }
    return DEFAULT_THEME;
}

export function applyTheme(theme: ThemeName) {
    document.documentElement.setAttribute('data-theme', theme);
    try {
        localStorage.setItem(STORAGE_KEY, theme);
    } catch {
        // Best-effort only: failing to remember the theme must not break the app.
    }
}

// Applied before first paint (see main.ts) so a non-default theme doesn't
// flash the default palette on startup.
export function applyStoredTheme() {
    document.documentElement.setAttribute('data-theme', loadTheme());
}

export function renderThemeSwitcher(container: HTMLElement) {
    container.innerHTML = `<label for="themeSelect">Appearance</label><select id="themeSelect">${THEMES.map(t => `<option value="${t.id}">${t.label}</option>`).join('')}</select>`;
    const select = container.querySelector<HTMLSelectElement>('select')!;
    select.value = loadTheme();
    select.addEventListener('change', () => applyTheme(select.value as ThemeName));
}
