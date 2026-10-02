# ThemeSelector

## Overview

UI component and initialization utility for switching between 21 application themes. Theme choice is persisted in `localStorage` and, for authenticated users, to the user account through `POST /api/v1/auth/update-theme`. It is applied by setting a `data-theme` attribute on `document.body`.

---

## Constants

### `THEMES`

- **Type**: `Array<{ id: string; label: string }>`
- **Description**: Available theme definitions.

| id | label |
|----|-------|
| `"standard"` | Standard |
| `"noc-terminal"` | NOC Terminal |
| `"high-contrast"` | High Contrast (Dark) |
| `"cyberpunk"` | Cyberpunk |
| `"solarized-dark"` | Solarized Dark |
| `"midnight-ocean"` | Midnight Ocean |
| `"arctic-command"` | Arctic Command |
| `"ember-watch"` | Ember Watch |
| `"forest-ops"` | Forest Ops |
| `"amethyst-grid"` | Amethyst Grid |
| `"slate-steel"` | Slate Steel |
| `"paper-light"` | Paper Light |
| `"nordic-frost"` | Nordic Frost |
| `"dracula-console"` | Dracula Console |
| `"synthwave"` | Synthwave |
| `"desert-signal"` | Desert Signal |
| `"olive-command"` | Olive Command |
| `"mono-ops"` | Monochrome Ops |
| `"rose-pine"` | Rose Pine |
| `"oceanic-teal"` | Oceanic Teal |
| `"copper-wire"` | Copper Wire |

### `STORAGE_KEY`

- **Type**: `string`
- **Value**: `"noc_theme"`
- **Purpose**: `localStorage` key used to persist the user's theme selection.

---

## Functions

### `getSavedTheme()`

- **Returns**: `string` — The theme ID from `localStorage`, or `"standard"` as default.
- **Flow**: Reads `localStorage` key `noc_theme`. Returns the saved value or `"standard"`.

---

### `applyTheme(themeId)`

| Parameter | Type | Description |
|-----------|------|-------------|
| `themeId` | `string` | The theme ID to apply |

- **Returns**: `void`
- **Flow**: Sets `document.body.dataset.theme = themeId` and writes the value to `localStorage` under key `noc_theme`.

---

### `ThemeSelector` (component)

- **Purpose**: Renders a button group allowing the user to select from all available themes.
- **Flow**:
  1. Initializes `theme` state from `getSavedTheme()`.
  2. On `theme` change, calls `applyTheme(theme)` via `useEffect`.
  3. Selecting a theme persists it locally and posts the preference to the account when a user is signed in.
  4. Renders a row of `<button>` elements, one per theme entry; the active theme is highlighted.
- **Returns**: A `<div>` containing theme selection buttons and a helper text note.

---

### `initTheme()`

- **Returns**: `void`
- **Purpose**: Call on application mount to restore the previously saved theme before the React tree renders.
- **Flow**: Calls `getSavedTheme()` then `applyTheme()` with the result. This ensures `data-theme` is set on `document.body` before any component uses CSS variables.

---

## State

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `theme` | `string` | `getSavedTheme()` | Currently selected theme ID |

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (useState, useEffect) | Component state and side-effect for theme application |
