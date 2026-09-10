# ThemeSelector

## Overview

UI component and initialization utility for switching between six application themes. Theme choice is persisted in `localStorage` and applied by setting a `data-theme` attribute on `document.body`.

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
  3. Renders a row of `<button>` elements, one per theme entry.
  4. The currently active theme button is highlighted with `accent-blue` background and bold text.
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
