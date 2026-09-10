# theme.css

## Overview

Root-level CSS custom properties defining the default "Standard" dark theme for the NOC Fusion application. Also provides global element resets, scrollbar styling, form input theming, link styles, a spin animation, and table styling.

---

## CSS Custom Properties (`:root`)

### Background Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--bg-primary` | `#0a0e1a` | Deep navy; primary page background |
| `--bg-secondary` | `#111827` | Dark slate; sidebar background |
| `--bg-tertiary` | `#1e293b` | Medium slate; hover/active states |
| `--bg-card` | `#1a2332` | Muted navy; card and panel backgrounds |
| `--bg-card-hover` | `#1e293b` | Card hover state |
| `--bg-input` | `#0f172a` | Very dark slate; form input backgrounds |

### Border Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--border-primary` | `#2d3a50` | Primary border color |
| `--border-secondary` | `#1e293b` | Secondary/subtle border color |

### Text Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--text-primary` | `#e2e8f0` | Light gray; primary text |
| `--text-secondary` | `#94a3b8` | Medium gray; secondary/meta text |
| `--text-muted` | `#64748b` | Darker gray; muted/hint text |

### Accent Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--accent-blue` | `#3b82f6` | Primary action and link blue |
| `--accent-cyan` | `#06b6d4` | Cyan for branding and highlights |
| `--accent-green` | `#01a46d` | Success/operational green |
| `--accent-yellow` | `#eab308` | Warning yellow |
| `--accent-orange` | `#f97316` | Severe/orange alert |
| `--accent-red` | `#ef4444` | Error/critical red |
| `--accent-purple` | `#a855f7` | Purple accent |
| `--accent-pink` | `#ec4899` | Pink accent |

### Risk Level Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--risk-green` | `#01a46d` | GREEN risk level |
| `--risk-blue` | `#377fc7` | BLUE risk level |
| `--risk-yellow` | `#eab308` | YELLOW risk level |
| `--risk-orange` | `#f97316` | ORANGE risk level |
| `--risk-red` | `#ef4444` | RED risk level |

### Shade (Background Tint) Colors

| Variable | Value | Description |
|----------|-------|-------------|
| `--shade-green` | `rgba(1, 164, 109, 0.15)` | Green tint background |
| `--shade-blue` | `rgba(55, 127, 199, 0.15)` | Blue tint background |
| `--shade-yellow` | `rgba(234, 179, 8, 0.15)` | Yellow tint background |
| `--shade-orange` | `rgba(249, 115, 22, 0.15)` | Orange tint background |
| `--shade-red` | `rgba(239, 68, 68, 0.15)` | Red tint background |

### Typography

| Variable | Value | Description |
|----------|-------|-------------|
| `--font-mono` | `'Courier New', Courier, monospace` | Monospace font stack |
| `--font-sans` | `system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif` | Sans-serif font stack |

### Border Radius

| Variable | Value | Description |
|----------|-------|-------------|
| `--radius-sm` | `4px` | Small border radius (buttons, badges) |
| `--radius-md` | `8px` | Medium border radius (cards) |
| `--radius-lg` | `12px` | Large border radius (modals) |

### Shadows

| Variable | Value | Description |
|----------|-------|-------------|
| `--shadow-sm` | `0 1px 2px rgba(0, 0, 0, 0.3)` | Subtle card shadow |
| `--shadow-md` | `0 4px 6px rgba(0, 0, 0, 0.4)` | Medium elevation shadow |
| `--shadow-lg` | `0 10px 25px rgba(0, 0, 0, 0.5)` | High elevation shadow (modals) |

---

## Global Styles

### `*` (Universal Selector)
- `box-sizing: border-box` — applied to all elements.

### `body`
- **margin**: `0`
- **font-family**: `var(--font-sans)`
- **background**: `var(--bg-primary)`
- **color**: `var(--text-primary)`
- **-webkit-font-smoothing**: `antialiased`

### Custom Scrollbar (WebKit)
- **Width**: 6px (both vertical and horizontal)
- **Track**: `var(--bg-secondary)`
- **Thumb**: `var(--border-primary)`, rounded 3px
- **Thumb hover**: `var(--text-muted)`

### Form Elements (`input`, `textarea`, `select`)
- **background**: `var(--bg-input)` with `!important`
- **border**: 1px solid `var(--border-primary)` with `!important`
- **color**: `var(--text-primary)` with `!important`
- **border-radius**: `var(--radius-sm)` with `!important`
- **padding**: `0.5rem 0.75rem` with `!important`
- **focus state**: border becomes `var(--accent-blue)` with a blue glow box-shadow
- All form elements use `!important` to ensure consistency across theme overrides.

### `button`
- Inherits `font-family` from root.

### `a` (Links)
- **color**: `var(--accent-cyan)`
- **text-decoration**: `none`
- **hover**: underline

### Spin Animation (`@keyframes spin`)
- Full 360-degree rotation over 1 second, linear timing.
- Applied via class `.spin`.

### Table Styling
- Full width, collapsed borders.
- `th`: left-aligned, `0.5rem` padding, `var(--text-muted)` color, 600 weight, `0.8rem` font, 2px bottom border.
- `td`: `0.5rem` padding, `var(--text-secondary)` color, `0.85rem` font, 1px bottom border.
- `tr:hover td`: subtle blue tint background (`rgba(59, 130, 246, 0.05)`).

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| None | Standalone CSS file; imported by the application entry point |
