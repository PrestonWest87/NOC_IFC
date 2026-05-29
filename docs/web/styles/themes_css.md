# themes.css

## Overview

Alternative theme definitions applied via the `data-theme` attribute on `document.body`. Each theme overrides the same set of CSS custom properties defined in `:root` by `theme.css`. The "Standard" theme is the default and uses the `:root` values directly (no `[data-theme="standard"]` block needed).

---

## Theme: Standard (Default)

- **Selector**: `:root` (defined in `theme.css`)
- No `[data-theme="standard"]` block is required; the base variables serve as the standard theme.

---

## Theme: NOC Terminal

- **Selector**: `[data-theme="noc-terminal"]`
- **Design**: Green monospace on pure black. All accent and risk colors are a single green `#00ff00`.
- **Key differences from Standard**:
  - Backgrounds: `#000000` (pure black)
  - Text: `#00ff00` (primary), `#00cc00` (secondary), `#007700` (muted)
  - Borders: `#00ff00` (primary), `#003300` (secondary)
  - All accent/risk colors: `#00ff00`
  - Fonts: `'Courier New', Courier, monospace` for both mono and sans
  - Shadows: green-tinted rgba

---

## Theme: High Contrast (Dark)

- **Selector**: `[data-theme="high-contrast"]`
- **Design**: Yellow on pure black, maximum contrast for accessibility. All accent and risk colors are a single yellow `#FFFF00`.
- **Key differences from Standard**:
  - Backgrounds: `#000000` (pure black)
  - Text: `#FFFF00` (primary), `#DDDD00` (secondary), `#888800` (muted)
  - Borders: `#FFFF00` (primary), `#444400` (secondary)
  - All accent/risk colors: `#FFFF00`
  - Font-mono: `'Courier New', Courier, monospace`
  - No shadows defined (all remain as inherited)

---

## Theme: Cyberpunk

- **Selector**: `[data-theme="cyberpunk"]`
- **Design**: Cyan text on dark purple with pink/red accents. Neon aesthetic.
- **Key differences from Standard**:
  - Backgrounds: `#0b0213` (near-black purple) to `#1a0633` (card)
  - Text: `#00ffcc` (cyan primary), `#00ccaa` (secondary), `#8866aa` (muted purple)
  - Primary borders: `#ff007f` (hot pink)
  - Accents: `#00ffcc` (cyan for blue/cyan/green), `#ffd700` (gold for yellow), `#ff6600` (orange), `#ff007f` (pink for red/purple/pink)
  - Risk colors: same breakdown with distinct red/orange/yellow
  - Shadows: pink-tinted

---

## Theme: Solarized Dark

- **Selector**: `[data-theme="solarized-dark"]`
- **Design**: Solarized dark palette with distinctive warm and cool tones.
- **Key differences from Standard**:
  - Backgrounds: `#002b36` (base03) to `#073642` (base02)
  - Text: `#839496` (base0 primary), `#657b83` (base00 secondary), `#586e75` (base01 muted)
  - Accents: `#268bd2` (blue), `#2aa198` (cyan), `#859900` (green), `#b58900` (yellow), `#cb4b16` (orange), `#dc322f` (red), `#6c71c4` (purple), `#d33682` (pink)
  - Risk colors map to the same accent values

---

## Theme: Midnight Ocean

- **Selector**: `[data-theme="midnight-ocean"]`
- **Design**: Blue-tinted dark theme. Navy backgrounds with sky-blue accent.
- **Key differences from Standard**:
  - Backgrounds: `#011627` (deep navy primary), `#0f172a` (secondary/card)
  - Text: `#cbd5e1` (primary), `#94a3b8` (secondary), `#64748b` (muted)
  - Accents: `#38bdf8` (sky blue for both blue and cyan)
  - All other accent/risk colors match Standard

---

## Shared Variable Contract

Every theme block overrides the following variables to ensure full coverage:

### Backgrounds (6)
`--bg-primary`, `--bg-secondary`, `--bg-tertiary`, `--bg-card`, `--bg-card-hover`, `--bg-input`

### Borders (2)
`--border-primary`, `--border-secondary`

### Text (3)
`--text-primary`, `--text-secondary`, `--text-muted`

### Accents (8)
`--accent-blue`, `--accent-cyan`, `--accent-green`, `--accent-yellow`, `--accent-orange`, `--accent-red`, `--accent-purple`, `--accent-pink`

### Risk Colors (5)
`--risk-green`, `--risk-blue`, `--risk-yellow`, `--risk-orange`, `--risk-red`

### Shade Colors (5)
`--shade-green`, `--shade-blue`, `--shade-yellow`, `--shade-orange`, `--shade-red`

### Typography (2)
`--font-mono`, `--font-sans`

### Shadows (3 — optional)
`--shadow-sm`, `--shadow-md`, `--shadow-lg`

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `theme.css` | Base `:root` variable definitions; themes override these via `[data-theme]` selector specificity |
