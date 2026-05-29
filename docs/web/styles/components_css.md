# components.css

## Overview

Utility and component class library for the NOC Fusion application. Provides reusable CSS classes for cards, risk badges, metric cards, buttons, tabs, grid layouts, flex utilities, spacing, dividers, expanders, alert boxes, modals, status dots, and responsive breakpoints.

---

## Card Classes

### `.card`
| Property | Value |
|----------|-------|
| background | `var(--bg-card)` |
| border | `1px solid var(--border-primary)` |
| border-radius | `var(--radius-md)` |
| padding | `1.25rem` |
| box-shadow | `var(--shadow-sm)` |

**Purpose**: Standard card container for dashboard panels.

### `.card-header`
- `font-size: 1.05rem`, `font-weight: 600`, `color: var(--text-primary)`, no bottom margin `0.75rem`.

---

## Risk Badge Classes

### `.risk-badge`
- **Display**: `inline-flex`, centered
- **Padding**: `0.2rem 0.6rem`
- **Border-radius**: `var(--radius-sm)`
- **Typography**: `font-weight: 700`, `font-size: 0.75rem`, `uppercase`, `letter-spacing: 0.5px`

| Modifier | Background | Color |
|----------|-----------|-------|
| `.risk-badge.green` | `var(--shade-green)` | `var(--risk-green)` |
| `.risk-badge.blue` | `var(--shade-blue)` | `var(--risk-blue)` |
| `.risk-badge.yellow` | `var(--shade-yellow)` | `var(--risk-yellow)` |
| `.risk-badge.orange` | `var(--shade-orange)` | `var(--risk-orange)` |
| `.risk-badge.red` | `var(--shade-red)` | `var(--risk-red)` |

---

## Metric Card Classes

### `.metric-card`
- Card-like container with `text-align: center`, padding `1rem`, standard card border and shadow.

### `.metric-value`
- `font-size: 1.8rem`, `font-weight: 700`, `color: var(--text-primary)`.

### `.metric-label`
- `font-size: 0.78rem`, `color: var(--text-muted)`, `margin-top: 0.25rem`.

---

## Button Classes

### `.btn`
- **Display**: `inline-flex`, centered, gap `0.4rem`
- **Padding**: `0.45rem 0.9rem`
- **Border-radius**: `var(--radius-sm)`
- **Font**: `0.82rem`, weight `500`
- **Border**: `1px solid var(--border-primary)`
- **Background**: `var(--bg-tertiary)`, color `var(--text-secondary)`
- **Transition**: all `0.15s`
- **Hover**: background `var(--border-primary)`, color `var(--text-primary)`
- **Disabled**: `opacity: 0.5`, `cursor: not-allowed`

### `.btn-primary`
- Background: `var(--accent-blue)`, color `#fff`, border matches.
- Hover: `#2563eb`.

### `.btn-danger`
- Background: `var(--accent-red)`, color `#fff`, border matches.
- Hover: `#dc2626`.

### `.btn-warning`
- Background: `var(--accent-orange)`, color `#fff`, border matches.

### `.btn-success`
- Background: `var(--accent-green)`, color `#fff`, border matches.

### `.btn-sm`
- Reduced padding `0.3rem 0.6rem`, font `0.75rem`.

---

## Tab Classes

### `.tabs`
- **Display**: `flex`, no gap, bottom border `1px solid var(--border-primary)`, margin-bottom `1.25rem`, `overflow-x: auto`.

### `.tab`
- **Padding**: `0.6rem 1.2rem`
- **Font**: `0.85rem`, color `var(--text-muted)`
- **Background**: none, border `none`
- **Bottom border**: `2px solid transparent`
- **Cursors**: pointer, `white-space: nowrap`
- **Transition**: all `0.15s`
- **Hover**: color `var(--text-secondary)`, subtle blue tint background.
- **`.tab.active`**: color `var(--accent-blue)`, bottom-border `var(--accent-blue)`.

---

## Grid Layout Classes

| Class | Template | Gap |
|-------|----------|-----|
| `.grid-2` | `1fr 1fr` | `1rem` |
| `.grid-3` | `1fr 1fr 1fr` | `1rem` |
| `.grid-4` | `repeat(4, 1fr)` | `1rem` |
| `.grid-auto` | `repeat(auto-fit, minmax(220px, 1fr))` | `1rem` |

---

## Flex Utility Classes

| Class | Properties |
|-------|-----------|
| `.flex-row` | `display: flex; align-items: center; gap: 0.75rem` |
| `.flex-wrap` | `flex-wrap: wrap` |
| `.flex-1` | `flex: 1` |
| `.flex-between` | `display: flex; justify-content: space-between; align-items: center` |

---

## Spacing Classes

### Gap
| Class | Value |
|-------|-------|
| `.gap-1` | `0.25rem` |
| `.gap-2` | `0.5rem` |
| `.gap-3` | `0.75rem` |
| `.gap-4` | `1rem` |

### Margin Bottom
| Class | Value |
|-------|-------|
| `.mb-1` | `0.25rem` |
| `.mb-2` | `0.5rem` |
| `.mb-3` | `0.75rem` |
| `.mb-4` | `1rem` |

### Margin Top
| Class | Value |
|-------|-------|
| `.mt-2` | `0.5rem` |
| `.mt-4` | `1rem` |

### Padding
| Class | Value |
|-------|-------|
| `.p-4` | `1rem` |

---

## Typography Utility Classes

| Class | Properties |
|-------|-----------|
| `.text-sm` | `font-size: 0.82rem` |
| `.text-xs` | `font-size: 0.75rem` |
| `.text-muted` | `color: var(--text-muted)` |
| `.text-secondary` | `color: var(--text-secondary)` |
| `.text-center` | `text-align: center` |
| `.font-mono` | `font-family: var(--font-mono)` |
| `.font-bold` | `font-weight: 700` |
| `.truncate` | `overflow: hidden; text-overflow: ellipsis; white-space: nowrap` |

---

## Divider

### `.divider`
- `height: 1px`, background `var(--border-primary)`, margin `1rem 0`.

---

## Expander (Collapsible Panel)

### `.expander`
- `border: 1px solid var(--border-primary)`, `border-radius: var(--radius-md)`, `overflow: hidden`, `margin-bottom: 0.5rem`.

### `.expander-header`
- **Padding**: `0.6rem 1rem`, background `var(--bg-secondary)`, cursor `pointer`, flex `space-between`.
- **Font**: `0.85rem`, weight `600`, color `var(--text-secondary)`, `user-select: none`.
- **Hover**: background `var(--bg-tertiary)`.

### `.expander-body`
- **Padding**: `0.75rem 1rem`, `border-top: 1px solid var(--border-primary)`.

---

## Alert Box Classes

### `.alert-box`
- **Padding**: `0.75rem 1rem`, `border-radius: var(--radius-sm)`, `font-size: 0.85rem`, `margin-bottom: 0.75rem`.
- **Left border**: `3px solid`.

| Modifier | Background | Border Color | Text Color |
|----------|-----------|--------------|------------|
| `.alert-box.info` | `rgba(59, 130, 246, 0.1)` | `var(--accent-blue)` | `#93c5fd` |
| `.alert-box.success` | `rgba(1, 164, 109, 0.1)` | `var(--accent-green)` | `#6ee7b7` |
| `.alert-box.warning` | `rgba(234, 179, 8, 0.1)` | `var(--accent-yellow)` | `#fde68a` |
| `.alert-box.error` | `rgba(239, 68, 68, 0.1)` | `var(--accent-red)` | `#fca5a5` |

---

## Modal Classes

### `.modal-overlay`
- **Position**: fixed, full viewport coverage.
- **Background**: `rgba(0, 0, 0, 0.7)`.
- **Display**: flex, centered both axes.
- **z-index**: `1000`.

### `.modal-content`
- **Background**: `var(--bg-card)`, border `1px solid var(--border-primary)`.
- **Border-radius**: `var(--radius-lg)`.
- **Padding**: `1.5rem`, max-width `600px`, width `90%`, max-height `80vh`, `overflow-y: auto`.
- **Box-shadow**: `var(--shadow-lg)`.

---

## Status Dot Classes

### `.status-dot`
- **Display**: `inline-block`, `width: 8px`, `height: 8px`, `border-radius: 50%`, `margin-right: 0.4rem`.

| Modifier | Background |
|----------|-----------|
| `.status-dot.online` | `var(--accent-green)` |
| `.status-dot.warning` | `var(--accent-yellow)` |
| `.status-dot.critical` | `var(--accent-red)` |
| `.status-dot.offline` | `var(--text-muted)` |

---

## Responsive Breakpoints

### `@media (max-width: 768px)`
- `.grid-2`, `.grid-3`, `.grid-4`: collapsed to single column (`1fr`).

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `theme.css` | CSS custom properties consumed by all component classes (e.g. `--bg-card`, `--border-primary`) |
