# Layout

## Overview

Primary application shell providing a collapsible sidebar navigation and a main content area. Integrates with the auth context to show the current user and conditionally render navigation items based on allowed pages.

---

## Interface: `Layout` Props

| Prop | Type | Description |
|------|------|-------------|
| `children` | `React.ReactNode` | Page content rendered in the main area |

---

## Constants

### `navItems`

- **Type**: `Array<{ label: string; icon: LucideIcon; href: string }>`
- **Description**: Static route definitions for the sidebar. Each entry maps a display label, icon component, and hash-based href.

| Label | Icon | href |
|-------|------|------|
| Global Dashboards | `Activity` | `/` |
| Threat Telemetry | `Globe` | `/threat-telemetry` |
| Regional Grid | `Crosshair` | `/regional-grid` |
| Threat Hunting & IOCs | `Shield` | `/threat-hunting` |
| AIOps RCA | `Radio` | `/aiops-rca` |
| Shift Logbook | `BookOpen` | `/shift-logbook` |
| Reporting & Briefings | `FileText` | `/reporting` |
| Settings & Admin | `Settings` | `/settings` |

---

## Functions

### `Layout` (component)

- **Purpose**: Provides the persistent application layout with a collapsible sidebar navigation, user profile section, and logout button.
- **Flow**:
  1. Reads `user` and `logout` from `useAuth()`.
  2. Maintains `collapsed` state for the sidebar width (56px collapsed, 230px expanded).
  3. Maintains `showProfile` toggle for profile info display.
  4. Filters `navItems` against `user.allowed_pages` — items whose label is NOT in the array are hidden.
  5. Each navigation item renders as an `<a>` tag pointing to `#/{href}` (hash routing).
  6. Bottom sidebar section shows the user's name, job title (or role), and a logout button.
  7. Main content area renders `children` with `overflow: auto`.
- **Returns**: A flex container with a `<nav>` sidebar and a `<main>` content area.

---

## State

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `collapsed` | `boolean` | `false` | Sidebar collapsed state |
| `showProfile` | `boolean` | `false` | Profile detail visibility toggle |

---

## Dependencies

| Dependency | Purpose |
|-----------|---------|
| `react` (useState) | Local component state |
| `../utils/AuthContext` (useAuth) | User auth state and logout function |
| `lucide-react` | Icon components for navigation items |
