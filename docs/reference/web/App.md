# App.tsx

Application root component tree with route definitions, authentication guard, and data provider setup.

---

## `PAGE_PERMISSION_MAP`

### Purpose
Maps URL paths to human-readable page names used for permission-based access control.

### Type
`Record<string, string>`

### Entries
| Path | Page Name |
|------|-----------|
| `/` | Global Dashboards |
| `/threat-telemetry` | Threat Telemetry |
| `/regional-grid` | Regional Grid |
| `/threat-hunting` | Threat Hunting & IOCs |
| `/aiops-rca` | AIOps RCA |
| `/shift-logbook` | Shift Logbook |
| `/reporting` | Reporting & Briefings |
| `/settings` | Settings & Admin |

---

## `ProtectedRoute({ children, path })`

### Purpose
Authentication and authorization gate that wraps page components. Redirects unauthenticated users to `/login` and unauthorized users (missing page-level permission) to `/`.

### Props
| Prop | Type | Description |
|------|------|-------------|
| `children` | `React.ReactNode` | The page component to render when authorized |
| `path` | `string` (optional) | URL path used to look up the required page permission |

### Returns
- `<Navigate to="/login" replace />` when `user` is null (not authenticated).
- `<Navigate to="/" replace />` when the user's `allowed_pages` does not include the mapped page name.
- `<Layout>{children}</Layout>` when authorized.

### Flow
1. Calls `useAuth()` to get the current `user`.
2. If `user` is falsy, redirect to login.
3. If `path` is provided, looks up `PAGE_PERMISSION_MAP[path]` and checks `user.allowed_pages`.
4. If the page is not allowed, redirect to dashboard root.
5. Otherwise renders the `Layout` wrapper around `children`.

### Dependencies
- `useAuth` from `../utils/AuthContext`
- `Navigate` from `react-router-dom`
- `Layout` from `../components/Layout`

---

## `AppRoutes()`

### Purpose
Defines the full route configuration for the SPA using React Router's `Routes` and `Route` components.

### Returns
A `<Routes>` block containing:
- `/login` -> `LoginPage` (unprotected)
- `/` -> `ProtectedRoute` with `DashboardPage`
- `/threat-telemetry` -> `ProtectedRoute` with `ThreatTelemetryPage`
- `/regional-grid` -> `ProtectedRoute` with `RegionalGridPage`
- `/threat-hunting` -> `ProtectedRoute` with `ThreatHuntingPage`
- `/aiops-rca` -> `ProtectedRoute` with `AiopsRcaPage`
- `/shift-logbook` -> `ProtectedRoute` with `ShiftLogbookPage`
- `/reporting` -> `ProtectedRoute` with `ReportingPage`
- `/settings` -> `ProtectedRoute` with `SettingsPage`

### Dependencies
- `Routes`, `Route` from `react-router-dom`
- All page components from `../pages/*`

---

## `App` (default export)

### Purpose
Root component that composes the provider hierarchy and route definitions.

### Returns
```tsx
<QueryClientProvider client={queryClient}>
  <HashRouter>
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  </HashRouter>
</QueryClientProvider>
```

### Flow
1. Creates a `QueryClient` instance for React Query.
2. Wraps the entire application in `QueryClientProvider` (provides caching/refetching to all pages).
3. Uses `HashRouter` (hash-based routing suitable for static file serving).
4. Wraps routes in `AuthProvider` for global authentication context.
5. Renders `AppRoutes` which handles all page routing and protection.

### Dependencies
- `QueryClient`, `QueryClientProvider` from `@tanstack/react-query`
- `HashRouter` from `react-router-dom`
- `AuthProvider` from `../utils/AuthContext`
- `AppRoutes` (local)
