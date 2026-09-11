# Module: `web/src/App.tsx`

Application root for the React SPA. It provides React Query, hash routing, authentication, theme synchronization, a page error boundary, and the realtime AIOps bridge.

## `ProtectedRoute({ children, path })`

Reads `user` from `useAuth()`.

- No user: redirects to `/login`.
- Authenticated user with an empty `allowed_pages` array: renders an access-denied message.
- Missing page permission: redirects to the first allowed page through `PAGE_ROUTE_MAP`, falling back to `/`.
- Authorized route: renders `<Layout>{children}</Layout>`.

Page maps are imported from `web/src/utils/routeConfig.ts`; they are not declared in this module.

## `AppRoutes()`

Uses `Suspense` around lazy page imports. The fallback is `Loading NOC workspace...`. Routes:

| Path | Component | Access |
|---|---|---|
| `/login` | `LoginPage` | Public |
| `/register` | `RegistrationPage` | Public invitation flow |
| `/` | `DashboardPage` | `Global Dashboards` |
| `/threat-telemetry` | `ThreatTelemetryPage` | `Threat Telemetry` |
| `/regional-grid` | `RegionalGridPage` | `Regional Grid` |
| `/threat-hunting` | `ThreatHuntingPage` | `Threat Hunting & IOCs` |
| `/aiops-rca` | `AiopsRcaPage` | `AIOps RCA` |
| `/shift-logbook` | `ShiftLogbookPage` | `Shift Logbook` |
| `/reporting` | `ReportingPage` | `Reporting & Briefings` |
| `/settings` | `SettingsPage` | `Settings & Admin` |
| `/keyword-analysis` | `KeywordAnalysisPage` | `Keyword Analysis` |

All protected pages are lazy-loaded with `React.lazy`. A page import/render error is handled by `PageErrorBoundary`, which logs the component stack and offers a full-page reload.

## `PageErrorBoundary`

Class error boundary around `AppRoutes`. `getDerivedStateFromError` stores the error; `componentDidCatch` logs it; the fallback shows the error message and a reload button.

## `RealtimeBridge()`

Calls `useAIOpsWebSocket()` once inside the authenticated provider tree and renders no visible markup. The hook publishes dashboard state and command behavior to the Zustand store and React Query cache.

## `queryClient`

Global `QueryClient` defaults:

- Query stale time: 30 seconds.
- No refetch on window focus.
- Refetch on reconnect.
- One retry.

## Default `App()` Export

Provider hierarchy, from outermost to innermost:

1. `QueryClientProvider`.
2. `HashRouter`.
3. `AuthProvider`.
4. `ThemeSync`.
5. `RealtimeBridge`.
6. `PageErrorBoundary` around `AppRoutes`.

`HashRouter` allows the nginx static server to serve all client routes without server-side route rewriting.
