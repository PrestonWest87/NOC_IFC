# web/package.json — Node.js Project Manifest

**Path:** `/home/weast/docker/NOC_IFC/web/package.json`

## Purpose

NPM package manifest for the React/TypeScript frontend. Declares project metadata, dependency versions, and build/development scripts. Consumed by `npm ci` (Docker build) and `npm install` (local development).

## Metadata

| Field | Value | Description |
|-------|-------|-------------|
| `name` | `noc-fusion-frontend` | Package name. Not published to any registry — marked `"private": true`. |
| `private` | `true` | Prevents accidental publication to the npm registry. |
| `version` | `2.0.0` | Semantic version. Version 2 corresponds to the decoupled architecture (architecture/monolith-to-decoupled branch). |
| `type` | `module` | Treats all `.js`/`.ts` files as ES modules by default. Enables `import`/`export` syntax without `.mjs` extensions. |

## Scripts

| Script | Command | Description |
|--------|---------|-------------|
| `dev` | `vite` | Starts the Vite development server with hot-module replacement on port 5173 (or as configured in `vite.config.ts`). |
| `build` | `tsc -b && vite build` | **Production build pipeline.** First runs TypeScript's build mode (`tsc -b`) for type-checking and declaration generation (despite `noEmit: true` in tsconfig), then runs Vite's production bundler. Fails if type errors exist. |
| `preview` | `vite preview` | Starts a local static file server to preview the production build output (`dist/`). Useful for verifying the built bundle before deployment. |

## Dependencies (Production)

| Package | Version | Purpose |
|---------|---------|---------|
| `@deck.gl/react` | `^9.0.0` | Deck.gl React bindings — `<DeckGL>` component for map-based visualizations. |
| `@tanstack/react-query` | `^5.100.11` | Server state management — caching, background refetching, and pagination for REST API calls. |
| `axios` | `^1.7.0` | HTTP client for REST API requests. Used by `web/src/utils/api.ts`. |
| `deck.gl` | `^9.0.0` | WebGL-powered geospatial visualization framework. Core library for map layers. |
| `lucide-react` | `^1.16.0` | Open-source icon library as React components. Used throughout the UI for navigation and status indicators. |
| `mapbox-gl` | `^3.0.0` | Mapbox GL JS — map rendering engine (optional fallback). |
| `maplibre-gl` | `^4.7.1` | MapLibre GL JS — open-source map rendering engine (primary choice for self-hosted tiles). |
| `react` | `^18.3.1` | Core React library — component model, hooks, fiber reconciler. |
| `react-dom` | `^18.3.1` | React DOM renderer — `createRoot`, hydration, event handling. |
| `react-map-gl` | `^7.1.0` | React wrapper for Mapbox GL / MapLibre GL. Provides declarative `<Map>` component. |
| `react-router-dom` | `^7.15.1` | Client-side routing — `<BrowserRouter>`, `<Routes>`, `<Route>`, `<Link>`. |
| `recharts` | `^3.8.1` | Declarative charting library for React. Used for analytics charts and dashboards. |
| `zustand` | `^4.5.0` | Lightweight state management — stores for UI state, WebSocket data, and dashboard state. |

## Dev Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@types/react` | `^18.3.0` | TypeScript type declarations for React. |
| `@types/react-dom` | `^18.3.0` | TypeScript type declarations for ReactDOM. |
| `@vitejs/plugin-react` | `^4.3.0` | Vite plugin — enables React Fast Refresh, JSX transform, and Babel integration. |
| `typescript` | `^5.5.0` | TypeScript compiler (`tsc`) for type-checking. |
| `vite` | `^5.4.0` | Bundler and dev server with native ES module support. |

## Dependency Notes

- **Caret ranges** (`^X.Y.Z`): Allow updates to minor and patch versions. The lockfile (`package-lock.json`) captures exact resolved versions.
- **`npm ci`** (used in Docker build): Installs from `package-lock.json` only — fails if lockfile is missing or out of sync. Guarantees reproducible builds.
- **Dual map libraries**: Both `mapbox-gl` and `maplibre-gl` are included. The application primarily uses MapLibre GL (open-source); Mapbox GL is retained as a fallback or for Mapbox tile service integration.

## Dependencies

| Dependency | Relationship |
|------------|-------------|
| `package-lock.json` | Auto-generated lockfile. Must be committed and kept in sync with `package.json`. |
| `tsconfig.json` | TypeScript configuration read during `npm run build` (`tsc -b`). |
| `vite.config.ts` | Vite configuration read during `npm run dev` and `npm run build`. |
| `index.html` | Entry point detected by Vite. |
| `src/` | Application source code. |

## Usage

```bash
# Local development
cd web && npm install && npm run dev

# Production build
cd web && npm run build

# Type-checking only
cd web && npx tsc --noEmit
```

In Docker, the `web` container runs `npm ci` (clean install), then `npm run build`. The `web-dev` container also runs `npm ci` then `npm run dev -- --host 0.0.0.0`.
