# web/package.json — Node.js Project Manifest

**Path:** `web/package.json`

## Purpose

NPM package manifest for the React/TypeScript frontend. Declares project metadata, dependency ranges, and build/development scripts. `npm ci` uses the committed lockfile for Docker and local installs.

## Metadata

| Field | Value | Description |
|-------|-------|-------------|
| `name` | `noc-fusion-frontend` | Package name. Not published to any registry — marked `"private": true`. |
| `private` | `true` | Prevents accidental publication to the npm registry. |
| `version` | `2.0.0` | Private package metadata version; it does not identify a Git branch or deployed release. |
| `type` | `module` | Treats all `.js`/`.ts` files as ES modules by default. Enables `import`/`export` syntax without `.mjs` extensions. |

## Scripts

| Script | Command | Description |
|--------|---------|-------------|
| `dev` | `vite` | Starts the Vite development server with hot-module replacement on port 5173 (or as configured in `vite.config.ts`). |
| `build` | `tsc -b && vite build` | **Production build pipeline.** TypeScript build mode checks the source first; `noEmit: true` prevents JavaScript/declaration output, then Vite creates the production bundle. Fails if type errors exist. |
| `preview` | `vite preview` | Starts a local static file server to preview the production build output (`dist/`). Useful for verifying the built bundle before deployment. |

## Dependencies (Production)

| Package | Version | Purpose |
|---------|---------|---------|
| `@deck.gl/core` | `^9.3.0` | Deck.gl core types and runtime primitives imported directly by map components. |
| `@deck.gl/layers` | `^9.3.0` | Only the map layers used by this UI (scatterplot, GeoJSON, bitmap, and polygon). |
| `@deck.gl/react` | `^9.3.0` | Deck.gl React bindings — `<DeckGL>` component for map visualizations. |
| `@deck.gl/widgets` | `^9.3.0` | Required peer package for deck.gl React bindings. |
| `@loaders.gl/core` | `^4.4.1` | Required deck.gl layer peer. |
| `@luma.gl/core` | `^9.3.3` | Required deck.gl rendering peer. |
| `@luma.gl/engine` | `^9.3.3` | Required deck.gl rendering peer. |
| `@tanstack/react-query` | `^5.100.11` | Server state management — caching, background refetching, and pagination for REST API calls. |
| `axios` | `^1.20.0` | Patched HTTP client for REST API requests. Used by `web/src/utils/api.ts`. |
| `lucide-react` | `^1.16.0` | Open-source icon library as React components. Used throughout the UI for navigation and status indicators. |
| `maplibre-gl` | `^6.11.2` | Patched MapLibre GL JS — open-source map rendering engine. |
| `react` | `^18.3.1` | Core React library — component model, hooks, fiber reconciler. |
| `react-dom` | `^18.3.1` | React DOM renderer — `createRoot`, hydration, event handling. |
| `@vis.gl/react-maplibre` | `^8.1.3` | MapLibre-only React map wrapper; replaces the dual Mapbox/MapLibre wrapper. |
| `react-router-dom` | `^7.18.4` | Client-side routing — this app uses `<HashRouter>`, `<Routes>`, `<Route>`, and `<Link>`. |
| `recharts` | `^3.8.1` | Declarative charting library for React. Used for analytics charts and dashboards. |
| `zustand` | `^4.5.0` | Lightweight state management — stores for UI state, WebSocket data, and dashboard state. |

## Dev Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `@types/react` | `^18.3.0` | TypeScript type declarations for React. |
| `@types/react-dom` | `^18.3.0` | TypeScript type declarations for ReactDOM. |
| `@vitejs/plugin-react` | `^5.0.4` | Vite plugin — enables React Fast Refresh, JSX transform, and Babel integration. |
| `typescript` | `^5.5.0` | TypeScript compiler (`tsc`) for type-checking. |
| `vite` | `^7.3.6` | Patched bundler and dev server with native ES module support. |

## Dependency Notes

- **Caret ranges** (`^X.Y.Z`): Allow updates to minor and patch versions. The lockfile (`package-lock.json`) captures exact resolved versions.
- **`npm ci`** (used in Docker build): Installs from `package-lock.json` only — fails if lockfile is missing or out of sync. Guarantees reproducible builds.
- **Map dependencies**: The `deck.gl` umbrella and Mapbox React wrapper are intentionally omitted. The manifest declares only deck.gl modules used by source and the MapLibre-only wrapper.

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
cd web && npm ci && npm run dev

# Production build
cd web && npm run build

# Type-checking only
cd web && npx tsc --noEmit
```

In Docker, the `web` builder runs `npm ci` (clean install) with a BuildKit npm cache mount, then `npm run build`. `web-dev` keeps `node_modules` in a named volume and checks a package-lock hash, reinstalling only after dependency changes.
