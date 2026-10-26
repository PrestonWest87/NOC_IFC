# web/vite.config.ts — Vite Build & Dev Server Configuration

**Path:** `web/vite.config.ts`

## Purpose

Configures the Vite bundler for the React/TypeScript frontend. Defines build plugins, dev server port, and HTTP/WebSocket proxy rules to the FastAPI backend.

The `maplibre-assets` plugin serves MapLibre's module worker and shared module during development and emits both files into `dist/assets/` for production. MapLibre resolves these files relative to its bundled JavaScript, and the worker imports the shared module by its fixed sibling filename. It also removes an obsolete Firefox-only focus selector and guards MapLibre's drag-selection reset against undefined CSS values. A dependency-optimizer compatibility plugin uses WebGL's standard renderer value in Firefox rather than requesting the deprecated unmasked-renderer extension.

## Configuration Options

### `plugins`

| Option | Value | Description |
|--------|-------|-------------|
| `plugins` | `[react(), maplibreAssets(), lumaFirefoxRendererInfo()]` | React transform/HMR plus MapLibre asset handling and Firefox compatibility fixes. |
| `maplibre-assets` | MapLibre compatibility and worker plugin | Serves `maplibre-gl-worker.mjs` and `maplibre-gl-shared.mjs` in development, emits them together under `assets/` in production builds, and applies the Firefox CSS/drag-selection compatibility fixes. |
| `optimizeDeps.esbuildOptions.plugins` | Browser compatibility optimizer | Avoids Firefox's deprecated `WEBGL_debug_renderer_info` query while retaining standard `VENDOR`/`RENDERER` device information. |

### `server`

| Option | Value | Default | Description |
|--------|-------|---------|-------------|
| `server.port` | `5173` | `5173` | Port the Vite dev server listens on. Must match the port exposed in `Dockerfile` and mapped in `docker-compose.yml`. |
| `server.host` | `0.0.0.0` | — | Binds the dev server to all container interfaces so the published Compose port is reachable. |
| `server.allowedHosts` | `["test.weasts.net"]` | — | Explicit extra host accepted by Vite's dev host validation. |
| `server.watch.usePolling` | `true` | `false` | Enables container bind-mount change detection. |
| `server.watch.interval` | `500` ms | `100` ms | Poll interval used with `usePolling`. |

### `server.proxy`

Two proxy rules forward browser requests to the backend during development:

#### `/api` — REST API Proxy

| Option | Value | Description |
|--------|-------|-------------|
| `target` | `VITE_API_URL` env var, falls back to `http://localhost:8101` | Backend FastAPI server address. Resolved at startup from `process.env.VITE_API_URL`. |
| `changeOrigin` | `true` | Rewrites the `Origin` header to match the target. Required for CORS and host-based routing. |

#### `/ws` — WebSocket Proxy

| Option | Value | Description |
|--------|-------|-------------|
| `target` | `apiUrl` with `http` replaced by `ws` (e.g., `ws://localhost:8101`) | Backend WebSocket endpoint. Protocol is rewritten from HTTP to WS. |
| `ws` | `true` | Enables WebSocket proxying. Vite forwards WebSocket upgrade requests to the target. |

**Proxy resolution logic:**

```typescript
const apiUrl = process.env.VITE_API_URL || "http://localhost:8101";
```

- **Development (`web-dev`):** `VITE_API_URL=http://api:8101` → the running Vite dev server proxies to the Docker-internal API service.
- **Production (`web`):** Vite is not running. The container serves the already-built static frontend and Nginx handles `/api/` and `/ws`; the Compose `VITE_API_URL=http://localhost:8101` runtime variable is not consumed by that static bundle or Nginx configuration.

## Environment Variables

| Variable | Required | Default | Scope | Description |
|----------|----------|---------|-------|-------------|
| `VITE_API_URL` | No | `http://localhost:8101` | Vite dev server | Target used to construct development HTTP and WebSocket proxy addresses. The production React client uses relative `/api/v1` and `/ws` URLs, with Nginx as its proxy. |

## Dependencies

- **`@vitejs/plugin-react`** — Vite plugin for React. Listed in `devDependencies` in `package.json`.
- **`vite`** — Bundler and dev server. Listed in `devDependencies`.

## Usage

Invoked indirectly via `package.json` scripts:

```bash
# Development server
npm run dev         # vite

# Production build
npm run build       # tsc -b && vite build

# Preview production build locally
npm run preview     # vite preview
```

During a Docker build, `npm run build` calls `vite build` which produces optimised output in `web/dist/` (or `/app/dist` in the container).
