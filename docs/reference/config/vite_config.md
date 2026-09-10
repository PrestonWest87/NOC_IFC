# web/vite.config.ts — Vite Build & Dev Server Configuration

**Path:** `/home/weast/docker/NOC_IFC/web/vite.config.ts`

## Purpose

Configures the Vite bundler for the React/TypeScript frontend. Defines build plugins, dev server port, and HTTP/WebSocket proxy rules to the FastAPI backend.

## Configuration Options

### `plugins`

| Option | Value | Description |
|--------|-------|-------------|
| `plugins` | `[react()]` | Official Vite plugin for React — enables JSX transform, Fast Refresh (HMR), and Babel-based compilation. Imported from `@vitejs/plugin-react`. |

### `server`

| Option | Value | Default | Description |
|--------|-------|---------|-------------|
| `server.port` | `5173` | `5173` | Port the Vite dev server listens on. Must match the port exposed in `Dockerfile` and mapped in `docker-compose.yml`. |

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

- **Development (`web-dev`):** `VITE_API_URL=http://api:8101` → proxy targets Docker internal service name.
- **Production (`web`):** `VITE_API_URL=http://localhost:8101` → proxy targets host-localhost. In production, Nginx (not Vite) handles proxying via `nginx.conf`.

## Environment Variables

| Variable | Required | Default | Scope | Description |
|----------|----------|---------|-------|-------------|
| `VITE_API_URL` | No | `http://localhost:8101` | Build/Dev | Backend API base URL. Used to construct both HTTP and WebSocket proxy targets. Must include protocol and port. |

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
