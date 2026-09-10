# web/Dockerfile — Frontend Build (Multi-Stage)

**Path:** `/home/weast/docker/NOC_IFC/web/Dockerfile`

## Purpose

Multi-stage Docker build for the React frontend. Stage 1 compiles the TypeScript application with Vite. Stage 2 serves the compiled static assets via Nginx on port 5173.

## Stages

### Stage 1: Builder (`node:20-alpine`)

| Directive | Value | Description |
|-----------|-------|-------------|
| `FROM` | `node:20-alpine AS builder` | Lightweight Node.js 20 Alpine image for dependency installation and build. |
| `WORKDIR` | `/app` | Working directory for the build stage. |
| `COPY` | `package.json package-lock.json ./` | Copies manifest and lockfile first to leverage Docker layer caching — `npm ci` re-runs only when dependencies change. |
| `RUN` | `npm ci` | Clean install from lockfile. Faster and more deterministic than `npm install`. Fails if `package-lock.json` is out of sync with `package.json`. |
| `COPY` | `. .` | Copies all frontend source (`src/`, `public/`, `index.html`, `vite.config.ts`, `tsconfig.json`, etc.). |
| `RUN` | `npm run build` | Executes `tsc -b && vite build`. Outputs production assets to `/app/dist`. |

### Stage 2: Production (`nginx:alpine`)

| Directive | Value | Description |
|-----------|-------|-------------|
| `FROM` | `nginx:alpine` | Minimal Nginx Alpine image for static file serving. |
| `COPY --from=builder` | `/app/dist /usr/share/nginx/html` | Copies compiled JS/CSS/HTML from the builder stage into Nginx's default web root. |
| `COPY` | `nginx.conf /etc/nginx/conf.d/default.conf` | Overrides the default Nginx config with the project's custom config (proxy pass to API, WebSocket support). |
| `EXPOSE` | `5173` | Documents the port the container listens on. Does not publish the port — that is handled by `docker-compose.yml` `ports:` mapping. |
| `CMD` | `["nginx", "-g", "daemon off;"]` | Runs Nginx in the foreground so the container stays alive. |

## Dependencies

- **`package.json` / `package-lock.json`** — Node dependency manifest.
- **`vite.config.ts`** — Vite build configuration with React plugin and dev proxy.
- **`tsconfig.json`** — TypeScript compiler options used during `tsc -b` (build mode).
- **`nginx.conf`** — Nginx server block copied into the production image.
- **`src/`** — Application source code compiled during the build stage.

## Usage

Referenced by the `web` service in `docker-compose.yml`:

```yaml
web:
    build:
      context: ./web
      dockerfile: Dockerfile
```

Build and run (production):

```bash
docker compose up --build -d web
```

Because the production `web` container has no source volume mount, any frontend changes require a full rebuild:

```bash
docker compose up --build -d --force-recreate web
```
