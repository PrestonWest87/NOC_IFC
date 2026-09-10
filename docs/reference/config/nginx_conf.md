# web/nginx.conf — Nginx Production Server Block

**Path:** `/home/weast/docker/NOC_IFC/web/nginx.conf`

## Purpose

Nginx server configuration for serving the production React SPA and reverse-proxying API and WebSocket traffic to the FastAPI backend. Deployed in the production `web` container at `/etc/nginx/conf.d/default.conf`.

## Directives

### `server` Block

| Directive | Value | Description |
|-----------|-------|-------------|
| `listen` | `5173` | Listens on TCP port 5173. Must match `EXPOSE 5173` in the `web/Dockerfile` and the port mapping in `docker-compose.yml`. |
| `server_name` | `localhost` | Virtual host name. Since this is a container-internal deployment, `localhost` is sufficient. In production with a domain, this would be the FQDN. |
| `root` | `/usr/share/nginx/html` | Document root — the directory where the compiled frontend assets (`index.html`, JS bundles, CSS) are copied from the builder stage. |
| `index` | `index.html` | Default file served when a directory is requested. |

### `location /` — Static SPA Serving

| Directive | Value | Description |
|-----------|-------|-------------|
| `try_files` | `$uri /index.html` | **SPA fallback.** Attempts to serve the exact URI path; if the file is not found (e.g., for client-side routes like `/threat-hunting`), falls back to `index.html` so React Router can handle the route. |

### `location /api/` — REST API Reverse Proxy

| Directive | Value | Description |
|-----------|-------|-------------|
| `proxy_pass` | `http://api:8101` | Forwards all `/api/` requests to the backend `api` service on port 8101 (Docker internal DNS). |
| `proxy_set_header Host` | `$host` | Passes the original `Host` header from the client. |
| `proxy_set_header X-Real-IP` | `$remote_addr` | Passes the client's real IP address. |
| `proxy_set_header X-Forwarded-For` | `$proxy_add_x_forwarded_for` | Appends the client IP to the X-Forwarded-For chain. |

### `location /ws` — WebSocket Reverse Proxy

| Directive | Value | Description |
|-----------|-------|-------------|
| `proxy_pass` | `http://api:8101` | Forwards WebSocket upgrade requests to the backend `api` service. Note: uses `http://` (not `ws://`) — Nginx handles the protocol upgrade via headers. |
| `proxy_http_version` | `1.1` | Required for WebSocket — HTTP/1.1 is the minimum version that supports the `Upgrade` header. |
| `proxy_set_header Upgrade` | `$http_upgrade` | Passes the `Upgrade: websocket` header from the client to the backend. |
| `proxy_set_header Connection` | `"upgrade"` | Overrides the `Connection` header to `upgrade`, signalling the backend to switch protocols. |
| `proxy_set_header Host` | `$host` | Passes the original `Host` header. |

**Critical detail:** The `/ws` location does **not** include a trailing slash. This means a request to `ws://host:5173/ws` (without trailing content) is matched, while `/ws/something` would **not** match this location block. The frontend WebSocket client should connect to `ws://host:5173/ws` (exact path).

## Dependencies

| Dependency | Relationship |
|------------|-------------|
| `api` service (Docker Compose) | Backend target for both `/api/` and `/ws` proxy_pass directives. Must be reachable via Docker internal DNS at `http://api:8101`. |
| `web/Dockerfile` | Copies this file to `/etc/nginx/conf.d/default.conf` in the production image. |
| Frontend build output (`dist/`) | Static assets placed in `/usr/share/nginx/html` during the multi-stage build. |

## Usage

This configuration is **not** used during development (`web-dev` service) — Vite's built-in dev server handles proxying via `vite.config.ts`. It only applies to the production `web` service.

The file is copied into the Nginx container during the Docker build:

```dockerfile
COPY nginx.conf /etc/nginx/conf.d/default.conf
```

To test configuration validity inside a running container:

```bash
docker compose exec web nginx -t
```

To reload Nginx after config changes (requires container rebuild since the config is baked in):

```bash
docker compose up --build -d --force-recreate web
```
