# Configuration: `web/nginx.conf`

Production nginx server block copied to `/etc/nginx/conf.d/default.conf` by `web/Dockerfile`.

## Server

| Directive | Current value | Behavior |
|---|---|---|
| `listen` | `5173` | Container listener; Compose maps host `8501` to it. |
| `server_name` | `localhost test.weasts.net` | Accepted host names. |
| `resolver` | `127.0.0.11 valid=30s` | Docker DNS resolver for variable upstream resolution. |
| `client_max_body_size` | `101g` | Nginx-level request-body ceiling; API-level backup-upload limits remain controlled separately by `BACKUP_MAX_BYTES`. |
| `root` | `/usr/share/nginx/html` | Production Vite build output. |
| `index` | `index.html` | SPA entry document. |

## Locations

### `location = /health`

Exact-match liveness endpoint. Disables access logging, adds a text content type, and returns `ok` without contacting the API.

### `location ~ \.mjs$`

Serves JavaScript module files with `application/javascript`. Missing `.mjs` files return `404` rather than the SPA entry document, preventing module workers from receiving HTML with an invalid MIME type.

### `location /`

Uses `try_files $uri /index.html` for the React SPA fallback and contains an `allow 10.0.0.0/8` directive. There is no corresponding `deny all` in this location/server configuration, so this directive does **not** form an allowlist that blocks all other client addresses. The exact health endpoint is separate. Enforce the intended network boundary at a firewall or reverse proxy; changing the source configuration is outside this documentation-only pass.

### `location /api/`

Uses:

```nginx
set $api_upstream http://api:8101;
proxy_pass $api_upstream;
```

Passes `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers. The backend API handles authentication and route authorization.

### `location ^~ /api/v1/admin/backups`

This more-specific location proxies large backup downloads/uploads directly to the API. It sets 3600-second proxy/body timeouts and disables both proxy response buffering and request buffering so large backup streams are not buffered to disk or memory by Nginx.

### `location /ws`

Uses the same variable upstream and enables HTTP/1.1 upgrade headers:

- `proxy_http_version 1.1`
- `Upgrade: $http_upgrade`
- `Connection: "upgrade"`
- `Host: $host`

The frontend connects to the exact `/ws` path and supplies the session token as a query parameter.

## Usage

This configuration applies only to the production `web` container. The `web-dev` service uses Vite’s proxy configuration. The `allow 10.0.0.0/8` directive alone does not deny unmatched clients; see the `location /` note above.

```bash
docker compose exec web nginx -t
```
