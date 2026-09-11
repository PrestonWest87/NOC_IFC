# Configuration: `web/nginx.conf`

Production nginx server block copied to `/etc/nginx/conf.d/default.conf` by `web/Dockerfile`.

## Server

| Directive | Current value | Behavior |
|---|---|---|
| `listen` | `5173` | Container listener; Compose maps host `8501` to it. |
| `server_name` | `localhost test.weasts.net` | Accepted host names. |
| `resolver` | `127.0.0.11 valid=30s` | Docker DNS resolver for variable upstream resolution. |
| `root` | `/usr/share/nginx/html` | Production Vite build output. |
| `index` | `index.html` | SPA entry document. |

## Locations

### `location = /health`

Exact-match liveness endpoint. Disables access logging, adds a text content type, and returns `ok` without contacting the API.

### `location /`

Allows `10.0.0.0/8` clients and uses `try_files $uri /index.html` for the React SPA fallback. The allow rule applies to normal workspace routes, while the exact health endpoint is separate.

### `location /api/`

Uses:

```nginx
set $api_upstream http://api:8101;
proxy_pass $api_upstream;
```

Passes `Host`, `X-Real-IP`, and `X-Forwarded-For` headers. The backend API handles authentication and route authorization.

### `location /ws`

Uses the same variable upstream and enables HTTP/1.1 upgrade headers:

- `proxy_http_version 1.1`
- `Upgrade: $http_upgrade`
- `Connection: "upgrade"`
- `Host: $host`

The frontend connects to the exact `/ws` path and supplies the session token as a query parameter.

## Usage

This configuration applies only to the production `web` container. The `web-dev` service uses Vite’s proxy configuration.

```bash
docker compose exec web nginx -t
```
