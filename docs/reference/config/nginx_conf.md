# Configuration: `web/nginx.conf`

This is the active dev-c production Nginx server block, copied into the web image by `web/Dockerfile`. Compose adds the `noc-ifc-dev-c-api` host-gateway alias so Nginx can proxy to the C# API on port 8101.

## Server and static assets

The server listens on container port 5173, serves the Vite production build from `/usr/share/nginx/html`, enables gzip, and serves `/health` locally. Versioned `/maps/` GeoJSON gets a one-year immutable cache header. Missing `.mjs` files return 404 instead of the SPA shell.

The root SPA location has an `allow 10.0.0.0/8` directive but no matching `deny all`; it is not an allowlist. Enforce network restrictions at a firewall or trusted reverse proxy.

## API, backup, and WebSocket proxying

`/api/`, the more-specific backup upload/download route, and `/ws` proxy to `http://noc-ifc-dev-c-api:8101`. The backup route disables request and response buffering and sets one-hour timeouts for large encrypted package transfers. `/ws` enables HTTP/1.1 upgrade headers.

The Vite development service uses its own proxy from `vite.config.ts`; the Python runtime proxy and duplicate Nginx configuration have been removed from `dev-c`.

```bash
docker compose exec web nginx -t
```
