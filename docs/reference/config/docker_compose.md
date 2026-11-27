# C# Compose Topology

The tracked `compose.yaml` is the only application stack on `dev-c`; it includes `compose.dev-c.yaml`. The Python runtime Compose file has been removed.

| Service | Build target | Host port | Storage |
|---|---|---:|---|
| `api` | `deploy/Dockerfile.backend:api` | 8101 | `./data-dev-c:/app/data` |
| `worker` | `deploy/Dockerfile.backend:worker` | Internal | `./data-dev-c:/app/data` |
| `webhook` | `deploy/Dockerfile.backend:webhook` | 8100 | `./data-dev-c:/app/data` |
| `web` | `web/Dockerfile` | 8501 | None |
| `web-dev` (`dev` profile) | `node:22-alpine` | 5173 | `./web` and named node_modules volume |

All services use Docker's built-in `bridge` network. Nginx/Vite reach the API using the host-gateway alias. Backend services read `.env`; the web services receive `VITE_API_URL` in Compose.

```bash
docker compose config
docker compose up --build -d
docker compose --profile dev up --build -d
```

The host-side Python environment under `tools/offline-python/` is used only to prepare or upgrade SQLite/backup data. It is not part of any application image.
