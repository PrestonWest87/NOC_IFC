# C# Backend Dockerfile

**Path:** `deploy/Dockerfile.backend`

The multi-stage .NET 10 build publishes three separate runtime targets from the shared solution:

| Target | Entry point | Host |
|---|---|---|
| `api` | `NocIfc.Api.dll` | REST/WebSocket API, port 8101 |
| `worker` | `NocIfc.Worker.dll` | Scheduled jobs |
| `webhook` | `NocIfc.Webhook.dll` | SolarWinds gateway, port 8100 |

The build restores `NocIfc.sln`, runs the application/API test projects, then publishes each target from the same build stage. Runtime images use `mcr.microsoft.com/dotnet/aspnet:10.0`; no Python runtime or Python package set is copied into them. The React/Nginx frontend remains a separate build in `web/Dockerfile`.

The host-side Python migration and backup tools are excluded from the Docker context through `.dockerignore` and run from the pinned environment in `tools/offline-python/`.
