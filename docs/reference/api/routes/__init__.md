# Package: `src.api.routes`

Package marker for the FastAPI route modules. Each route module owns its `/api/v1/...` prefix, tags, page permission dependency, and route-level action dependencies.

The current router set is documented in `src.api.main` and includes authentication, dashboards, threat telemetry, regional data, hunting, RCA, AIOps, logbook, reporting, settings, admin, LLM, email, keyword analysis, permissions, user administration, and application settings. Each mounted route module has a corresponding page in this directory; `docs/API.md` is the path/method inventory checked against FastAPI's OpenAPI routes.
