# Documentation Audit and Verification Record

**Audit date:** 2026-11-10
**Implementation branch:** `dev`
**Change scope:** Operational Email implementation, isolated dev Compose defaults, and source-aligned documentation.
**Previous full source/docs audit:** 2026-10-26. Its build and test results are historical checkpoints, not current verification results.

## Audit method and source inventory

Documentation claims were checked against the current tracked Python, TypeScript/React, migration, Docker Compose, dependency, and environment files. The detailed source-to-reference map is maintained in [the reference coverage index](reference/SOURCE_COVERAGE.md).

The implementation inventory checked includes:

- FastAPI lifecycle, all 18 router modules, auth/permission middleware, and WebSocket manager.
- SQLite models and migration revisions; 40 mapped ORM tables.
- The 22-job scheduler registry, startup-run groups, dynamic reload path, worker and maintenance entry points.
- Data-access/service algorithms, scoring/categorization/IOC extraction, AIOps correlation, LLM, email, and model training.
- The React SPA route map, user/session state, permission utilities, pages, shared components, and web runtime configuration.
- `docker-compose.yml`, Dockerfiles, nginx/Vite configuration, Python/Node dependency manifests, `.env.example`, and operational/restore scripts.

The OpenAPI schema generated from the checked-out source contains **188 paths and 202 HTTP operations**. The source defines 22 registry-managed scheduler jobs and 15 routed React page components (including public account-recovery pages). The current single Alembic head is `20261110_0009`.

## Corrections made in this documentation pass

The guides and module references were refreshed to describe current behavior for:

- The 188-path/202-operation API inventory, including Operational Email endpoints.
- All 22 scheduler jobs, including the non-disableable Operational Email queue, their startup policy, Central-time schedules, dynamic reload, and the consolidated Daily Fusion scheduler.
- The internal AIOps ontology spelling (`INTERNET`), rather than treating `PRIMARY_INTERNET` as the engine's canonical domain.
- Current scoring and asset-correlation windows, category names, IOC output/number of rules, and map/reduce execution semantics.
- Dynamic alert/Elastic settings, the supported LLM provider protocols, and the Arkansas 50-mile coverage/CAP filtering module.
- The webhook's actual acceptance response (HTTP 200 with an accepted body), HMAC/replay checks, and background persistence boundary.
- Bearer/session storage, structured 401/403 behavior, per-tab/action grants, site-type scoping, and WebSocket authorization/revalidation.
- The current dashboard/settings/reporting/AIOps/logbook UI and the Operational Email workspace with its page-level permission.
- Backup/restore operations, legacy partial imports, SQLite migration ordering through `20261110_0009`, request limits, and dev Compose port/network/data isolation.
- Current model/job/API inventory counts, source-reference mappings, and the optional `DATABASE_URL` template description.

## Source-level mismatches surfaced during the audit

These are implementation inconsistencies, not documentation facts to conceal:

1. **Category names are not yet aligned across producers and consumers.** `src/services/categorizer.py` emits `Cloud & IT Infrastructure`, `Physical Security & Crime`, and `Severe Weather & Natural Hazards`. The frontend filter list and parts of `get_executive_grid_intel()` still use older `Cloud & IT Infra`, `Physical Security`, and `Severe Weather` values; the global scoring queries compare exact category strings. `Data Breach & Privacy` is also absent from the telemetry page's category list. The guides identify the canonical labels and this mismatch.
2. **The test suite is intentionally untracked.** `tests/` is excluded by repository policy. Local-only regression tests were run for this change and remain unstaged.
3. **The production nginx `allow` rule is not an IP allowlist.** `web/nginx.conf` includes `allow 10.0.0.0/8` in `location /` but has no `deny all`; unmatched client addresses are not denied by that rule. Deployment network restriction must therefore be provided by the host firewall or an upstream proxy.

### Resolved since the previous audit

- The stale Streamlit/PyDeck comments previously noted in `src/services.py` were removed during the in-code documentation pass; no such references remain in the checked-in Python source.
- `.env.example` labels `DATABASE_URL` as an optional override, matching the default supplied by `src/core/config.py`. The environment reference now matches that template.

## Verification record

**Completed:** 2026-11-10. The Operational Email branch was checked against the generated OpenAPI schema, all mapped ORM tables, the scheduler registry, frontend/API source references, and dev Compose settings.

| Check | Outcome |
|---|---|
| OpenAPI inventory | Passed: 188 paths / 202 HTTP operations from `app.openapi()`; every operation is represented in `docs/API.md`. |
| Permission catalog | Passed: all 10 page, 23 action, and 34 tab keys from `src/core/permissions.py` are represented in `docs/PERMISSIONS.md`. |
| ORM schema | Passed: all 40 mapped tables are represented in `docs/DATABASE_SCHEMA.md`. |
| Scheduler registry | Passed: all 22 jobs are counted in the scheduler reference and trigger-flow summary. |
| Migration head | Passed: Alembic reports `20261110_0009` as the single head; fresh and legacy-upgrade tests pass. |
| Local Markdown links | Passed: local target paths resolve across the available repository documentation. |
| Documentation contracts | Passed: API operations, schema columns/nullability/indexes, environment references, routed source pages, and scheduler defaults match source. |
| Python regression suite | Passed: 195 local-only tests, including Operational Email validation, BCC, maintenance linking, scheduling, and permission coverage; test files remain excluded from version control. |
| Frontend production build | Passed in the Node 22 web image; the existing large MapLibre/deck.gl chunk warning remains. |
| Backend image and Python compilation | Passed using the Python 3.11 API image. |
| Docker Compose configuration | Passed: host ports 8099, 8102, 8502, and 5174; isolated `data-dev`; Docker's built-in bridge without a new subnet. |
| Nginx configuration | Passed: `nginx -t` with the dev API host-gateway alias. |
| Whitespace | Passed: `git diff --check`. |

The dev stack and the existing main instance ran concurrently with their respective port mappings. Operational Email changes remain on `dev`; the unrelated untracked integration-plan documents remain preserved and outside the feature commits.

External feed content, provider uptime, SMTP delivery, and LLM answers are runtime-dependent; documentation specifies the code's configured request/processing behavior and failure handling rather than asserting that an external service is currently reachable.

## In-code documentation

The source commenting pass was completed on 2026-10-26. See [In-Code Documentation Plan](IN_CODE_DOCUMENTATION_PLAN.md) for its scope and dated verification record; this audit changes no docstrings or source comments.
