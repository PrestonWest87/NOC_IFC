# Documentation Audit and Verification Record

**Audit date:** 2026-11-23
**Implementation branch:** `dev`
**Change scope:** Reconcile tracked documentation and in-code contracts against the current backend, frontend, migrations, deployment files, and dependency manifests; update only documentation/comments.
**Previous full source/docs audit:** 2026-10-26. The 2026-11-12 checkpoint below is historical where current source has since changed.

## Audit method and source inventory

Documentation claims were checked against the current tracked Python, TypeScript/React, migration, Docker Compose, dependency, and environment files. The detailed source-to-reference map is maintained in [the reference coverage index](reference/SOURCE_COVERAGE.md).

The implementation inventory checked includes:

- FastAPI lifecycle, all 18 router modules, auth/permission middleware, and WebSocket manager.
- SQLite models and migration revisions; 45 mapped ORM tables.
- The 22-job scheduler registry, startup-run groups, dynamic reload path, worker and maintenance entry points.
- Data-access/service algorithms, scoring/categorization/IOC extraction, AIOps correlation, LLM, email, and model training.
- The React SPA route map, user/session state, permission utilities, pages, shared components, and web runtime configuration.
- `docker-compose.yml`, Dockerfiles, nginx/Vite configuration, Python/Node dependency manifests, `.env.example`, and operational/restore scripts.

The OpenAPI schema generated from the checked-out source contains **203 paths and 219 HTTP operations**. The source defines 18 API router modules, 22 registry-managed scheduler jobs, 15 routed React page components (including public account-recovery pages), and 45 mapped ORM tables. The current single Alembic head is `20261123_0023`.

## Corrections made in this documentation pass

The guides and module references were refreshed to describe current behavior for:

- The 203-path/219-operation API inventory, including Operational Email reference data, Settings directories, CSV-import endpoints, Microsoft 365 status, and SMTP test delivery.
- All 22 scheduler jobs, including the non-disableable Operational Email queue, their startup policy, Central-time schedules, dynamic reload, and the consolidated Daily Fusion scheduler.
- The internal AIOps ontology spelling (`INTERNET`), rather than treating `PRIMARY_INTERNET` as the engine's canonical domain.
- Current scoring and asset-correlation windows, category names, IOC output/number of rules, and map/reduce execution semantics.
- Dynamic alert/Elastic settings, the supported LLM provider protocols, and the Arkansas 50-mile coverage/CAP filtering module.
- The webhook's actual acceptance response (HTTP 200 with an accepted body), HMAC/replay checks, and background persistence boundary.
- Bearer/session storage, structured 401/403 behavior, per-tab/action grants, site-type scoping, and WebSocket authorization/revalidation.
- The current dashboard/settings/reporting/AIOps/logbook UI, Operational Email workspace, and permissioned Email Contacts/Network Orders Settings tabs.
- Backup/restore operations, legacy partial imports, SQLite migration ordering through `20261123_0023`, request limits, and dev Compose port/network/data isolation.
- Current sender-provider behavior (SMTP or Gmail), Operational Email calendar controls/unified Expected impact behavior, Maintenance Complete circuit-detail transfer, HTML identifier emphasis, template-specific timezone suffixes, model/job/API counts, source-reference mappings, and the optional `DATABASE_URL` template description.
- Public service/core/scheduler helper inventories in their source reference pages, plus source comment/docstring and TypeScript TSDoc coverage added after the 2026-10-26 pass.

## Constraints documented from source

These are current implementation constraints, not documentation errors:

1. **The test suite is intentionally untracked.** `tests/` is excluded by repository policy. Tests run for this audit remain local-only.
2. **The production nginx `allow` rule is not an IP allowlist.** `web/nginx.conf` includes `allow 10.0.0.0/8` in `location /` but has no `deny all`; unmatched client addresses are not denied by that rule. Deployment network restriction must therefore be provided by the host firewall or an upstream proxy.

### Resolved since the previous audit

- The stale Streamlit/PyDeck comments previously noted in `src/services.py` were removed during the in-code documentation pass; no such references remain in the checked-in Python source.
- `.env.example` labels `DATABASE_URL` as an optional override, matching the default supplied by `src/core/config.py`. The environment reference now matches that template.
- Category labels are aligned across the categorizer, Global Risk scoring filters, and the Threat Telemetry selector. The selector includes all nine non-General categories; `KeywordAnalysisPage` retains color aliases for older stored labels.

## Verification record

**Completed:** 2026-11-23. The current dev branch was checked against generated API/schema/scheduler inventories, source-reference coverage, in-code documentation, and Markdown links.

| Check | Outcome |
|---|---|
| OpenAPI inventory | Passed: 203 paths / 219 HTTP operations from `app.openapi()`; every operation is represented in `docs/API.md`. |
| Permission catalog | Passed: all 10 page, 23 action, and 36 tab keys from `src/core/permissions.py` are represented in `docs/PERMISSIONS.md`. |
| ORM schema | Passed: all 45 mapped tables are represented in `docs/DATABASE_SCHEMA.md`. |
| Scheduler registry | Passed: all 22 jobs are counted in the scheduler reference and trigger-flow summary. |
| Migration head | Passed: Alembic reports `20261123_0023` as the single head; the fresh/legacy migration suite passes. |
| Local Markdown links | Passed: local target paths resolve across tracked and available repository documentation. |
| Documentation contracts | Passed: 8 tests covering OpenAPI operations, schema columns/nullability/indexes, environment variables, routed reference pages, scheduler defaults, and Markdown links. |
| Source coverage | Passed: 66 Python modules mapped; the API package initializer and Python Markdown renderer are indexed. |
| Public symbol references | Passed: exported classes/functions in mapped backend, worker, scheduler, and script modules appear in their reference pages; API route operations are covered from OpenAPI. |
| In-code documentation | Passed: all 66 `src/` modules have module docs, all Python classes/functions outside frozen `migrations/schema_v1.py` have docstrings, and 66/66 exported TypeScript/TSX declarations have TSDoc. |
| Focused regression tests | Passed: 42 Operational Email tests and 18 migration tests; test files remain local-only. |
| Container/config checks | Passed: API/web Docker builds and `docker compose -p noc-ifc-dev config --quiet`; the web build retains the existing >500 kB map-chunk warning. |
| Whitespace | Passed: `git diff --check`. |

The 2026-11-12 checkpoint recorded 223 local-only Python tests and an nginx syntax check; those results remain historical. This pass changed documentation/comments only and did not alter runtime behavior.

External feed content, provider uptime, SMTP delivery, and LLM answers are runtime-dependent; documentation specifies the code's configured request/processing behavior and failure handling rather than asserting that an external service is currently reachable.

## In-code documentation

The original source commenting pass was completed on 2026-10-26; this audit added missing helper docstrings and exported TSDoc without changing runtime behavior. See [In-Code Documentation Plan](IN_CODE_DOCUMENTATION_PLAN.md) for the dated coverage records.
