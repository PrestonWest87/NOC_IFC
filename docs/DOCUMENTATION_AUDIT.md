# Documentation Audit and Verification Record

**Audit date:** 2026-11-06
**Implementation branch:** `main`
**Change scope:** Documentation only; application source is unchanged.
**Previous full source/docs audit:** 2026-10-26. Its build and test results are historical checkpoints, not current verification results.

## Audit method and source inventory

Documentation claims were checked against the current tracked Python, TypeScript/React, migration, Docker Compose, dependency, and environment files. The detailed source-to-reference map is maintained in [the reference coverage index](reference/SOURCE_COVERAGE.md).

The implementation inventory checked includes:

- FastAPI lifecycle, all 17 router modules, auth/permission middleware, and WebSocket manager.
- SQLite models and migration revisions; 36 mapped ORM tables.
- The 21-job scheduler registry, startup-run groups, dynamic reload path, worker and maintenance entry points.
- Data-access/service algorithms, scoring/categorization/IOC extraction, AIOps correlation, LLM, email, and model training.
- The React SPA route map, user/session state, permission utilities, pages, shared components, and web runtime configuration.
- `docker-compose.yml`, Dockerfiles, nginx/Vite configuration, Python/Node dependency manifests, `.env.example`, and operational/restore scripts.

The current app's OpenAPI schema was generated from the checked-out source in the running application container. It contains **179 paths and 193 HTTP operations**; the inventory includes the two operations on `/application-settings/integrations`. The source also defines 21 registry-managed scheduler jobs and 14 routed React page components (including public account-recovery pages). The current single Alembic head is `20261105_0008`.

## Corrections made in this documentation pass

The guides and module references were refreshed to describe current behavior for:

- The 179-path/193-operation API inventory, including operational integrations.
- All 21 scheduler jobs, their startup policy, Central-time schedule formats, dynamic reload, and the consolidated Daily Fusion scheduler.
- The internal AIOps ontology spelling (`INTERNET`), rather than treating `PRIMARY_INTERNET` as the engine's canonical domain.
- Current scoring and asset-correlation windows, category names, IOC output/number of rules, and map/reduce execution semantics.
- Dynamic alert/Elastic settings, the supported LLM provider protocols, and the Arkansas 50-mile coverage/CAP filtering module.
- The webhook's actual acceptance response (HTTP 200 with an accepted body), HMAC/replay checks, and background persistence boundary.
- Bearer/session storage, structured 401/403 behavior, per-tab/action grants, site-type scoping, and WebSocket authorization/revalidation.
- The current dashboard/settings/reporting/AIOps/logbook UI, including the separated Application Settings sections and Mark Site Up/Resolve Site behavior.
- Backup/restore operations, legacy partial imports, SQLite migration ordering through `20261105_0008`, request limits, and current deployment topology.
- Current model/job/API inventory counts, source-reference mappings, and the optional `DATABASE_URL` template description.

## Source-level mismatches surfaced during the audit

These are implementation inconsistencies, not documentation facts to conceal:

1. **Category names are not yet aligned across producers and consumers.** `src/services/categorizer.py` emits `Cloud & IT Infrastructure`, `Physical Security & Crime`, and `Severe Weather & Natural Hazards`. The frontend filter list and parts of `get_executive_grid_intel()` still use older `Cloud & IT Infra`, `Physical Security`, and `Severe Weather` values; the global scoring queries compare exact category strings. `Data Breach & Privacy` is also absent from the telemetry page's category list. The guides identify the canonical labels and this mismatch.
2. **The test suite is intentionally untracked.** `tests/` is excluded by repository policy. This documentation refresh can verify checked-in code and configuration but cannot inspect or run the local-only regression suite.
3. **The production nginx `allow` rule is not an IP allowlist.** `web/nginx.conf` includes `allow 10.0.0.0/8` in `location /` but has no `deny all`; unmatched client addresses are not denied by that rule. Deployment network restriction must therefore be provided by the host firewall or an upstream proxy.

### Resolved since the previous audit

- The stale Streamlit/PyDeck comments previously noted in `src/services.py` were removed during the in-code documentation pass; no such references remain in the checked-in Python source.
- `.env.example` labels `DATABASE_URL` as an optional override, matching the default supplied by `src/core/config.py`. The environment reference now matches that template.

## Verification record

**Completed:** 2026-11-06. Inventory checks used the checked-out source and the running API application container. The full frontend image build was not repeated because this refresh changes documentation only.

| Check | Outcome |
|---|---|
| OpenAPI inventory | Passed: 179 paths / 193 HTTP operations from `app.openapi()`; the two integration operations are present in `docs/API.md`. |
| Permission catalog | Passed: all 9 page, 23 action, and 34 tab keys from `src/core/permissions.py` are represented in `docs/PERMISSIONS.md`. |
| ORM schema | Passed: all 36 mapped tables are represented in `docs/DATABASE_SCHEMA.md`. |
| Scheduler registry | Passed: all 21 jobs are counted in the scheduler reference and trigger-flow summary. |
| Migration head | Passed: Alembic reports `20261105_0008` as the single head. |
| Local Markdown links | Passed: local target paths verified across 137 Markdown files; no missing targets. |
| Docker Compose configuration | Passed: `docker compose config --quiet`. |
| Nginx configuration | Passed: `nginx -t` in the running web container. |
| Whitespace | Passed: `git diff --check`. |
| Architecture worktree synchronization | The 16 changed Markdown paths were mirrored to `architecture/monolith-to-decoupled`; byte comparison and `git diff --check` passed in both worktrees. |

The local-only Python regression suite is not present in the checked-out worktree and remains excluded from version control. The previous full source audit's Compose, frontend-image, and Nginx results are retained only as historical verification; this documentation-only refresh does not change application source or configuration.

External feed content, provider uptime, SMTP delivery, and LLM answers are runtime-dependent; documentation specifies the code's configured request/processing behavior and failure handling rather than asserting that an external service is currently reachable.

## In-code documentation

The source commenting pass was completed on 2026-10-26. See [In-Code Documentation Plan](IN_CODE_DOCUMENTATION_PLAN.md) for its scope and dated verification record; this audit changes no docstrings or source comments.
