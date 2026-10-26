# Documentation Audit and Verification Record

**Audit date:** 2026-10-26
**Implementation branch:** `main`
**Change scope:** Documentation only; source files are not modified in this stage.

## Audit method and source inventory

Documentation claims were checked against the current tracked Python, TypeScript/React, migration, Docker Compose, dependency, and environment files. The detailed source-to-reference map is maintained in [the reference coverage index](reference/SOURCE_COVERAGE.md).

The implementation inventory checked includes:

- FastAPI lifecycle, all 17 router modules, auth/permission middleware, and WebSocket manager.
- SQLite models and migration revisions; 35 mapped ORM tables.
- The 20-job scheduler registry, startup-run groups, dynamic reload path, worker and maintenance entry points.
- Data-access/service algorithms, scoring/categorization/IOC extraction, AIOps correlation, LLM, email, and model training.
- The React SPA route map, user/session state, permission utilities, pages, shared components, and web runtime configuration.
- `docker-compose.yml`, Dockerfiles, nginx/Vite configuration, Python/Node dependency manifests, `.env.example`, and operational/restore scripts.

The current app's OpenAPI schema was generated from the checked-out source using the available Python 3.11 application container. It contains **177 paths and 189 HTTP operations**; the operation inventory in `docs/API.md` was reconciled to that schema. The source also defines 20 registry-managed scheduler jobs and 14 routed React page components (including public account-recovery pages).

## Corrections made in this documentation pass

The guides and module references now describe current behavior for:

- Scheduler defaults, startup-only jobs, Central-time schedule formats, dynamic reload, and the consolidated Daily Fusion scheduler.
- The internal AIOps ontology spelling (`INTERNET`), rather than treating `PRIMARY_INTERNET` as the engine's canonical domain.
- Current scoring and asset-correlation windows, category names, IOC output/number of rules, and map/reduce execution semantics.
- The webhook's actual acceptance response (HTTP 200 with an accepted body), HMAC/replay checks, and background persistence boundary.
- Bearer/session storage, structured 401/403 behavior, per-tab/action grants, site-type scoping, and WebSocket authorization/revalidation.
- The current dashboard/settings/reporting/AIOps/logbook UI, including the separated Application Settings sections and Mark Site Up/Resolve Site behavior.
- Backup/restore operations, legacy partial imports, SQLite migration ordering, request limits, and current deployment topology.

## Source-level mismatches surfaced during the audit

These are implementation inconsistencies, not documentation facts to conceal. This stage documents them without editing source:

1. **Category names are not yet aligned across producers and consumers.** `src/services/categorizer.py` emits `Cloud & IT Infrastructure`, `Physical Security & Crime`, and `Severe Weather & Natural Hazards`. The frontend filter list and parts of `get_executive_grid_intel()` still use older `Cloud & IT Infra`, `Physical Security`, and `Severe Weather` values; the global scoring queries compare exact category strings. `Data Breach & Privacy` is also absent from the telemetry page's category list. The guides identify the canonical labels and this mismatch.
2. **Historical comments remain in service code.** Some comments/section labels in `src/services.py` still mention Streamlit or PyDeck although the active application is a React/Deck.gl SPA and the relevant helpers are server-side Shapely processing. These are included in the in-code documentation plan for a later source-only change.
3. **The test suite is intentionally untracked.** `tests/` is excluded by repository policy. The source audit can verify checked-in code and configuration, but cannot inspect or run the local-only regression suite from this worktree.
4. **The production nginx `allow` rule is not an IP allowlist.** `web/nginx.conf` includes `allow 10.0.0.0/8` in `location /` but has no `deny all`; unmatched client addresses are not denied by that rule. Deployment network restriction must therefore be provided by the host firewall or an upstream proxy. This audit documents the current configuration without changing it.
5. **The environment template overstates the database variable requirement.** `.env.example` comments that `DATABASE_URL` is required, while `src/core/config.py` supplies the SQLite path when the variable is unset. The deployment guides describe the runtime behavior; the template comment is left unchanged in this documentation-only pass.

## Verification record

**Completed:** 2026-10-26. Application source/configuration files were mounted read-only during source-backed inventory checks.

| Check | Outcome |
|---|---|
| OpenAPI schema and documented operations | Passed: 177 paths / 189 HTTP operations; all 189 method/path operations were found in `docs/API.md`. |
| Permission catalog coverage | Passed: all 9 page, 23 action, and 34 tab keys from `src/core/permissions.py` appear in `docs/PERMISSIONS.md`. |
| ORM table coverage | Passed: all 35 mapped tables appear in `docs/DATABASE_SCHEMA.md`. |
| Migration head | Passed: Alembic reports `20261013_0005` as the single head. |
| Docker Compose configuration | Passed: `docker compose config --quiet`. |
| Production frontend build | Passed: `docker compose build web` uses the lockfile under Node 22. The build retains the existing >500 kB chunk warning. |
| Nginx configuration | Passed: `nginx -t` against the checked-out `web/nginx.conf`. |
| Markdown links | Passed: 145 local links checked; two incorrect relative links in `docs/reference/api/routes/settings_admin.md` were corrected before the final check. |
| Whitespace and changed-file scope | Passed: `git diff --check`; tracked/untracked changes are Markdown documentation only. |
| Architecture worktree synchronization | Passed: the same 51 changed Markdown paths were mirrored to `architecture/monolith-to-decoupled`; byte comparison found zero differences, and its `git diff --check` passed. No application source or tracked configuration was changed in either worktree. |

The host-side `npm run build` could not use the incomplete, permission-restricted local `web/node_modules` and host Node 18; the Docker Node 22 production build passed. `npm ci` on the host stopped with `EACCES` while unlinking a root-owned ignored dependency file. No source or tracked configuration file was changed. The local-only Python regression suite and `compileall` were not run because this pass changes documentation only; the suite is also intentionally excluded from version control.

External feed content, provider uptime, SMTP delivery, and LLM answers are runtime-dependent; documentation specifies the code's configured request/processing behavior and failure handling rather than asserting that an external service is currently reachable.

## Follow-on in-code documentation

The source commenting work is planned separately in [In-Code Documentation Plan](IN_CODE_DOCUMENTATION_PLAN.md). No docstrings or source comments are changed by this audit.
