# NOC IFC `dev-c`: Backend Conversion and Project Restructure

## Purpose and decisions

This branch is dedicated to replacing the running Python backend with C# and, only where profiling justifies it, C++. The React frontend remains React and continues to use the existing HTTP and WebSocket contracts.

Confirmed direction:

- C# owns the running API, worker, webhook, persistence, integrations, and application workflows.
- C++ is an optional native compute library for measured CPU bottlenecks, not a second general-purpose backend.
- No Python runtime or Python package set is shipped in an active application container.
- Python may remain isolated in host-side/offline tools such as historical database migration and data-seeding utilities.
- Retire the local scikit-learn article classifier and Keep/Dismiss feedback feature.
- Preserve the external LLM provider integrations; they are configured remote services, not bundled model weights.
- Keep the existing frontend architecture and public API behavior. Removing the classifier and feedback controls is a focused feature removal, not a frontend rewrite.
- Start from the current `dev` branch. Do not modify `main` or `original-main`; do not merge or push this branch without a later request.

The GitHub tracking issue is [#1 — Re-architect and rebuild the back end in a C lang. C++ and C#](https://github.com/PrestonWest87/NOC_IFC/issues/1). Use it as the project checklist and status log.

## Current architecture and constraints

The current backend is Python 3.11 and consists of three processes: FastAPI REST/WebSocket API, scheduler worker, and SolarWinds webhook listener. All three share one SQLite database and persistent data volume. The frontend is a separately built React/Vite app served by Nginx, which proxies `/api/` and `/ws` to the API.

The current source and checked-in documentation identify these compatibility areas; regenerate or verify them from `dev` before implementation because counts can change:

- 18 API routers and a documented inventory of 203 paths / 219 HTTP operations.
- 45 SQLAlchemy models and SQLite migration head `20261123_0023`.
- 22 scheduler-managed jobs, including Central-time/DST schedules, dynamic reload, non-overlap, and jobs that cannot be disabled.
- REST authorization, structured 401/403 behavior, user sessions, site scoping, WebSocket authorization/revalidation, and WebSocket message shapes.
- `POST /regional/compile-map` returns a six-position response consumed positionally by the frontend.
- SolarWinds webhook signing, validation, payload normalization, and accepted-response behavior.
- Operational Email snapshots, scheduling, attachments, recipient routing, and backup/restore behavior.

Important source boundaries today:

| Current source | Responsibility | Target location |
|---|---|---|
| `src/api/main.py`, `src/api/routes/` | REST, WebSocket, middleware, endpoint binding | `src/NocIfc.Api/` |
| `src/services.py` | Cross-cutting domain behavior and data access | Feature use cases in `NocIfc.Application`; query adapters in `NocIfc.Infrastructure` |
| `src/models/schema.py`, `src/core/db.py` | SQLite schema and connection behavior | `NocIfc.Infrastructure/Persistence/Sqlite/` |
| `src/scheduler.py`, `src/workers/` | Job schedule and provider jobs | `src/NocIfc.Worker/Jobs/` |
| `src/webhook_listener.py` | SolarWinds ingestion host | `src/NocIfc.Webhook/` |
| `src/core/`, `src/utils/` | Configuration, permissions, email, LLM, backup, validation | Split by domain/application/infrastructure responsibility |
| `migrations/` | Alembic history and SQLite upgrades | `tools/offline-python/migrations/` |
| `scripts/` | Offline restore and seed tools | Shared C# CLI where logic is also used at runtime; remaining offline utilities under `tools/offline-python/` |
| `web/` | React, Vite, Nginx, frontend assets | Retain; remove only retired model/feedback controls and their calls |
| `Dockerfile`, `docker-compose.yml` | Current Python image and Compose topology | Shared multi-stage backend Dockerfile and tracked Compose files |

`src/services.py` and `src/scheduler.py` are large cross-cutting modules. The redesign should split responsibilities by feature and make API and worker hosts call the same application use cases rather than reproduce business logic. Remove compatibility shims such as the dynamic `src/services/` loader and `src/database.py` re-exports after all callers have moved.

## Model and feedback retirement

There is no neural-network implementation in the repository. The local model is a scikit-learn TF-IDF plus logistic-regression article classifier. Its artifact was absent from the inspected mounted data directories, but the code supports inference when an artifact exists and includes scheduled/manual training, Settings UI, permissions, and backup integration. The separately configured OpenAI-compatible, Ollama, and vLLM integrations are used for briefs and reports and remain in scope for the C# port.

Retire the complete local classifier and feedback feature:

- Remove model inference and the `joblib` artifact path from article scoring.
- Remove `src/train_model.py`, weekly retraining, manual retraining/count endpoints, and the ML Settings tab/actions.
- Remove classifier-specific permissions, `scikit-learn`/`joblib` runtime dependencies, tests, and documentation.
- Remove Keep/Dismiss controls, request paths, feedback-label behavior, and feedback-driven keyword-weight mutation.
- Keep deterministic keyword scoring and explicit administrator/operator keyword-weight editing.
- Do not silently reset current keyword weights: feedback-derived and manually edited weights cannot be reliably distinguished. Preserve existing weights unless a separate data correction is approved.
- Do not delete historical feedback columns or rows as part of the first behavior-removal step. Stop reading/writing them, then assess a later additive/cleanup migration with backup and rollback coverage.
- Keep old backup packages readable and integrity-checked. Do not restore or use a retired classifier artifact from a legacy package.

## Target architecture

Use a modular monolith with three separately deployable C# process hosts. The hosts share application and infrastructure libraries; they do not call one another over the network. Keep SQLite and its shared volume initially. Splitting the database or creating per-feature microservices would introduce distributed transaction, migration, backup, and restore work without first removing the current code duplication.

Dependency direction:

1. `NocIfc.Domain` contains domain types and rules and has no web, database, or integration dependency.
2. `NocIfc.Application` contains feature use cases and narrow ports needed by those use cases.
3. `NocIfc.Infrastructure` implements persistence and external-system ports.
4. `NocIfc.Api`, `NocIfc.Worker`, and `NocIfc.Webhook` are composition roots and transport/host adapters. They call shared application use cases; they do not contain duplicate business rules.

Add abstractions at real boundaries: SQLite access, email delivery, external feeds, LLM providers, system time, and optional native compute. Avoid an interface or generic repository for every class/table. Use feature-specific queries and keep SQL behavior explicit where that best preserves the legacy schema.

## Proposed file structure

```text
NOC_IFC/
├── README.md                         # Existing project overview
├── README_DEV_C.md                   # This migration plan
├── NocIfc.sln
├── global.json                       # Pinned .NET SDK
├── Directory.Build.props             # Shared compiler/analyzer settings
├── Directory.Packages.props          # Central package versions
├── .editorconfig
├── compose.yaml                      # Canonical tracked Compose topology
├── compose.dev-c.yaml                # dev-c project name, ports, and data-dev-c
│
├── src/
│   ├── NocIfc.Domain/
│   │   ├── Identity/
│   │   ├── Threat/
│   │   ├── AIOps/
│   │   ├── Regional/
│   │   ├── Reporting/
│   │   ├── Settings/
│   │   └── OperationalEmail/
│   │
│   ├── NocIfc.Application/
│   │   ├── Abstractions/
│   │   │   ├── Clock/
│   │   │   ├── Persistence/
│   │   │   ├── Email/
│   │   │   ├── Feeds/
│   │   │   ├── Llm/
│   │   │   └── NativeCompute/
│   │   └── Features/
│   │       ├── Identity/
│   │       ├── Threat/
│   │       ├── AIOps/
│   │       ├── Regional/
│   │       ├── Reporting/
│   │       ├── Settings/
│   │       ├── OperationalEmail/
│   │       └── BackupRestore/
│   │
│   ├── NocIfc.Infrastructure/
│   │   ├── Persistence/Sqlite/
│   │   │   ├── Connections/
│   │   │   ├── Queries/
│   │   │   └── SchemaVersionCheck/
│   │   ├── Integrations/
│   │   │   ├── Feeds/
│   │   │   ├── Weather/
│   │   │   ├── Elastic/
│   │   │   ├── Llm/
│   │   │   └── Email/
│   │   ├── BackupRestore/
│   │   └── NativeCompute/            # Only if the C++ gate passes
│   │
│   ├── NocIfc.Api/
│   │   ├── Endpoints/
│   │   ├── Authentication/
│   │   ├── WebSockets/
│   │   └── Program.cs
│   ├── NocIfc.Worker/
│   │   ├── Jobs/
│   │   ├── Scheduling/
│   │   └── Program.cs
│   └── NocIfc.Webhook/
│       ├── Endpoints/SolarWinds/
│       └── Program.cs
│
├── native/                           # Not created until profiling justifies it
│   └── NocIfc.Compute/
│       ├── CMakeLists.txt
│       ├── include/nocifc_compute.h   # Stable, versioned C ABI
│       └── src/
│
├── web/                              # Existing React/Vite/Nginx application
├── assets/
│   └── regional/                     # Canonical map inputs/generated artifacts
│
├── qa/                               # Tracked .NET/contract test projects
│   ├── NocIfc.UnitChecks/
│   ├── NocIfc.IntegrationChecks/
│   ├── NocIfc.ContractChecks/
│   └── Fixtures/
│       ├── Api/
│       └── Sqlite/
│
├── tools/
│   ├── offline-python/
│   │   ├── pyproject.toml
│   │   ├── requirements.lock
│   │   ├── migrations/               # Historical Alembic revisions, host-side
│   │   └── seed/
│   └── assets/
│       └── build-basemap.mjs          # One canonical basemap generator
│
├── deploy/
│   ├── Dockerfile.backend             # Shared stages; separate runtime targets
│   └── compose.production.yaml
├── docs/
│   ├── architecture/
│   ├── contracts/
│   ├── data/
│   └── operations/
└── .github/
    └── workflows/
        └── build-and-verify.yml
```

The `native/` project and `NocIfc.Infrastructure/NativeCompute/` adapter remain absent until a C++ use case passes the benchmark gate. Keep the existing `web/` application structure; this is not a frontend rewrite. The only planned frontend feature deletions are the classifier and Keep/Dismiss UI.

## Build and deployment redesign

- Pin the .NET SDK and centralize package versions and compiler/analyzer settings at the solution root.
- Build API, worker, and webhook from a shared multi-stage backend Dockerfile, publishing separate minimal runtime images. Reuse build layers without copying tests, docs, offline Python tools, or frontend source into runtime images.
- Keep the frontend in its existing independent Node/Vite-to-Nginx image. Preserve `/api/`, `/ws`, REST paths, payloads, session behavior, and error responses so the frontend does not need an API rewrite.
- Keep `compose.yaml` as the tracked common topology. Add `compose.dev-c.yaml` with a unique Compose project, host ports, and `./data-dev-c`; do not mount `data/` or `data-dev/` into dev-c.
- Run the existing Alembic migration tool from a pinned host-side Python environment as an explicit pre-start deployment step. It remains the single schema-migration authority and is excluded from all application images. C# services verify that the database is at the expected revision and fail readiness rather than attempting startup migrations in three processes.
- Port operational backup/restore into shared C# infrastructure so the API and any offline C# command-line utility reuse one implementation. Keep legacy encrypted package compatibility, including retired model payloads.
- Generate the regional basemap once in the build and share the resulting artifact with the backend and web build. The current backend consumes geometry built from frontend assets, and the generator currently runs in more than one build path.
- Use `qa/` for tracked tests. The existing `tests/` directory is intentionally local-only/ignored; do not stage or re-add it.
- CI should build/test .NET, run contract and persistence checks, build the unchanged frontend, exercise offline migration compatibility on disposable SQLite databases, build Compose targets, and inspect backend images for Python executables/packages.
- If C++ is introduced, build it with CMake and run native tests as a separate optional CI stage. Only backend images that call the native library should include it.

## Step-by-step implementation and acceptance gates

### 1. Baseline and branch isolation

- Confirm `dev-c` is based on the intended current `dev` commit and retain `dev`, `main`, and `original-main` unchanged.
- Preserve unrelated existing worktree changes and keep dev-c in its own worktree/Compose project/data directory.
- Regenerate API/OpenAPI and permission inventories. Snapshot representative status codes, JSON shapes, WebSocket messages, and frontend workflows.
- Record SQLite schema/migration head, scheduler jobs/settings, backup format, and representative runtime/performance baselines.

**Gate:** the parity inventory and isolated dev-c deployment are reproducible before porting begins.

### 2. Retire scikit-learn and Keep/Dismiss

- Remove the classifier, artifact loading, training script/job/routes, Settings UI/actions, permissions, backup model handling, `scikit-learn`/`joblib`, and associated docs/tests.
- Remove Keep/Dismiss actions, endpoints, stored-feedback behavior, and feedback-driven keyword-weight updates.
- Retain keyword scoring and explicit keyword-weight settings. Preserve current keyword weights; do not infer or reset which changes came from feedback.
- Keep historical feedback storage inert initially. Drop old columns/data only in a separately tested migration after backup compatibility is established.
- Keep old encrypted backups verifiable and restorable without reinstating a retired model artifact.

**Gate:** no model/feedback code path or UI remains; keyword scoring and unaffected article workflows pass regression checks.

### 3. Create the C# solution and container build

- Add the solution projects and dependency rules from the target tree.
- Implement configuration, logging, health/readiness, structured errors, and a backend image with no Python runtime.
- Keep API, worker, and webhook as separate process images sharing the same application/infrastructure libraries.

**Gate:** all C# images build; their startup and health checks work in isolated dev-c Compose; the existing frontend reaches the API through the same proxy paths.

### 4. Establish persistence and migration behavior

- Port the SQLite connection and query layer against the existing schema without changing schema semantics as a side effect of ORM setup.
- Keep Alembic as a single host-side migration command; run it once before C# services start, not from API/worker/webhook startup.
- Add schema-version readiness checks and tests for fresh, current-head, legacy, and partial databases.

**Gate:** row preservation, indexes/constraints, backup/restore, and concurrent-start behavior pass on disposable database copies.

### 5. Port API features by vertical slice

For each feature, port endpoint binding, application use case, persistence query, permission check, and parity test together. Suggested order:

1. Authentication, sessions, authorization catalog, user administration, recovery.
2. Settings, reference directories, and read-only dashboard/threat data.
3. Regional data, map compilation, AIOps/RCA, and shift logbook.
4. Reporting, LLM integrations, and Operational Email.
5. Backup, restore, and other administrative operations.

Preserve API and WebSocket contracts, the six-position regional map response, exact permission strings, site scoping, and structured 401/403 semantics.

**Gate per slice:** contract, authorization, persistence, and unchanged-frontend workflow checks pass before the slice is considered ported.

### 6. Port worker jobs and webhook

- Port SolarWinds webhook validation/normalization as its own C# host.
- Port scheduler jobs incrementally, calling shared application use cases rather than duplicating route logic.
- Preserve Central-time/DST schedules, startup policy, bounds, dynamic reload, non-overlap, last-good-data handling, and delivery deduplication.
- Use fake external transports while validating email, paging, and other side effects.

**Gate:** one active scheduler and webhook writer only; no duplicate alerts/emails; job recovery and reload checks pass.

### 7. Add C++ only after measuring C#

- Profile representative workloads after the C# implementation is functional.
- Port only a proven CPU bottleneck; likely candidates to measure include scoring, AIOps clustering, IOC extraction, and geometry calculations.
- Expose a narrow versioned C ABI and call it through one C# P/Invoke adapter. Do not use C++/CLI in Linux containers or let native types leak into application/domain code.
- Require reproducible benchmark improvement and matching correctness tests before keeping a native component.

**Gate:** C++ is omitted if it does not deliver a meaningful measured improvement without correctness or operational regressions.

### 8. Cut over and retire Python runtime

- Validate against isolated dev-c storage, then stop all old Python writers before starting C# writers on the target database.
- Run the host-side migration step once, take/verify a safety backup, start C# API/worker/webhook, and validate the unchanged frontend, WebSocket, webhook, scheduled delivery, backup, and restore paths.
- Keep offline Python utilities under `tools/offline-python`; exclude them from every runtime build context/image.
- Remove Python service entrypoints and backend runtime dependency files only after all required features pass parity checks.

**Final gate:** backend runtime images contain no Python executable or package set; the application, deployment, migration, rollback, and operator documentation is current.

## Issue #1 progress log

Use issue #1 as the master checklist. Update it at phase gates with completed feature groups, commits/PR links, verification results, and blockers. Suggested top-level checklist:

- [ ] Lock target architecture, compatibility inventory, and performance baselines.
- [ ] Remove local classifier and Keep/Dismiss feature.
- [ ] Add C# solution, layered modules, isolated dev-c Compose, and image build.
- [ ] Port SQLite access and schema readiness; validate host-side migrations.
- [ ] Port identity/permissions and REST/WebSocket feature groups.
- [ ] Port worker jobs and SolarWinds webhook.
- [ ] Port LLM, email, backup, and restore workflows.
- [ ] Evaluate C++ candidate(s); document benchmark decision (including “not needed”).
- [ ] Verify unchanged frontend, rollback, and Python-free runtime images.
- [ ] Update source, deployment, schema, API, and operations documentation.

## Current status

This branch currently contains the plan only. No backend code, frontend code, schema, migrations, tests, deployment files, or GitHub issue content are changed by this plan commit.
