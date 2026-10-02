# Implementation Log: Startup Migrations and Efficiency

Date started: 2026-10-02
Implementation branch: `main`
Status: Complete

## Decisions recorded

- SQLite is the supported application database; PostgreSQL backend support has been removed.
- Migrations run automatically at application startup, use a persistent Alembic revision, and apply only pending revisions.
- Migration validation/application must precede data seeding, API readiness, webhook processing, and scheduled jobs.
- Elasticsearch remains in normal requirements and its current production handling is preserved. Tests use a blank endpoint or mocks.
- Scikit-learn/joblib remain in normal requirements; scheduled model training and scoring remain supported.
- Removed direct Python packages with no source imports: BeautifulSoup, aiofiles, OpenAI SDK, and Google Generative AI SDK.
- Removed direct `mapbox-gl` and the `deck.gl` umbrella package; explicitly retained imported deck.gl modules and replaced the dual map wrapper with `@vis.gl/react-maplibre`.
- Branch workflow: implement on `main`, verify, then synchronize to `architecture/monolith-to-decoupled`.

## Progress

| Date | Stage | Status | Notes |
|---|---|---|---|
| 2026-10-02 | Baseline and plan | Complete | Confirmed clean `main` worktree at `7d65f06`; architecture worktree is `/tmp/opencode/noc-arch` at `9bf0261`. Added this implementation document and log. |
| 2026-10-02 | Startup migration implementation | Complete | Added Alembic startup runner, cross-process SQLite migration lock, frozen v1 schema snapshot, legacy adoption revision, SQLite URL validation, post-migration PRAGMA setup, and conditional bootstrap data. Snapshot DDL/index parity matches all 35 current tables. Fresh/legacy/partial migration, frozen-baseline, duplicate-email failure, concurrent startup, and no-DDL/no-DML-at-head tests pass. A locked Python 3.11 container smoke seeded 7 feeds, 70 keywords, and 4 roles, then restarted at head. |
| 2026-10-02 | Dependency/runtime improvements | Complete | Removed unused Python SDK/parser/file-I/O dependencies and pandas; retained Elasticsearch and ML. Replaced DataFrame paths with record lists/counters; adopted RapidFuzz at the existing >85% title threshold. Batched CVE, crime, weather, and cloud duplicate lookups. Replaced the deck.gl umbrella and dual Mapbox/MapLibre React wrapper with used deck.gl modules and `@vis.gl/react-maplibre`. Added a hash-pinned `requirements.lock`, BuildKit caches, lockfile-hash-gated web-dev installs, and Docker ignores for the runtime data directory and generated model. The Python image is 589,260,648 bytes on `main`, down 17,356,291 bytes from the preceding local build that had copied ignored database/model artifacts; the architecture image is 589,046,181 bytes. Axios, React Router, MapLibre, Vite, and the React plugin were updated; npm reports zero vulnerabilities. |
| 2026-10-02 | Verification and review | Complete | Follow-up coverage tests frozen baseline independence and duplicate records within a worker batch. Frozen-schema parity passed; all 77 Python tests pass on the host and Python 3.11 container. Python 3.11 and host compile checks pass. Node 22 `npm ci`, production build, and both audit modes pass with zero vulnerabilities; Vite retains the large map-chunk warning. Docker Compose validation and shell syntax checks pass. `git diff --check` is clean. |
| 2026-10-02 | Branch synchronization | Complete | Synchronized verified main changes into `/tmp/opencode/noc-arch`, preserving architecture-only work. Reconciled two stale untracked permission-review files and byte-compared all current main changed/untracked implementation paths with their architecture-worktree counterparts. |

## Verification record

Verification checkpoint: all 77 Python tests pass on `main` and the architecture worktree, both with the host venv and the Python 3.11 Docker images; host/container `compileall` passes in both. Frozen v1 table DDL and indexes match the 35 current model tables. Fresh/legacy/partial/concurrent migration cases and no-work-at-head are covered. The final Python image builds exclude local databases/backups and generated model weights; the tests confirmed these artifacts are absent. Node 22 `npm ci`, frontend production builds, `npm audit`, and `npm audit --omit=dev` pass on both worktrees; both audits report zero vulnerabilities. Vite reports the existing large MapLibre/deck.gl chunk warning. `docker compose config --quiet`, `sh -n web/dev-entrypoint.sh`, and `git diff --check` pass on both. The implementation changes are synchronized and parity-checked. No cold/warm timing baseline had been recorded before this work.
