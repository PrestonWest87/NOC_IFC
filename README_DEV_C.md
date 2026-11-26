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
- Start from the current `dev` branch. Do not modify or merge into `main` or `original-main`. Checkpoint commits and pushes to `dev-c` are user-authorized.

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
| `src/api/main.py`, `src/api/routes/` | REST, WebSocket, middleware, endpoint binding | Feature-scoped controllers and WebSocket handlers in `src/NocIfc.Api/` |
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

### HTTP API style

- Use ASP.NET Core MVC controllers as the default for REST operations. Organize controllers by feature/resource rather than putting all operations into one controller or one large `Program.cs` route map.
- Keep controllers as thin HTTP adapters: bind and validate requests, apply authorization policies, call an application use case, and return a response DTO. Do not put business logic or SQLite queries in controllers.
- Preserve existing `/api/v1` paths, methods, status codes, JSON shapes, and permission behavior. Centralize exception and validation response mapping and verify it with contract tests.
- ASP.NET Core's `[ApiController]` validation defaults differ from FastAPI's validation response (including status code and body shape). Configure a compatibility response rather than allowing framework defaults to change the frontend contract.
- Keep health/readiness in a small diagnostics controller. WebSockets use a dedicated connection handler, not an MVC action. The separate SolarWinds webhook host can use a focused controller.
- Avoid a generic `BaseController` unless a concrete repeated HTTP concern requires it; use shared middleware, filters, authorization policies, and application services for cross-cutting behavior.

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
├── contracts/
│   └── permission_catalog.json       # Shared Python/C# permission contract
│
├── src/
│   ├── NocIfc.Domain/
│   │   ├── Identity/
│   │   │   ├── AuthenticatedUser.cs
│   │   │   ├── FailedLoginAlert.cs
│   │   │   ├── LoginCredential.cs
│   │   │   ├── LoginUser.cs
│   │   │   ├── PendingRegistrationInvite.cs
│   │   │   ├── PasswordResetRequestInfo.cs
│   │   │   ├── RecoveryEmailRequestInfo.cs
│   │   │   ├── RegistrationInviteInfo.cs
│   │   │   ├── RoleDefinition.cs
│   │   │   ├── UserAdminTarget.cs
│   │   │   └── UserDirectoryEntry.cs
│   │   ├── Threat/
│   │   │   ├── CisaKevEntry.cs
│   │   │   ├── KeywordWeight.cs
│   │   │   ├── ThreatArticle.cs
│   │   │   ├── RssCatalog.cs
│   │   │   ├── ThreatStatus.cs
│   │   │   └── ThreatHuntingData.cs
│   │   ├── Dashboard/
│   │   │   ├── ExecutiveIntel.cs
│   │   │   ├── InternalRiskData.cs
│   │   │   └── OperationalDashboard.cs
│   │   ├── AIOps/
│   │   ├── Logbook/
│   │   │   └── ShiftLogEntry.cs
│   │   ├── Regional/
│   │   │   └── GeoJsonFeedStatus.cs
│   │   ├── Reporting/
│   │   ├── Settings/
│   │   │   ├── RiskScoringSettings.cs
│   │   │   ├── MonitoredLocationEntry.cs
│   │   │   └── SettingsReferenceDirectoryEntry.cs
│   │   └── OperationalEmail/
│   │
│   ├── NocIfc.Application/
│   │   ├── Abstractions/
│   │   │   ├── Identity/
│   │   │   │   ├── IUserSessionResolver.cs
│   │   │   │   ├── IAuthenticationStore.cs
│   │   │   │   ├── IAccountRecoveryStore.cs
│   │   │   │   ├── IFailedLoginAlertStore.cs
│   │   │   │   ├── IRecoveryEmailStore.cs
│   │   │   │   ├── IRoleDirectory.cs
│   │   │   │   ├── IRoleWriter.cs
│   │   │   │   ├── IPasswordVerifier.cs
│   │   │   │   ├── IPasswordHasher.cs
│   │   │   │   ├── ISiteTypeDirectory.cs
│   │   │   │   ├── IUserDirectory.cs
│   │   │   │   └── IUserAdminStore.cs
│   │   │   ├── Clock/
│   │   │   ├── Persistence/
│   │   │   ├── Settings/
│   │   │   │   ├── IApplicationSettingsStore.cs
│   │   │   │   ├── IAiSmtpSettingsStore.cs
│   │   │   │   ├── IAssetInventoryStore.cs
│   │   │   │   ├── IFacilityDirectoryStore.cs
│   │   │   │   ├── IOperationalIntegrationSettingsStore.cs
│   │   │   │   ├── IRiskScoringSettingsStore.cs
│   │   │   │   ├── ISchedulerSettingsStore.cs
│   │   │   │   └── ISettingsReferenceDirectoryStore.cs
│   │   │   ├── Threat/
│   │   │   │   ├── ICisaKevStore.cs
│   │   │   │   ├── IRssSettingsStore.cs
│   │   │   │   ├── IThreatArticleStore.cs
│   │   │   │   ├── IThreatStatusStore.cs
│   │   │   │   └── IThreatHuntingStore.cs
│   │   │   ├── Dashboard/
│   │   │   │   ├── IExecutiveIntelStore.cs
│   │   │   │   ├── IInternalRiskStore.cs
│   │   │   │   └── IOperationalDashboardStore.cs
│   │   │   ├── Email/
│   │   │   │   └── IEmailSender.cs
│   │   │   ├── Logbook/
│   │   │   │   └── IShiftLogbookStore.cs
│   │   │   ├── Regional/
│   │   │   │   ├── IRegionalPreferenceStore.cs
│   │   │   │   ├── IRegionalDataStore.cs
│   │   │   │   ├── INwsForecastProvider.cs
│   │   │   │   ├── IRegionalCountyGeometryProvider.cs
│   │   │   │   ├── IRegionalHazardSyncProvider.cs
│   │   │   │   └── IRegionalWildfireProvider.cs
│   │   │   ├── Elastic/
│   │   │   │   └── IElasticEventSource.cs
│   │   │   ├── Feeds/
│   │   │   ├── Llm/
│   │   │   │   ├── ILlmConnectionTester.cs
│   │   │   │   └── ILlmChatCompletionClient.cs
│   │   │   └── NativeCompute/
│   │   └── Features/
│   │       ├── Identity/
│   │       │   ├── AccountRecoveryCommands.cs
│   │       │   ├── AuthenticationService.cs
│   │       │   ├── CapabilityTokenHash.cs
│   │       │   ├── EmailAddressRules.cs
│   │       │   ├── PermissionCatalog.cs
│   │       │   ├── RoleAccessPolicy.cs
│   │       │   ├── RoleCommands.cs
│   │       │   ├── RoleQueries.cs
│   │       │   ├── RecoveryEmailCommands.cs
│   │       │   ├── RecoveryReviewerQueries.cs
│   │       │   ├── SiteTypeQueries.cs
│   │       │   ├── UserAdminCommands.cs
│   │       │   └── UserDirectoryQueries.cs
│   │       ├── Regional/
│   │       │   ├── RegionalWeatherPreferenceCommands.cs
│   │       │   ├── RegionalForecastQueries.cs
│   │       │   ├── RegionalMapQueries.cs
│   │       │   ├── RegionalHazardSyncCommands.cs
│   │       │   ├── RegionalWildfireQueries.cs
│   │       │   ├── RegionalDataQueries.cs
│   │       │   └── RegionalGeoJsonViewportFilter.cs
│   │       ├── Logbook/
│   │       │   └── ShiftLogbookCommands.cs
│   │       ├── Threat/
│   │       │   ├── CisaKevQueries.cs
│   │       │   ├── KeywordScorer.cs
│   │       │   ├── RssSettingsCommands.cs
│   │       │   ├── ThreatArticleQueries.cs
│   │       │   ├── ThreatStatusQueries.cs
│   │       │   ├── ThreatHuntingQueries.cs
│   │       │   └── ThreatHuntingCommands.cs
│   │       ├── Dashboard/
│   │       │   ├── DashboardQueries.cs
│   │       │   ├── ExecutiveIntelQueries.cs
│   │       │   └── InternalRiskQueries.cs
│   │       ├── AIOps/
│   │       ├── Regional/
│   │       ├── Reporting/
│   │       ├── Settings/
│   │       │   ├── ApplicationSettingsCommands.cs
│   │       │   ├── AiSmtpSettingsCommands.cs
│   │       │   ├── AssetInventoryCommands.cs
│   │       │   ├── CsvRecordParser.cs
│   │       │   ├── FacilityDirectoryCommands.cs
│   │       │   ├── LlmConnectionTestCommands.cs
│   │       │   ├── OperationalIntegrationSettingsCommands.cs
│   │       │   ├── RiskScoringCommands.cs
│   │       │   ├── SchedulerSettingsCommands.cs
│   │       │   ├── SiteContactRules.cs
│   │       │   └── SettingsReferenceDirectoryCommands.cs
│   │       ├── OperationalEmail/
│   │       └── BackupRestore/
│   │
│   ├── NocIfc.Infrastructure/
│   │   ├── Persistence/
│   │   │   ├── Sqlite/
│   │   │   │   ├── SqliteConnectionFactory.cs
│   │   │   │   ├── SqliteReadinessProbe.cs
│   │   │   │   ├── SqliteCisaKevStore.cs
│   │   │   │   ├── SqliteRssSettingsStore.cs
│   │   │   │   ├── SqliteInternalRiskStore.cs
│   │   │   │   ├── SqliteExecutiveIntelStore.cs
│   │   │   │   ├── SqliteThreatArticleStore.cs
│   │   │   │   ├── SqliteThreatStatusStore.cs
│   │   │   │   ├── SqliteThreatHuntingStore.cs
│   │   │   │   ├── SqliteRegionalPreferenceStore.cs
│   │   │   │   ├── SqliteRegionalDataStore.cs
│   │   │   │   ├── SqliteRegionalHazardSyncStore.cs
│   │   │   │   ├── SqliteShiftLogbookStore.cs
│   │   │   │   ├── SqliteOperationalDashboardStore.cs
│   │   │   │   ├── SqliteAuthenticationStore.cs
│   │   │   │   ├── SqliteAccountRecoveryStore.cs
│   │   │   │   ├── SqliteFailedLoginAlertStore.cs
│   │   │   │   ├── SqliteRecoveryEmailStore.cs
│   │   │   │   ├── SqliteUserSessionResolver.cs
│   │   │   │   ├── SqliteRoleDirectory.cs
│   │   │   │   ├── SqliteSiteTypeDirectory.cs
│   │   │   │   ├── SqliteUserDirectory.cs
│   │   │   │   ├── SqliteUserAdminStore.cs
│   │   │   │   ├── SqliteJson.cs
│   │   │   │   ├── SqliteApplicationSettingsStore.cs
│   │   │   │   ├── SqliteAiSmtpSettingsStore.cs
│   │   │   │   ├── SqliteAssetInventoryStore.cs
│   │   │   │   ├── SqliteFacilityDirectoryStore.cs
│   │   │   │   ├── SqliteSettingsReferenceDirectoryStore.cs
│   │   │   │   ├── SqliteOperationalIntegrationSettingsStore.cs
│   │   │   │   ├── SqliteRiskScoringSettingsStore.cs
│   │   │   │   └── SqliteSchedulerSettingsStore.cs
│   │   │   └── Queries/
│   │   ├── Email/
│   │   │   ├── GmailOAuthTokenProvider.cs
│   │   │   └── SqliteEmailSender.cs
│   │   ├── Security/
│   │   │   └── BCryptPasswordVerifier.cs
│   │   ├── Integrations/
│   │   │   ├── Feeds/
│   │   │   ├── Weather/
│   │   │   │   ├── NwsForecastClient.cs
│   │   │   │   ├── ArkansasFireCoverage.cs
│   │   │   │   ├── RegionalHazardSyncClient.cs
│   │   │   │   └── WfcaWildfireClient.cs
│   │   │   ├── Elastic/
│   │   │   │   └── ElasticSearchClient.cs
│   │   │   ├── Llm/
│   │   │   │   └── ProviderAwareLlmClient.cs
│   │   │   └── Email/
│   │   ├── BackupRestore/
│   │   └── NativeCompute/            # Only if the C++ gate passes
│   │
│   ├── NocIfc.Api/
│   │   ├── Controllers/
│   │   │   ├── AuthenticationController.cs
│   │   │   ├── AccountRecoveryController.cs
│   │   │   ├── ApplicationSettingsController.cs
│   │   │   ├── AiSmtpSettingsController.cs
│   │   │   ├── AssetInventoryController.cs
│   │   │   ├── DiagnosticsController.cs
│   │   │   ├── DashboardController.cs
│   │   │   ├── FacilitiesController.cs
│   │   │   ├── LlmController.cs
│   │   │   ├── PermissionsController.cs
│   │   │   ├── SettingsReferenceDirectoriesController.cs
│   │   │   ├── ThreatController.cs
│   │   │   ├── ThreatHuntingController.cs
│   │   │   ├── UserAdminController.cs
│   │   │   ├── UserInvitationsController.cs
│   │   │   ├── RecoveryEmailController.cs
│   │   │   ├── RecoveryEmailAdminController.cs
│   │   │   ├── Regional/RegionalController.cs
│   │   │   ├── Identity/
│   │   │   ├── Threat/
│   │   │   ├── AIOps/
│   │   │   ├── Regional/
│   │   │   ├── Settings/
│   │   │   ├── Logbook/ShiftLogbookController.cs
│   │   │   └── OperationalEmail/
│   │   ├── Authentication/AuthenticatedUserContext.cs
│   │   ├── Authorization/PermissionFilters.cs
│   │   ├── Contracts/RoleDefinitionRequest.cs
│   │   ├── Contracts/RoleResponse.cs
│   │   ├── Contracts/LoginRequest.cs
│   │   ├── Contracts/LoginResponse.cs
│   │   ├── Contracts/InvitationResponses.cs
│   │   ├── Contracts/RegistrationRequest.cs
│   │   ├── Contracts/PasswordResetRequestResponse.cs
│   │   ├── Contracts/ApplicationSettingsContracts.cs
│   │   ├── Contracts/AiSmtpSettingsContracts.cs
│   │   ├── Contracts/AssetInventoryContracts.cs
│   │   ├── Contracts/DashboardContracts.cs
│   │   ├── Contracts/ExecutiveIntelResponse.cs
│   │   ├── Contracts/CisaKevResponse.cs
│   │   ├── Contracts/FacilityDirectoryContracts.cs
│   │   ├── Contracts/RssSettingsContracts.cs
│   │   ├── Contracts/ThreatArticleContracts.cs
│   │   ├── Contracts/ThreatStatusContracts.cs
│   │   ├── Contracts/ThreatHuntingContracts.cs
│   │   ├── Contracts/IntegrationSettingsContracts.cs
│   │   ├── Contracts/SchedulerSettingsContracts.cs
│   │   ├── Contracts/ShiftLogbookContracts.cs
│   │   ├── Contracts/SettingsReferenceDirectoryContracts.cs
│   │   ├── Contracts/RecoveryEmailRequestResponse.cs
│   │   ├── Contracts/UserAdminRequests.cs
│   │   ├── Contracts/UserDirectoryResponse.cs
│   │   ├── Middleware/SessionAuthenticationMiddleware.cs
│   │   ├── WebSockets/
│   │   └── Program.cs
│   ├── NocIfc.Worker/
│   │   ├── Jobs/
│   │   ├── Scheduling/
│   │   └── Program.cs
│   └── NocIfc.Webhook/
│       ├── Controllers/SolarWindsController.cs
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
│   ├── NocIfc.Application.Tests/
│   │   ├── SqliteRegionalPreferenceStoreTests.cs
│   │   ├── RegionalForecastQueriesTests.cs
│   │   ├── RegionalHazardSyncCommandsTests.cs
│   │   ├── RegionalHazardSyncClientTests.cs
│   │   ├── NwsForecastClientTests.cs
│   │   ├── RegionalMapQueriesTests.cs
│   │   ├── ArkansasFireCoverageTests.cs
│   │   ├── WfcaWildfireClientTests.cs
│   │   ├── RegionalWildfireQueriesTests.cs
│   │   ├── RegionalDataQueriesTests.cs
│   │   ├── SqliteRegionalDataStoreTests.cs
│   │   ├── SqliteRegionalHazardSyncStoreTests.cs
│   │   ├── ShiftLogbookCommandsTests.cs
│   │   ├── SqliteShiftLogbookStoreTests.cs
│   │   ├── ThreatHuntingQueriesTests.cs
│   │   ├── ThreatHuntingCommandsTests.cs
│   │   ├── ElasticSearchClientTests.cs
│   │   └── SqliteThreatHuntingStoreTests.cs
│   ├── NocIfc.Api.Tests/
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

For each feature, port controller action, application use case, persistence query, permission check, and parity test together. Organize controllers by feature/resource; do not create one controller per operation or move business logic into controllers. Suggested order:

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
- [x] Remove local classifier and Keep/Dismiss feature.
- [ ] Add C# solution, layered modules, feature-scoped MVC controllers, isolated dev-c Compose, and image build.
- [ ] Port SQLite access and schema readiness; validate host-side migrations.
- [ ] Port identity/permissions and REST/WebSocket feature groups.
- [ ] Port worker jobs and SolarWinds webhook.
- [ ] Port LLM, email, backup, and restore workflows.
- [ ] Evaluate C++ candidate(s); document benchmark decision (including “not needed”).
- [ ] Verify unchanged frontend, rollback, and Python-free runtime images.
- [ ] Update source, deployment, schema, API, and operations documentation.

## Current status

The first conversion slices are committed and pushed on `dev-c`; implementation continues in user-authorized checkpoints:

- Removed the local scikit-learn classifier, training routes/job/permission, Keep/Dismiss actions, and related UI controls. Keyword weights and scoring remain; historical `human_feedback` column values remain inert and are no longer exposed by the service serializer.
- New backups omit the retired classifier. Legacy encrypted packages remain verifiable, but restore ignores model payloads and does not overwrite an existing stale artifact.
- Added the .NET 10 solution, shared SQLite connection factory, schema-version readiness probe, MVC diagnostics and global application-settings controllers, and separate C# API Docker image. `/health` and `/ready` retain their paths and basic response shapes; readiness requires Alembic head `20261125_0025`, while migration execution remains host-side Python.
- Added C# session validation against existing `user_sessions` and legacy `users.session_token` rows, plus MVC permissions-catalog, authentication, user-admin, and application-settings controllers. Login verifies existing Python bcrypt hashes, creates compatible session tokens, and returns the same sanitized profile/grants. Hashed invitation validation, single-use registration, and user-admin invitation list/create/resend/revoke are ported, along with `/auth/me`, logout, theme updates, profile/password updates, account-type changes, and assisted resets. Password-reset requests are rate-limited and anti-enumerating; review, one-time reset tokens, session revocation, and audit events are ported. Recovery-email request/review, mailbox verification, resend cooldown, and reviewer notifications are also ported. Global application defaults preserve recipient secrecy and validate the selected SMTP/Gmail profile before enabling failed-login alerts. Role choices/definitions, site types, the sanitized user directory, custom-role create/update, display-account creation, user role/status changes, and session revocation preserve permission boundaries. The canonical permission data now lives in `contracts/permission_catalog.json`, consumed by both Python and C#.
- Ported keyword scoring into `NocIfc.Domain`/`NocIfc.Application` with a unit test for matching and score capping; it is not yet used by the Python ingestion worker.
- Ported notification/Elastic integration settings with environment fallback, explicit reset-to-environment behavior, validation, secret-safe reads, and changed-field-only audit; ported registry-backed scheduler settings reads/writes with revision increments, Central-time validation, job bounds, non-disableable safety jobs, and transactional audit.
- Ported Fiber/ONPAGE and network-order/circuit reference directories with scoped reads, administrator-only ordered replacement, CSV merge/replace, reciprocal links, and row-count-only audits. Added permissioned read-only CISA KEV listing with date lookback and result bounds.
- Ported all read-only Threat Telemetry GETs: paginated RSS triage/detail, CISA KEV, cloud outages, Microsoft 365 feed freshness/service mapping, and perimeter-crime incidents, with tab permissions and response-shape compatibility.
- Ported RSS Settings catalog reads and admin keyword/feed bulk-add, weight-update, and delete operations; the existing Settings RSS UI now has matching C# routes. Added operational dashboard metrics, pinned/live articles, current hazards, threat trends, tab-filtered saved briefs, and authorized article pin/score actions.
- Added permissioned Internal Risk snapshot/history reads with legacy JSON payloads and failure-notice-safe saved briefs.
- Ported the Settings AI/SMTP tab read/write path with write-only secret handling, provider-change key clearing, test email through the saved active profile, and provider-aware LLM connection testing with private-endpoint policy.
- Ported Facilities site-type-scoped reads, admin location edit/import, site-contact validation/replace, and contact preservation for same-name sites on replace imports. Added administrator-only software and hardware asset CSV replacement endpoints for the existing Internal Assets tab.
- Ported Global Risk executive intelligence using persisted OSINT, CISA, crime, hazard, history, and scoring settings, including CIS thresholds, manual/hybrid overrides, output annotations, and daily score persistence.
- Ported Regional Grid site-scoped location reads, site-type catalog, per-user weather preferences, cached GeoJSON layer selection/summary, current-alert filtering, WGS84 viewport filtering, feed freshness and active-event metadata, weather-alert logs, cached NWS forecasts, and six-position map compilation with NWS overlays, county-code fallback, site/hazard intersections, viewport filtering, analytics, and a 120-second versioned result cache. Map compilation rebuilds submitted rows from the caller's authorized database locations. Added permissioned manual hazard sync for combined NWS alerts, SPC outlooks, and filtered USGS feeds, including the shared 60-second NWS lease, conditional requests, CAP lifecycle reconciliation, last-good cache retention, and earthquake/wildfire proximity email delivery through the active sender. NWS alert geometry is intersected against the projected Arkansas county boundary and its 50-mile buffer; missing/invalid geometries retain county/state fallback precision. Also ported WFCA wildfire incidents/perimeters/FIRMS footprints with 50-mile Arkansas coverage, small-fire site proximity, viewport filtering, five-minute caching, and last-good fallback. WFCA perimeter shards are grouped as MultiPolygon rather than topologically dissolved.
- Ported Shift Logbook role/date-scoped reads, role catalog, authenticated-author entry creation, ownership/manager-checked soft delete and restore, plus handoff-summary generation with bounded map/reduce, source-fidelity prompts, a 30-second timeout, deterministic fallback, and optional auto-append.
- Ported Threat Hunting IOC listing and repeated-CVE grouping, validated OSINT pivots, bounded quoted-term article search, paginated Elastic-cache reads, manual Elastic sync, and bounded SIEM triage across both `/api/v1/hunting` and the legacy `/api/v1/threat` aliases. Manual sync and triage retain their page/tab/action authorization and compatible skip/error/payload-size responses.
- The no-cache C# Docker build and all 149 C# tests pass (125 application, 24 API). Isolated HTTP smoke checks covered authentication, settings, read-only Threat Telemetry GETs, Regional Grid locations, site types, weather preferences, GeoJSON layer/viewport/lifecycle filtering, weather-alert log, six-position map compilation/site scoping/permission checks, wildfire bounds/permissions, manual hazard-sync action authorization, Shift Logbook read/create/soft-delete/restore/ownership checks, summary fallback/auto-append, and tab/site scoping; RSS management, Facilities edits/import/site contacts, Internal Assets imports, operational dashboard reads and article actions, Internal Risk history, Global Risk scoring, Threat Hunting and both sync/triage route prefixes, payload bounds, and page/tab/action permissions. NWS, SPC, USGS, WFCA, LLM, and SMTP integrations use test doubles or disabled settings; no live provider credentials were used and no SMTP delivery was attempted. The C# API is not yet wired into Compose, and the existing Python API/worker/webhook continue serving scheduled operations. Remaining work includes AIOps/RCA; Backup & Restore and Danger Zone settings; dashboard/internal risk and brief generation; other manual syncs; full LLM/email/Operational Email workflows; WebSockets, scheduled C# worker jobs, webhook, and Compose cutover.

The legacy database column is intentionally retained for compatibility. No database cleanup, schema change, GitHub issue update, or cross-branch merge is included in this conversion slice.
