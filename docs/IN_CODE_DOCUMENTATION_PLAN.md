# In-Code Documentation Plan

**Status:** Coverage pass complete on `main` and mirrored to `architecture/monolith-to-decoupled` (2026-10-26); source docstrings/comments describe existing behavior without changing runtime logic.
**Goal:** Add concise, durable docstrings and comments to the code paths whose contracts or reasoning are difficult to infer safely from names and types alone.

## Documentation principles

1. **Executable behavior remains authoritative.** Code comments explain the current code and must change with it. User workflows and deployment procedures remain in `docs/`.
2. **Explain intent and invariants, not syntax.** Do not narrate an obvious assignment, loop, or API call. Explain why an unusual branch exists, what contract it protects, and what would break if it changed.
3. **Document boundaries explicitly.** State who owns a transaction/session, whether work is synchronous or backgrounded, whether a result is cached, whether a function writes data, and how errors are surfaced.
4. **Be exact about security.** Document authorization prerequisites, site-scope checks, token lifetimes, secret handling, and restore gates next to the code that enforces them. Never include secret values or live customer data in comments.
5. **Keep reference prose in one place.** A function docstring gives its local contract and links to a detailed guide when the algorithm needs more space; it does not duplicate a whole Markdown chapter.
6. **Avoid stale numeric claims.** Put operational values in named constants/registries where feasible, and point documentation to those values rather than repeating unexplained thresholds.

## Coverage target

The implementation pass should document:

- Every Python module's responsibility and runtime boundary.
- Every externally consumed API/WebSocket handler, scheduler job, CLI entry point, and worker entry point.
- Every exported service/helper and every private helper that implements a nontrivial algorithm, data migration, security check, cache, concurrency rule, or destructive operation.
- Every exported React component, hook, permission/auth utility, and shared data contract.
- Complex local functions only when they contain non-obvious state transitions, data transformations, browser compatibility workarounds, or security-relevant behavior.

Simple presentational JSX, straightforward type aliases, and self-explanatory CSS should not receive boilerplate comments merely to increase comment count.

## Docstring style

### Python

Use a short summary followed by only the sections that add information. Google-style sections are recommended:

```python
def operation(value: str, *, commit: bool = True) -> Result:
    """Normalize and persist an operator-submitted value.

    Args:
        value: Untrusted input; normalized before storage.
        commit: Whether this helper commits its caller-owned transaction.

    Returns:
        The persisted result, or `None` when the target does not exist.

    Raises:
        ValueError: If the value is invalid or violates a domain invariant.

    Side effects:
        Writes the domain row and invalidates the related process-local cache.
    """
```

For route handlers, document the HTTP contract in the route page, and use the code docstring for handler-specific behavior not captured by the Pydantic model/dependencies. For background jobs, include trigger, lock/non-overlap expectations, external calls, and retry/failure behavior. For migrations, state the source schema assumptions, idempotence/partial-application behavior, data preservation, and downgrade policy.

### TypeScript / React

Use TSDoc for exported components, hooks, and utilities when the signature does not fully express the contract:

```ts
/**
 * Opens the AIOps stream for an authorized session and merges updates into
 * the existing query cache without creating an incomplete dashboard record.
 * @returns The latest push payload and current socket connection state.
 */
```

Use inline comments for non-obvious query-cache merge rules, permission-driven UI states, local-vs-server persistence, data races, browser APIs, and fallback behavior. Keep the API endpoint and full permission matrix in `docs/API.md` and `docs/PERMISSIONS.md`.

## Phased implementation

### Progress record — 2026-10-26

The Phase 1–6 coverage pass is complete across the checked-in Python and React
runtime: all 67 Python modules have module docstrings; all top-level and nested
callables outside the frozen schema snapshot have docstrings; all 49 exported
TypeScript/TSX declarations have TSDoc; and non-obvious cache, restore, migration,
network, and browser-compatibility invariants have focused comments. Stale active
Streamlit/PyDeck comments in `src/services.py` were replaced with current server/map
terminology. No runtime behavior was changed. The 101 changed paths in the main and
architecture worktrees were byte-compared with zero differences.

`migrations/schema_v1.py` remains byte-for-byte frozen per `AGENTS.md`; its mapped
runtime counterparts are documented in `src/models/schema.py`. The frozen copy has
a module-level description but its snapshot classes were not edited.

### Phase 1 — Security, identity, restore, and permission contracts

**Status:** Complete. These paths determine access and recoverability.

Document module/handler contracts in `src/api/auth_guard.py`, `src/api/routes/auth.py`, `src/api/routes/user_admin.py`, `src/core/permissions.py`, `src/core/bootstrap.py`, `src/core/backup_manager.py`, `src/core/restore_control.py`, and `src/core/ui_restore.py`. Focus comments on public-vs-protected route boundaries, reviewer eligibility/self-approval rules, token hashing and expiry, cross-process restore coordination, rollback, and the exact site-scope invariant.

### Phase 2 — Background execution and external integrations

**Status:** Complete.

Document `src/core/scheduler_registry.py`, `src/scheduler.py`, every `src/workers/*.py` entry point, and `src/webhook_listener.py`. Explain startup-run policy, job reload/non-overlap behavior, bounded network/input processing, idempotency, HMAC signing format/replay memory, source-specific normalization, and which failures are isolated versus fatal.

### Phase 3 — Risk, correlation, ingestion, and map algorithms

**Status:** Complete.

Document the algorithms in `src/services.py`, `src/services/logic.py`, `src/services/categorizer.py`, `src/services/ioc_extractor.py`, and `src/services/aiops_engine.py`. Cover scoring thresholds, exact category/domain names, what data is considered, tie/fallback behavior, title/asset match caps, patient-zero scoring, fleet thresholds, site-health semantics, and positional map response contracts. Replace stale copied comments that mention removed Streamlit/PyDeck behavior when the corresponding source areas are next edited.

### Phase 4 — LLM, email, reporting, and ML lifecycle

**Status:** Complete.

Document `src/utils/llm.py`, `src/utils/mailer.py`, `src/utils/risk_alert.py`, `src/train_model.py`, and `src/workers/report_worker.py`. Capture context-window resolution, timeout/fallback behavior, map/reduce sequencing, progress-store lifetime, trusted/untrusted prompt inputs, email recipient/config requirements, training labels/minimum sample count, and atomic model replacement.

### Phase 5 — Frontend state and page contracts

**Status:** Complete.

Add TSDoc to exported APIs in `web/src/App.tsx`, `web/src/utils/*`, `web/src/hooks/*`, `web/src/store/*`, and shared components. Add focused comments to large pages only for state transitions and permission-bound controls. Prioritize 401/403 handling, session storage, account theme synchronization, reconnect behavior, AIOps workflow state, large file downloads/restores, and the Regional Grid six-position compile-map response.

### Phase 6 — Runtime configuration and maintenance tools

**Status:** Complete.

Document all functions and CLI flags in `scripts/*.py`, configuration loaders, database/migration setup, compatibility shims, and Docker/Vite/nginx startup behavior. Keep default values and bounds synchronized with `.env.example`, `JOB_REGISTRY`, and the matching config references.

## Review checklist for each code change

- Does every changed public or operational callable have an accurate signature/contract docstring?
- Are all side effects, database transaction ownership, cache invalidations, thread/task behavior, and expected errors stated where they are non-obvious?
- Are permissions and site-scope checks described at the enforcement point, not only in the UI?
- Did a threshold, field name, enum, response shape, schedule, or default change? Update the nearest source reference and affected user/API/flow guide in the same change.
- Do comments describe why rather than restate what the next line does?
- Are examples safe, minimal, and free of real secrets/identifiers?
- Does the documentation index/source-coverage map still include the module?
- Do Python compile/import checks and the frontend production build pass? Run focused tests when code behavior changes.

## Verification record

- Python 3.11-compatible compile check passed for `src/`, `scripts/`, and `migrations/`.
- FastAPI import/OpenAPI generation passed: 177 paths and 189 HTTP operations.
- Frontend production build passed in the Node 22 Docker builder; the existing >500 kB chunk warning remains.
- `docker compose config --quiet`, Nginx `-t`, and `git diff --check` passed.
- The architecture worktree also passed Python compilation, OpenAPI import, Docker frontend build, Compose configuration (using the main worktree's env file), and Nginx syntax checks.
- The exported-symbol inventory reports 67 Python modules with module docs, no undocumented top-level/nested definitions outside frozen `migrations/schema_v1.py`, and 49/49 exported TypeScript/TSX declarations with TSDoc.

This coverage pass is complete. Future code changes should follow the review checklist above and keep the in-code contracts synchronized with `docs/reference/` and the operational guides.
