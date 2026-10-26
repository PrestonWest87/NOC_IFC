# `.gitignore` — Repository Exclusion Rules

**Path:** `.gitignore`

Git uses this file to hide matching untracked paths from normal status/add operations. It does not untrack a path already committed, and entries here are separate from the Docker build exclusions in `.dockerignore`.

## Current patterns

| Pattern | Purpose |
|---|---|
| `.env` | Local environment/secrets file. `.env.example` is not ignored and is the checked-in template. |
| `docker-compose.yml` | Ignore pattern in this working copy. The current `docker-compose.yml` is already tracked, so Git continues to include and version it; the ignore rule does not untrack it. |
| `src/ml_model.pkl` | Legacy generated model location; current trained model lives under `data/models/`. |
| `data/` | Runtime SQLite database, backup packages, cached data, and persisted model artifacts. |
| `src/__pycache__/`, `__pycache__/`, `*.pyc`, `*.pyo` | Python bytecode and cache directories/files. |
| `.vscode/`, `.idea/` | Local editor/workspace configuration. |
| `debug_raw_payloads.json`, `export_payloads.py`, `noc_fusion_MASTER_BACKUP_2026-06-30_13-43.tar.gz` | Named local debug/export/archive artifacts. |
| `.DS_Store`, `Thumbs.db` | Operating-system metadata. |
| `web/node_modules/`, `web/dist/`, `*.tsbuildinfo` | Installed frontend dependencies, production build output, and TypeScript incremental-build state. |
| `**/tests/` | Automated tests are maintained locally and intentionally excluded from version control by repository policy. |

## Safe inspection

```bash
git check-ignore -v path/to/file
git status --short --ignored
```

`.env` contains secrets and must not be force-added. The checked-in `.env.example` is already outside the `.env` ignore pattern; review its contents for placeholders before use. Do not use `git add -f` to bypass a secret or test exclusion.
