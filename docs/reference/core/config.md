# Offline Tool Configuration

**File:** `src/core/config.py`

This module loads settings needed by host-side SQLite migration/bootstrap and encrypted-backup maintenance. C# API, Worker, and Webhook configuration is read by the .NET hosts and is documented in [the environment reference](../config/env_example.md).

## `Settings(BaseSettings)`

| Field | Type | Default | Purpose |
|---|---|---|---|
| `database_url` | `str` | `sqlite:////app/data/noc_fusion.db` | SQLite database path; host tools override it to point at the isolated `data-dev-c` file. |
| `demo_seed_data` | `bool` | `False` | Enable synthetic asset seeds for disposable demonstrations. |
| `default_admin_email` | `str` | `""` | Optional trusted mailbox for the initial administrator during offline bootstrap. |
| `backup_encryption_keys` | `str` | `""` | JSON map of backup key IDs to 32-byte hexadecimal keys. |
| `backup_encryption_active_key_id` | `str` | `"primary"` | Key ID selected for new encrypted backups. |
| `backup_max_bytes` | `int` | `10737418240` (greater than 0, at most 107374182400) | Maximum encrypted backup/upload size in bytes. |

The nested `Config` reads `.env` and ignores unrelated environment variables so the host tools can share the C# deployment template. `load_dotenv()` runs before the singleton `settings` is created. `DATABASE_URL` is retained as a module-level alias for the database initializer.
