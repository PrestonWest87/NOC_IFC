# Backup and Restore Modules

This page covers `src.core.backup_manager`, `src.core.restore_control`, `src.core.ui_restore`, and the offline entrypoint `scripts/restore_backup.py`. Operator procedures are in [`docs/MAINTENANCE.md`](../../MAINTENANCE.md).

## `src.core.backup_manager`

`create_backup()` uses SQLite's online backup API to snapshot the entire database and includes the persistent ML model artifact when present. The snapshot is packed with a versioned manifest and SHA-256 file metadata, then encrypted in authenticated AES-256-GCM chunks. `.env` and environment-only secrets are excluded. `BACKUP_ENCRYPTION_KEYS` contains 32-byte keys encoded as 64 hexadecimal characters; retain old key IDs until all corresponding packages are retired. `BACKUP_MAX_BYTES` bounds packages and uploads.

`validate_backup()` authenticates/decrypts to a temporary workspace, checks archive layout, manifest/checksums, and SQLite integrity, then removes temporary files. Management helpers list, download, stage, relabel legacy pre-restore files, and delete backups/staged uploads. Scheduled snapshots retain the newest three scheduled packages; manual and pre-restore safety packages are not automatically pruned.

`restore_backup()` requires `maintenance_confirmed=True`, upgrades the extracted database to the packaged application's migration head, invalidates restored sessions and outstanding account links, creates a pre-restore safety backup, and atomically installs the database/model with rollback handling. The offline script requires API, worker, and webhook writers to be stopped before it invokes this path.

## `src.core.restore_control`

Stores a mode-restricted cross-container maintenance marker, restore progress, API active-request/background-writer counts, and worker/webhook process acknowledgements under the shared application data directory. Status reads validate the restore ID and expire after 24 hours; process heartbeats expire after 10 seconds. API middleware uses `begin_api_request()`/`end_api_request()` to reject or drain requests while maintenance is active.

## `src.core.ui_restore`

`prepare_staged_restore()` verifies the staged file and creates the maintenance marker. `launch_staged_restore()` starts the coordinator in a background thread, and `resume_pending_restore()` resumes a durable pending operation after an API restart when its staged package still exists. The coordinator waits up to 600 seconds for API writes, the scheduler worker, and the webhook listener to become idle before installing the snapshot. On success it reinitializes the database and refreshes in-process caches/scorer state; failures are reported through restore status.
