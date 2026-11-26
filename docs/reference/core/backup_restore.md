# Backup and Restore Modules

This page covers `src.core.backup_manager`, `src.core.restore_control`, `src.core.ui_restore`, and the offline entrypoint `scripts/restore_backup.py`. Operator procedures are in [`docs/MAINTENANCE.md`](../../MAINTENANCE.md).

## `src.core.backup_manager`

`create_backup()` uses SQLite's online backup API to snapshot the entire database. The snapshot is packed with a versioned manifest and SHA-256 file metadata, then encrypted in authenticated AES-256-GCM chunks. New packages do not include the retired article classifier. Legacy optional model payloads are still validated for archive integrity but are never installed by restore. `.env` and environment-only secrets are excluded. `BACKUP_ENCRYPTION_KEYS` contains 32-byte keys encoded as 64 hexadecimal characters; retain old key IDs until all corresponding packages are retired. `BACKUP_MAX_BYTES` bounds packages and uploads.

`validate_backup()` authenticates/decrypts to a temporary workspace, checks archive layout, manifest/checksums, and SQLite integrity, then removes temporary files. Management helpers list, download, stage, relabel legacy pre-restore files, and delete backups/staged uploads. Scheduled snapshots retain the newest three scheduled packages; manual and pre-restore safety packages are not automatically pruned.

`restore_backup()` requires `maintenance_confirmed=True`, upgrades the extracted database to the packaged application's migration head, invalidates restored sessions and outstanding account links, creates a pre-restore safety backup, and atomically installs the database with rollback handling. `scripts/restore_backup.py:main()` parses the package and maintenance-confirmation flag, supersedes an active UI restore when confirmed, invokes this path, prints JSON, and exits nonzero on a safe restore error. The offline script requires API, worker, and webhook writers to be stopped before it runs.

### Public backup-manager helpers

| Function/class | Current contract |
|---|---|
| `BackupError` | Safe domain error for invalid, unavailable, or unsafe backup operations. |
| `backup_directory() -> Path` | Return the persistent full-backup directory under the SQLite data volume. |
| `encryption_configured() -> bool` | Report whether a valid active encryption key is configured without returning it. |
| `list_backups(*, backup_dir=None) -> list[dict]` | List regular recognized package files without decrypting them. |
| `get_backup_path(backup_id, *, backup_dir=None) -> Path` | Resolve a strict package filename and reject missing files or symlinks. |
| `relabel_legacy_pre_restore_backup(backup_id, *, backup_dir=None) -> str` | Rename an older manual-named safety package only after validating its encrypted manifest. |
| `delete_backup(backup_id, *, backup_dir=None) -> None` | Delete a manual or pre-restore package; scheduled packages remain retention-managed. |
| `stage_uploaded_backup(source, *, backup_dir=None, max_bytes=None) -> dict` | Persist an uploaded package only after full authentication and validation. |
| `list_staged_backups(*, backup_dir=None) -> list[dict]` | List regular staged package filenames and file timestamps. |
| `delete_staged_backup(stage_id, *, backup_dir=None) -> None` | Delete one staged package after validating its opaque ID. |
| `clear_staged_backups(*, backup_dir=None) -> int` | Remove all staged packages after a successful restore. |
| `get_staged_backup_path(stage_id, *, backup_dir=None) -> Path` | Resolve a staged package ID without following symlinks or accepting arbitrary paths. |

## `src.core.restore_control`

Stores a mode-restricted cross-container maintenance marker, restore progress, API active-request/background-writer counts, and worker/webhook process acknowledgements under the shared application data directory. Status reads validate the restore ID and expire after 24 hours; process heartbeats expire after 10 seconds. API middleware uses `begin_api_request()`/`end_api_request()` to reject or drain requests while maintenance is active.

| Function/class | Current contract |
|---|---|
| `RestoreInProgressError` | Raised when a restore marker already holds the shared application in maintenance mode. |
| `active_restore()` | Return the current restore marker or `None`. |
| `maintenance_requested()` | Check the marker file so each service can gate new writes. |
| `begin_api_background_writer() -> bool` / `end_api_background_writer() -> None` | Register/release a detached API writer around its database-writing lifetime. |
| `api_background_writer()` | Context manager for the detached-writer registration. |
| `api_activity()` | Snapshot this API process's in-flight request and background-writer counts. |
| `begin_restore(stage_id, requested_by)` | Publish a unique shared restore marker and reject a concurrent restore. |
| `update_restore(restore_id, state, message, *, percent=None, result=None)` | Update the active marker and pollable progress record. |
| `finish_restore(restore_id, state, message, *, result=None)` | Record terminal status and clear only the matching marker. |
| `restore_status(restore_id)` | Return a valid UUID capability's status while the record is within its 24-hour lifetime. |
| `publish_process_status(process_name, state, *, active=0, jobs=None)` | Publish a worker/webhook drain heartbeat to the shared volume. |
| `process_status(process_name, restore_id)` | Return the matching heartbeat only while it is at most ten seconds old. |

## `src.core.ui_restore`

`prepare_staged_restore()` verifies the staged file and creates the maintenance marker. `launch_staged_restore()` starts the coordinator in a background thread, and `resume_pending_restore()` resumes a durable pending operation after an API restart when its staged package still exists. The coordinator waits up to 600 seconds for API writes, the scheduler worker, and the webhook listener to become idle before installing the snapshot. On success it reinitializes the database and refreshes in-process caches/scorer state; failures are reported through restore status.
