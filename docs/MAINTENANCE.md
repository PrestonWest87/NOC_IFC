# Production Maintenance Guide

This guide provides recurring maintenance procedures for operators and maintainers of the NOC Intelligence Fusion Center. It is intended to keep the platform available, data useful, alerting reliable, and recovery possible without changing active application behavior unnecessarily.

## Maintenance Principles

- Perform a backup before database, migration, restore, release, or destructive administrative work.
- Confirm the current branch, release, and deployment before changing configuration.
- Prefer additive, reversible changes.
- Review logs before restarting services.
- Do not shorten scheduler intervals without considering provider rate limits, database contention, LLM cost, and email volume.
- Never delete production data as a first troubleshooting action.
- Record maintenance actions, operator, timestamp, reason, and result in the shift log or change system.

## Current Production Layout

| Component | Role | Verification |
|---|---|---|
| `api` | REST API, authentication, readiness, WebSocket | `curl -fsS http://localhost:8101/ready` |
| `worker` | Ingestion, scoring, briefs, maintenance, escalation | `docker compose ps`, worker logs |
| `webhook` | SolarWinds gateway | `curl -fsS http://localhost:8100/health` |
| `web` | Production React workspace | `curl -I http://localhost:8501` |
| Database | SQLite in `./data` | API `/ready` and database backup |

## Before Maintenance

Run the following before any planned change:

```bash
$ git status -sb
$ git log -1 --oneline --decorate
$ docker compose ps
$ docker compose logs --tail=100 api worker webhook web
$ curl -fsS http://localhost:8101/health
$ curl -fsS http://localhost:8101/ready
$ curl -fsS http://localhost:8100/health
```

Confirm that the worktree is clean, the intended release is deployed, no active incident is being obscured, and required alert recipients are available.

## Daily Checklist

1. Confirm `api` and `webhook` are healthy and `worker` is running.
2. Review worker logs for feed failures, database errors, memory growth, and SMTP errors.
3. Confirm RSS, hazard, telemetry, crime, cloud, and KEV data are receiving recent updates.
4. Review unresolved RCA alerts, maintenance states, ticketed alerts, and escalation failures.
5. Confirm the latest Unified Brief and internal/global briefs are present when expected.
6. Check that daily email recipients and SMTP status are still valid.
7. Review disk space and database growth.
8. Record important anomalies in the shift log.

Useful commands:

```bash
$ docker compose ps
$ docker compose logs --since=24h worker | grep -iE 'error|warn|failed|skipping|complete'
$ docker compose stats --no-stream
$ du -sh data 2>/dev/null || true
```

## Weekly Checklist

1. Review high-volume and repeatedly failing feed sources.
2. Review keyword weights, unused keywords, and analyst feedback in Keyword Analysis.
3. Confirm the article corpus has enough labeled feedback before ML retraining.
4. Review site maintenance records, stale alerts, and recurring RCA patterns.
5. Confirm a current database backup can be located and opened.
6. Review user roles, inactive accounts, page permissions, action permissions, and site-type access.
7. Review webhook signing configuration and source IP restrictions.
8. Review Docker image age and dependency security findings.

ML retraining runs Sunday at 02:00 and requires at least 10 labeled articles. The trained model is reloaded by the worker after successful training.

## Monthly Checklist

1. Perform and test a restore into an isolated database or disposable environment.
2. Rotate SMTP, LLM, Elastic, webhook, and administrator credentials according to organizational policy.
3. Review `CORS_ORIGINS`, firewall rules, reverse-proxy TLS certificates, and exposed ports.
4. Review database retention volume and SQLite file capacity.
5. Review the current release notes and compare deployed commit with `origin/main`.
6. Rebuild the containers in a controlled maintenance window and verify all health checks.
7. Review backup retention and confirm rollback tags are available for the deployed release.
8. Review external feed URLs and remove sources that are permanently retired or untrusted.

## Scheduled Maintenance and Retention

`run_database_maintenance()` runs every 60 minutes and performs the following cleanup:

| Data | Retention behavior |
|---|---|
| Low-score, unpinned articles | Deletes articles older than 3 days when score is below 50 |
| Other unpinned articles | Deletes articles older than 30 days |
| SolarWinds alerts | Deletes records older than 60 days |
| Regional hazards | Deletes records older than 48 hours |
| Regional outages | Deletes records older than 12 hours |
| BGP anomalies | Deletes records older than 12 hours |
| CISA KEV items | Deletes records older than 7 days |
| Cloud outages | Deletes resolved records older than 24 hours and unresolved records older than 14 days |
| Crime incidents | Deletes records older than 7 days |
| Internal risk snapshots | Deletes records older than 90 days |
| Timeline events | Deletes records older than 90 days |
| Elastic events | Deletes records older than 72 hours |
| Orphaned IOCs | Deletes IOC rows whose article no longer exists |

The job also runs SQLite optimization and a passive WAL checkpoint. Pinned articles are excluded from normal article deletion. Confirm organizational retention requirements before changing these policies.

## Database Backups

The full-backup service uses SQLite's online backup API, so a snapshot is consistent while the API and worker are writing (including committed WAL content). It captures the complete SQLite database rather than an ORM allowlist, and includes the persistent ML model artifact when present. Stored database credentials are inside the encrypted database snapshot; `.env` and environment secrets are intentionally outside the package.

Configure `BACKUP_ENCRYPTION_ACTIVE_KEY_ID` and `BACKUP_ENCRYPTION_KEYS` in the deployment environment before using backup operations. Each key is 32 random bytes encoded as 64 hex characters; `BACKUP_ENCRYPTION_KEYS` is a JSON map from key IDs to keys. Generate a key with `python -c 'import secrets; print(secrets.token_hex(32))'`. Protect it separately from the application host and retain previous key IDs while backups still use them. Losing a key makes its backups unrecoverable. `.env` is not stored in backup packages.

After adding or rotating keys in `.env`, recreate the API and worker containers so the admin endpoints and scheduled job load the updated key map.

Administrators can create/download manual snapshots under Settings > Backup & Restore. The worker also creates a scheduled snapshot every Sunday at 00:00 `America/Chicago`; that registry-managed job cannot be disabled. The latest three scheduled packages are retained; manual and pre-restore safety packages are retained until explicitly deleted. Files are stored under `./data/backups` on the shared persistent volume. Download or copy verified packages to protected off-host storage for host-loss recovery.

Packages use versioned manifests, per-file SHA-256 checksums, and chunked authenticated AES-256-GCM encryption. The admin staging endpoint verifies the key/tag, checksums, archive layout, and SQLite integrity before saving an uploaded encrypted package in `./data/backups/staged`. `BACKUP_MAX_BYTES` bounds backup and upload size (default 10 GiB; maximum 100 GiB). Do not put plaintext database exports or encryption keys in the repository or expose the backup directory through the web container.

The older Settings JSON tools remain partial data migration utilities: the legacy JSON backup covers four configuration collections, while `export-all` covers supported ORM models and omits session, recovery, failed-login, audit, and scheduler state. `/admin/upload-db` imports table records into the current database; it does not replace the SQLite file. Use encrypted full snapshots for disaster recovery.

## Database Initialization and Migrations

At API, worker, webhook, and standalone worker startup, the application checks the Alembic revision under a SQLite file lock and applies only pending revisions. A current database receives no schema DDL. Migration failures stop the affected service before it accepts work.

Migrations are not a separate one-shot service or administrative API. To retry after resolving a reported failure, restart the affected backend service; it will re-read the database revision before applying upgrades.

`RESCORE_ON_STARTUP` defaults to false. Set it temporarily only when a deliberate full article rescore is required; restart the affected containers and unset it afterward. A full rescore can create database contention and extend startup time.

## Restore and Disaster Recovery

For full disaster recovery, stage a `.nocbackup` file from Settings > Backup & Restore and choose **Restore now**. The UI starts a coordinated maintenance window: API writes are gated, the worker stops launching jobs and drains in-flight jobs, the webhook stops intake and drains accepted payloads, and active WebSocket clients are disconnected. The UI displays restore progress and returns when services resume. Restored login sessions are revoked, so the operator signs in again.

If the UI or API is unavailable, use the offline fallback from the deployment directory with the same `.env` encryption keys used by the package:

```bash
docker compose stop api worker webhook
docker compose run --rm --no-deps api python scripts/restore_backup.py \
  /app/data/backups/staged/<stage-id>.nocbackup --maintenance-confirmed
```

The UI restore and offline command decrypt and validate the package, upgrade the staged database to the packaged application's migration head, create an encrypted pre-restore safety backup, invalidate restored login sessions and outstanding registration/reset/recovery-email links, and atomically install the database and model artifact. On success, all staged restore packages are removed; the permanent manual/scheduled backups and pre-restore safety package remain. Request and account-audit history are preserved. If validation or installation fails, the live files are left intact or rolled back and staged packages remain available for retry. For the offline command, keep all writers stopped until it exits. If it exits with an error, review the output and bring the services back up before troubleshooting.

The backup directory labels pre-restore safety snapshots separately from user-created manual backups. Packages created before this label was added may still appear as manual backups until their manifest is checked and they are relabeled.

Allow sufficient free space for the uploaded package, a temporary database snapshot/archive, the current database, and the encrypted pre-restore safety backup. Large databases can require several times their file size during restore.

After a successful restore, verify `docker compose ps`, `curl http://localhost:8101/ready`, administrator sign-in with a newly issued session, dashboards, feeds, RCA data, email configuration, and WebSocket updates. Record the package timestamp and restore result. Ensure the key map contains the key ID used by the package and preserve the `.env`/environment configuration separately.

For a failed release, use the rollback tag or a previously verified image/commit. Do not move a published release tag; create a corrective release instead.

## Scheduler Maintenance

The worker scheduler starts jobs during boot and then runs them through a bounded two-thread executor. Boot can immediately generate external requests, emails, and LLM work.

Current high-impact jobs include:

- Escalation every minute.
- RSS ingestion every 5 minutes.
- Database maintenance every 60 minutes.
- Internal risk every 2 hours.
- Internal brief every 3 hours.
- Unified brief every 6 hours.
- Global brief daily at 02:00.
- Encrypted full-database backup Sunday at 00:00 Central; latest three scheduled packages retained.
- Daily email brief at 07:00 Central time.
- ML retraining Sunday at 02:00.

Schedules are registry-managed and configurable from Settings > Application Settings; escalation and encrypted database backup cannot be disabled. The worker reloads persisted schedule changes without a restart. Updating a Markdown table does not change runtime behavior.

## Feed and Integration Maintenance

When a source fails:

1. Check whether the failure is DNS, TLS, timeout, HTTP status, parsing, authentication, or rate limiting.
2. Test the source from the worker network when appropriate.
3. Confirm the feed URL remains valid in Settings.
4. Check whether the source has changed format or requires a user agent.
5. Keep one failing source from blocking the rest of the ingestion cycle.
6. Disable or replace permanently retired sources.

Common external failures are not automatically platform failures. A 403 from an individual feed, a provider outage, or a rate limit should be recorded separately from API or worker health.

## Keyword and Scoring Maintenance

Use Keyword Analysis to review:

- Keyword weight ranges and outliers.
- Frequently triggered or unused keywords.
- Average score contribution.
- Category distributions and timelines.
- Score buckets and category/keyword relationships.
- Articles behind a keyword match.

Change keyword weights deliberately and review the effect on new articles. Use recategorization only when a full corpus update is intended. Use full rescoring only during a controlled window and with a backup.

## Asset, RBAC, and Configuration Maintenance

- Remove retired assets and verify hardware/software versions.
- Review exact asset versions when evaluating CVE and KEV exposure.
- Remove inactive users and review administrator assignments.
- Confirm page, action, and site-type permissions after role changes.
- Review monitored location coordinates, site types, districts, priorities, and maintenance data.
- Verify SMTP sender/recipient configuration after personnel changes.
- Verify LLM endpoint, model, context window, and access restrictions after provider changes.
- Keep `DEMO_SEED_DATA=false` outside disposable demonstrations.

## Release and Upgrade Procedure

Before upgrading:

```bash
$ git fetch origin --prune
$ git switch main
$ git pull --ff-only origin main
$ git show --no-patch --decorate HEAD
$ docker compose ps
```

Then:

1. Create and verify a database backup.
2. Review release notes and known operational issues.
3. Confirm a rollback tag or prior release exists.
4. Rebuild the required containers:

```bash
$ docker compose up --build -d
```

5. Verify API, readiness, webhook, and frontend checks.
6. Review API, worker, webhook, and web logs.
7. Test login, dashboard loading, one feed path, one webhook path, and one permitted operational action.
8. Confirm scheduled jobs are running and no unexpected email dispatch occurred.

## Post-Maintenance Verification

```bash
$ docker compose ps
$ curl -fsS http://localhost:8101/health
$ curl -fsS http://localhost:8101/ready
$ curl -fsS http://localhost:8100/health
$ curl -fsSI http://localhost:8501
$ docker compose logs --tail=100 api worker webhook web
```

Confirm:

- All required containers are running.
- API readiness returns `200`.
- Webhook health returns `200`.
- The web workspace loads.
- No migration, authentication, database-lock, SMTP, or scheduler errors are present.
- A test action did not generate unintended notifications.
- The final commit and deployed release are recorded.

## Maintenance Records

For every production maintenance event record:

- Date and time in Central time.
- Operator and approving owner.
- Current release/commit.
- Reason and scope.
- Backup location and verification result.
- Commands or configuration changed.
- Services restarted.
- Health-check results.
- Any warnings, failed integrations, or rollback actions.

## Related Guides

- [Deployment](DEPLOYMENT.md)
- [Scheduler](SCHEDULER.md)
- [Database Schema](DATABASE_SCHEMA.md)
- [Operations Quick Reference](OPERATIONS_REFERENCE.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Git Operations](GIT_OPERATIONS.md)
