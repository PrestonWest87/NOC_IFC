# NOC IFC Documentation

`docs/` is the only canonical documentation root. The former `Documentation/` directory was consolidated into `docs/reference/`; do not create a second documentation tree.

## Start Here

| Need | Document |
|---|---|
| Understand runtime boundaries and data flow | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Install and deploy | [GETTING_STARTED.md](GETTING_STARTED.md), [DEPLOYMENT.md](DEPLOYMENT.md) |
| Operate features | [USER_GUIDE.md](USER_GUIDE.md) |
| Find REST endpoints | [API.md](API.md) |
| Review exact permission keys and enforcement | [PERMISSIONS.md](PERMISSIONS.md) |
| Understand tables and retention | [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) |
| Review SQLite upgrade compatibility and recovery | [MIGRATION_COMPATIBILITY.md](MIGRATION_COMPATIBILITY.md) |
| Follow service call chains and functions | [CODE_REFERENCE.md](CODE_REFERENCE.md) and `reference/` |
| Change polling, email, and security settings | [OPERATIONS_REFERENCE.md](OPERATIONS_REFERENCE.md) |
| Diagnose and recover from failures | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Work with Git and GitHub safely | [GIT_OPERATIONS.md](GIT_OPERATIONS.md) |
| Maintain, back up, and recover production | [MAINTENANCE.md](MAINTENANCE.md) |
| Understand job timing and escalation | [SCHEDULER.md](SCHEDULER.md), [ESCALATION.md](ESCALATION.md) |
| Understand ingestion pipelines | [DATA_FLOWS.md](DATA_FLOWS.md), [TRIGGER_ACTION_FLOWS.md](TRIGGER_ACTION_FLOWS.md) |
| Review the source/docs audit | [DOCUMENTATION_AUDIT.md](DOCUMENTATION_AUDIT.md) |
| Plan source docstrings and comments | [IN_CODE_DOCUMENTATION_PLAN.md](IN_CODE_DOCUMENTATION_PLAN.md) |
| Review startup migration and efficiency work | [IMPLEMENTATION_PLAN_EFFICIENCY_AND_MIGRATIONS.md](IMPLEMENTATION_PLAN_EFFICIENCY_AND_MIGRATIONS.md), [implementation log](IMPLEMENTATION_LOG_EFFICIENCY_AND_MIGRATIONS.md) |

## Authority and Maintenance

Source code is authoritative for behavior. `ARCHITECTURE.md`, `API.md`, `DATABASE_SCHEMA.md`, `SCHEDULER.md`, `PERMISSIONS.md`, `OPERATIONS_REFERENCE.md`, and `TROUBLESHOOTING.md` describe the current operational contracts. Module pages under `reference/` provide source-oriented detail and must be updated when signatures, inputs, outputs, side effects, algorithms, or error handling change. `IN_CODE_DOCUMENTATION_PLAN.md` is a plan; it does not mean source comments have already been added.

Use repository-relative source paths. Do not document secrets, machine-specific absolute paths, generated build output, or undocumented environment variables as if they were deployment requirements.
