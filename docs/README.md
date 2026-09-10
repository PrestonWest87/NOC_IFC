# NOC IFC Documentation

`docs/` is the only canonical documentation root. The former `Documentation/` directory was consolidated into `docs/reference/`; do not create a second documentation tree.

## Start Here

| Need | Document |
|---|---|
| Understand runtime boundaries and data flow | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Install and deploy | [GETTING_STARTED.md](GETTING_STARTED.md), [DEPLOYMENT.md](DEPLOYMENT.md) |
| Operate features | [USER_GUIDE.md](USER_GUIDE.md) |
| Find REST endpoints | [API.md](API.md) |
| Understand tables and retention | [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) |
| Follow service call chains and functions | [CODE_REFERENCE.md](CODE_REFERENCE.md) and `reference/` |
| Change polling, email, and security settings | [OPERATIONS_REFERENCE.md](OPERATIONS_REFERENCE.md) |
| Diagnose and recover from failures | [TROUBLESHOOTING.md](TROUBLESHOOTING.md) |
| Work with Git and GitHub safely | [GIT_OPERATIONS.md](GIT_OPERATIONS.md) |
| Understand job timing and escalation | [SCHEDULER.md](SCHEDULER.md), [ESCALATION.md](ESCALATION.md) |
| Understand ingestion pipelines | [DATA_FLOWS.md](DATA_FLOWS.md), [TRIGGER_ACTION_FLOWS.md](TRIGGER_ACTION_FLOWS.md) |

## Authority and Maintenance

Source code is authoritative for behavior. `ARCHITECTURE.md`, `SCHEDULER.md`, `OPERATIONS_REFERENCE.md`, and `TROUBLESHOOTING.md` are the operational source-of-truth documents. Module pages under `reference/` provide function-level detail and must be updated when signatures, inputs, outputs, side effects, algorithms, or error handling change.

Use repository-relative source paths. Do not document secrets, machine-specific absolute paths, generated build output, or undocumented environment variables as if they were deployment requirements.
