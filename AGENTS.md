# NOC Intelligence Fusion Center - Agent Instructions

## Overview

Enterprise intelligence HUD for Network Operations Centers. Ingests RSS feeds, weather/telemetry data, crime incidents, and generates AI-powered reports.

## Architecture

- **Frontend** (`src/app.py`): Streamlit dashboard on port 8501
- **Worker** (`src/scheduler.py`): Background scheduler for data ingestion
- **Webhook** (`src/webhook_listener.py`): FastAPI gateway on port 8100
- **Database**: SQLite (default) or PostgreSQL (set `DATABASE_URL` in `.env`)

## Developer Commands

```bash
# Build and run all services
docker compose up --build -d

# Monitor background worker logs
docker compose logs -f worker

# Monitor webhook gateway logs
docker compose logs -f webhook

# Restart worker after code changes
docker compose restart worker
```

## Key Files

| File | Purpose |
|------|--------|
| `src/app.py` | Streamlit UI entrypoint |
| `src/services.py` | Data Access Layer (DAL) |
| `src/database.py` | SQLAlchemy models and init |
| `src/scheduler.py` | Background task scheduler |
| `src/llm.py` | LLM integration |
| `src/risk_alert.py` | Risk level change alerts |

## Environment Variables (`.env`)

```
DATABASE_URL=sqlite:////app/data/noc_fusion.db  # Required
RISK_ALERT_RECIPIENTS=email1,email2              # For risk alerts
```

## Default Credentials

- Login: `admin` / `admin123`
- Webhook: `POST http://localhost:8100/webhook/solarwinds`

## Scheduler Jobs

| Job | Interval |
|-----|---------|
| RSS Feed Fetch | 15 min |
| Crime Fetch | 3 min |
| Regional Hazards | 2 min |
| Cloud Outages | 5 min |
| CISA KEV | 6 hours |
| Internal Risk | 6 hours |
| Unified Brief | 2 hours |
| DB Maintenance | 60 min |
| ML Retrain | Sunday 02:00 |

## Risk Levels

GREEN < BLUE < YELLOW < ORANGE < RED

## Webhook Endpoints

- `POST /webhook/solarwinds` - ITSM alerts
- `GET /health` - Health check