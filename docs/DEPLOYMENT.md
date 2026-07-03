# NOC Intelligence Fusion Center — Deployment Guide

## Production Deployment

### System Requirements

| Environment | Spec | Notes |
|-------------|------|-------|
| Production Server | 4 vCPU, 8 GB RAM, 20 GB SSD | Linux x86_64 recommended |
| Development Machine | 2 vCPU, 4 GB RAM, 10 GB SSD | Docker Desktop (WSL2 on Windows) |
| Network | Ports 5173 (public), 8100-8101 (internal) | Use reverse proxy for TLS |

### Recommended Architecture

```
Internet
    │
    ▼
┌──────────────┐     ┌──────────────┐
│  Reverse     │────▶│  nginx:5173  │
│  Proxy       │     │  (web svc)   │
│  (TLS term)  │     └──────┬───────┘
└──────────────┘            │
                     ┌──────▼───────┐
                     │  API:8101    │
                     │  (FastAPI)   │
                     └──┬───┬───┬───┘
                        │   │   │
              ┌─────────┘   │   └──────────┐
              ▼             ▼              ▼
       ┌──────────┐  ┌──────────┐  ┌──────────────┐
       │ Worker   │  │ Webhook  │  │ PostgreSQL   │
       │ :8101    │  │ :8100    │  │ :5432        │
       └──────────┘  └──────────┘  └──────────────┘
```

### Step-by-Step Production Deployment

#### 1. Prepare the Server

```bash
# Install Docker Engine
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Verify installation
docker --version
docker compose version
```

#### 2. Clone and Configure

```bash
git clone <repository-url> /opt/noc-ifc
cd /opt/noc-ifc
cp .env.example .env
```

#### 3. Configure PostgreSQL (Optional but Recommended)

Add to `.env`:
```bash
DATABASE_URL=postgresql://noc_user:secure_password@postgres:5432/noc_fusion
```

Create a `docker-compose.override.yml`:
```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: noc_user
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: noc_fusion
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U noc_user -d noc_fusion"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - DATABASE_URL=postgresql://noc_user:secure_password@postgres:5432/noc_fusion

  worker:
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - DATABASE_URL=postgresql://noc_user:secure_password@postgres:5432/noc_fusion

  webhook:
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - DATABASE_URL=postgresql://noc_user:secure_password@postgres:5432/noc_fusion

volumes:
  postgres_data:
```

#### 4. Configure TLS (Reverse Proxy)

Example nginx reverse proxy configuration:

```nginx
server {
    listen 443 ssl http2;
    server_name noc.aecc.com;

    ssl_certificate /etc/letsencrypt/live/noc.aecc.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/noc.aecc.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://127.0.0.1:5173;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}

server {
    listen 80;
    server_name noc.aecc.com;
    return 301 https://$server_name$request_uri;
}
```

#### 5. Configure Environment

```bash
# Production .env
DATABASE_URL=sqlite:////app/data/noc_fusion.db  # or postgresql://...
SECRET_KEY=<random-64-char-string>
RISK_ALERT_RECIPIENTS=noc-manager@aecc.com, soc@aecc.com
REMEDYFORCE_TICKET_EMAIL=remedyforce@aecc.com
NOC_NOTIFY_EMAIL=noc-team@aecc.com
NOC_ONPAGE_EMAIL=noc-oncall@aecc.com
ITNETWORK_ONPAGE_EMAIL=network-oncall@aecc.com
LLM_API_URL=https://api.openai.com/v1
```

> Generate a secure SECRET_KEY: `openssl rand -hex 32`

#### 6. Build and Launch

```bash
docker compose up --build -d
```

#### 7. Verify Deployment

```bash
# Check all services are healthy
docker compose ps

# Test API health
curl http://localhost:8101/health

# Test webhook
curl -X POST http://localhost:8100/webhook/solarwinds \
  -H "Content-Type: application/json" \
  -d '{"AlertName":"Test Alert","severity":"INFO"}'

# Check logs for any errors
docker compose logs --tail=50
```

#### 8. Post-Deployment Tasks

1. **Login** with admin credentials
2. **Change default passwords** (Settings > Users & Roles)
3. **Configure AI** (Settings > AI & SMTP)
4. **Configure SMTP** (Settings > AI & SMTP)
5. **Add facilities** (Settings > Facilities)
6. **Add RSS sources** (Settings > RSS Sources)
7. **Verify data ingestion** (check worker logs)
8. **Configure webhook** in your ITSM tool

---

## Environment-Specific Deployments

### Single Server (Small NOC)

```
One machine, all containers, SQLite
```

```bash
docker compose up --build -d
```

**Pros**: Simple, minimal dependencies
**Cons**: No high availability, SQLite concurrency limits

### Two-Tier (Medium NOC)

```
App Server: API + Worker + Webhook + Web
Database Server: PostgreSQL
```

1. Deploy PostgreSQL on database server
2. Configure `DATABASE_URL` pointing to the database server
3. Ensure network connectivity between servers

### Three-Tier (Enterprise NOC)

```
Load Balancer: nginx (TLS, routing)
App Servers (x2): API + Worker + Webhook
Web Server: nginx + static assets
Database: PostgreSQL with replication
```

**Considerations:**
- Use Redis for WebSocket state sharing across API instances
- Configure sticky sessions or use WebSocket-compatible load balancer
- Set up read replicas for analytics queries
- Implement health checks and auto-scaling

---

## CI/CD Pipeline

### Example GitHub Actions Workflow

```yaml
name: Deploy NOC Fusion

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build and push images
        run: |
          docker build -t noc-api:latest .
          docker build -t noc-web:latest ./web

      - name: Deploy to server
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.DEPLOY_HOST }}
          username: ${{ secrets.DEPLOY_USER }}
          key: ${{ secrets.DEPLOY_KEY }}
          script: |
            cd /opt/noc-ifc
            git pull
            docker compose up --build -d
```

---

## Monitoring & Maintenance

### Monitoring Checklist

| What to Monitor | How | Frequency |
|----------------|-----|-----------|
| Container health | `docker compose ps` | Every 5 min |
| API health | `curl /health` | Every 1 min |
| Worker logs | `docker compose logs worker --tail=20` | Every 15 min |
| Database size | `du -sh data/noc_fusion.db` | Daily |
| Disk usage | `df -h` | Daily |
| Memory usage | `docker stats --no-stream` | Daily |

### Routine Maintenance

**Daily:**
- Review worker logs for errors
- Check database size growth
- Monitor memory usage of all containers

**Weekly:**
- Review and purge old log entries (Settings > Danger Zone)
- Check for stuck/unresolved alerts
- Update RSS feed sources as needed

**Monthly:**
- Review and clean up internal assets
- Archive old shift log data
- Update LLM configuration if needed
- Review user accounts and roles

**Quarterly:**
- Full database backup
- Review and update keyword weights
- Retrain ML model with accumulated feedback
- Update incident response procedures

### Backup & Recovery

#### Automatic Backups
Add a cron job on the host:

```bash
# Daily database backup
0 2 * * * docker compose exec -T api python -c "
from src.services import export_backup
export_backup('/tmp/backup.json')
" && docker cp $(docker compose ps -q api):/tmp/backup.json /backups/noc-$(date +\%Y\%m\%d).json
```

#### Manual Backup
```bash
# Via Settings > Backup & Restore
curl -X POST http://localhost:5173/api/v1/admin/backup -o backup.json

# Or directly
docker compose exec api python -c "
from src.services import export_backup
export_backup('/app/data/backup.json')
print('Backup saved')
"
docker cp $(docker compose ps -q api):/app/data/backup.json ./backup.json
```

#### Recovery
```bash
# Via Settings > Backup & Restore
curl -X POST http://localhost:5173/api/v1/admin/restore \
  -H "Content-Type: application/json" \
  -d @backup.json

# Or full database reset with restore
docker compose down
rm data/noc_fusion.db
docker compose up -d
docker compose exec api python -c "
from src.services import import_backup
with open('/app/data/backup.json') as f:
    import json
    import_backup(json.load(f))
print('Restore complete')
"
```

### Scaling Considerations

| Bottleneck | Solution |
|------------|----------|
| SQLite concurrency | Migrate to PostgreSQL |
| Worker throughput | Increase `chunk_size` in feed fetcher |
| API response time | Add Redis caching layer |
| WebSocket connections | Use dedicated WebSocket server |
| Storage growth | Configure retention policies in scheduler |
| LLM rate limits | Configure multiple LLM endpoints |

---

## Security Hardening

### Network Security

1. **Firewall rules**:
   - Allow 5173 (frontend) from NOC subnet only
   - Allow 8100 (webhook) from monitoring tools only
   - Allow 8101 (API) from frontend only (or use internal Docker network)
   - Restrict SSH access

2. **Webhook authentication**: Add HMAC signature verification in production (modify `webhook_listener.py`)

3. **API rate limiting**: Add middleware for production API endpoints

4. **CORS**: Restrict `allow_origins` in `main.py` to specific domains

### Authentication

1. **Change default passwords immediately**
2. **Use strong passwords**: Minimum 12 characters with complexity requirements
3. **Session management**: JWT tokens expire on browser close (sessionStorage)
4. **Audit logging**: User actions are logged in timeline_events and shift_logs

### Data Security

1. **Encryption at rest**: Database file permissions should be 600
2. **HTTPS**: Always use TLS in production
3. **API keys**: LLM and SMTP credentials stored in the database (not in containers)
4. **Backup encryption**: Encrypt backup JSON files for offsite storage

### Container Security

1. **Non-root user**: Modify Dockerfiles to run as non-root user
2. **Read-only filesystem**: Where possible, mount volumes as read-only
3. **Resource limits**: Already configured for worker (`memory: 1G`)
4. **Image scanning**: Regular vulnerability scanning of Docker images
5. **Secrets**: Use Docker secrets or external vault for sensitive values

---

## Upgrade Procedure

### In-Place Upgrade

```bash
# 1. Backup
docker compose exec api python -c "
from src.services import export_backup
export_backup('/app/data/pre-upgrade-backup.json')
print('Pre-upgrade backup saved')
"

# 2. Pull latest code
git pull

# 3. Rebuild and restart
docker compose up --build -d

# 4. Verify
docker compose ps
curl http://localhost:8101/health

# 5. Check data integrity
docker compose logs --tail=30 worker
```

### Blue-Green Deployment

1. Deploy new version alongside existing on different ports
2. Run database migrations
3. Switch reverse proxy to new version
4. Verify functionality
5. Tear down old version

---

## Troubleshooting Production Issues

| Symptom | Likely Cause | Resolution |
|---------|-------------|-----------|
| API won't start | Database connection issue | Check `DATABASE_URL` and database server connectivity |
| Worker errors on startup | Database not seeded | `docker compose exec api python -c "from src.core.db import init_db; init_db()"` |
| Webhook returns 500 | Invalid payload format | Check SolarWinds payload structure |
| Frontend blank page | Build cache or proxy issue | Clear browser cache, restart web container |
| WebSocket disconnects | Network timeout | Adjust nginx proxy_read_timeout |
| Memory exhaustion | SQLite with many concurrent connections | Switch to PostgreSQL or reduce worker threads |
| Slow page loads | Large database tables | Run maintenance from Settings > Danger Zone |
| Emails not sending | SMTP configuration | Verify SMTP settings in Settings > AI & SMTP |
| AI features not working | LLM configuration | Check LLM endpoint, API key, and `is_active` flag |
| No RSS data | Feed sources not configured | Add feeds in Settings > RSS Sources |
| Score all zero | Keywords not seeded | Run `init_db()` or rebuild API container |
