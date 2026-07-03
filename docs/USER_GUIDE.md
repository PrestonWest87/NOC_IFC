# NOC Intelligence Fusion Center — User Guide

## Overview

The NOC Intelligence Fusion Center is a web-based HUD (Heads-Up Display) for Network Operations Center analysts, engineers, and management. It aggregates multi-domain telemetry into a unified operational picture with AI-powered analysis and automated response capabilities.

### Primary User Roles

| Role | Typical User | Capabilities |
|------|-------------|--------------|
| **Admin** | NOC Manager, System Admin | Full access to all pages, settings, user management, RBAC configuration |
| **Analyst** | NOC Analyst, Shift Lead | All operational pages, article pinning/boosting, shift logs, report generation |
| **Custom** | IT Engineer, Executive | Configurable page/action permissions per organizational need |

---

## Navigation

### Sidebar Layout

The application uses a collapsible sidebar navigation with 8 main sections:

```
+---------------------------+
|  NOC Fusion Center        |
|  ──────────────────────── |
|  ◉ Global Dashboards      |  ← Home / default landing
|  ◎ Threat Telemetry       |  ← RSS, CVEs, cloud, crime
|  ◈ Regional Grid          |  ← Maps, weather, hazards
|  ⚡ Threat Hunting        |  ← IOCs, OSINT, deep hunt
|  ◆ AIOps RCA              |  ← Root cause analysis, dispatch
|  ☰ Shift Logbook          |  ← Shift entries, handoffs
|  📋 Reporting             |  ← Briefings, custom reports
|  ⚙ Settings               |  ← Admin configuration
+---------------------------+
```

Each section contains multiple tabs. The visible tabs depend on the user's role-based permissions.

---

## Page Guides

### 1. Global Dashboards (`/`)

Four dashboards providing a top-down operational view:

#### Operational Dashboard
- **KPI Panels**: 24-hour metrics showing alert counts, active sites, and system health
- **Threat Triage**: Auto-rotating display of high-scoring intelligence articles with score badges
- **Infrastructure Status**: Monitored location status indicators with color-coded risk levels
- **AI Analysis**: LLM-generated summary of current threat landscape

#### Global Risk
- **Threat Matrix**: Executive-level view of unified threat posture
- **14-Day Trend**: Historical comparison using MS-ISAC/CIS Alert Framework (GREEN through RED)
- **Risk Escalation**: Automatic detection of risk level increases with email alerting

#### Internal Asset Posture
- **Asset Inventory**: Hardware and software asset tracking against active OSINT threats
- **Vulnerability Summary**: Aggregated CVSS scores and exploit availability
- **Historical Trends**: Risk score changes over time

#### Unified Brief
- **AI Brief**: Autonomous Map-Reduce narrative merging global OSINT threat data with internal asset risk
- **Email Broadcast**: Send the current brief to `RISK_ALERT_RECIPIENTS`

### How to Use
1. Monitor KPI panels for anomaly spikes
2. Review threat triage for high-scoring articles (red/orange score badges)
3. Click any article to expand and read full summary
4. Pin important articles for team visibility
5. Review Global Risk dashboard during shift handoffs
6. Broadcast Unified Brief to management via email button

---

### 2. Threat Telemetry (`/threat-telemetry`)

Four intelligence feeds in one page:

#### RSS Triage
- **Sub-tabs**: Pinned | Live | Low | Search
- **Category Filter**: Filter by intelligence category (Cyber, ICS/OT, Weather, etc.)
- **Pagination**: Independent per-tab with configurable page size
- **Score Badges**: Color-coded relevance scores (red >= 70, orange >= 50, yellow >= 30)
- **Actions**: Pin articles, submit feedback for ML training, view extracted IOCs
- **Search**: Full-text search across all ingested articles

#### CISA KEV
- **Catalog**: Offline CISA Known Exploited Vulnerabilities database
- **Search**: By CVE ID, vendor, product, or keyword
- **Date Filtering**: Sort by date added to catalog

#### Cloud Services
- **Status Cards**: 18+ cloud provider current outage status
- **Provider Filters**: Toggle providers on/off
- **Details**: Expand to view outage description, affected services, and resolution status

#### Perimeter Crime
- **Incident Table**: Geofenced law enforcement CAD data
- **Severity Badges**: Color-coded by severity (High/Critical/Low/Info)
- **Dynamic Filtering**: Adjustable radius from monitored locations

### How to Use
1. Monitor the Live tab for real-time threat intelligence
2. Use category filters to focus on relevant domains
3. Pin high-value intelligence for team review
4. Cross-reference CISA KEV entries with internal assets
5. Check cloud status during reported outages
6. Monitor perimeter crime for facility security awareness

---

### 3. Regional Grid (`/regional-grid`)

Six tabs for geospatial situational awareness:

#### Geospatial Overlay
- **Map**: Deck.gl interactive map with MapLibre dark basemap
- **Layers**: Toggle SPC convective outlooks, NWS warnings/watches, active wildfires, red flag warnings
- **Site Overlays**: NOC facility markers with alert status indicators
- **PDS Detection**: Particularly Dangerous Situation alerts highlighted
- **Controls**: Layer toggles in right sidebar

#### Executive Dashboard
- **Analytics**: Infrastructure exposure by district, priority, and threat type
- **Risk Matrices**: Quantified site-level weather risk
- **Bubble Charts**: At-risk site visualization
- **Highest Risk**: Auto-identified highest-risk locations

#### Deep Hazard Analytics
- **Point-in-Polygon**: Shapely intersection calculations between facilities and weather geometries
- **Affected Sites**: Detailed list of sites under each active warning

#### Location Matrix
- **Table**: Raw data view of all monitored locations with current SPC risk and NWS alerts

#### Weather Alerts Log
- **Raw Feed**: Chronological log of all NWS alerts with severity classification

#### Atmos Weather
- **Forecast**: Weather forecast data for monitored locations

### How to Use
1. Use the Geospatial Overlay as your primary situational awareness view
2. Enable/disable layers based on current threat type
3. Click on facility markers for detailed site information
4. Reference Executive Dashboard for management briefings
5. Use Deep Hazard Analytics during severe weather events
6. Check the Alerts Log for NWS bulletin details

---

### 4. Threat Hunting (`/threat-hunting`)

Three tools for proactive threat investigation:

#### Live IOC Matrix
- **Extracted IOCs**: Autonomously extracted indicators from ingested articles
- **IOC Types**: IPv4, SHA256, SHA1, MD5, domains, URLs, CVE IDs, MITRE ATT&CK, email, BTC, file paths
- **Type-Specific Colors**: Visual differentiation by IOC type
- **OSINT Pivots**: Click any IOC to search VirusTotal, Shadon, or other external tools
- **CSV Export**: Export IOC matrix for external analysis

#### Deep Hunt & Detection Builder
- **Input**: Target entity (IP, domain, hash) and optional TTP description
- **LLM Analysis**: Generates custom Splunk/SIEM queries, MITRE ATT&CK mappings, and YARA rules
- **Results**: Download or copy generated detection content

#### Elastic SIEM Report
- **Integration**: Connect to Elasticsearch for synced security events
- **Query Builder**: Natural-language to Elastic DSL query conversion

### How to Use
1. Review the IOC matrix for indicators related to active threats
2. Click IOCs for instant OSINT enrichment via external tools
3. Export IOC matrix for incident response documentation
4. Use Deep Hunt builder for targeted threat hypotheses
5. Feed generated SIEM queries into your detection infrastructure

---

### 5. AIOps RCA (`/aiops-rca`)

Three tabs for root cause analysis and response:

#### Active Board
- **Map**: Auto-focusing Deck.gl map showing alerting locations
- **Correlation Cards**: Per-site alert clusters with severity, count, and timeline
- **Investigation Locks**: Toggle investigation state for sites under active review
- **Acknowledge**: Clear acknowledged alerts from the board
- **5-Second Polling**: Auto-refresh for real-time alert visibility

#### Patterns
- **Predictive Analytics**: State-flapping node detection
- **Chronic Degradation**: 60-day trend analysis for recurring issues
- **Insight Cards**: Generated by `generate_chronic_insights()` from the correlation engine

#### Global Correlation
- **Engine**: Deterministic causal analysis linking external intelligence to telemetry drops
- **Fleet Detection**: Identifies massive carrier/infrastructure outages

#### Site Maintenance & Dispatch
- **Maintenance Form**: Set sites into maintenance mode with ETR and reason
  - Requires `Action: Manage Site Maintenance`
  - Auto-clears expired ETRs during RCA analysis
  - Tracks who modified status and when
- **Dispatch Controls**: Generate and send ticket emails
  - Requires `Action: Dispatch RCA Tickets`
  - Ticket text includes priority, district, SLA target, patient zero, and alert details
  - Manual dispatch sends email via SMTP with proper formatting
- **Ticket Generation**: Preview ticket text before sending

### How to Use
1. Monitor the Active Board for new alert clusters
2. Click clusters to view detailed alert information
3. Lock sites under investigation to coordinate team response
4. Use the Analyze button to run root cause analysis
5. Set sites to maintenance mode for planned work
6. Generate and dispatch tickets for actionable incidents
7. Review Patterns tab for recurring issues
8. Check Global Correlation for upstream cause identification

---

### 6. Shift Logbook (`/shift-logbook`)

Two-column layout for shift documentation:

#### Left Column — Entry Form
- **Analyst/Auto-fill**: Name and role from user profile
- **Shift Period**: Morning, Afternoon, or Night
- **Content**: Free-text entry for shift notes and handoff information
- **Date Override**: For historical entries
- **Auto-Draft**: Automatically populates active outage information from AIOps

#### Right Column — Explorer
- **Recent Entries**: Chronological list of recent log entries
- **Day/Week Navigation**: Calendar interface for browsing historical entries
- **Soft Delete**: Entries can be hidden without permanent deletion
- **CSV Export**: Download entries for external reporting

#### Summary Generation
- **End-of-Morning / End-of-Day**: AI-generated handoff reports summarizing active issues
- **Executive Summaries**: Aggregated analysis over current week or month periods targeting organizational roles

### How to Use
1. Start each shift by selecting your name and shift period
2. Document significant events, handoff notes, and ongoing issues
3. Use auto-draft to capture active outage context
4. Generate end-of-shift summaries for the next shift
5. Browse previous entries in the explorer
6. Export shift data for compliance documentation

---

### 7. Reporting (`/reporting`)

Three tabs for intelligence reporting:

#### Daily Fusion Briefing
- **Generation**: AI-synthesized daily intelligence report
- **Display**: Formatted markdown converted to HTML
- **Broadcast**: Email distribution to configured recipients
- **Archive**: Historical brief storage and retrieval

#### Custom Report Builder
- **Article Selection**: Multi-select interface for manual article aggregation
- **AI Pipeline**: Selected articles fed to LLM for targeted synthesis
- **Custom Instructions**: Optional guidance for the LLM generation

#### Shared Library
- **Storage**: Save and organize generated reports
- **Retrieval**: Search and view historical reports
- **Management**: Delete outdated or superseded reports

### How to Use
1. Generate the Daily Fusion Brief at the start of each day
2. Broadcast to management via the email button
3. Use Custom Report Builder for incident-specific intelligence packages
4. Save important reports to the Shared Library
5. Reference archived briefs for trend analysis

---

### 8. Settings (`/settings`)

Ten tabs for system administration:

#### Profile
- Update personal information (name, job title, contact info, default shift)

#### Theme
- Six visual themes: Standard, NOC Terminal, High Contrast, Cyberpunk, Solarized Dark, Midnight Ocean
- Persisted in browser localStorage

#### Facilities
- Add, edit, or delete monitored locations
- Set coordinates, location type, district, and priority
- Bulk import via JSON

#### Internal Assets
- Hardware and software inventory management
- Bulk import via CSV

#### RSS Sources
- Add, edit, or delete RSS/Atom feed sources
- Toggle active/inactive status
- View last fetch time

#### ML Training
- Keyword weighting interface (70 default keywords)
- Model retraining from analyst feedback
- Requires at least 10 labeled articles

#### AI & SMTP
- LLM endpoint, API key, and model configuration
- SMTP server configuration for email features
- Tech stack description for AI context
- Risk baseline overrides

#### Users & Roles
- Create custom roles with granular page/action/site-type permissions
- Add, edit, or delete users
- Assign roles to users

#### Backup & Restore
- Export full system configuration as JSON
- Import from previously exported JSON backup

#### Danger Zone
- Database garbage collection
- Telemetry purging
- Taxonomy migration tools
- Full database reset (nuke)

### How to Use
1. Configure AI & SMTP first for full feature enablement
2. Add your facilities and internal assets
3. Customize RSS sources for your intelligence requirements
4. Create user accounts for each team member
5. Set up custom roles if standard admin/analyst roles are insufficient
6. Regularly export backups
7. Monitor ML training to improve article scoring accuracy

---

## WebSocket Real-Time Features

The application maintains a persistent WebSocket connection to the backend:

- **Connection**: Auto-established on page load to `ws://localhost:8101/ws`
- **Updates**: Receives `dashboard_update` payloads every 5 seconds with current alert data
- **Reconnection**: Exponential backoff if connection drops
- **Browser Notifications**: CRITICAL/HIGH severity alerts trigger desktop notifications
- **Bi-directional**: Send commands through the WebSocket for synchronized team actions

### WebSocket Commands

| Command | Effect |
|---------|--------|
| `{"type": "INVESTIGATING_UPDATE", "site": "SiteName", "is_investigating": true}` | Lock site for investigation (visible to all users) |
| `{"type": "RCA_UPDATE"}` | Manually trigger a dashboard refresh for all connected clients |

---

## Risk Level Reference

The application uses the MS-ISAC/CIS Alert Framework:

```
GREEN  → Normal operations, baseline threat posture
BLUE   → Elevated vigilance, minor anomalies detected
YELLOW → Significant threat, heightened monitoring required
ORANGE → High risk, active threat present, prepare response
RED    → Critical, confirmed compromise or imminent threat
```

These levels appear throughout the application:
- Dashboard risk panels
- Article score badges
- Site status indicators
- Alert severity classification
- Unified brief tone assessment
- Tiered escalation priority mapping

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+Shift+N` | Toggle sidebar collapse |
| `Ctrl+Shift+1-8` | Navigate to sidebar items (order as listed) |
| `Ctrl+Shift+R` | Refresh current page data |
| `Escape` | Close open modals |

---

## Best Practices

### Shift Change Procedure
1. Review current dashboard metrics and Global Risk level
2. Check Active Board for unresolved alerts
3. Read recent shift logbook entries
4. Generate end-of-shift summary
5. Document key events in current shift entry
6. Broadcast Unified Brief for management awareness

### Incident Response Workflow
1. Alert appears on Active Board (AIOps RCA)
2. Lock site for investigation
3. Run RCA analysis to identify root cause
4. Check Global Correlation for upstream causes
5. Set site to maintenance if needed
6. Generate and dispatch ticket
7. Document in shift logbook
8. Acknowledge alerts upon resolution

### Daily Routine
1. **Start of Day**: Review overnight alerts, check cloud/weather status
2. **Morning Brief**: Generate and broadcast Unified Brief
3. **Ongoing**: Monitor RSS feeds, triage articles, pin important intel
4. **Mid-Day**: Run threat hunting queries, check internal risk posture
5. **End of Day**: Generate shift summary, document handoff notes

### Intelligence Analysis
1. Review RSS Live tab for new high-scoring articles
2. Pin articles relevant to current operations
3. Review extracted IOCs for actionable indicators
4. Cross-reference CISA KEV with internal hardware assets
5. Use Deep Hunt builder for specific threat hypotheses
6. Archive important intelligence via Custom Report Builder
