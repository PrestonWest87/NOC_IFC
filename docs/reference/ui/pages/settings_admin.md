# Module: `src/ui/pages/settings_admin.py`

## Overview

Settings and Administration page renderer. Provides up to 8 permission-gated tabs: Facilities (JSON import, manual data editor), Internal Assets (CSV ingestion for software and hardware), RSS Sources (keyword and feed management), ML Training (model retraining), AI & SMTP (LLM, SMTP, threat matrix baseline, CIS countermeasures configuration), Users & Roles (create/edit users and roles with granular permissions), Backup & Restore (JSON export/import), and Danger Zone (destructive database operations and black ops features).

---

## Function: `render_settings_admin()`

**Purpose:** Renders the complete Settings & Admin page with up to 8 permission-gated tabs.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, black ops state, current user. Builds tab list based on allowed actions.

2. **Tab: Facilities**:
   - Left column: JSON file upload for mass import (requires name, lat, lon; optional type, priority). "Import Data" button calls `svc.import_locations()`.
   - Right column: Manual adjustments - loads all locations into a `st.data_editor()` with disabled ID column. "Save Manual Adjustments" button calls `svc.update_locations()`.

3. **Tab: Internal Assets**:
   - **Software Assets**: CSV upload (must contain 'name' column). On sync, deletes all existing `SoftwareAsset` records and bulk inserts new ones.
   - **Hardware Assets**: CSV upload (requires 'IP Address' column). Supports column mapping for operating system fields, numeric coercion for vulnerability counts, and validation against `HardwareAsset` table columns. On sync, deletes existing records and bulk inserts.

4. **Tab: RSS Sources**:
   - Left column: Bulk keyword management (word, weight format). Lists active keywords with delete buttons.
   - Right column: Bulk feed management (URL, Name format). Lists active feeds with delete buttons.
   - Both use `svc.add_bulk_keywords()` and `svc.add_bulk_feeds()` respectively.

5. **Tab: ML Training**:
   - Displays ML sample counts (total, positives, negatives).
   - "Retrain Model Now" button (60s cooldown, requires `can_train` permission, minimum 10 samples). Calls `train()` from `src.train_model`.

6. **Tab: AI & SMTP**:
   - Single form with three sections:
     - **LLM Configuration**: endpoint URL, API key (password field), model name, internal tech stack text area, AI enable checkbox.
     - **SMTP Broadcast Configuration**: server, port, username, password, sender address, default recipient list, enable checkbox.
     - **Threat Matrix Baseline Overrides**: cyber and physical baseline override number inputs (0 = auto 14-day moving average).
     - **CIS Alert Level Countermeasures**: System Countermeasures (1-5 slider) and Network Countermeasures (1-5 slider).
   - "Save Global Config" submits the form data via `svc.save_global_config()`.

7. **Tab: Users & Roles**:
   - Left column:
     - **Create New User**: username, password, role select. Calls `svc.create_user()`.
     - **Change User Role**: select user + new role. Calls `svc.update_user_role()`.
     - **Create Custom Role**: name, allowed master pages multi-select, allowed sub-tabs and actions multi-select, allowed site types multi-select. Calls `svc.create_role()`.
     - **Edit Existing Role**: selects non-admin role, edits pages/actions/site types. Calls `svc.update_role()`.
   - Right column:
     - **Active Users**: lists users with role and delete button (self-deletion prevented).
     - **Force Reset Password**: select user + new password. Calls `svc.force_reset_pwd()`.
     - **Active Roles**: lists roles with page/action counts and delete button (admin and analyst roles protected).

8. **Tab: Backup & Restore**:
   - **Export Data**: "Generate Backup JSON" button calls `svc.get_backup_data()`. Download button for the JSON file.
   - **Import Data**: JSON file upload. "Execute Import" button calls `svc.restore_backup_data()` and reports counts of restored keywords, feeds, and locations.

9. **Tab: Danger Zone**:
   - Left column:
     - **Routine Maintenance**: "Run Garbage Collector" button (60s cooldown) calls `run_database_maintenance()`.
     - **Reset Cloud Telemetry**: "Purge Cloud Data" button (60s cooldown) calls `svc.nuke_tables(["CloudOutage"])`.
     - **Data Migration**: "Recategorize Articles" button (60s cooldown) calls `svc.recategorize_all_articles()`.
   - Middle column:
     - **Clear History**: "Delete All Articles" calls `svc.nuke_tables(["Article", "ExtractedIOC"])`.
     - **Clear Locations**: "Delete All Locations" calls `svc.nuke_tables(["MonitoredLocation"])` + cache clear.
     - **Crime Data Reset**: "PURGE CRIME DATA" calls `svc.nuke_crime_data()`.
   - Right column:
     - **Weather & Fire Telemetry**: "PURGE WEATHER & FIRE DATA" calls `svc.nuke_weather_data()`.
     - **Factory Reset**: "FULL RESET" calls `svc.nuke_tables()` on articles, IOCs, feeds, keywords, locations.
   - **Black Ops** section:
     - **Operation: Nick** (user `pwest` only): toggle for the Nick Troll feature.
     - **Operation: Dean** (admin only): select target user, toggle to engage cascading failure simulation protocol.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | DataFrames for editors and CSV parsing |
| `numpy` | NaN handling in hardware CSV import |
| `src.services` | Data access layer |
| `src.models.schema` | `SoftwareAsset`, `HardwareAsset` |
| `src.train_model.train` | ML model retraining |
| `src.scheduler.run_database_maintenance` | Garbage collection |
| `src.ui.state_manager` | Safe rerun, cooldowns, permissions, black ops state, constants, timezone |
