# Module: `src/ui/pages/reporting.py`

## Overview

Intelligence Reporting and Briefings page renderer. Provides three permission-gated tabs: Daily Fusion Briefing (AI-generated daily reports with email broadcast), Custom Report Builder (article search with AI synthesis), and Shared Library (persisted report management).

---

## Function: `render_reporting()`

**Purpose:** Renders the complete Reporting & Briefings page with up to 3 permission-gated tabs.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, AI-enabled flag, current user. Builds tab list based on allowed actions.

2. **Tab: Daily Fusion Briefing**:
   - Displays "Daily Master Fusion Report" header.
   - Calculates yesterday's date in local timezone and checks if a report already exists for that date.
   - "Generate Yesterday's Report" button (300s cooldown, requires AI enabled):
     - Calls `generate_daily_fusion_report()` via LLM.
     - Saves result via `svc.save_daily_briefing()`.
   - If reports exist, renders a selectbox to browse historical briefings.
   - Selected report displayed in bordered container.
   - **Broadcast Report** section:
     - Email recipient input.
     - "Transmit Report" button: generates HTML email via `svc.generate_daily_report_email_html()` and dispatches via `send_alert_email()`.

3. **Tab: Custom Report Builder**:
   - Search articles by keyword with result limit selector.
   - Multi-select articles from search results.
   - Analyst name and contact info fields.
   - AI Objective text area for custom LLM prompt.
   - "Generate Report" button (60s cooldown): calls `build_custom_intel_report()` with selected articles.
   - Generated report displayed with markdown rendering.
   - "Save to Library" button: saves report with title via `svc.save_custom_report()`.

4. **Tab: Shared Library**:
   - Lists all saved reports via `svc.get_saved_reports()`.
   - Each report in an expander with title, creation time, content.
   - "Delete" button per report via `svc.delete_record("SavedReport", id)`.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `src.services` | Data access layer |
| `src.utils.llm` | `generate_daily_fusion_report`, `build_custom_intel_report` |
| `src.utils.mailer.send_alert_email` | Email dispatch |
| `src.ui.state_manager` | `safe_rerun`, `check_cooldown`, `apply_cooldown`, `format_local_time`, `get_permission_flags`, `LOCAL_TZ` |
