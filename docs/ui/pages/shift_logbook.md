# Module: `src/ui/pages/shift_logbook.py`

## Overview

NOC Shift Logbook page renderer. Provides incident-based running log entry with AIOps telemetry integration, automated End of Morning and End of Day report generation, aggregated Weekly/Monthly executive summaries, Day/Week log explorer views, and admin log export utility.

---

## Function: `render_shift_logbook()`

**Purpose:** Renders the complete Shift Logbook page with log entry form, auto-drafting, summary generation, explorer views, and export.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**

1. **Setup**: Reads permissions, system config, AI-enabled flag, current user.

2. **Nested Function: `open_log_modal(log_entry)`** (decorated with `@st.dialog`):
   - Opens a modal dialog for a shift log entry showing analyst, role, date, shift, content.
   - If not deleted: "Soft Delete Log" button sets `is_deleted = True`.
   - If deleted and admin: "Restore Log" button sets `is_deleted = False`.

3. **Log Entry Section** (two columns):
   - **AIOps Telemetry Integration** (right):
     - "Auto-Draft Active Outages" button: fetches active alerts via `get_aiops_dashboard_data()`, clusters via `EnterpriseAIOpsEngine`, computes durations, appends draft lines to `st.session_state.aiops_draft`.
   - **Incident Entry Form** (left):
     - Shift selection: date input (if "No Shift") or Morning/Afternoon/Night select (based on user's `default_shift`).
     - Analyst name text input.
     - Incident notes text area (pre-populated from `aiops_draft`).
     - "Append to Running Log" button (requires `can_submit_log`): calls `svc.save_shift_log()`.

4. **Daily Persistent Summaries**:
   - **End of Morning Report** expander:
     - "Generate Morning Report" button: queries logs with "Morning" in shift_period for today, calls `call_llm()` with supervisor prompt, saves to session state and persists as a new `ShiftLogEntry`.
   - **End of Day Report** expander:
     - Same flow as Morning but for all day logs, stores as "Afternoon/Evening" shift period.
   - **Admin: Retroactive End of Day Report** expander:
     - Date picker, role select, generates report for a historical date, injects log entry with backdated `created_at`.

5. **Aggregated Executive Summaries**:
   - Period selector: Current Week, Previous Week, Current Month, Previous Month.
   - Role selector (admin sees "All" + all roles; others see their own role).
   - "Generate Summary" button (60s cooldown, requires AI): calculates UTC date range, queries logs, calls `generate_aggregated_shift_summary()` with map-reduce.
   - Displays result in bordered container.

6. **Shift Log Explorer**:
   - **Day View / Week View** radio toggle.
   - **Day View**:
     - Previous/Next day navigation buttons with date input.
     - Log entries table: time, shift (Morning/Evening), analyst, log message (preview 250 chars), "Expand" button (opens modal).
     - Soft-deleted entries shown with strikethrough and red "(DELETED)" label to admin.
   - **Week View**:
     - Previous/Next week navigation with header display.
     - 7-column calendar grid. Each day button navigates to Day View.
     - Per-day log entries shown as buttons with time and shift abbreviation.

7. **Admin Log Export Utility**:
   - Role filter, start/end date pickers.
   - Filtered logs displayed as downloadable CSV with columns: Local Time, Analyst, Role, Shift Period, Content.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | UI framework |
| `pandas` | CSV export DataFrame |
| `src.services` | Data access layer |
| `src.services.aiops_engine.EnterpriseAIOpsEngine` | Alert clustering for auto-draft |
| `src.utils.llm` | `call_llm`, `generate_aggregated_shift_summary` |
| `src.database.ShiftLogEntry` | Log persistence and soft-delete |
| `src.ui.state_manager` | Safe rerun, cooldowns, time formatting, permissions, timezone |
