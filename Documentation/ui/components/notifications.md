# Module: `src/ui/components/notifications.py`

## Overview

Browser push notification component for the NOC Intelligence Fusion Center. Evaluates cached geospatial data against user preferences and injects JavaScript to trigger native browser desktop notifications for new NWS weather alerts within monitored zones.

---

## Function: `trigger_browser_notifications()`

**Purpose:** Evaluates cached geospatial alert data and injects JavaScript to trigger native browser desktop notifications for new weather alerts that have not been previously notified.

**Parameters:** None

**Returns:** None

**Raises:** None (all exceptions silently caught)

**Flow:**
1. Initializes `st.session_state.notified_alerts` as an empty `set()` if not present.
2. Fetches cached locations and GeoJSON data (`ar_data`, `oos_data`) from the service layer.
3. Calls `svc.get_filtered_notification_alerts()` with the current user, AR data, OOS data, and locations to get relevant alerts.
4. Compares each alert against the `notified_alerts` set using a composite key `"{Event}_{Affected Area}_{Expires}"`:
   - If the key is new, appends to `new_alerts` and adds the key to the set.
5. If new alerts exist, builds a JavaScript string that:
   - Calls `new Notification()` for each alert with a 500ms stagger delay.
   - Title: `"NWS Alert: {Event}"`
   - Body: `"Affected: {Affected Area}"`
6. Injects the JavaScript via `st.components.v1.html()` inside a `<script>` block that checks for `Notification.permission === "granted"`.

**Dependencies:**
| Module | Usage |
|--------|-------|
| `streamlit` | Session state, HTML component rendering |
| `src.services` | Data access layer for locations, GeoJSON, filtered alerts |
