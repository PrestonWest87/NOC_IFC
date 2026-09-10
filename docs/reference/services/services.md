# Services Layer Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services.py`

The `services.py` module is the central Data Access Layer (DAL) for the NOC Intelligence Fusion Center. It contains 104+ functions that bridge the API routes to the database, providing authentication, dashboards, threat telemetry, regional grid analytics, AIOps RCA, reporting, and administrative operations.

---

## Utility Classes

### `TTLCache`
A decorator class that implements a time-to-live (TTL) cache to replace Streamlit's `@st.cache_data`.

**Purpose:** Decorator that caches function return values with a configurable TTL and max entry count.

**Constructor Parameters:**
- `ttl` (int) -- Time-to-live in seconds (default: 300)
- `max_entries` (int) -- Maximum number of cached entries (default: 128)

**Methods:**
- `__call__(func)` -- Decorator wrapper. Caches results keyed by args+kwargs. Evicts oldest entry when max_entries exceeded.
- `clear()` -- Clears the entire cache store and timestamps.

**Flow:** On invocation, generates a key from `str(args) + str(sorted(kwargs.items()))`. If the key exists and is within TTL, returns cached value. Otherwise, executes the function, stores the result, and returns it.

---

### `DotDict`
A utility class extending `dict` to allow dot-notation attribute access.

**Purpose:** Provides seamless dot-notation access to dictionary keys for UI integration.

**Methods:**
- `__getattr__` -- Delegates to `dict.get`
- `__setattr__` -- Delegates to `dict.__setitem__`
- `__delattr__` -- Delegates to `dict.__delitem__`

---

## Utility Functions

### `sanitize_text(text: str) -> str`

**Purpose:** Strips supplementary Unicode planes and unwanted characters from text.

**Parameters:**
- `text` (str) -- Input text to sanitize

**Returns:** (str) -- Sanitized text with supplementary Unicode removed and question marks stripped.

**Flow:** Uses regex to remove characters in range `U+10000` to `U+10FFFF`, then strips `?` characters and whitespace.

---

### `to_dotdict(obj) -> DotDict | None`

**Purpose:** Converts a SQLAlchemy model instance to a DotDict by reading column names.

**Parameters:**
- `obj` -- A SQLAlchemy model instance

**Returns:** `DotDict` or `None` if obj is falsy.

---

### `to_dotdict_list(objs) -> list[DotDict]`

**Purpose:** Converts a list of SQLAlchemy model instances to a list of DotDicts.

**Parameters:**
- `objs` -- List of SQLAlchemy model instances

**Returns:** `list[DotDict]`

---

### `central_now() -> datetime`

**Purpose:** Returns the current time in the America/Chicago timezone.

**Returns:** `datetime` -- Current Central timezone datetime.

**Dependencies:** `LOCAL_TZ` (ZoneInfo("America/Chicago"))

---

### `utc_now() -> datetime`

**Purpose:** Returns the current UTC time.

**Returns:** `datetime` -- Current UTC datetime (naive).

---

### `format_central(dt) -> str`

**Purpose:** Formats a UTC datetime as a Central timezone string.

**Parameters:**
- `dt` (datetime | None) -- UTC datetime to format

**Returns:** (str) -- Formatted string in `YYYY-MM-DD HH:MM:SS` Central time, or `"Unknown"` if input is None.

**Flow:** If `dt` is None, returns "Unknown". If `dt` is timezone-naive, assumes UTC. Converts to Central time and formats.

---

### `get_cached_config() -> DotDict`

**Purpose:** Retrieves the global system configuration, cached for 300 seconds.

**Returns:** `DotDict` -- SystemConfig model converted to DotDict.

**Raises:** None (creates a new SystemConfig if none exists).

**Dependencies:** `SystemConfig`, `SessionLocal`, `TTLCache(ttl=300)`

---

### `get_cached_locations() -> list[DotDict]`

**Purpose:** Retrieves all monitored locations, cached for 600 seconds.

**Returns:** `list[DotDict]` -- All MonitoredLocation records.

**Dependencies:** `MonitoredLocation`, `SessionLocal`, `TTLCache(ttl=600, max_entries=1)`

---

### `get_cached_geojson() -> tuple`

**Purpose:** Retrieves all cached GeoJSON data (SPC day 1/2/3, NWS AR/OOS, USGS AR/OOS).

**Returns:** `tuple` -- `(spc_d1, spc_d2, spc_d3, ar, oos, usgs_ar, usgs_oos)` where each element is GeoJSON data or None.

**Dependencies:** `GeoJsonCache`, `SessionLocal`, `TTLCache(ttl=120, max_entries=1)`

---

### `get_ar_counties_mapping() -> dict`

**Purpose:** Fetches and caches US county boundaries, filtering for Arkansas (FIPS 05).

**Returns:** `dict` -- Mapping of lowercase county names to geometry objects.

**Raises:** Logs error on failure, returns empty dict.

**Dependencies:** `requests`, `TTLCache(ttl=86400, max_entries=1)`

**Flow:** Fetches county GeoJSON from GitHub, filters features where STATE == "05", returns dict keyed by lowercase county name.

---

### `get_regional_counties_mapping() -> dict`

**Purpose:** Fetches and caches all US county boundaries keyed by 5-digit FIPS code.

**Returns:** `dict` -- Mapping of FIPS codes to dicts containing `state_fips`, `geometry`, and `name`.

**Raises:** Logs error on failure, returns empty dict.

**Dependencies:** `requests`, `TTLCache(ttl=86400, max_entries=1)`

**Flow:** Fetches county GeoJSON from GitHub, indexes features by concatenated STATE+COUNTY FIPS codes.

---

### `get_all_site_types() -> list[str]`

**Purpose:** Returns all distinct location types from MonitoredLocation.

**Returns:** `list[str]` -- Unique location types.

**Dependencies:** `MonitoredLocation`, `SessionLocal`

---

### `set_cluster_dispatch(alert_ids: list, is_dispatched: bool) -> bool`

**Purpose:** Sets the dispatch flag on a batch of SolarWinds alerts.

**Parameters:**
- `alert_ids` (list) -- List of alert IDs to update
- `is_dispatched` (bool) -- Dispatch status to set

**Returns:** `True` on success.

**Dependencies:** `SolarWindsAlert`, `SessionLocal`

---

### `get_shift_logs(role_filter: str = "All", start_date=None, end_date=None) -> list[DotDict]`

**Purpose:** Retrieves shift log entries with optional role, date range filtering.

**Parameters:**
- `role_filter` (str) -- Role to filter by ("All" for no filter)
- `start_date` (date | None) -- Start of date range
- `end_date` (date | None) -- End of date range

**Returns:** `list[DotDict]` -- Shift log entries ordered by created_at ascending.

**Dependencies:** `ShiftLogEntry`, `SessionLocal`

---

### `save_shift_log(analyst, role, shift_period, content, custom_date=None) -> bool`

**Purpose:** Saves a new shift log entry.

**Parameters:**
- `analyst` (str) -- Analyst name
- `role` (str) -- Author role
- `shift_period` (str) -- Shift period identifier
- `content` (str) -- Log content
- `custom_date` (date | None) -- Custom date override (for "No Shift" entries)

**Returns:** `True` on success.

**Dependencies:** `ShiftLogEntry`, `SessionLocal`, `ZoneInfo`

---

### `set_site_maintenance(site_name: str, is_maint: bool, etr_date, reason: str)`

**Purpose:** Sets maintenance mode on a monitored location.

**Parameters:**
- `site_name` (str) -- Name of the site
- `is_maint` (bool) -- Whether maintenance is active
- `etr_date` (date | None) -- Estimated time of restoration
- `reason` (str) -- Maintenance reason

**Flow:** Queries location by name, updates maintenance fields, clears cached locations.

**Dependencies:** `MonitoredLocation`, `SessionLocal`

---

### `get_nws_forecast(lat: float, lon: float) -> list | None`

**Purpose:** Fetches 7-day weather forecast for a coordinate using NWS API.

**Parameters:**
- `lat` (float) -- Latitude
- `lon` (float) -- Longitude

**Returns:** `list | None` -- Forecast periods array, or None on failure.

**Raises:** Logs error on any network/API failure.

**Dependencies:** `requests`, `TTLCache(ttl=3600)`

**Flow:** Step 1: Calls `https://api.weather.gov/points/{lat},{lon}` to get grid points. Step 2: Fetches forecast from the returned forecast URL. Returns periods array.

---

### `get_filtered_notification_alerts(username, ar_data, oos_data, locs) -> list`

**Purpose:** Retrieves weather alerts filtered by user preferences with geofencing for OOS data.

**Parameters:**
- `username` (str) -- Username to fetch preferences for
- `ar_data` (dict) -- Arkansas NWS alert GeoJSON
- `oos_data` (dict) -- Out-of-state NWS alert GeoJSON
- `locs` (list) -- List of monitored locations with lat/lon

**Returns:** `list[dict]` -- Deduplicated alert dicts with Event, Affected Area, Expires, Description.

**Dependencies:** `UserWeatherPreference`, `SessionLocal`, `shapely`

**Flow:** Fetches user's alert type preferences. For AR data, keeps all matching alerts. For OOS data, performs polygon intersection check against monitored locations. Deduplicates by event+area+expires.

---

## 1. Authentication and User Profile

### `get_role_permissions(role_name: str) -> dict`

**Purpose:** Returns permissions (pages, actions, site types) for a given role.

**Parameters:**
- `role_name` (str) -- Name of the role

**Returns:** `dict` -- Contains keys `allowed_pages`, `allowed_actions`, `allowed_site_types`.

**Dependencies:** `Role`, `SessionLocal`

**Flow:** Admin role returns hardcoded full permissions. Other roles query the Role table.

---

### `authenticate_user(username: str, password: str) -> tuple`

**Purpose:** Authenticates a user by username and password.

**Parameters:**
- `username` (str) -- Username
- `password` (str) -- Plain-text password

**Returns:** `tuple[DotDict | None, str | None]` -- `(user_dotdict, session_token)` on success, `(None, None)` on failure.

**Dependencies:** `User`, `SessionLocal`, `bcrypt`

**Flow:** Looks up user, verifies password with bcrypt, generates new UUID session token, fetches role permissions, returns user DotDict with permissions attached.

---

### `get_user_by_token(token: str) -> DotDict | None`

**Purpose:** Retrieves a user by session token.

**Parameters:**
- `token` (str) -- Session token

**Returns:** `DotDict | None` -- User DotDict with permissions, or None.

**Dependencies:** `User`, `SessionLocal`

---

### `get_user_by_username(username: str) -> DotDict | None`

**Purpose:** Retrieves a user by username.

**Parameters:**
- `username` (str) -- Username

**Returns:** `DotDict | None` -- User DotDict, or None.

**Dependencies:** `User`, `SessionLocal`

---

### `update_user_profile(username, full_name, job_title, contact_info, old_pwd, new_pwd, default_shift="") -> tuple`

**Purpose:** Updates a user's profile with optional password change.

**Parameters:**
- `username` (str) -- Username
- `full_name` (str) -- Full name
- `job_title` (str) -- Job title
- `contact_info` (str) -- Contact information
- `old_pwd` (str) -- Current password (required if changing password)
- `new_pwd` (str) -- New password (empty string to skip)
- `default_shift` (str) -- Default shift (default: "")

**Returns:** `tuple[bool, str]` -- `(success, message)`

**Raises:** Returns `(False, "Incorrect current password.")` if old password does not match.

**Dependencies:** `User`, `SessionLocal`, `bcrypt`

---

### `logout_user(username: str)`

**Purpose:** Invalidates a user's session token.

**Parameters:**
- `username` (str) -- Username

**Dependencies:** `User`, `SessionLocal`

---

## 2. Operational Dashboard and Article Actions

### `get_dashboard_metrics() -> dict`

**Purpose:** Retrieves counts for the operational dashboard (RSS, CVE, hazards, cloud outages in last 24h).

**Returns:** `dict` -- Keys: `rss_count`, `cve_count`, `hazard_count`, `cloud_count`.

**Dependencies:** `Article`, `CveItem`, `RegionalHazard`, `CloudOutage`, `SessionLocal`, `TTLCache(ttl=60)`

---

### `get_pinned_articles() -> list[DotDict]`

**Purpose:** Retrieves all pinned articles ordered by date descending.

**Returns:** `list[DotDict]`

**Dependencies:** `Article`, `SessionLocal`

---

### `get_live_articles(limit=15) -> list[DotDict]`

**Purpose:** Retrieves high-scoring recent articles (last 24h, score >= 50, not pinned).

**Parameters:**
- `limit` (int) -- Maximum articles to return (default: 15)

**Returns:** `list[DotDict]`

**Dependencies:** `Article`, `SessionLocal`

---

### `toggle_pin(art_id: int)`

**Purpose:** Toggles the pinned status of an article.

**Parameters:**
- `art_id` (int) -- Article ID

**Dependencies:** `Article`, `SessionLocal`

---

### `boost_score(art_id: int, amount=15)`

**Purpose:** Boosts an article's score (capped at 100).

**Parameters:**
- `art_id` (int) -- Article ID
- `amount` (float) -- Amount to add (default: 15)

**Dependencies:** `Article`, `SessionLocal`

---

### `change_status(art_id: int, new_feedback: int)`

**Purpose:** Changes human feedback status on an article and adjusts keyword weights.

**Parameters:**
- `art_id` (int) -- Article ID
- `new_feedback` (int) -- 1 (negative), 2 (positive)

**Dependencies:** `Article`, `Keyword`, `SessionLocal`

**Flow:** If feedback changes from 0 to 1/2 and article has keywords, adjusts each keyword weight: +1 for positive feedback, -1 (min 1) for negative feedback.

---

### `save_ai_bluf(art_id: int, bluf_text: str)`

**Purpose:** Saves AI-generated BLUF (Bottom Line Up Front) text on an article.

**Parameters:**
- `art_id` (int) -- Article ID
- `bluf_text` (str) -- AI-generated summary text

**Dependencies:** `Article`, `SessionLocal`

---

## 3. Executive Dashboard and Crime Intelligence

### `get_recent_crimes(max_distance=None, grid_only=False, hours_back=168) -> list[dict]`

**Purpose:** Queries recent perimeter crime incidents with dynamic filtering.

**Parameters:**
- `max_distance` (float | None) -- Maximum distance in miles
- `grid_only` (bool) -- Filter to grid threat categories only
- `hours_back` (int) -- Lookback window in hours (default: 168 = 7 days)

**Returns:** `list[dict]` -- Crime records with id, category, raw_title, timestamp, distance_miles, severity, lat, lon.

**Dependencies:** `CrimeIncident`, `SessionLocal`

**Flow:** Filters by timestamp cutoff. If grid_only, restricts to FBI UCR threat categories. If max_distance, filters by distance. Orders by timestamp descending.

---

### `force_fetch_crime_data() -> bool`

**Purpose:** Manually triggers crime data fetch from the UI.

**Returns:** `bool` -- True on success.

**Dependencies:** `crime_worker.fetch_live_crimes`, `dispatch_perimeter_crime_alerts`

---

### `get_historical_threat_scores(days=14) -> list[DotDict]`

**Purpose:** Fetches historical daily threat scores for baseline calculation.

**Parameters:**
- `days` (int) -- Lookback days (default: 14)

**Returns:** `list[DotDict]` -- DailyThreatScore records.

**Dependencies:** `DailyThreatScore`, `SessionLocal`

---

### `save_threat_score(c_pts, p_pts, c_base, p_base)`

**Purpose:** Saves the highest daily threat score to maintain deviation baseline.

**Parameters:**
- `c_pts` (float) -- Cyber points
- `p_pts` (float) -- Physical points
- `c_base` (float) -- Cyber baseline
- `p_base` (float) -- Physical baseline

**Dependencies:** `DailyThreatScore`, `SessionLocal`

**Flow:** Uses today's date (UTC midnight). If a record exists, updates with max values. Otherwise creates new record.

---

### `get_executive_grid_intel(active_warn_count, recent_crimes) -> dict`

**Purpose:** Synthesizes live OSINT and telemetry using CIS Alert Level Framework and FBI UCR Taxonomy.

**Parameters:**
- `active_warn_count` (int) -- Number of active weather warnings
- `recent_crimes` (list[dict]) -- Recent crime data

**Returns:** `dict` -- Comprehensive intelligence payload with unified_risk, physical_score, cyber_score, evidence_log, baseline data.

**Dependencies:** `Article`, `CveItem`, `DailyThreatScore`, `SystemConfig`, `SessionLocal`

**Flow:**
1. Fetches historical scores and calculates baselines
2. Processes cyber articles (48h window) with utility/APT/ransomware classification
3. Processes physical articles with Arkansas + threat keyword filters
4. Processes ICS/KCV advisories from CISA
5. Applies CIS Alert Level scoring: `(C + L) - (S + N)` for both cyber and physical
6. Classifies scores into RED/ORANGE/YELLOW/BLUE/GREEN tiers
7. Calculates unified risk as max of cyber and physical tiers
8. Saves threat score and returns comprehensive payload

---

### `calculate_internal_cis_score(db_session) -> dict`

**Purpose:** Calculates Internal CIS Threat Score based purely on OSINT correlations against hardware/software assets.

**Parameters:**
- `db_session` -- SQLAlchemy database session

**Returns:** `dict` -- score, risk_level, total_assets, hw_data, sw_data, and aggregate metrics.

**Dependencies:** `HardwareAsset`, `SoftwareAsset`, `Article`, `CveItem`, `Keyword`, `Article`, `re`

**Flow:**
1. **Phase 1: Engine Rules** -- Compiles search maps for HW/SW assets with regex patterns, handles common noun collisions with proximity checks
2. **Phase 2: Inverted Indexing** -- Double-gatekeeper: articles must have 1 strong or 2 weak cyber keywords; builds tokenized word sets
3. **Phase 3: Reverse-Indexed Batch Correlation** -- Builds trigger-to-asset reverse index, scans articles and CVEs for asset matches
4. **Phase 4: Posture Reconstruction** -- Annotates matched HW/SW with OSINT risk scores
5. **Phase 5: CIS Risk Calculation** -- Calculates lethality (from critical hits) and criticality (from % assets at risk), computes `(criticality + lethality) - (S + N)` score, maps to risk level

---

### `generate_and_save_internal_risk_snapshot() -> dict`

**Purpose:** Runs CIS calculation and saves the snapshot to the database.

**Returns:** `dict` -- CIS calculation results.

**Dependencies:** `InternalRiskSnapshot`, `calculate_internal_cis_score`, `SessionLocal`, `json`

---

### `generate_unified_brief_email_html(report_time, markdown_content, global_risk=None, internal_risk=None) -> str`

**Purpose:** Generates HTML email for the unified risk brief with CIS color-coded risk banners.

**Parameters:**
- `report_time` (str) -- Report generation timestamp
- `markdown_content` (str) -- Markdown body content
- `global_risk` (str | None) -- Global risk level (default: reads from DB)
- `internal_risk` (str | None) -- Internal risk level (default: reads from DB)

**Returns:** `str` -- Full HTML email string.

**Dependencies:** `SystemConfig`, `SessionLocal`, `re`

**Flow:** Fetches risk levels from DB if not provided. Determines overall risk as max of global and internal. Builds colored banners and converts markdown to HTML using regex substitutions. Wraps in styled email template.

---

### `generate_outlook_html_report(intel: dict) -> str`

**Purpose:** Generates a static fallback Outlook-safe HTML report.

**Parameters:**
- `intel` (dict) -- Intelligence data with unified_risk, physical_score, physical_brief, cyber_score, cyber_brief, timestamp

**Returns:** `str` -- HTML report string.

---

### `send_executive_report(recipient_email, intel, sys_config) -> tuple`

**Purpose:** Sends the executive threat intelligence report via email.

**Parameters:**
- `recipient_email` (str) -- Recipient email address
- `intel` (dict) -- Intelligence data
- `sys_config` (DotDict) -- System configuration

**Returns:** `tuple[bool, str]` -- `(success, message)`

**Dependencies:** `src.utils.mailer.send_alert_email`, `generate_outlook_html_report`

---

## 4. Daily Fusion Report

### `get_all_daily_briefings() -> list[DotDict]`

**Purpose:** Retrieves all daily briefings ordered by date descending.

**Dependencies:** `DailyBriefing`, `SessionLocal`

---

### `get_daily_briefing(target_date) -> DotDict | None`

**Purpose:** Retrieves a single daily briefing by date.

**Parameters:**
- `target_date` (date) -- Date to fetch

**Dependencies:** `DailyBriefing`, `SessionLocal`

---

### `save_daily_briefing(target_date, content)`

**Purpose:** Saves or updates a daily briefing.

**Parameters:**
- `target_date` (date) -- Briefing date
- `content` (str) -- Briefing markdown content

**Dependencies:** `DailyBriefing`, `SessionLocal`

---

### `generate_daily_report_email_html(report_date, markdown_content) -> str`

**Purpose:** Generates HTML email for the daily fusion report.

**Parameters:**
- `report_date` (str) -- Report date string
- `markdown_content` (str) -- Markdown content

**Returns:** `str` -- Formatted HTML email.

---

## 5. Threat Telemetry (CISA, Cloud, NWS, Regional Grid)

### `get_paginated_articles(feed_type, cat_filter, page, page_size, search_term=None, min_score=0) -> tuple`

**Purpose:** Retrieves paginated articles with filtering by feed type, category, and search.

**Parameters:**
- `feed_type` (str) -- "pinned", "live", "low", or other
- `cat_filter` (str) -- Category filter ("All" for no filter)
- `page` (int) -- Page number
- `page_size` (int) -- Items per page
- `search_term` (str | None) -- Search string for title/summary
- `min_score` (float) -- Minimum score threshold (default: 0)

**Returns:** `tuple[list[DotDict], int, int, int]` -- `(items, total_items, total_pages, current_page)`

**Dependencies:** `Article`, `SessionLocal`

---

### `get_cves(limit=15, days_back=None) -> list[DotDict]`

**Purpose:** Retrieves CVE items with optional time filter.

**Parameters:**
- `limit` (int) -- Max items (default: 15)
- `days_back` (int | None) -- Lookback days

**Dependencies:** `CveItem`, `SessionLocal`

---

### `get_cloud_outages(active_only=True, limit=None, days_back=None) -> list[DotDict]`

**Purpose:** Retrieves cloud service outages with optional filters.

**Parameters:**
- `active_only` (bool) -- Only unresolved outages (default: True)
- `limit` (int | None) -- Max items
- `days_back` (int | None) -- Lookback days

**Dependencies:** `CloudOutage`, `SessionLocal`

---

### `get_user_weather_prefs(username) -> list[str]`

**Purpose:** Retrieves a user's weather alert preferences.

**Parameters:**
- `username` (str) -- Username

**Returns:** `list[str]` -- Alert type strings.

**Dependencies:** `UserWeatherPreference`, `SessionLocal`

---

### `set_user_weather_prefs(username, alerts)`

**Purpose:** Sets a user's weather alert preferences (replaces all existing).

**Parameters:**
- `username` (str) -- Username
- `alerts` (list[str]) -- List of alert types

**Dependencies:** `UserWeatherPreference`, `SessionLocal`

---

### `get_active_wildfires() -> list[dict]`

**Purpose:** Fetches active wildfires from WFIGS ArcGIS REST API (7-day window, regional states).

**Returns:** `list[dict]` -- Wildfire records with name, state, acres, contained, lat, lon, color.

**Raises:** Returns empty list on any error (silently caught).

**Dependencies:** `requests`, `TTLCache(ttl=900, max_entries=1)`

**Flow:** Queries WFIGS API for wildfires in AR, MO, TN, MS, LA, TX, OK with `PercentContained < 100` or NULL, discovered in last 7 days. Filters out RX/prescribed fires and low-size/old fires.

---

### `dispatch_perimeter_crime_alerts() -> tuple`

**Purpose:** Checks for undispatch high-severity crimes within 0.4 miles and sends SMS alerts.

**Returns:** `tuple[bool, str]` -- `(success, message)`

**Dependencies:** `CrimeIncident`, `CRIME_ALERT_SMS`, `CRIME_ALERT_EMAIL`, `src.utils.mailer.send_alert_email`

**Flow:** Queries un-dispatched crimes with distance <= 0.4mi and High severity. For each, formats SMS body with Google Maps link, sends via mailer, marks as dispatched on success.

---

### `get_hazards(limit=15, hours_back=None) -> list[DotDict]`

**Purpose:** Retrieves recent regional hazards.

**Parameters:**
- `limit` (int) -- Max items (default: 15)
- `hours_back` (int | None) -- Lookback window

**Dependencies:** `RegionalHazard`, `SessionLocal`

---

### `process_nws_alerts(data, selected_events, is_oos=False) -> tuple`

**Purpose:** Processes NWS alert GeoJSON into categorized warning/watch geometries.

**Parameters:**
- `data` (dict) -- NWS GeoJSON Feed
- `selected_events` (list[str]) -- Selected event types to include
- `is_oos` (bool) -- Whether this is out-of-state data

**Returns:** `tuple[dict, dict, list, list]` -- `(warn_geo, watch_geo, zonewide_alerts, map_diagnostics)`

**Dependencies:** `get_regional_counties_mapping`, `shape` (shapely)

**Flow:** For zone-based alerts (no geometry), performs strict FIPS code matching using county boundaries. Separates warnings (red) from watches/advisories (orange). Detects PDS (Particularly Dangerous Situation) alerts.

---

### `get_weather_alerts_log(ar_data, oos_data, selected_events, usgs_ar_data=None, usgs_oos_data=None) -> list[dict]`

**Purpose:** Generates a comprehensive weather alerts log including NWS and USGS earthquake data.

**Parameters:**
- `ar_data` (dict) -- AR NWS GeoJSON
- `oos_data` (dict) -- OOS NWS GeoJSON
- `selected_events` (list[str]) -- Selected event types
- `usgs_ar_data` (dict | None) -- AR USGS earthquake data
- `usgs_oos_data` (dict | None) -- OOS USGS earthquake data

**Returns:** `list[dict]` -- Alert detail records with Event, Severity, Certainty, Headline, Effective, Expires, Description, Instructions.

**Dependencies:** `LOCAL_TZ`, `_get_eq_severity`

---

### `_get_eq_severity(mag: float) -> str`

**Purpose:** Maps earthquake magnitude to severity level.

**Parameters:**
- `mag` (float) -- Earthquake magnitude

**Returns:** `str` -- "Severe" (>=5.0), "High" (>=4.0), "Moderate" (>=3.0), or "Minor".

---

### `calculate_site_intersections(map_df, master_polygons) -> tuple`

**Purpose:** Efficiently calculates which monitored sites intersect with hazard polygons.

**Parameters:**
- `map_df` (pd.DataFrame) -- Site dataframe with Lat, Lon, Name, Type, District, Priority
- `master_polygons` (list) -- List of hazard polygons with shape, event, severity

**Returns:** `tuple[list, list]` -- `(toggled_affected_sites, master_affected_sites)`

**Dependencies:** `pandas`, `shapely.Point`, `shapely.shape`

**Flow:** Pre-calculates bounding boxes for all polygons. For each site, performs bounding box pre-check (fast float math) before expensive Shapely `within()` call. Builds toggled (visible) and master (all) affected site lists.

---

### `get_infrastructure_analytics(map_df, master_affected_sites) -> dict`

**Purpose:** Generates real-time infrastructure analytics from live geospatial intersection data.

**Parameters:**
- `map_df` (pd.DataFrame) -- Site dataframe
- `master_affected_sites` (list) -- Affected sites from intersection calculation

**Returns:** `dict` -- total_sites, at_risk_sites, highest_risk, spc_distribution, nws_distribution, type_distribution, district_distribution, priority/type/district risk matrices.

**Dependencies:** `pandas`

**Flow:** Processes affected sites into SPC risk levels and NWS alert types. Builds distribution DataFrames and cross-tab risk matrices by Priority, Type, and District. Maps risk levels back to all sites for complete distributions.

---

### `generate_hazard_sitrep_html(analytics_df) -> str`

**Purpose:** Generates HTML severe weather situation report for email broadcast.

**Parameters:**
- `analytics_df` (pd.DataFrame) -- Analytics dataframe with Monitored Site, Facility Type, Priority, Hazard

**Returns:** `str` -- Complete HTML email string.

---

### `import_locations(data: list[dict]) -> int`

**Purpose:** Bulk imports monitored locations from a list of dicts.

**Parameters:**
- `data` (list[dict]) -- Location records with name, lat, lon, type, district, priority

**Returns:** `int` -- Number of new locations added.

**Dependencies:** `MonitoredLocation`, `SessionLocal`

---

### `update_locations(edited_df)`

**Purpose:** Updates monitored locations from an edited dataframe.

**Parameters:**
- `edited_df` (pd.DataFrame) -- Dataframe with id, Name, Type, District, Priority, Lat, Lon

**Dependencies:** `MonitoredLocation`, `SessionLocal`

---

### `nuke_crime_data() -> tuple`

**Purpose:** Wipes all crime incident records.

**Returns:** `tuple[bool, int | str]` -- `(success, count_or_error)`

**Dependencies:** `CrimeIncident`, `SessionLocal`

---

## 6. Threat Hunting and IOCs

### `get_iocs(days_back=3) -> list[dict]`

**Purpose:** Retrieves extracted IOCs with their source articles.

**Parameters:**
- `days_back` (int) -- Lookback days (default: 3)

**Returns:** `list[dict]` -- IOC records with Type, Indicator, Context, Detected, Source Article link.

**Dependencies:** `ExtractedIOC`, `Article`, `SessionLocal`

---

### `search_articles_for_hunting(target: str, days_back: int) -> list[DotDict]`

**Purpose:** Searches articles for threat hunting by target string.

**Parameters:**
- `target` (str) -- Search string
- `days_back` (int) -- Lookback window in days

**Returns:** `list[DotDict]` -- Matching articles (max 30).

**Dependencies:** `Article`, `SessionLocal`

---

### `get_osint_pivot_link(ioc_type: str, value: str) -> str | None`

**Purpose:** Returns OSINT pivot link for a given IOC type and value.

**Parameters:**
- `ioc_type` (str) -- IOC type (SHA256, MD5, SHA1, IPv4, Domain, CVE, MITRE ATT&CK)
- `value` (str) -- IOC value

**Returns:** `str | None` -- URL to VirusTotal, Shodan, NVD, or MITRE ATT&CK.

---

## 7. AIOps RCA (Root Cause Analysis)

### `get_aiops_dashboard_data() -> tuple`

**Purpose:** Retrieves active alerts, recent timeline events, and active grid outages.

**Returns:** `tuple[list[DotDict], list[DotDict], list[DotDict]]` -- `(alerts, events, grid_outages)`

**Dependencies:** `SolarWindsAlert`, `TimelineEvent`, `RegionalOutage`, `SessionLocal`

---

### `clear_timeline_events()`

**Purpose:** Deletes all timeline events.

**Dependencies:** `TimelineEvent`, `SessionLocal`

---

### `nuke_active_alerts()`

**Purpose:** Deletes all SolarWinds alerts.

**Dependencies:** `SolarWindsAlert`, `SessionLocal`

---

### `resolve_alert(alert_id: int, node_name: str)`

**Purpose:** Manually resolves an alert and logs a timeline event.

**Parameters:**
- `alert_id` (int) -- Alert ID
- `node_name` (str) -- Node name for the timeline message

**Dependencies:** `SolarWindsAlert`, `TimelineEvent`, `SessionLocal`

---

### `acknowledge_cluster(alert_ids: list[int])`

**Purpose:** Marks a batch of alerts as correlated (acknowledged).

**Parameters:**
- `alert_ids` (list[int]) -- Alert IDs to acknowledge

**Dependencies:** `SolarWindsAlert`, `SessionLocal`

---

### `save_alias(alias_id: int, new_mapped_name: str)`

**Purpose:** Updates a node alias with verified mapping.

**Parameters:**
- `alias_id` (int) -- Alias record ID
- `new_mapped_name` (str) -- New mapped location name

**Dependencies:** `NodeAlias`, `SessionLocal`

---

### `generate_global_sitrep(sys_config_dict: dict) -> str`

**Purpose:** Generates a global situation report using the Enterprise AIOps Engine.

**Parameters:**
- `sys_config_dict` (dict) -- System configuration dict

**Returns:** `str` -- Markdown sitrep report.

**Dependencies:** `RegionalHazard`, `CloudOutage`, `BgpAnomaly`, `SolarWindsAlert`, `EnterpriseAIOpsEngine`, `src.utils.llm.call_llm`

**Flow:** Queries active alerts, clouds, weather, BGP anomalies. Feeds through `EnterpriseAIOpsEngine.analyze_and_cluster()` and `calculate_root_cause()`. Optionally generates AI executive summary via LLM.

---

### `generate_rca_ticket_text(site, data, priority, patient_zero, root_cause) -> str`

**Purpose:** Generates formatted ticket text for RCA dispatch.

**Parameters:**
- `site` (str) -- Site name
- `data` (dict) -- Incident cluster data
- `priority` (str) -- Priority string
- `patient_zero` (str) -- Patient zero identifier
- `root_cause` (str) -- Determined root cause

**Returns:** `str` -- Formatted ticket text.

---

## 8. Report Center

### `search_articles(query: str, limit: int) -> list[DotDict]`

**Purpose:** Searches articles by title or summary.

**Parameters:**
- `query` (str) -- Search query
- `limit` (int) -- Max results

**Returns:** `list[DotDict]`

**Dependencies:** `Article`, `SessionLocal`

---

### `get_saved_reports() -> list[DotDict]`

**Purpose:** Retrieves all saved reports ordered by creation date descending.

**Dependencies:** `SavedReport`, `SessionLocal`

---

### `save_custom_report(title, author, content)`

**Purpose:** Saves a custom report.

**Parameters:**
- `title` (str) -- Report title
- `author` (str) -- Author name
- `content` (str) -- Report content

**Dependencies:** `SavedReport`, `SessionLocal`

---

## 9. Settings and Administration

### `get_all_roles() -> list[DotDict]`

**Purpose:** Retrieves all roles, cached for 300 seconds.

**Returns:** `list[DotDict]`

**Dependencies:** `Role`, `SessionLocal`, `TTLCache(ttl=300)`

---

### `create_role(name, allowed_pages, allowed_actions, allowed_site_types=None) -> bool`

**Purpose:** Creates a new role.

**Parameters:**
- `name` (str) -- Role name
- `allowed_pages` (list) -- Allowed page names
- `allowed_actions` (list) -- Allowed action names
- `allowed_site_types` (list | None) -- Allowed site types (default: [])

**Returns:** `bool` -- True if created, False if already exists.

**Dependencies:** `Role`, `SessionLocal`

---

### `update_role(name, allowed_pages, allowed_actions, allowed_site_types=None) -> bool`

**Purpose:** Updates an existing role's permissions.

**Parameters:**
- `name` (str) -- Role name
- `allowed_pages` (list) -- Allowed page names
- `allowed_actions` (list) -- Allowed action names
- `allowed_site_types` (list | None) -- Allowed site types

**Returns:** `bool` -- True if updated, False if not found.

**Dependencies:** `Role`, `SessionLocal`

---

### `create_user(username, password, role, full_name="") -> bool`

**Purpose:** Creates a new user with hashed password.

**Parameters:**
- `username` (str) -- Username
- `password` (str) -- Plain text password
- `role` (str) -- Role name
- `full_name` (str) -- Full name (default: "")

**Returns:** `bool` -- True if created, False if already exists.

**Dependencies:** `User`, `SessionLocal`, `bcrypt`

---

### `force_reset_pwd(username, new_password) -> bool`

**Purpose:** Force-resets a user's password (admin operation).

**Parameters:**
- `username` (str) -- Username
- `new_password` (str) -- New plain text password

**Returns:** `bool` -- True if successful, False if user not found.

**Dependencies:** `User`, `SessionLocal`, `bcrypt`

---

### `update_user_role(username, new_role)`

**Purpose:** Updates a user's role and invalidates their session.

**Parameters:**
- `username` (str) -- Username
- `new_role` (str) -- New role name

**Dependencies:** `User`, `SessionLocal`

---

### `save_global_config(data: dict)`

**Purpose:** Saves global system configuration key-value pairs.

**Parameters:**
- `data` (dict) -- Configuration key-value pairs

**Dependencies:** `SystemConfig`, `SessionLocal`

---

### `get_latest_internal_risk() -> dict | None`

**Purpose:** Retrieves the latest internal risk snapshot.

**Returns:** `dict | None` -- Snapshot with id, timestamp, score, risk_level, total_assets, hw_data, sw_data.

**Dependencies:** `InternalRiskSnapshot`, `SessionLocal`, `json`

---

### `get_internal_risk_history(days: int = 28) -> list[dict]`

**Purpose:** Retrieves internal risk score history for trend analysis.

**Parameters:**
- `days` (int) -- Lookback period (default: 28)

**Returns:** `list[dict]` -- Records with timestamp, score, risk_level.

**Dependencies:** `InternalRiskSnapshot`, `SessionLocal`

---

### `trigger_unified_brief() -> dict`

**Purpose:** Force-generates the unified risk brief (same logic as scheduler job).

**Returns:** `dict` -- `{"status": "ok", "brief": str}` or `{"status": "error", "message": str}`.

**Dependencies:** `src.utils.llm.generate_unified_risk_brief`, `InternalRiskSnapshot`, `RegionalHazard`, `SessionLocal`

---

### `trigger_rolling_summary() -> dict`

**Purpose:** Force-generates and saves the rolling shift handover summary.

**Returns:** `dict` -- `{"status": "ok", "summary": str}` or `{"status": "error", "message": str}`.

**Dependencies:** `src.utils.llm.generate_rolling_summary`, `SessionLocal`

---

### `trigger_scoring_rationale(intel_data: dict) -> dict`

**Purpose:** Force-generates a dynamic scoring report from provided intel.

**Parameters:**
- `intel_data` (dict) -- Intelligence data for scoring

**Returns:** `dict` -- `{"status": "ok", "report": str}` or `{"status": "error", "message": str}`.

**Dependencies:** `src.utils.llm.generate_dynamic_scoring_report`, `SessionLocal`

---

### `trigger_shift_summary(role_filter="All", shift_period="Morning", timeframe_label="Morning Shift", auto_append=False) -> dict`

**Purpose:** Generates an aggregated shift summary from log entries.

**Parameters:**
- `role_filter` (str) -- Role filter (default: "All")
- `shift_period` (str) -- Shift period (default: "Morning")
- `timeframe_label` (str) -- Label for the timeframe (default: "Morning Shift")
- `auto_append` (bool) -- Whether to auto-append as shift log entry (default: False)

**Returns:** `dict` -- `{"status": "ok", "summary": str}` or `{"status": "error", "message": str}`.

**Dependencies:** `src.utils.llm.generate_aggregated_shift_summary`, `ShiftLogEntry`, `SessionLocal`

---

### `add_bulk_keywords(raw_text: str)`

**Purpose:** Bulk imports keywords from comma-separated text (one per line).

**Parameters:**
- `raw_text` (str) -- Newline-separated "word,weight" lines

**Dependencies:** `Keyword`, `SessionLocal`

---

### `add_bulk_feeds(raw_text: str)`

**Purpose:** Bulk imports RSS feed sources from comma-separated text.

**Parameters:**
- `raw_text` (str) -- Newline-separated "url,name" lines

**Dependencies:** `FeedSource`, `SessionLocal`

---

### `delete_record(model_name: str, record_id: int)`

**Purpose:** Deletes a record by model name and ID.

**Parameters:**
- `model_name` (str) -- One of "Keyword", "FeedSource", "User", "Role", "SavedReport"
- `record_id` (int) -- Record ID to delete

**Dependencies:** `Keyword`, `FeedSource`, `User`, `Role`, `SavedReport`, `SessionLocal`

---

### `get_admin_lists() -> tuple`

**Purpose:** Retrieves keywords, feeds, and users for admin lists.

**Returns:** `tuple[list[DotDict], list[DotDict], list[DotDict]]` -- `(keywords, feeds, users)`

**Dependencies:** `Keyword`, `FeedSource`, `User`, `SessionLocal`

---

### `get_ml_counts() -> tuple`

**Purpose:** Returns counts of positively and negatively reviewed articles.

**Returns:** `tuple[int, int, int]` -- `(positive_count, negative_count, total_count)`

**Dependencies:** `Article`, `SessionLocal`

---

### `get_backup_data() -> dict`

**Purpose:** Exports all configuration data for backup.

**Returns:** `dict` -- keywords, feeds, locations, aliases arrays.

**Dependencies:** `Keyword`, `FeedSource`, `MonitoredLocation`, `NodeAlias`, `SessionLocal`

---

### `restore_backup_data(data: dict) -> dict`

**Purpose:** Imports configuration data from a backup.

**Parameters:**
- `data` (dict) -- Backup data with keywords, feeds, locations, aliases

**Returns:** `dict` -- Counts of new records added per type.

**Dependencies:** `Keyword`, `FeedSource`, `MonitoredLocation`, `NodeAlias`, `SessionLocal`

---

### `recategorize_all_articles() -> int`

**Purpose:** Re-runs category classification on all articles.

**Returns:** `int` -- Number of articles whose category changed.

**Dependencies:** `Article`, `SessionLocal`, `src.services.categorizer.categorize_text`

---

### `rescore_all_articles() -> int`

**Purpose:** Re-scores all articles using current keywords, categorizer, and IOC extractor.

**Returns:** `int` -- Number of articles rescored.

**Dependencies:** `Article`, `ExtractedIOC`, `HybridScorer`, `categorize_text`, `ioc_engine`, `SessionLocal`

**Flow:** For each article, computes score + reasons via HybridScorer, updates category via categorizer, extracts IOCs for high-scoring cyber articles, saves all changes.

---

### `nuke_tables(model_names: list[str])`

**Purpose:** Wipes all records from specified tables.

**Parameters:**
- `model_names` (list[str]) -- Model names to clear (CloudOutage, MonitoredLocation, Article, ExtractedIOC, FeedSource, Keyword)

**Dependencies:** Model classes referenced in models_map, `SessionLocal`

---

### `truncate_db_table(table_query: str)`

**Purpose:** Truncates a specific database table based on name pattern.

**Parameters:**
- `table_query` (str) -- Table name to truncate (supports "monitored_locations")

---

### `nuke_weather_data() -> tuple`

**Purpose:** Wipes all weather-related data (hazards, GeoJSON cache, resets SPC risks).

**Returns:** `tuple[bool, int | str]` -- `(success, count_or_error)`

**Dependencies:** `RegionalHazard`, `GeoJsonCache`, `MonitoredLocation`, `SessionLocal`

---

## 10. UI Map Generation Engine (PyDeck)

### `build_crime_map_layers(df_crimes) -> tuple`

**Purpose:** Builds PyDeck layers and view state for the crime intelligence map.

**Parameters:**
- `df_crimes` (pd.DataFrame) -- Crime data with lon, lat columns

**Returns:** `tuple[list[pdk.Layer], pdk.ViewState]` -- Layers (campus boundary polygon + crime scatterplot) and view state.

**Dependencies:** `pydeck`, `pandas`

---

### `build_aiops_map_layers(alerts, locs) -> tuple`

**Purpose:** Builds PyDeck layers and view state for the AIOps RCA board.

**Parameters:**
- `alerts` (list) -- Active alerts with mapped_location
- `locs` (list) -- Monitored locations with name, lat, lon

**Returns:** `tuple[list[pdk.Layer], pdk.ViewState]` -- Layers (site scatterplot + alert pulses) and view state.

**Dependencies:** `pydeck`, `pandas`, `collections.Counter`

---

### `_precompute_geo_matrix(spc_data, ar_data, oos_data, usgs_ar_data, usgs_oos_data, selected_events_tuple, map_df) -> dict`

**Purpose:** Heavy math engine: parses JSON, builds Shapely objects, calculates all intersections once.

**Parameters:**
- `spc_data` (dict) -- SPC storm prediction GeoJSON
- `ar_data` (dict) -- Arkansas NWS alert GeoJSON
- `oos_data` (dict) -- Out-of-state NWS alert GeoJSON
- `usgs_ar_data` (dict | None) -- Arkansas USGS earthquake data
- `usgs_oos_data` (dict | None) -- Out-of-state USGS earthquake data
- `selected_events_tuple` (tuple) -- Selected event types
- `map_df` (pd.DataFrame) -- Site dataframe

**Returns:** `dict` -- spc_micro, ar_warn, ar_watch, oos_warn, oos_watch, ar_fire_geo, nifc_data, eq_data, master_affected_sites, map_diagnostics.

**Dependencies:** `shapely`, `pandas`, `process_nws_alerts`, `get_regional_counties_mapping`, `get_active_wildfires`, `calculate_site_intersections`, `TTLCache(ttl=120)`

**Flow:**
1. Processes SPC data with color mapping
2. Processes NWS warnings/watches via `process_nws_alerts`
3. Processes fire weather risk using county FIPS matching
4. Processes active wildfires from WFIGS
5. Processes USGS earthquakes
6. Executes `calculate_site_intersections` once for all master polygons

---

### `compile_regional_grid_map(map_df, spc_data, ar_data, oos_data, usgs_ar_data, usgs_oos_data, selected_events, toggles) -> tuple`

**Purpose:** Lightweight UI compiler that reads from RAM cache and filters by toggle states.

**Parameters:**
- `map_df` (pd.DataFrame) -- Site dataframe
- `spc_data` (dict) -- SPC GeoJSON
- `ar_data` (dict) -- AR NWS GeoJSON
- `oos_data` (dict) -- OOS NWS GeoJSON
- `usgs_ar_data` (dict | None) -- AR USGS data
- `usgs_oos_data` (dict | None) -- OOS USGS data
- `selected_events` (list) -- Selected event types
- `toggles` (dict) -- Layer toggle states (radar, spc, warn, watch, oos, fire_risk, active_wildfires, earthquakes)

**Returns:** `tuple[list[pdk.Layer], pdk.ViewState, list, list, list]` -- `(layers, view_state, diagnostics, toggled_affected_sites, master_affected_sites)`

**Dependencies:** `pydeck`, `pandas`, `_precompute_geo_matrix`

**Flow:** Calls `_precompute_geo_matrix` (reads from RAM cache). Builds PyDeck GeoJsonLayer/ScatterplotLayer/BitmapLayer for each visible toggle. Filters affected sites by toggled hazard visibility.

---

### `deduplicate_articles(session) -> int`

**Purpose:** De-duplicates articles by exact link and similar titles within the past 24 hours.

**Parameters:**
- `session` -- SQLAlchemy session

**Returns:** `int` -- Number of duplicates removed.

**Dependencies:** `Article`, `difflib.SequenceMatcher`

**Flow:**
1. Removes exact link duplicates
2. Within same source, removes articles with title similarity ratio > 85%
