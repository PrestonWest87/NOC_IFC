# Module: `src/app.py`

## Overview

Streamlit application entrypoint for the NOC Intelligence Fusion Center. Configures page layout, session state, authentication, theme rendering, navigation, and user profile management. Routes authenticated users to the appropriate page component based on role-based access control.

---

## Function: `setup_database()`

**Purpose:** Initializes the database schema and caches the result to avoid redundant initialization on every Streamlit re-run.

**Parameters:** None

**Returns:**
| Type | Description |
|------|-------------|
| `bool` | Always returns `True` after successful initialization. |

**Raises:** None

**Flow:**
1. Decorated with `@st.cache_resource` so it runs only once per session.
2. Calls `init_db()` from `src.database` to create all tables and seed default data.
3. Returns `True` to signal completion.

**Dependencies:** `src.database.init_db`

---

## Function: `force_db_migration()`

**Purpose:** Forces database schema initialization and clears the Streamlit data cache. Used to ensure schema changes take effect.

**Parameters:** None

**Returns:** None (implicitly `None`)

**Raises:** None

**Flow:**
1. Decorated with `@st.cache_resource` so it runs only once per session.
2. Calls `init_db()` to ensure tables exist.
3. Calls `st.cache_data.clear()` to purge any cached query results.
4. Executed unconditionally at module load.

**Dependencies:** `src.database.init_db`, `streamlit.cache_data.clear`

---

## Module-Level Execution Flow (Imperative Script)

**Purpose:** The module body executes sequentially to bootstrap the application on every page load or widget interaction.

**Flow:**
1. `set_page_config()`: Configures Streamlit page with title "Intelligence Fusion Center" and wide layout.
2. `setup_database()`: Initializes database schema.
3. `force_db_migration()`: Clears cache after schema init.
4. `init_session_state()`: Initializes default session state variables (`current_user`, `current_role`, `allowed_pages`, `allowed_actions`).
5. `authenticate_with_token()`: Attempts cookie-based authentication using `noc_session_token`.
6. If `current_user` is `None`, renders login form via `render_login_form()`.
7. `ensure_admin_permissions()`: Refreshes admin permissions if role is `admin`.
8. `get_permission_flags()`: Builds permission dictionary.
9. Fetches `current_user_obj` and `sys_config` from the service layer.
10. **Easter Egg - Nick Troll**: If `black_ops["nick_enabled"]` is `True` and user is `nwilson`, 15% chance of showing a full-screen "YOU SUCK" overlay for 10 seconds using `st_autorefresh`.
11. `trigger_browser_notifications()`: Checks for new NWS alerts and renders browser notification JavaScript.
12. `get_theme_css()`: Loads and applies the user's selected UI theme via inline CSS.
13. Renders sidebar with user info (name, title), logout button, and profile expander (theme selector, name/job title/contact info/shift/password change).
14. Builds navigation radio from `allowed_pages` session state.
15. Routes to the appropriate page renderer based on `active_page`:
    - "Global Dashboards" -> `render_global_dashboards()`
    - "Threat Telemetry" -> `render_threat_telemetry()`
    - "Regional Grid" -> `render_regional_grid()`
    - "Threat Hunting & IOCs" -> `render_threat_hunting()`
    - "AIOps RCA" -> `render_aiops_rca()`
    - "Shift Logbook" -> `render_shift_logbook()`
    - "Reporting & Briefings" -> `render_reporting()`
    - "Settings & Admin" -> `render_settings_admin()`

**Dependencies:**
- `streamlit` (core UI framework)
- `src.services` (data access layer)
- `src.database.init_db` (schema initialization)
- `src.ui.state_manager` (session state, auth, theme, permissions)
- `src.ui.components.notifications` (browser push notifications)
- All page renderer modules
- `CookieController` (from `streamlit_cookies_controller`)
- `st_autorefresh` (from `streamlit_autorefresh`, optional)
