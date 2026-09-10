# Module: `src/ui/state_manager.py`

## Overview

Streamlit session state management, authentication, theming, and shared UI component rendering for the NOC Intelligence Fusion Center. Provides cookie-based persistent authentication, role-based permission resolution, theme CSS generation, article feed rendering with interactive controls, and utility functions for cooldowns, time formatting, and scoring badges.

---

## Constants

| Constant | Type | Description |
|----------|------|-------------|
| `LOCAL_TZ` | `ZoneInfo` | Timezone for `America/Chicago`. |
| `cookie_controller` | `CookieController` | Streamlit cookie controller for persistent state. |
| `ALL_POSSIBLE_PAGES` | `list[str]` | All 8 navigation page names. |
| `ALL_POSSIBLE_ACTIONS` | `list[str]` | All 37 permission action strings (tabs and actions). |

---

## Function: `safe_rerun()`

**Purpose:** Triggers a Streamlit app rerun.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**
1. Calls `st.rerun()`.

**Dependencies:** `streamlit`

---

## Function: `check_cooldown(key, cooldown_seconds=60)`

**Purpose:** Checks if a cooldown period is still active for a given action key.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `str` | Unique cooldown identifier. |
| `cooldown_seconds` | `int` | Cooldown duration in seconds, default `60`. |

**Returns:**
| Type | Description |
|------|-------------|
| `bool` | `True` if still within cooldown period, `False` otherwise. |

**Raises:** None

**Flow:**
1. Reads `st.session_state[f"cooldown_{key}"]` (default 0).
2. Returns `(time.time() - last_click) < cooldown_seconds`.

**Dependencies:** `streamlit`, `time`

---

## Function: `apply_cooldown(key)`

**Purpose:** Sets the current timestamp as the cooldown start for a given action key.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `key` | `str` | Unique cooldown identifier. |

**Returns:** None

**Raises:** None

**Flow:**
1. Sets `st.session_state[f"cooldown_{key}"] = time.time()`.

**Dependencies:** `streamlit`, `time`

---

## Function: `format_local_time(utc_dt)`

**Purpose:** Converts a UTC datetime to the local timezone and formats it as a string.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `utc_dt` | `datetime \| None` | UTC datetime object. |

**Returns:**
| Type | Description |
|------|-------------|
| `str` | Formatted string `"YYYY-MM-DD HH:MM:SS"` in local timezone, or `"Unknown"` if input is None. |

**Raises:** None

**Flow:**
1. If `utc_dt` is None, returns `"Unknown"`.
2. Replaces timezone with UTC, converts to `LOCAL_TZ`, formats as `'%Y-%m-%d %H:%M:%S'`.

**Dependencies:** `datetime`, `zoneinfo`

---

## Function: `get_score_badge(score)`

**Purpose:** Generates a formatted score badge string with color-based styling.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `score` | `float` | Article relevance score (0-100). |

**Returns:**
| Type | Description |
|------|-------------|
| `str` | HTML-like badge string with score (e.g., `"[85]"`). |

**Raises:** None

**Flow:**
1. Returns `"[score]"` for all score ranges (visual distinction comes from CSS, not the string itself).

**Dependencies:** None

---

## Function: `get_cat_icon(cat)`

**Purpose:** Returns a category icon string for a given article category.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `cat` | `str` | Article category name. |

**Returns:**
| Type | Description |
|------|-------------|
| `str` | Icon string (empty strings currently, placeholder for emoji icons). |

**Raises:** None

**Flow:**
1. Looks up `cat` in the `icons` dictionary, returns the mapped icon or `""`.

**Dependencies:** None

---

## Function: `init_session_state()`

**Purpose:** Initializes the Streamlit session state with default authentication and permission values.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**
1. Checks if `"current_user"` is not in session state.
2. If missing, sets: `current_user = None`, `current_role = None`, `allowed_pages = []`, `allowed_actions = []`.

**Dependencies:** `streamlit`

---

## Function: `authenticate_with_token()`

**Purpose:** Attempts to authenticate the user by reading a saved session token cookie.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**
1. Reads `noc_session_token` from cookies.
2. If token exists, calls `svc.get_user_by_token(token)`.
3. If user found, populates session state:
   - `current_user`, `current_role`.
   - For admin role: grants all pages and all actions, sets `allowed_site_types = "ALL"`.
   - For non-admin: queries role object and sets allowed pages, actions, and site types from the role definition.

**Dependencies:** `cookie_controller`, `src.services.get_user_by_token`, `src.services.get_all_roles`

---

## Function: `render_login_form()`

**Purpose:** Renders the Streamlit login form with username/password fields and authentication logic.

**Parameters:** None

**Returns:** None

**Raises:** None (exceptions caught and displayed)

**Flow:**
1. Centers a login panel using three columns.
2. Displays app title and "Authentication Required" header.
3. Renders a form with username, password, and "Authenticate" button.
4. On submit:
   - Calls `svc.authenticate_user(username, password)`.
   - On success: sets session cookie (`noc_session_token`, 30-day expiry), populates session state (same logic as `authenticate_with_token` for roles), calls `st.rerun()`.
   - On failure: displays error message.
5. Calls `st.stop()` to prevent rendering the main app.

**Dependencies:** `streamlit`, `cookie_controller`, `src.services.authenticate_user`, `src.services.get_all_roles`

---

## Function: `ensure_admin_permissions()`

**Purpose:** Ensures admin users always have full page and action permissions.

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**
1. If `current_role == "admin"`, sets `allowed_pages` to all pages, `allowed_actions` to all actions, `allowed_site_types` to `"ALL"`.

**Dependencies:** `streamlit`

---

## Function: `get_permission_flags()`

**Purpose:** Builds a dictionary of boolean permission flags from the session state allowed actions list.

**Parameters:** None

**Returns:**
| Type | Description |
|------|-------------|
| `dict[str, bool]` | Dict with keys: `can_pin`, `can_train`, `can_boost`, `can_trigger_ai`, `can_sync`, base `can_dispatch_report`, `can_dispatch_rca`, `can_manage_maint`, `can_submit_log`. |

**Raises:** None

**Flow:**
1. Checks membership of each action string in `st.session_state.allowed_actions`.
2. Returns a dictionary mapping permission names to booleans.

**Dependencies:** `streamlit`

---

## Function: `get_theme_css()`

**Purpose:** Generates CSS styling for the selected UI theme and returns theme options and cookie key.

**Parameters:** None

**Returns:**
| Type | Description |
|------|-------------|
| `tuple[str, list[str], str]` | Tuple of `(css_string, theme_options_list, theme_cookie_key)`. |

**Raises:** None

**Flow:**
1. Defines 6 theme options: Standard, NOC Terminal, High Contrast (Dark), Cyberpunk, Solarized Dark, Midnight Ocean.
2. Builds cookie key as `noc_theme_{username}` or `noc_theme_guest`.
3. Reads saved theme from cookie, defaults to "Standard".
4. Constructs base CSS with padding/typography defaults, plus theme-specific CSS from a dictionary of six themes with color/font overrides.
5. Returns the complete CSS string, theme options list, and cookie key.

**Dependencies:** `cookie_controller`, `streamlit`

---

## Function: `render_article_feed(feed_articles, key_prefix="")`

**Purpose:** Renders an interactive article feed with scoring badges, AI BLUF summaries, and action buttons (Pin, Boost Score, Keep/Dismiss for ML training, AI BLUF generation).

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `feed_articles` | `list[Article]` | List of Article ORM objects to render. |
| `key_prefix` | `str` | Prefix for Streamlit widget keys to avoid collisions. |

**Returns:** None

**Raises:** None

**Flow:**
1. If no articles, shows "Queue is empty."
2. For each article:
   - Renders a bordered container with title (link), score badge, timestamp, source, category.
   - If `ai_bluf` exists, displays it in a success box.
   - Shows summary text (truncated to 500 chars).
   - Displays 5 action columns:
     - "Pin/Unpin": Toggles article pin status (requires `can_pin` permission).
     - "+15 Score": Boosts article score by 15 (requires `can_boost`).
     - "Keep": Marks article as important for ML training (requires `can_train`).
     - "Dismiss": Marks article as noise for ML training (requires `can_train`).
     - "BLUF" or "Generating...": Calls LLM to generate Bottom Line Up Front summary (requires `can_trigger_ai`, has 30s cooldown).

**Dependencies:** `src.utils.llm.generate_bluf`, `src.services`, `get_permission_flags`, `check_cooldown`, `apply_cooldown`, `format_local_time`, `get_score_badge`, `get_cat_icon`

---

## Function: `get_black_ops_state()`

**Purpose:** Returns a cached dictionary of black ops (undocumented) feature states.

**Parameters:** None

**Returns:**
| Type | Description |
|------|-------------|
| `dict` | Dict with keys: `nick_enabled` (bool), `dean_target` (str or None), `dean_start` (int). |

**Raises:** None

**Flow:**
1. Decorated with `@st.cache_resource` so the state persists across reruns.
2. Returns `{"nick_enabled": False, "dean_target": None, "dean_start": 0}`.

**Dependencies:** `streamlit.cache_resource`
