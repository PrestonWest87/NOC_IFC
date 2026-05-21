import streamlit as st
import time

st.set_page_config(page_title="Intelligence Fusion Center", layout="wide")

import src.services as svc
from src.database import init_db
from src.ui.state_manager import (
    safe_rerun, init_session_state, authenticate_with_token,
    render_login_form, ensure_admin_permissions, get_permission_flags,
    get_theme_css, get_black_ops_state, cookie_controller
)
from src.ui.components.notifications import trigger_browser_notifications
from src.ui.pages.global_dashboards import render_global_dashboards
from src.ui.pages.threat_telemetry import render_threat_telemetry
from src.ui.pages.regional_grid import render_regional_grid
from src.ui.pages.threat_hunting import render_threat_hunting
from src.ui.pages.aiops_rca import render_aiops_rca
from src.ui.pages.shift_logbook import render_shift_logbook
from src.ui.pages.reporting import render_reporting
from src.ui.pages.settings_admin import render_settings_admin
@st.cache_resource
def setup_database():
    init_db()
    return True

setup_database()

black_ops = get_black_ops_state()

@st.cache_resource
def force_db_migration():
    init_db()
    st.cache_data.clear()

force_db_migration()

init_session_state()
authenticate_with_token()

if st.session_state.current_user is None:
    render_login_form()

ensure_admin_permissions()
perms = get_permission_flags()

current_user_obj = svc.get_user_by_username(st.session_state.current_user)

sys_config = svc.get_cached_config()
ai_enabled = sys_config.is_active if sys_config else False

if black_ops["nick_enabled"] and st.session_state.current_user == "nwilson":
    import random
    if "nick_troll_end" not in st.session_state:
        if random.random() < 0.15:
            st.session_state.nick_troll_end = time.time() + 10
    if "nick_troll_end" in st.session_state:
        if time.time() < st.session_state.nick_troll_end:
            st.markdown("""
                <div style='position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background-color: black; z-index: 999999; display: flex; justify-content: center; align-items: center;'>
                    <h1 style='color: red; font-size: 15vw; font-family: Impact, sans-serif; text-transform: uppercase;'>YOU SUCK</h1>
                </div>
            """, unsafe_allow_html=True)
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=10000, limit=2, key="troll_refresh")
            st.stop()
        else:
            del st.session_state.nick_troll_end

if st.session_state.current_user:
    trigger_browser_notifications()

custom_css, theme_options, theme_cookie_key = get_theme_css()
st.markdown(custom_css, unsafe_allow_html=True)

st.sidebar.title("NOC Fusion")
display_name = current_user_obj.full_name if current_user_obj and current_user_obj.full_name else st.session_state.current_user.capitalize()
display_title = current_user_obj.job_title if current_user_obj and current_user_obj.job_title else st.session_state.current_role.upper()
st.sidebar.markdown(f" **{display_name}**\n\n<small>{display_title}</small>", unsafe_allow_html=True)

if st.sidebar.button("Log Out", width="stretch"):
    svc.logout_user(st.session_state.current_user)
    cookie_controller.remove("noc_session_token")
    st.session_state.current_user = None; st.session_state.current_role = None
    time.sleep(0.5); safe_rerun()

with st.sidebar.expander("My Profile"):
    selected_theme = st.selectbox("UI Theme", theme_options, index=theme_options.index(st.session_state.ui_theme))
    if selected_theme != st.session_state.ui_theme:
        st.session_state.ui_theme = selected_theme
        cookie_controller.set(theme_cookie_key, selected_theme, max_age=30*86400)
        time.sleep(0.1)
        safe_rerun()
    st.divider()
    with st.form("my_profile_form"):
        new_fn = st.text_input("Full Name", value=current_user_obj.full_name or "")
        new_jt = st.text_input("Job Title", value=current_user_obj.job_title or "")
        new_ci = st.text_input("Contact Info", value=current_user_obj.contact_info or "")
        shift_options = ["Morning", "Afternoon", "Night", "No Shift"]
        current_shift = getattr(current_user_obj, 'default_shift', "No Shift")
        if current_shift not in shift_options: current_shift = "No Shift"
        new_shift = st.selectbox("Default Shift", shift_options, index=shift_options.index(current_shift))
        st.divider()
        old_pwd = st.text_input("Current Password", type="password")
        new_pwd = st.text_input("New Password", type="password")
        if st.form_submit_button("Save Profile", width="stretch"):
            success, msg = svc.update_user_profile(st.session_state.current_user, new_fn, new_jt, new_ci, old_pwd, new_pwd)
            if success:
                with svc.SessionLocal() as db:
                    from src.database import User
                    u = db.query(User).filter_by(username=st.session_state.current_user).first()
                    if u:
                        u.default_shift = new_shift
                        db.commit()
                st.success(msg); time.sleep(0.5); safe_rerun()
            else: st.error(msg)

st.sidebar.divider()
PAGES = st.session_state.allowed_pages
if not PAGES: st.error("No assigned permissions. Please contact an administrator."); st.stop()
if "active_page" not in st.session_state or st.session_state.active_page not in PAGES: st.session_state.active_page = PAGES[0]

selected_page = st.sidebar.radio("Navigation", PAGES, index=PAGES.index(st.session_state.active_page), key="nav_radio")
if selected_page != st.session_state.active_page: st.session_state.active_page = selected_page; safe_rerun()
page = st.session_state.active_page

st.sidebar.divider()

# ================= 1. GLOBAL DASHBOARDS =================
if page == "Global Dashboards":
    render_global_dashboards()

# ================= 2. THREAT TELEMETRY =================
elif page == "Threat Telemetry":
    render_threat_telemetry()

elif page == "Regional Grid":
    render_regional_grid()

# ================= 3. THREAT HUNTING & IOCS =================
elif page == "Threat Hunting & IOCs":
    render_threat_hunting()

# ================= 4. AIOps RCA =================
elif page == "AIOps RCA":
    render_aiops_rca()

# ================= 5. SHIFT LOGBOOK =================
elif page == "Shift Logbook":
    render_shift_logbook()

# ================= 6. REPORTING & BRIEFINGS =================
elif page == "Reporting & Briefings":
    render_reporting()

# ================= 7. SETTINGS & ADMIN =================
elif page == "Settings & Admin":
    render_settings_admin()
