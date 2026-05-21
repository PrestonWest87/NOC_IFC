import streamlit as st
import pandas as pd
import json
import time
from datetime import datetime

import src.services as svc
from src.ui.state_manager import (
    safe_rerun, check_cooldown, apply_cooldown,
    get_permission_flags, get_black_ops_state,
    ALL_POSSIBLE_PAGES, ALL_POSSIBLE_ACTIONS, LOCAL_TZ
)


def render_settings_admin():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    black_ops = get_black_ops_state()
    current_user_obj = svc.get_user_by_username(st.session_state.current_user)

    st.title("Settings & Engine Room")

    set_tab_names = []

    if "Tab: Settings -> Facility Locations" in st.session_state.allowed_actions:
        set_tab_names.append("Facilities")
    if "Tab: Settings -> Internal Assets" in st.session_state.allowed_actions:
        set_tab_names.append("Internal Assets")
    if "Tab: Settings -> RSS Sources" in st.session_state.allowed_actions:
        set_tab_names.append("RSS Sources")
    if "Tab: Settings -> ML Training" in st.session_state.allowed_actions:
        set_tab_names.append("ML Training")
    if "Tab: Settings -> AI & SMTP" in st.session_state.allowed_actions:
        set_tab_names.append("AI & SMTP")
    if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions:
        set_tab_names.append("Users & Roles")
    if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions:
        set_tab_names.append("Backup & Restore")
    if "Tab: Settings -> Danger Zone" in st.session_state.allowed_actions:
        set_tab_names.append("Danger Zone")

    if not set_tab_names:
        st.warning("No permission to view tabs in this module.")
    else:
        set_tabs = st.tabs(set_tab_names)
        set_idx = 0

        if "Tab: Settings -> Facility Locations" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Facility Database Management")
                c_up, c_ed = st.columns([1, 2])
                with c_up:
                    st.markdown("**Mass Import (JSON)**")
                    st.caption("Requires 'name', 'lat', 'lon'. Optional: 'type', 'priority'.")
                    uploaded_file = st.file_uploader("Upload Sites", type=["json"], key="loc_uploader")
                    if uploaded_file is not None:
                        if st.button("Import Data", width="stretch"):
                            try:
                                data = json.load(uploaded_file)
                                added = svc.import_locations(data)
                                st.success(f"Imported {added} new locations!")
                                time.sleep(1.5)
                                safe_rerun()
                            except Exception as e:
                                st.error(f"Import failed: {e}")

                with c_ed:
                    st.markdown("**Manual Adjustments**")
                    locs = svc.get_cached_locations()
                    df_locs = pd.DataFrame([{
                        "id": l.id,
                        "Name": l.name,
                        "Type": l.loc_type,
                        "District": l.district,
                        "Priority": l.priority,
                        "Lat": l.lat,
                        "Lon": l.lon
                    } for l in locs]) if locs else pd.DataFrame()
                    if not df_locs.empty:
                        edited_df = st.data_editor(df_locs, hide_index=True, disabled=["id"], width="stretch", key="loc_editor")
                        if st.button("Save Manual Adjustments", width="stretch"):
                            svc.update_locations(edited_df)
                            st.success("Changes saved!")
                            time.sleep(1)
                            safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Internal Assets" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Internal Asset CSV Ingestion")
                col_sw, col_hw = st.columns(2)

                with col_sw:
                    st.markdown("**Software Assets**")
                    sw_csv = st.file_uploader("Upload Software CSV (Must contain 'name' column)", type=["csv"], key="sw_upload")
                    if sw_csv and st.button("Sync Software Inventory", width="stretch"):
                        try:
                            df = pd.read_csv(sw_csv)
                            if 'name' not in df.columns.str.lower():
                                st.error("CSV must contain a 'name' column.")
                            else:
                                df.columns = df.columns.str.lower()
                                with svc.SessionLocal() as session:
                                    from src.database import SoftwareAsset
                                    session.query(SoftwareAsset).delete()
                                    for _, row in df.iterrows():
                                        session.add(SoftwareAsset(name=str(row['name'])))
                                    session.commit()
                                st.success(f"Imported {len(df)} software assets!")
                                time.sleep(1)
                                safe_rerun()
                        except Exception as e:
                            st.error(f"Error parsing CSV: {e}")

                with col_hw:
                    st.markdown("**Hardware Assets**")
                    hw_csv = st.file_uploader("Upload Hardware CSV", type=["csv"], key="hw_upload")
                    if hw_csv and st.button("Sync Hardware Inventory", width="stretch"):
                        import numpy as np
                        try:
                            df = pd.read_csv(hw_csv)
                            df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
                            col_mapping = {
                                'operating_system_architecture': 'os_architecture',
                                'operating_system_family': 'os_family',
                                'operating_system_product': 'os_product',
                                'operating_system_vendor': 'os_vendor',
                                'operating_system_version': 'os_version'
                            }
                            df.rename(columns=col_mapping, inplace=True)

                            if 'ip_address' not in df.columns:
                                st.error("CSV must contain an 'IP Address' column.")
                            else:
                                numeric_cols = ['instances', 'critical_instances', 'severe_instances', 'moderate_instances', 'vulnerabilities', 'critical_vulnerabilities', 'severe_vulnerabilities', 'moderate_vulnerabilities', 'exploit_count', 'malware_count', 'raw_risk_score', 'risk_score']
                                for col in numeric_cols:
                                    if col in df.columns:
                                        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

                                df.replace(r'^\s*$', np.nan, regex=True, inplace=True)
                                df.replace({np.nan: None}, inplace=True)

                                from src.database import HardwareAsset
                                valid_columns = {c.name for c in HardwareAsset.__table__.columns}

                                with svc.SessionLocal() as session:
                                    session.query(HardwareAsset).delete()
                                    for _, row in df.iterrows():
                                        row_dict = {k: v for k, v in row.to_dict().items() if k in valid_columns}
                                        if row_dict.get('ip_address'):
                                            session.add(HardwareAsset(**row_dict))
                                    session.commit()
                                st.success(f"Imported {len(df)} hardware assets!")
                                time.sleep(1)
                                safe_rerun()
                        except Exception as e:
                            st.error(f"Error parsing CSV: {e}")
            set_idx += 1

        if "Tab: Settings -> RSS Sources" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                col1, col2 = st.columns(2)
                kws, feeds, usrs = svc.get_admin_lists()

                with col1:
                    st.subheader("Manage Keywords")
                    with st.form("bulk_kw"):
                        raw_text = st.text_area("Bulk Add Keywords (word, weight)", placeholder="infrastructure, 80", key="set_kw_bulk")
                        if st.form_submit_button("Add Keywords", width="stretch"):
                            svc.add_bulk_keywords(raw_text)
                            safe_rerun()
                    with st.expander("Active Keywords"):
                        for k in kws:
                            c_a, c_b, c_c = st.columns([3, 1, 1])
                            c_a.code(k.word)
                            c_b.write(f"**{k.weight}**")
                            if c_c.button("", key=f"del_kw_{k.id}", width="stretch"):
                                svc.delete_record("Keyword", k.id)
                                safe_rerun()

                with col2:
                    st.subheader("Manage RSS Feeds")
                    with st.form("bulk_feed"):
                        raw_text_feeds = st.text_area("Bulk Add Feeds (URL, Name)", placeholder="https://site.com/feed, Tech News", key="set_feed_bulk")
                        if st.form_submit_button("Add Sources", width="stretch"):
                            svc.add_bulk_feeds(raw_text_feeds)
                            safe_rerun()
                    with st.expander("Active Feeds"):
                        for f in feeds:
                            st.text(f.name)
                            st.caption(f.url)
                            if st.button("Delete", key=f"del_src_{f.id}", width="stretch"):
                                svc.delete_record("FeedSource", f.id)
                                safe_rerun()
            set_idx += 1

        if "Tab: Settings -> ML Training" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Smart Filter Training")
                pos, neg, total = svc.get_ml_counts()
                c1, c2, c3 = st.columns(3)
                c1.metric("Total Samples", total)
                c2.metric("Positives (Keep)", pos)
                c3.metric("Negatives (Dismiss)", neg)

                is_train_cooling = check_cooldown("ml_train", 60)
                if st.button("Training..." if is_train_cooling else "Retrain Model Now", type="primary", disabled=not perms["can_train"] or is_train_cooling, key="set_ml_retrain", width="stretch"):
                    apply_cooldown("ml_train")
                    if total < 10:
                        st.error("Not enough data! Please review at least 10 articles.")
                    else:
                        with st.spinner("Training neural pathways..."):
                            try:
                                from src.train_model import train
                                train()
                                st.success("Model retrained successfully!")
                            except Exception as e:
                                st.error(f"Training failed: {e}")
            set_idx += 1

        if "Tab: Settings -> AI & SMTP" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Universal LLM, System Integrations & Scoring")
                config_dict = sys_config or {}

                with st.form("llm_config"):
                    st.markdown("### LLM Configuration")
                    endpoint = st.text_input("Endpoint URL", value=config_dict.get('llm_endpoint', ''))
                    api_key = st.text_input("API Key", value=config_dict.get('llm_api_key', ''), type="password")
                    model_name = st.text_input("Model Name", value=config_dict.get('llm_model_name', ''))
                    tech_stack_input = st.text_area("Internal Tech Stack", value=config_dict.get('tech_stack', 'SolarWinds, Cisco SD-WAN'), height=100)
                    is_active = st.checkbox("Enable AI Features", value=config_dict.get('is_active', False))

                    st.divider()
                    st.markdown("### SMTP Broadcast Configuration")
                    c_s1, c_s2 = st.columns([3, 1])
                    smtp_server = c_s1.text_input("SMTP Server (e.g. smtp.office365.com)", value=config_dict.get('smtp_server', ''))
                    smtp_port = c_s2.number_input("Port", value=config_dict.get('smtp_port', 587))
                    c_s3, c_s4 = st.columns(2)
                    smtp_user = c_s3.text_input("SMTP Username", value=config_dict.get('smtp_username', ''))
                    smtp_pass = c_s4.text_input("SMTP Password", value=config_dict.get('smtp_password', ''), type="password")
                    c_s5, c_s6 = st.columns(2)
                    smtp_sender = c_s5.text_input("Sender Address", value=config_dict.get('smtp_sender', ''))
                    smtp_recip = c_s6.text_input("Default Recipient List", value=config_dict.get('smtp_recipient', ''))
                    smtp_enabled = st.checkbox("Enable SMTP Broadcasts", value=config_dict.get('smtp_enabled', False))

                    st.divider()
                    st.markdown("###  Threat Matrix Baseline Overrides")
                    st.caption("Leave at 0 to use the automatic 14-day moving average. Values > 0 will lock the baseline to that specific number.")
                    c_b1, c_b2 = st.columns(2)
                    base_cyb = c_b1.number_input("Cyber Baseline Override", value=float(config_dict.get('baseline_override_cyber', 0.0)), step=5.0)
                    base_phy = c_b2.number_input("Physical Baseline Override", value=float(config_dict.get('baseline_override_phys', 0.0)), step=5.0)

                    st.divider()
                    st.markdown("### CIS Alert Level Countermeasures")
                    st.caption("Configure your organization's security posture per the CIS Alert Level framework. Higher values = better defenses = lower overall risk.")
                    c_c1, c_c2 = st.columns(2)

                    sys_counter_val = config_dict.get('sys_countermeasures', 3)
                    net_counter_val = config_dict.get('net_countermeasures', 3)

                    with c_c1:
                        st.markdown("**System Countermeasures** (Host-based security)")
                        st.caption("1=Old OS/no AV | 2=Missing patches | 3=Patched/AV | 4=Hardened | 5=Patched+Hardened+IDS")
                        sys_counter = st.select_slider("sys_counter", options=[1, 2, 3, 4, 5], value=sys_counter_val)
                    with c_c2:
                        st.markdown("**Network Countermeasures** (Network security)")
                        st.caption("1=No firewall | 2=Permissive FW | 3=Restrictive FW | 4=FW+validated | 5=FW+IDS+validated")
                        net_counter = st.select_slider("net_counter", options=[1, 2, 3, 4, 5], value=net_counter_val)

                    if st.form_submit_button("Save Global Config", width="stretch"):
                        new_config = {
                            "llm_endpoint": endpoint, "llm_api_key": api_key, "llm_model_name": model_name,
                            "tech_stack": tech_stack_input, "is_active": is_active, "smtp_server": smtp_server,
                            "smtp_port": smtp_port, "smtp_username": smtp_user, "smtp_password": smtp_pass,
                            "smtp_sender": smtp_sender, "smtp_recipient": smtp_recip, "smtp_enabled": smtp_enabled,
                            "baseline_override_cyber": base_cyb, "baseline_override_phys": base_phy,
                            "sys_countermeasures": sys_counter, "net_countermeasures": net_counter
                        }
                        svc.save_global_config(new_config)
                        st.success("Configuration Saved!")
                        time.sleep(1)
                        safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Users & Roles" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("User & Role Management")
                col_u1, col_u2 = st.columns(2)
                with col_u1:
                    available_roles = [r.name for r in svc.get_all_roles()]
                    with st.container(border=True):
                        st.markdown("###  Create New User")
                        with st.form("new_user_form"):
                            new_username = st.text_input("Username").strip()
                            new_password = st.text_input("Password", type="password")
                            new_role = st.selectbox("Assign Role", available_roles)
                            if st.form_submit_button("Create User", width="stretch"):
                                if not new_username or not new_password:
                                    st.error("Username and password required.")
                                else:
                                    if svc.create_user(new_username, new_password, new_role):
                                        st.success(f"User '{new_username}' created!")
                                        safe_rerun()
                                    else:
                                        st.error("Username already exists.")

                    with st.container(border=True):
                        st.markdown("###  Change User Role")
                        with st.form("update_user_role_form"):
                            usrs = svc.get_admin_lists()[2]
                            target_user = st.selectbox("Select User", [u.username for u in usrs])
                            new_assigned_role = st.selectbox("Assign New Role", available_roles)
                            if st.form_submit_button("Update Role", width="stretch"):
                                svc.update_user_role(target_user, new_assigned_role)
                                st.success(f"Updated {target_user} to role: {new_assigned_role}")
                                safe_rerun()

                    with st.container(border=True):
                        st.markdown("###  Create Custom Role")
                        with st.form("new_role_form", clear_on_submit=True):
                            new_role_name = st.text_input("Role Name").strip().lower()
                            new_role_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES)
                            new_role_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS)

                            avail_types = svc.get_all_site_types()
                            new_role_site_types = st.multiselect("Allowed Site Types", avail_types, default=avail_types)

                            if st.form_submit_button("Create Role", width="stretch"):
                                if not new_role_name or not new_role_pages:
                                    st.error("Role name and at least one page required.")
                                else:
                                    if svc.create_role(new_role_name, new_role_pages, new_role_actions, new_role_site_types):
                                        if hasattr(svc.get_all_roles, "clear"):
                                            svc.get_all_roles.clear()
                                        st.success(f"Role '{new_role_name}' created!")
                                        time.sleep(1)
                                        safe_rerun()
                                    else:
                                        st.error("Role name already exists.")

                    with st.container(border=True):
                        st.markdown("###  Edit Existing Role")
                        editable_roles = [r for r in available_roles if r != "admin"]
                        if editable_roles:
                            role_to_edit = st.selectbox("Select Role to Edit", editable_roles)
                            if role_to_edit:
                                selected_role_obj = next((r for r in svc.get_all_roles() if r.name == role_to_edit), None)
                                current_pages = selected_role_obj.allowed_pages if selected_role_obj and selected_role_obj.allowed_pages else []
                                current_actions = selected_role_obj.allowed_actions if selected_role_obj and selected_role_obj.allowed_actions else []

                                with st.form(f"edit_role_form_{role_to_edit}"):
                                    valid_default_pages = [p for p in current_pages if p in ALL_POSSIBLE_PAGES]
                                    valid_default_actions = [a for a in current_actions if a in ALL_POSSIBLE_ACTIONS]

                                    avail_types = svc.get_all_site_types()
                                    current_types = getattr(selected_role_obj, 'allowed_site_types', []) or []
                                    valid_default_types = [t for t in current_types if t in avail_types]

                                    updated_pages = st.multiselect("Allowed Master Pages", ALL_POSSIBLE_PAGES, default=valid_default_pages)
                                    updated_actions = st.multiselect("Allowed Sub-Tabs & Actions", ALL_POSSIBLE_ACTIONS, default=valid_default_actions)
                                    updated_site_types = st.multiselect("Allowed Site Types", avail_types, default=valid_default_types)

                                    if st.form_submit_button("Update Role", width="stretch"):
                                        if not updated_pages:
                                            st.error("A role must have at least one allowed page.")
                                        else:
                                            svc.update_role(role_to_edit, updated_pages, updated_actions, updated_site_types)
                                            if hasattr(svc.get_all_roles, "clear"):
                                                svc.get_all_roles.clear()
                                            st.success(f"Role '{role_to_edit}' updated!")
                                            time.sleep(1)
                                            safe_rerun()
                        else:
                            st.info("No editable roles available.")

                with col_u2:
                    usrs = svc.get_admin_lists()[2]
                    with st.container(border=True):
                        st.markdown("### Active Users")
                        for u in usrs:
                            c_name, c_role, c_act = st.columns([3, 2, 1])
                            c_name.write(f"**{u.username}**")
                            c_role.caption(u.role.upper())
                            if u.username != st.session_state.current_user:
                                if c_act.button("", key=f"del_u_{u.id}", width="stretch"):
                                    svc.delete_record("User", u.id)
                                    safe_rerun()

                    with st.container(border=True):
                        st.markdown("###  Force Reset Password")
                        with st.form("admin_reset_pwd_form"):
                            target_user = st.selectbox("Select User ", [u.username for u in usrs])
                            force_new_pwd = st.text_input("New Password", type="password")
                            if st.form_submit_button("Reset Password", width="stretch"):
                                if force_new_pwd:
                                    svc.force_reset_pwd(target_user, force_new_pwd)
                                    st.success(f"Password reset for {target_user}.")

                    with st.container(border=True):
                        st.markdown("### Active Roles")
                        for r in svc.get_all_roles():
                            c_name, c_pages, c_act = st.columns([2, 3, 1])
                            c_name.write(f"**{r.name}**")
                            action_count = len(r.allowed_actions) if r.allowed_actions else 0
                            c_pages.caption(f"{len(r.allowed_pages)} pages | {action_count} perms")
                            if r.name not in ["admin", "analyst"]:
                                if c_act.button("", key=f"del_role_{r.id}", width="stretch"):
                                    svc.delete_record("Role", r.id)
                                    safe_rerun()
            set_idx += 1

        if "Tab: Settings -> Backup & Restore" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.subheader("Database Export & Import")
                st.write("Backup or restore configurations, keywords, RSS feeds, and location mappings.")

                c_exp, c_imp = st.columns(2)
                with c_exp:
                    st.markdown("### Export Data")
                    if st.button("Generate Backup JSON", width="stretch"):
                        backup_data = svc.get_backup_data()
                        json_str = json.dumps(backup_data, indent=4)
                        st.download_button("Download System_Backup.json", data=json_str, file_name=f"NOC_Backup_{datetime.now().strftime('%Y%m%d')}.json", mime="application/json", width="stretch")

                with c_imp:
                    st.markdown("### Import Data")
                    uploaded_backup = st.file_uploader("Upload JSON Backup File", type=["json"])
                    if uploaded_backup is not None:
                        if st.button("Execute Import", width="stretch", type="primary"):
                            try:
                                data = json.load(uploaded_backup)
                                added = svc.restore_backup_data(data)
                                st.success(f"Restored: {added['kw']} Keywords, {added['feeds']} Feeds, {added['locs']} Locations.")
                            except Exception as e:
                                st.error(f"Import Failed: {e}")
            set_idx += 1

        if "Tab: Settings -> Danger Zone" in st.session_state.allowed_actions:
            with set_tabs[set_idx]:
                st.error("Database Maintenance & Irreversible Actions")
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.write("**Routine Maintenance**")
                    st.caption("Safely sweeps stale alerts & intel.")
                    is_gc_cooling = check_cooldown("gc_run", 60)
                    if st.button("Sweeping..." if is_gc_cooling else "Run Garbage Collector", width="stretch", disabled=is_gc_cooling):
                        apply_cooldown("gc_run")
                        with st.spinner("Purging stale data and vacuuming database..."):
                            from src.scheduler import run_database_maintenance
                            run_database_maintenance()
                            st.success("Swept and optimized!")
                            time.sleep(1)
                            safe_rerun()

                    st.write("**Reset Cloud Telemetry**")
                    st.caption("Wipes all cloud outages to force a clean sync.")
                    is_nuke_cloud_cooling = check_cooldown("nuke_cloud", 60)
                    if st.button("Purging..." if is_nuke_cloud_cooling else "Purge Cloud Data", width="stretch", disabled=is_nuke_cloud_cooling):
                        apply_cooldown("nuke_cloud")
                        svc.nuke_tables(["CloudOutage"])
                        st.success("Cloud data purged! Go to Threat Telemetry -> Cloud Services to repull.")
                        time.sleep(1.5)
                        safe_rerun()

                    st.write("**Data Migration**")
                    st.caption("Applies new categories to historical 'General' data.")
                    is_recat_cooling = check_cooldown("recategorize", 60)
                    if st.button("Scanning..." if is_recat_cooling else "Recategorize Articles", width="stretch", disabled=is_recat_cooling):
                        apply_cooldown("recategorize")
                        with st.spinner("Scanning database..."):
                            updated_count = svc.recategorize_all_articles()
                            st.success(f"Successfully recategorized {updated_count} articles!")
                            time.sleep(2)
                            safe_rerun()

                with col2:
                    st.write("**Clear History**")
                    st.caption("Deletes all articles & IOCs.")
                    if st.button("Delete All Articles", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC"])
                        safe_rerun()

                    st.write("**Clear Locations**")
                    st.caption("Deletes all monitored facilities.")
                    if st.button("Delete All Locations", width="stretch"):
                        svc.nuke_tables(["MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()

                    st.write("**Crime Data Reset**")
                    st.caption("Purges all local LRPD dispatch and crime records from the database.")
                    if st.button("PURGE CRIME DATA", width="stretch"):
                        success, count = svc.nuke_crime_data()
                        if success:
                            st.toast(f"Successfully purged {count} crime records.")
                            safe_rerun()
                        else:
                            st.error(f"Failed to purge crime data: {count}")

                with col3:
                    st.markdown("####  Weather & Fire Telemetry")
                    st.caption("Instantly drops all active NWS warnings, SPC outlooks, and Fire polygons from the map.")
                    if st.button("PURGE WEATHER & FIRE DATA", type="primary", width="stretch"):
                        success, count = svc.nuke_weather_data()
                        if success:
                            st.success(f"Erased {count} hazard records and cleared map cache.")
                            time.sleep(1)
                            safe_rerun()
                        else:
                            st.error(f"Failed: {count}")

                    st.divider()
                    st.write("**Factory Reset**")
                    st.caption("Destroys all data entirely.")
                    if st.button("FULL RESET", width="stretch"):
                        svc.nuke_tables(["Article", "ExtractedIOC", "FeedSource", "Keyword", "MonitoredLocation"])
                        svc.get_cached_locations.clear()
                        safe_rerun()

                st.divider()
                st.markdown("###  Black Ops (Undocumented Features)")
                c_troll1, c_troll2 = st.columns(2)

                with c_troll1:
                    if st.session_state.current_user == "pwest":
                        with st.container(border=True):
                            st.write("**Operation: Nick**")
                            st.caption("Target: `nwilson`. 15% chance on refresh to lock their screen.")
                            tn = st.toggle("Enable Nick Troll", value=black_ops["nick_enabled"])
                            if tn != black_ops["nick_enabled"]:
                                black_ops["nick_enabled"] = tn
                                safe_rerun()
                    else:
                        st.info("Classified Operations Area.")

                with c_troll2:
                    if st.session_state.current_role == "admin":
                        with st.container(border=True):
                            st.write("**Operation: Dean**")
                            st.caption("Targeted silent cascading failure simulation (2 sites/min until 100%).")

                            usrs = [u.username for u in svc.get_admin_lists()[2]] if svc.get_admin_lists()[2] else []
                            tgt_idx = usrs.index(black_ops["dean_target"]) if black_ops["dean_target"] in usrs else 0

                            selected_target = st.selectbox("Select Target User", ["None"] + usrs, index=(tgt_idx + 1 if black_ops["dean_target"] else 0))
                            td = st.toggle("Engage Protocol", value=(black_ops["dean_target"] is not None))

                            if td and selected_target != "None":
                                if black_ops["dean_target"] != selected_target:
                                    black_ops["dean_target"] = selected_target
                                    black_ops["dean_start"] = time.time()
                                    safe_rerun()
                            elif not td and black_ops["dean_target"] is not None:
                                black_ops["dean_target"] = None
                                safe_rerun()

            set_idx += 1
