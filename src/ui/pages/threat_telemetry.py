import streamlit as st
import pandas as pd
import time
from datetime import datetime
import pydeck as pdk

import src.services as svc
from src.scheduler import fetch_feeds
from src.ui.state_manager import safe_rerun, check_cooldown, apply_cooldown, format_local_time, render_article_feed, get_permission_flags


def render_threat_telemetry():
    perms = get_permission_flags()

    st.title("Unified Threat Telemetry")
    tt_tab_names = []

    if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions:
        tt_tab_names.append("RSS Triage")
    if "Tab: Threat Telemetry -> CISA KEV" in st.session_state.allowed_actions:
        tt_tab_names.append("Exploits (KEV)")
    if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions:
        tt_tab_names.append("Cloud Services")
    if "Tab: Threat Telemetry -> Perimeter Crime" in st.session_state.allowed_actions:
        tt_tab_names.append("Perimeter Crime")

    if not tt_tab_names:
        st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(tt_tab_names)
        tab_idx = 0

        if "Tab: Threat Telemetry -> RSS Triage" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col_title, col_btn = st.columns([3, 1])
                is_rss_cooling = check_cooldown("sync_rss", 60)
                if col_btn.button("Syncing..." if is_rss_cooling else "Force Fetch Feeds", width="stretch", disabled=not perms["can_sync"] or is_rss_cooling):
                    apply_cooldown("sync_rss")
                    with st.spinner("Fetching feeds..."):
                        fetch_feeds(source="User Force")
                        time.sleep(1)
                        safe_rerun()
                cat_filter = st.selectbox("Filter Active Feeds", [
                    "All", "Cyber: Exploits & Vulns", "Cyber: Malware & Threats",
                    "ICS/OT & SCADA", "Cloud & IT Infra", "Physical Security",
                    "Severe Weather", "Geopolitics & Policy", "AI & Emerging Tech", "General"
                ])
                st.divider()

                def handle_pagination(feed_id, q_type, pg_size, s_term=None, m_score=0):
                    s_key = f"page_{feed_id}"
                    if s_key not in st.session_state:
                        st.session_state[s_key] = 1
                    items, t_items, t_pages, cur_page = svc.get_paginated_articles(q_type, cat_filter, st.session_state[s_key], pg_size, s_term, m_score)
                    st.session_state[s_key] = cur_page

                    def p_ctrls(loc):
                        c1, c2, c3 = st.columns([1, 2, 1])
                        if c1.button("Previous", key=f"p_{feed_id}_{loc}", disabled=(cur_page <= 1), width="stretch"):
                            st.session_state[s_key] -= 1;
                            safe_rerun()
                        c2.markdown(f"<div style='text-align: center; margin-top: 0.4rem;'><b>Page {cur_page} of {t_pages}</b> <span style='font-size: 0.85em; color: gray;'>(Total: {t_items})</span></div>", unsafe_allow_html=True)
                        if c3.button("Next ", key=f"n_{feed_id}_{loc}", disabled=(cur_page >= t_pages), width="stretch"):
                            st.session_state[s_key] += 1;
                            safe_rerun()

                    if t_items > pg_size:
                        p_ctrls("top");
                        st.divider()
                    elif t_items == 0:
                        st.info("No articles found.");
                        return
                    render_article_feed(items, key_prefix=f"{feed_id}_")
                    if t_items > pg_size:
                        st.divider();
                        p_ctrls("bot")

                s1, s2, s3, s4 = st.tabs(["Pinned", "Live", "Low", "Search"])
                with s1:
                    handle_pagination("pinned", "pinned", 10)
                with s2:
                    handle_pagination("live", "live", 20)
                with s3:
                    handle_pagination("low", "low", 20)
                with s4:
                    sc1, sc2, sc3 = st.columns([2, 1, 1])
                    s_term = sc1.text_input("Search")
                    m_score = sc2.number_input("Min Score", value=0)
                    pg_sz = sc3.selectbox("Items per Page", [10, 20, 50], index=1)
                    handle_pagination("search", "search", pg_sz, s_term, m_score)
            tab_idx += 1

        if "Tab: Threat Telemetry -> CISA KEV" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                is_kev_cooling = check_cooldown("sync_kev", 60)
                if st.button("Syncing..." if is_kev_cooling else "Sync CISA KEV", disabled=not perms["can_sync"] or is_kev_cooling, width="stretch"):
                    apply_cooldown("sync_kev")
                    with st.spinner("Fetching CISA Database..."):
                        from src.workers.cve_worker import fetch_cisa_kev;
                        fetch_cisa_kev();
                        safe_rerun()
                for cve in svc.get_cves(limit=50, days_back=30):
                    with st.expander(f" {cve.cve_id} | {cve.vendor} {cve.product}"):
                        st.markdown(f"**{cve.vulnerability_name}**\n\n{cve.description}")
            tab_idx += 1

        if "Tab: Threat Telemetry -> Cloud Services" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                is_cloud_cooling = check_cooldown("sync_cloud", 60)
                if st.button("Syncing..." if is_cloud_cooling else "Sync Cloud Status", disabled=not perms["can_sync"] or is_cloud_cooling, width="stretch"):
                    apply_cooldown("sync_cloud")
                    with st.spinner("Pulling data from Global Providers..."):
                        from src.workers.cloud_worker import fetch_cloud_outages;
                        fetch_cloud_outages();
                        safe_rerun()

                raw_outages = svc.get_cloud_outages(active_only=True)
                active_outages = []
                now = datetime.utcnow()
                today_fmts = [now.strftime("%b %d").lower(), now.strftime("%B %d").lower(), now.strftime("%Y-%m-%d"), now.strftime("%m/%d/%Y")]

                for o in raw_outages:
                    text = (o.title + " " + str(o.description)).lower()
                    is_maint = any(k in text for k in ["maintenance", "scheduled", "upcoming", "update"])
                    is_active = any(k in text for k in ["in progress", "started", "currently undergoing"])
                    if is_maint and not is_active and not any(fmt in text for fmt in today_fmts):
                        continue
                    active_outages.append(o)

                if not active_outages:
                    st.success("All tracked global SaaS and IaaS providers are reporting Operational status.")
                else:
                    affected_providers = sorted(list(set([o.provider for o in active_outages])))
                    st.warning(f"Active service degradations detected across {len(affected_providers)} providers.")
                    provider_tabs = st.tabs(affected_providers)
                    for p_idx, provider_name in enumerate(affected_providers):
                        with provider_tabs[p_idx]:
                            prov_outs = [o for o in active_outages if o.provider == provider_name]
                            for o in prov_outs:
                                with st.expander(f" {o.service} ({format_local_time(o.updated_at)})"):
                                    st.markdown(f"**[{o.title}]({o.link})**\n\n{o.description}")

                st.divider()
                with st.expander("View Historical / Resolved Incidents (Last 72 Hours)"):
                    all_recent_outages = svc.get_cloud_outages(active_only=False, limit=100)
                    resolved_outages = [o for o in all_recent_outages if o.is_resolved]
                    if not resolved_outages:
                        st.info("No recently resolved incidents.")
                    for o in resolved_outages:
                        st.markdown(f" **{o.provider}** | {o.service} <br><small>[{o.title}]({o.link})</small>", unsafe_allow_html=True)
            tab_idx += 1

        if "Tab: Threat Telemetry -> Perimeter Crime" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    st.subheader("Perimeter Crime Telemetry")
                    st.caption("LRPD incident aggregation geofenced around HQ (Last 7 Days - All Categories).")
                with col2:
                    radius_filter = st.selectbox("Geofence Radius", [1, 3, 5, 10], index=0, format_func=lambda x: f"{x} Miles")
                with col3:
                    st.write("")
                    if st.button("Force Fetch LRPD", width='stretch'):
                        with st.spinner("Polling Little Rock Dispatches..."):
                            if svc.force_fetch_crime_data():
                                st.success("Sync Complete!")
                                safe_rerun()
                            else:
                                st.error("Fetch Failed. Check Logs.")

                crime_data = svc.get_recent_crimes(max_distance=radius_filter, grid_only=False, hours_back=168)

                if not crime_data:
                    st.success(f"No crime incidents logged within {radius_filter} miles of HQ in the last 7 days.")
                else:
                    df_crimes = pd.DataFrame(crime_data)

                    if "lat" not in df_crimes.columns or "lon" not in df_crimes.columns:
                        st.error("Coordinate data missing from cache! Please run `python src/crime_worker.py` in your terminal to fetch fresh geometry.")
                    else:
                        df_crimes = df_crimes.dropna(subset=['lat', 'lon'])
                        layers, view_state = svc.build_crime_map_layers(df_crimes)

                        map_zoom = 15.5 if radius_filter == 1 else 13.5 if radius_filter == 3 else 12.0
                        view_state.zoom = map_zoom

                        map_container = st.container()

                        st.divider()
                        st.subheader(f"Raw Incident Logs ({radius_filter} Mile Radius)")
                        display_crimes = df_crimes[["timestamp", "distance_miles", "category", "severity", "raw_title"]]

                        event = st.dataframe(
                            display_crimes,
                            width='stretch',
                            hide_index=True,
                            on_select="rerun",
                            selection_mode="single-row"
                        )

                        if event.selection.rows:
                            selected_idx = event.selection.rows[0]
                            selected_crime = df_crimes.iloc[selected_idx]

                            view_state.latitude = selected_crime['lat']
                            view_state.longitude = selected_crime['lon']
                            view_state.zoom = 17

                            highlight_layer = pdk.Layer(
                                "ScatterplotLayer",
                                data=[{"lat": selected_crime['lat'], "lon": selected_crime['lon']}],
                                get_position='[lon, lat]',
                                get_fill_color='[255, 0, 0, 200]',
                                get_line_color='[255, 255, 255, 255]',
                                stroked=True,
                                line_width_min_pixels=3,
                                get_radius=40,
                                pickable=False
                            )
                            layers.append(highlight_layer)

                        with map_container:
                            st.pydeck_chart(pdk.Deck(
                                layers=layers,
                                initial_view_state=view_state,
                                tooltip={"html": "<b>{raw_title}</b><br/>{timestamp}<br/>Dist: {distance_miles} miles"}
                            ), width='stretch')
            tab_idx += 1
