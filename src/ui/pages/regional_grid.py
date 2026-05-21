import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import pydeck as pdk
import streamlit.components.v1 as components

import src.services as svc
from src.utils.llm import generate_executive_weather_brief
from src.ui.state_manager import safe_rerun, check_cooldown, apply_cooldown, format_local_time, get_permission_flags, LOCAL_TZ


def render_regional_grid():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    ai_enabled = sys_config.is_active if sys_config else False

    st.title("Regional Grid & Hazard Analytics")

    col_sync1, col_sync2 = st.columns([3, 1])
    is_infra_cooling = check_cooldown("sync_infra", 60)
    if col_sync2.button("Syncing..." if is_infra_cooling else "Sync Regional Telemetry", disabled=not perms["can_sync"] or is_infra_cooling, key="tt_sync_infra", width="stretch"):
        apply_cooldown("sync_infra")
        with st.spinner("Pulling Radar & Calculating Geospatial Intersections..."):
            from src.workers.infra_worker import fetch_regional_hazards
            fetch_regional_hazards()
            time.sleep(1)
            svc.get_cached_geojson.clear()
            safe_rerun()

    locs = svc.get_cached_locations()
    if st.session_state.allowed_site_types != "ALL":
        locs = [l for l in locs if l.loc_type in st.session_state.allowed_site_types]

    df = pd.DataFrame([{
        "id": l.id, "Name": l.name, "Type": l.loc_type, "District": l.district,
        "Priority": l.priority, "Risk": l.current_spc_risk,
        "Lat": l.lat, "Lon": l.lon
    } for l in locs]) if locs else pd.DataFrame()

    spc_d1, spc_d2, spc_d3, ar_data, oos_data, usgs_ar_data, usgs_oos_data = svc.get_cached_geojson()
    spc_data = spc_d1

    active_event_types = set()
    for geo_dataset in [ar_data, oos_data]:
        if geo_dataset:
            for f in geo_dataset.get("features", []):
                active_event_types.add(f.get("properties", {}).get("event", "Unknown"))
    active_event_types = sorted(list(active_event_types))

    rg_tab_names = []
    if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
        rg_tab_names.append("Geospatial Overlay")
    if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions:
        rg_tab_names.append("Executive Dashboard")
    if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions:
        rg_tab_names.append("Deep Hazard Analytics")
    if "Tab: Regional Grid -> Location Matrix" in st.session_state.allowed_actions:
        rg_tab_names.append("Location Matrix")
    if "Tab: Regional Grid -> Weather Alerts Log" in st.session_state.allowed_actions:
        rg_tab_names.append("Weather Alerts Log")
    if "Tab: Regional Grid -> Atmos Weather" in st.session_state.allowed_actions:
        rg_tab_names.append("Atmos Weather")

    if not rg_tab_names:
        st.warning("You do not have permission to view any modules within the Regional Grid.")
    else:
        rg_tabs = st.tabs(rg_tab_names)
        rg_idx = 0

        map_toggles = {"radar": False, "spc": False, "warn": False, "watch": False, "oos": False, "fire_risk": False, "active_wildfires": False, "earthquakes": True}
        selected_events = active_event_types
        map_df = df.copy()
        show_radar_panel = False

        if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                c_ctrl, c_map_main = st.columns([1, 4])

                with c_ctrl:
                    st.subheader("Map Controls")
                    with st.container(border=True):
                        st.markdown("**Master Layers**")
                        map_toggles["radar"] = st.toggle("Radar Overlay", value=False)
                        show_radar_panel = st.toggle("Animated Panel", value=False)
                        st.divider()
                        map_toggles["spc"] = st.toggle("SPC Convective", value=False)
                        map_toggles["warn"] = st.toggle("Warnings (AR)", value=False)
                        map_toggles["watch"] = st.toggle("Watches (AR)", value=False)
                        map_toggles["oos"] = st.toggle("Out-of-State", value=False)

                        st.divider()
                        map_toggles["fire_risk"] = st.toggle("NWS Fire Weather & Red Flags", value=False)
                        map_toggles["active_wildfires"] = st.toggle("Active Wildfires (NIFC)", value=False)
                        map_toggles["earthquakes"] = st.toggle("Earthquakes (USGS)", value=True)

                        if map_toggles["fire_risk"] or map_toggles["active_wildfires"] or map_toggles["earthquakes"]:
                            with st.container(border=True):
                                st.markdown("** Fire Desk Legend:**")
                                if map_toggles["fire_risk"]:
                                    st.markdown(" **Red Flag Warning** *(Extreme/Burn Ban)*")
                                    st.markdown(" **Fire Weather Watch** *(High Risk)*")
                                if map_toggles["active_wildfires"]:
                                    st.markdown(" **Active Wildfire** *(Scales by Acreage)*")
                                if map_toggles["earthquakes"]:
                                    st.markdown(" **Earthquake** *(Blue: M2-3, Yellow: M3-4, Orange: M4-5, Red: M5+)*")

                    with st.container(border=True):
                        st.markdown("**Hazard Isolation**")
                        if not active_event_types:
                            st.info("No active hazards to filter.")
                            selected_events = []
                        else:
                            selected_events = st.multiselect("Active Threats", active_event_types, default=active_event_types, label_visibility="collapsed")

                    with st.container(border=True):
                        st.markdown("**Facility Filters**")
                        if not df.empty:
                            available_types = df['Type'].unique().tolist()
                            available_prios = sorted(df['Priority'].unique().tolist())
                            selected_types = st.multiselect("Facility Type", available_types, default=available_types)
                            selected_prios = st.multiselect("Priority Level", available_prios, default=available_prios)
                            map_df = df[df['Type'].isin(selected_types) & df['Priority'].isin(selected_prios)].copy()
                            map_df['info'] = map_df['Name'] + "\nType: " + map_df['Type'] + "\nRisk: " + map_df['Risk']
                        else:
                            map_df = df.copy()

        layers, view_state, map_diagnostics, toggled_affected_sites, master_affected_sites = svc.compile_regional_grid_map(
            map_df, spc_data, ar_data, oos_data, usgs_ar_data, usgs_oos_data, selected_events, map_toggles
        )

        if "Tab: Regional Grid -> Geospatial Map" in st.session_state.allowed_actions:
            with c_map_main:
                if show_radar_panel:
                    cm1, cm2 = st.columns([2, 1])
                    with cm1:
                        st.subheader("Live Threat Overlay")
                        st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")
                    with cm2:
                        st.subheader("Precipitation Loop")
                        components.html("""<iframe src="https://www.rainviewer.com/map.html?loc=34.8,-92.2,6&oFa=0&oC=1&oU=0&oCS=1&oF=0&oAP=1&c=3&o=83&lm=1&layer=radar&sm=1&sn=1" width="100%" height="500" frameborder="0" style="border-radius: 8px;" allowfullscreen></iframe>""", height=500)
                else:
                    st.subheader("Live Threat Overlay")
                    st.pydeck_chart(pdk.Deck(layers=layers, initial_view_state=view_state, tooltip={"text": "{info}"}), width="stretch")

                st.divider()
                st.subheader("Sites Impacted by Currently Toggled Layers")
                st.caption("This table dynamically updates based on the layer switches and filters in the left sidebar.")

                if not toggled_affected_sites:
                    st.success("No sites intersect with the specific layers and hazard types currently rendered on the map.")
                else:
                    st.dataframe(pd.DataFrame(toggled_affected_sites).sort_values(by=['Priority', 'Monitored Site']), hide_index=True, width="stretch")
            rg_idx += 1

        if "Tab: Regional Grid -> Executive Dash" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Executive Infrastructure Threat Dashboard")
                st.markdown("Holistic situational overview of physical asset exposure parsed by District and Priority.")

                if map_df.empty:
                    st.info("No monitored locations match current filters.")
                else:
                    import plotly.express as px
                    import plotly.graph_objects as go

                    analytics = svc.get_infrastructure_analytics(map_df, master_affected_sites)

                    p1_at_risk = len(set(site['Monitored Site'] for site in master_affected_sites if site['Priority'] == 1))
                    total_at_risk = analytics.get("at_risk_sites", 0)
                    total_sites = analytics.get("total_sites", 0)
                    risk_pct = round((total_at_risk / total_sites) * 100, 1) if total_sites > 0 else 0

                    with st.container(border=True):
                        c_kpi1, c_kpi2, c_kpi3, c_kpi4 = st.columns(4)
                        c_kpi1.metric("Total Tracked Assets", total_sites)
                        c_kpi2.metric("Assets in Active Risk Zones", total_at_risk, f"{risk_pct}% Exposure", delta_color="inverse")
                        c_kpi3.metric("Critical (P1) Assets at Risk", p1_at_risk, "Immediate Attention" if p1_at_risk > 0 else "Clear", delta_color="inverse")
                        c_kpi4.metric("Highest Regional Risk", analytics["highest_risk"])

                    st.divider()

                    st.markdown("###  AI Executive Weather Briefing")
                    c_ai_text, c_ai_btn = st.columns([4, 1])

                    if "exec_weather_brief" not in st.session_state:
                        st.session_state.exec_weather_brief = "Click 'Generate Briefing' to synthesize current telemetry."

                    if c_ai_btn.button("Generate Briefing", type="primary", width='stretch', disabled=not ai_enabled):
                        with st.spinner("Synthesizing meteorological telemetry..."):
                            st.session_state.exec_weather_brief = generate_executive_weather_brief(analytics, p1_at_risk, sys_config)
                            safe_rerun()

                    st.info(st.session_state.exec_weather_brief)

                    st.divider()

                    c_viz1, c_viz2, c_viz3 = st.columns(3)
                    color_map_spc = {"HIGH": "#dc3545", "MDT": "#e67e22", "ENH": "#f39c12", "SLGT": "#f1c40f", "MRGL": "#17a2b8", "TSTM": "#28a745", "None": "#6c757d"}
                    color_map_nws = {"WARNING": "#dc3545", "WATCH": "#f39c12", "ADVISORY": "#f1c40f", "STATEMENT": "#17a2b8", "None": "#6c757d"}

                    with c_viz1:
                        st.markdown(f"**SPC Risk (Total Sites: {total_sites})**")
                        if not analytics["spc_distribution"].empty:
                            fig_spc = px.pie(analytics["spc_distribution"], values='count', names='SPC Risk', hole=0.6, color='SPC Risk', color_discrete_map=color_map_spc)
                            fig_spc.update_layout(margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))
                            st.plotly_chart(fig_spc, width='stretch')
                        else:
                            st.success("All Clear.")

                    with c_viz2:
                        st.markdown(f"**NWS Alerts (Total Sites: {total_sites})**")
                        if not analytics["nws_distribution"].empty:
                            fig_nws = px.pie(analytics["nws_distribution"], values='count', names='NWS Alert', hole=0.6, color='NWS Alert', color_discrete_map=color_map_nws)
                            fig_nws.update_layout(margin=dict(t=10, b=10, l=10, r=10), showlegend=True, legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5))
                            st.plotly_chart(fig_nws, width='stretch')
                        else:
                            st.success("All Clear.")

                    with c_viz3:
                        st.markdown("**At-Risk Assets by District**")
                        if not analytics["district_distribution"].empty:
                            fig_dist = px.bar(analytics["district_distribution"].reset_index(), x='District', y='Count', color_discrete_sequence=['#1f77b4'])
                            fig_dist.update_layout(margin=dict(t=10, b=10, l=10, r=10), xaxis_title="", yaxis_title="")
                            st.plotly_chart(fig_dist, width='stretch')
                        else:
                            st.success("All Clear.")

                    st.divider()

                    st.markdown("###  Broadcast Executive SitRep")
                    st.caption("Dispatches the KPIs, AI Briefing, and HTML Visual Breakdowns directly to leadership.")

                    with st.form("exec_dash_email"):
                        c_em1, c_em2 = st.columns([2, 1])
                        default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                        target_email = c_em1.text_input("Recipient Email(s)", value=default_email)
                        custom_notes = st.text_area("Additional Analyst Notes (Optional)", placeholder="Add any specific context or instructions here...")

                        if st.form_submit_button("Transmit Report", type="primary", disabled=not ("Action: Dispatch Exec Report" in st.session_state.allowed_actions)):
                            if not target_email:
                                st.error("Please provide a recipient email address.")
                            else:
                                with st.spinner("Compiling HTML visual graphs and transmitting..."):

                                    def build_html_bar_chart(df, label_col, count_col, c_map, title):
                                        total = df[count_col].sum()
                                        if total == 0:
                                            return ""
                                        html = f"<h3 style='color:#2980b9; margin-bottom: 5px;'>{title}</h3>"
                                        html += "<table style='width:100%; border-collapse: collapse; font-family: Arial, sans-serif; margin-bottom: 20px;'>"
                                        for _, row in df.iterrows():
                                            label, count = row[label_col], row[count_col]
                                            if count == 0:
                                                continue
                                            pct = int((count / total) * 100)
                                            color = c_map.get(label, "#6c757d")
                                            html += f"<tr>"
                                            html += f"<td style='width:20%; padding: 4px 0; font-size:13px; font-weight:bold; color:#444;'>{label}</td>"
                                            html += f"<td style='width:70%; padding: 4px 10px;'><div style='background-color:#e9ecef; width:100%; border-radius:3px;'><div style='background-color:{color}; width:{pct}%; height:18px; border-radius:3px;'></div></div></td>"
                                            html += f"<td style='width:10%; padding: 4px 0; font-size:13px; text-align:right; font-weight:bold; color:#333;'>{count}</td>"
                                            html += f"</tr>"
                                        html += "</table>"
                                        return html

                                    spc_html = build_html_bar_chart(analytics["spc_distribution"], "SPC Risk", "count", color_map_spc, f"SPC Convective Risk (Total Sites: {total_sites})")
                                    nws_html = build_html_bar_chart(analytics["nws_distribution"], "NWS Alert", "count", color_map_nws, f"NWS Hazard Alerts (Total Sites: {total_sites})")

                                    html_body = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto;">
                                        <h2 style='color:#2c3e50;'>Executive Grid Threat Report</h2>
                                        <div style='background:#f8f9fa; padding:15px; border-left:4px solid #d9534f; margin-bottom: 20px;'>
                                            <b>Total Assets Monitored:</b> {total_sites}<br/>
                                            <b>Assets at Risk:</b> {total_at_risk} ({risk_pct}%)<br/>
                                            <b>Critical (P1) Exposures:</b> {p1_at_risk}<br/>
                                            <b>Highest Threat Level:</b> {analytics["highest_risk"]}
                                        </div>

                                        {spc_html}
                                        {nws_html}

                                        <div style="background-color: #ffffff; padding: 15px; border: 1px solid #dee2e6; border-radius: 5px; margin-top: 20px;">
                                            <h3 style='color:#2980b9; margin-top: 0;'>AI Meteorological Brief</h3>
                                            <p style='color: #495057; line-height: 1.5;'>{st.session_state.exec_weather_brief.replace(chr(10), '<br>')}</p>
                                        </div>

                                        <h3 style='color:#2980b9;'>Analyst Notes</h3>
                                        <p style='color: #495057; line-height: 1.5;'>{custom_notes.replace(chr(10), '<br>') if custom_notes else 'None provided.'}</p>
                                    </div>
                                    """
                                    from src.utils.mailer import send_alert_email
                                    success, msg = send_alert_email("Executive Weather & Infrastructure SitRep", html_body, recipient_override=target_email, is_html=True)
                                    if success:
                                        st.success(f"Report dispatched to {target_email}")
                                    else:
                                        st.error(f"SMTP Error: {msg}")

                    with st.expander("View Raw Matrices & Export Data"):
                        st.write("")
                        cx1, cx2, cx3 = st.columns(3)
                        with cx1:
                            st.markdown("**Risk by Priority Level**")
                            st.dataframe(analytics["priority_risk_matrix"], width="stretch")
                        with cx2:
                            st.markdown("**Risk by District**")
                            st.dataframe(analytics["district_risk_matrix"], width="stretch")
                        with cx3:
                            st.markdown("**Risk by Facility Type**")
                            st.dataframe(analytics["type_risk_matrix"], width="stretch")
            rg_idx += 1

        if "Tab: Regional Grid -> Hazard Analytics" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Deep Hazard Analytics & Executive Broadcast")
                st.markdown("Comprehensive breakdown of active weather geometry against physical infrastructure.")

                if not master_affected_sites:
                    st.success("All infrastructure is currently clear of severe weather geometry based on your current filters.")
                else:
                    analytics_df = pd.DataFrame(master_affected_sites).drop_duplicates()

                    p1_count = len(analytics_df[analytics_df['Priority'] == 1]['Monitored Site'].unique())
                    p2_count = len(analytics_df[analytics_df['Priority'] == 2]['Monitored Site'].unique())

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Total Sites Impacted", len(analytics_df['Monitored Site'].unique()))
                    c2.metric("Critical (P1) Impacts", p1_count, delta="High Risk" if p1_count > 0 else None, delta_color="inverse")
                    c3.metric("High (P2) Impacts", p2_count)
                    c4.metric("Unique Hazards", len(analytics_df['Hazard'].unique()))

                    st.divider()

                    st.write("**Complete Intersectional Dataset**")
                    st.dataframe(analytics_df.sort_values(by=['Priority', 'Severity', 'Monitored Site']), width="stretch", hide_index=True)

                    st.divider()
                    st.subheader("Broadcast Executive HTML SitRep")
                    st.caption("Generates a boardroom-ready HTML email containing the filtered hazard data.")

                    c_em1, c_em2 = st.columns([2, 1])
                    default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                    sitrep_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="sitrep_recip")

                    if c_em2.button("Transmit Priority SitRep", type="primary", width='stretch'):
                        if not sitrep_recipients:
                            st.error("Please enter at least one recipient email.")
                        else:
                            with st.spinner("Compiling HTML and transmitting..."):
                                html_safe = svc.generate_hazard_sitrep_html(analytics_df)
                                from src.utils.mailer import send_alert_email
                                success, msg = send_alert_email("URGENT: Active Severe Weather Impacting Operations", html_safe, recipient_override=sitrep_recipients, is_html=True)
                                if success:
                                    st.success("Executive HTML SitRep successfully transmitted!")
                                else:
                                    st.error(f"SMTP Error: {msg}")
            rg_idx += 1

        if "Tab: Regional Grid -> Location Matrix" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Active Infrastructure Matrix")
                st.caption("All tracked locations overlaid with current SPC Convective Outlooks.")
                if not map_df.empty:
                    display_df = map_df.drop(columns=['id', 'Lat', 'Lon', 'info'])
                    st.dataframe(display_df.sort_values(by=['Risk', 'Priority'], ascending=[True, True]), width="stretch", hide_index=True)
            rg_idx += 1

        if "Tab: Regional Grid -> Weather Alerts Log" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Comprehensive Weather Alerts Log")
                st.markdown("Human-readable log of all active NWS Watches, Warnings, and Special Weather Statements.")

                all_alert_details = svc.get_weather_alerts_log(ar_data, oos_data, selected_events, usgs_ar_data, usgs_oos_data)

                if not all_alert_details:
                    st.success("No active weather alerts matching your current hazard filters.")
                else:
                    df_alerts = pd.DataFrame(all_alert_details)

                    for col in ['Effective', 'Expires']:
                        parsed_dates = pd.to_datetime(df_alerts[col], errors='coerce', utc=True)
                        df_alerts[col] = parsed_dates.dt.tz_convert(LOCAL_TZ).dt.strftime('%Y-%m-%d %H:%M')
                        df_alerts[col] = df_alerts[col].fillna("N/A")

                    st.dataframe(df_alerts[["Event", "Severity", "Affected Area", "Expires", "Headline"]], hide_index=True, width="stretch")

                    st.divider()
                    st.subheader("Deep Dive Inspection")

                    dropdown_options = [f"{a['Event']} - {a['Affected Area'][:40]}..." for a in all_alert_details]
                    sel_alert_idx = st.selectbox("Select Alert to Review Full Details", range(len(dropdown_options)), format_func=lambda x: dropdown_options[x])

                    if sel_alert_idx is not None:
                        details = all_alert_details[sel_alert_idx]
                        with st.container(border=True):
                            st.markdown(f"### {details['Event']}")
                            st.write(f"**Affected Zones/Counties:** {details['Affected Area']}")
                            st.write(f"**Severity:** {details['Severity']} | **Certainty:** {details['Certainty']}")
                            st.write(f"**Effective:** {details['Effective']} | **Expires:** {details['Expires']}")

                            st.divider()
                            st.markdown("**NWS Description:**\n\n> " + details['Description'].replace('\n', '\n> '))

                            if details['Instructions'] and details['Instructions'] != "No explicit instructions provided.":
                                st.error(f"**NWS Actionable Instructions:**\n\n{details['Instructions']}")
            rg_idx += 1

        if "Tab: Regional Grid -> Atmos Weather" in st.session_state.allowed_actions:
            with rg_tabs[rg_idx]:
                st.subheader("Atmos Weather & Alerts")
                st.markdown("Integrated lightweight weather platform for live US alerts and personalized browser notifications.")

                st.components.v1.html("""
                    <div style="text-align: right;">
                        <button onclick="requestPerms()" style="padding: 8px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-family: sans-serif;"> Enable Browser Notifications</button>
                    </div>
                    <script>
                        function requestPerms() {
                            if ("Notification" in window) {
                                Notification.requestPermission().then(permission => {
                                    if (permission === "granted") {
                                        new Notification("Atmos Weather", {body: "Browser notifications enabled successfully!"});
                                    }
                                });
                            } else {
                                alert("Your browser does not support desktop notifications.");
                            }
                        }
                    </script>
                """, height=50)

                st.divider()

                c_prefs, c_alerts = st.columns([1, 2])

                with c_prefs:
                    st.markdown("###  Alert Preferences")
                    st.caption("Select which NWS event types should trigger browser push notifications.")

                    user_prefs = svc.get_user_weather_prefs(st.session_state.current_user)
                    available_events = [
                        "Tornado Warning", "Severe Thunderstorm Warning", "Flash Flood Warning",
                        "Special Marine Warning", "Snow Squall Warning", "Winter Storm Warning",
                        "Ice Storm Warning", "Blizzard Warning", "Red Flag Warning", "Hurricane Warning",
                        "Severe Weather Statement", "Severe Thunderstorm Watch", "Tornado Watch"
                    ]

                    with st.form("atmos_prefs_form"):
                        selected_alerts = st.multiselect("Notify me for:", available_events, default=[e for e in user_prefs if e in available_events])
                        if st.form_submit_button("Save Preferences", width="stretch", type="primary"):
                            svc.set_user_weather_prefs(st.session_state.current_user, selected_alerts)
                            st.success("Preferences saved!")
                            time.sleep(0.5)
                            safe_rerun()

                with c_alerts:
                    st.markdown("###  Active Watched Alerts")

                    if not selected_alerts:
                        st.info("No alert types selected. Update your preferences to track specific warnings.")
                    else:
                        all_logs = svc.get_filtered_notification_alerts(
                            st.session_state.current_user, ar_data, oos_data, map_df.to_dict('records') if not map_df.empty else locs
                        )

                        if not all_logs:
                            st.success("No active alerts matching your preferences in the monitored zones.")
                        else:
                            for alert in all_logs:
                                with st.container(border=True):
                                    st.markdown(f"** {alert['Event']}**")
                                    st.caption(f"**Area:** {alert['Affected Area']} | **Expires:** {alert['Expires']}")
                                    with st.expander("Read NWS Description"):
                                        st.write(alert['Description'])

                    st.divider()

                st.markdown("###  Site-Specific 7-Day Forecast")
                if not map_df.empty:
                    site_names = map_df['Name'].tolist()
                    default_idx = site_names.index("LR - Campus") if "LR - Campus" in site_names else 0

                    target_site = st.selectbox("Select Monitored Facility", site_names, index=default_idx)
                    site_data = map_df[map_df['Name'] == target_site].iloc[0]

                    forecast_data = svc.get_nws_forecast(site_data['Lat'], site_data['Lon'])

                    if forecast_data:
                        max_periods = min(len(forecast_data), 14)
                        chunk_size = 7

                        for i in range(0, max_periods, chunk_size):
                            chunk = forecast_data[i:i + chunk_size]
                            cols = st.columns(len(chunk))

                            for j, col in enumerate(cols):
                                period = chunk[j]
                                with col:
                                    with st.container(border=True):
                                        st.markdown(f"<div style='text-align:center; font-weight:bold; font-size:1.05em; color: #333;'>{period['name']}</div>", unsafe_allow_html=True)

                                        if 'icon' in period:
                                            st.markdown(f"<div style='text-align:center;'><img src='{period['icon']}' style='border-radius:15px; width:65px; height:65px; margin:10px 0; box-shadow: 0px 4px 6px rgba(0,0,0,0.1);'></div>", unsafe_allow_html=True)

                                        temp_color = "#dc3545" if period['isDaytime'] else "#007bff"
                                        st.markdown(f"<div style='text-align:center; color:{temp_color}; font-size:1.4em; font-weight:bold; margin-bottom:5px;'>{period['temperature']}{period['temperatureUnit']}</div>", unsafe_allow_html=True)

                                        st.markdown(f"<div style='text-align:center; font-size:0.85em; color:#555; line-height: 1.2;'>{period['shortForecast']}</div>", unsafe_allow_html=True)
                                        st.markdown(f"<div style='text-align:center; font-size:0.75em; color:#888; margin-top:8px;'> {period.get('windSpeed', '')} {period.get('windDirection', '')}</div>", unsafe_allow_html=True)

                        with st.expander("View Detailed Forecast Descriptions"):
                            for period in forecast_data[:14]:
                                border_color = '#dc3545' if period['isDaytime'] else '#007bff'
                                st.markdown(f"""
                                <div style="padding: 15px; margin-bottom: 12px; border-left: 5px solid {border_color}; background-color: #f8f9fa; border-radius: 6px; box-shadow: 0 1px 2px rgba(0,0,0,0.05);">
                                    <div style="font-size: 1.05em; font-weight: 600; color: #2c3e50; margin-bottom: 6px;">{period['name']}</div>
                                    <div style="font-size: 0.95em; color: #444; line-height: 1.5;">{period['detailedForecast']}</div>
                                </div>
                                """, unsafe_allow_html=True)
                    else:
                        st.warning("Forecast unavailable for this location. Ensure coordinates are exact.")
                else:
                    st.info("No facilities loaded. Add facilities in Settings to view site forecasts.")

                st.divider()

                st.markdown("###  Predictive Convective Outlooks (SPC)")
                st.caption("NOAA Storm Prediction Center risk areas projected out to 72 hours.")

                d1_tab, d2_tab, d3_tab = st.tabs(["Day 1 (Today)", "Day 2 (Tomorrow)", "Day 3"])

                def render_spc_map(geojson_data):
                    valid_geo = geojson_data if geojson_data and 'features' in geojson_data else {"type": "FeatureCollection", "features": []}

                    if not valid_geo['features']:
                        st.success("No Convective Risk Expected for this period.")

                    color_map = {
                        "TSTM": [192, 232, 192, 150], "MRGL": [124, 205, 124, 180],
                        "SLGT": [246, 246, 123, 180], "ENH": [230, 153, 0, 180],
                        "MDT": [255, 0, 0, 180], "HIGH": [255, 0, 255, 180]
                    }

                    for f in valid_geo['features']:
                        lbl = f.get('properties', {}).get('LABEL', '')
                        f['properties']['fill_color'] = color_map.get(lbl, [0, 0, 0, 0])

                    layer = pdk.Layer(
                        "GeoJsonLayer", valid_geo, pickable=True, stroked=True, filled=True,
                        get_fill_color="properties.fill_color", get_line_color=[0, 0, 0, 255], line_width_min_pixels=1
                    )

                    st.pydeck_chart(pdk.Deck(
                        layers=[layer],
                        initial_view_state=pdk.ViewState(latitude=38.0, longitude=-95.0, zoom=3.5),
                        tooltip={"text": "Risk Level: {LABEL}"}
                    ))

                with d1_tab:
                    render_spc_map(spc_d1)
                with d2_tab:
                    render_spc_map(spc_d2)
                with d3_tab:
                    render_spc_map(spc_d3)

                st.divider()

                st.markdown("###  Live Atmospheric Radar")
                st.components.v1.html("""
                    <iframe src="https://embed.windy.com/embed.html?type=map&location=coordinates&metricRain=in&metricTemp=F&metricWind=mph&zoom=5&overlay=radar&product=radar&level=surface&lat=34.746&lon=-92.289" width="100%" height="500" frameborder="0" style="border-radius: 8px;"></iframe>
                """, height=600)
                st.divider()
            rg_idx += 1
