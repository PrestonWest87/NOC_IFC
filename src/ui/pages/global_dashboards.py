import streamlit as st
import pandas as pd
import time
import json
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from streamlit_autorefresh import st_autorefresh
import pydeck as pdk
import streamlit.components.v1 as components

import src.services as svc
from src.utils.llm import generate_rolling_summary, cross_reference_cves, call_llm, generate_executive_weather_brief, generate_unified_risk_brief
from src.ui.state_manager import safe_rerun, check_cooldown, apply_cooldown, format_local_time, get_score_badge, get_cat_icon, get_permission_flags, LOCAL_TZ


def render_global_dashboards():
    sys_config = svc.get_cached_config()
    ai_enabled = sys_config.is_active if sys_config else False
    perms = get_permission_flags()

    refresh_rate = st.sidebar.selectbox("Live Refresh", ["Off", "10 Seconds", "1 Minute", "5 Minutes"], index=0)
    rmap = {"Off": 0, "10 Seconds": 10, "1 Minute": 60, "5 Minutes": 300}
    current_refresh_sec = rmap[refresh_rate]
    refresh_count = 0
    if current_refresh_sec > 0:
        refresh_count = st_autorefresh(interval=current_refresh_sec * 1000)

    st.title("Global NOC Dashboards")
    dash_tabs = st.tabs(["Operational Dashboard", "Global Risk", "Internal Risk", "Unified Brief"])

    with dash_tabs[0]:
        metrics = svc.get_dashboard_metrics()
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("High-Threat RSS (24h)", metrics["rss_count"])
        c2.metric("Active KEVs (24h)", metrics["cve_count"])
        c3.metric("Hazards (24h)", metrics["hazard_count"])
        c4.metric("Cloud Outages (24h)", metrics["cloud_count"])
        st.divider()

        dash_panels = ["Threat Triage", "Infrastructure Status", "AI Analysis"]
        if "auto_rotate_dash" not in st.session_state:
            st.session_state.auto_rotate_dash = True
        c_tog, c_space = st.columns([1, 5])
        auto_rotate = c_tog.toggle("Auto-Rotate", key="auto_rotate_dash")

        calculated_index = refresh_count % len(dash_panels) if auto_rotate else 0
        selected_panel = st.radio("Views", dash_panels, index=calculated_index, horizontal=True, label_visibility="collapsed")
        st.write("")

        if selected_panel == "Threat Triage":
            col_pin, col_rss = st.columns([1, 1])
            with col_pin:
                st.subheader("Pinned Intel")
                for art in svc.get_pinned_articles():
                    st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small> {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)
                    if art.ai_bluf:
                        st.success(f"**AI BLUF:** {art.ai_bluf}")
                    st.write("")
            with col_rss:
                st.subheader("Live Feed (Top 15)")
                for art in svc.get_live_articles():
                    st.markdown(f"{get_score_badge(art.score)} [{art.title}]({art.link}) <br><small> {art.source} | {get_cat_icon(art.category)} {art.category}</small>", unsafe_allow_html=True)

        elif selected_panel == "Infrastructure Status":
            col_cve, col_cld, col_reg = st.columns(3)
            with col_cve:
                st.subheader("CISA KEVs (Top 15)")
                for cve in svc.get_cves(limit=15):
                    st.markdown(f" **[{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id})**<br><small>{cve.vendor} {cve.product}</small>", unsafe_allow_html=True)
            with col_cld:
                st.subheader("Active Cloud Outages")
                outages = svc.get_cloud_outages(active_only=True, limit=5)
                if not outages:
                    st.success("Clear.")
                for out in outages:
                    st.markdown(f" **{out.provider}**<br><small>[{out.title}]({out.link})</small>", unsafe_allow_html=True)
            with col_reg:
                st.subheader("Regional Hazards")
                hazards = svc.get_hazards(limit=15)
                if not hazards:
                    st.success("Clear.")
                for haz in hazards:
                    icon = "" if haz.severity in ["Extreme", "Severe"] else "" if haz.severity == "Moderate" else ""
                    st.markdown(f"{icon} **{haz.severity}**<br><small>{haz.title} ({haz.location})</small>", unsafe_allow_html=True)

        elif selected_panel == "AI Analysis":
            col_ai1, col_ai2 = st.columns([2, 1])
            with col_ai1:
                st.subheader("AI Shift Briefing")
                if ai_enabled:
                    now = datetime.utcnow()
                    if not sys_config.rolling_summary or not sys_config.rolling_summary_time or (now - sys_config.rolling_summary_time).total_seconds() > 1800:
                        with st.spinner("Updating..."):
                            with svc.SessionLocal() as session:
                                ns = generate_rolling_summary(session)
                            if ns:
                                svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": now})
                    c_time, c_btn = st.columns([3, 2])
                    c_time.caption(f"Last Sync: {format_local_time(sys_config.rolling_summary_time)}")

                    is_ai_refresh_cooling = check_cooldown("ai_refresh", 120)
                    if c_btn.button("Generating..." if is_ai_refresh_cooling else "Force Refresh Briefing", width="stretch", disabled=not perms["can_trigger_ai"] or is_ai_refresh_cooling):
                        apply_cooldown("ai_refresh")
                        with st.spinner("Forcing AI Summary..."):
                            with svc.SessionLocal() as session:
                                ns = generate_rolling_summary(session)
                            if ns:
                                svc.save_global_config({"rolling_summary": ns, "rolling_summary_time": datetime.utcnow()});
                                safe_rerun()
                    st.info(sys_config.rolling_summary if sys_config.rolling_summary else "Initializing...")
                else:
                    st.info("AI Disabled.")

            with col_ai2:
                st.subheader("Security Auditor")
                is_scan_cooling = check_cooldown("ai_scan", 60)
                if st.button("Scanning..." if is_scan_cooling else "Scan Stack Against 30-Day KEVs", width="stretch", disabled=not perms["can_trigger_ai"] or is_scan_cooling):
                    apply_cooldown("ai_scan")
                    with st.spinner("Scanning..."):
                        from src.database import CveItem
                        with svc.SessionLocal() as dbtmp:
                            cves = dbtmp.query(CveItem).filter(CveItem.date_added >= datetime.utcnow() - timedelta(days=30)).all()
                            res = cross_reference_cves(cves, dbtmp)
                        if res and ("clear" in res.lower() or "no active" in res.lower()):
                            st.success(" " + res)
                        else:
                            st.error(f" **MATCH DETECTED:**\n{res}")

    with dash_tabs[1]:
        @st.dialog("CIS Threat Level Legend")
        def show_cis_legend():
            st.markdown("""
            ### Official MS-ISAC / CIS Alert Levels

            **Formula:** `Severity = (Criticality + Lethality)  (System + Network Countermeasures)`

            *  **GREEN (LOW | -8 to -5):** Low risk. Normal probing, low-risk viruses. Continue routine monitoring and patching.
            *  **BLUE (GUARDED | -4 to -2):** General risk of increased hacking/malicious activity. No known severe exploits or significant impacts yet.
            *  **YELLOW (ELEVATED | -1 to +2):** Significant risk. Known vulnerabilities being exploited with moderate damage, or high potential for disruption.
            *  **ORANGE (HIGH | +3 to +5):** High risk targeting core infrastructure. Multiple service outages, critical vulnerabilities actively exploited with significant impact.
            *  **RED (SEVERE | +6 to +8):** Severe risk. Widespread outages, destructive compromises to SCADA/critical systems. Potential for actual loss of life or economic security.
            """)
            if st.button("Close", width='stretch'):
                st.rerun()

        st.subheader("Executive Grid Threat Matrix")

        col_title, col_leg = st.columns([3, 1])
        col_title.caption("Strategic synthesis of Physical and Cyber telemetry measured against a 14-day operational baseline.")
        col_title.caption("Updates every 30 minutes.")
        if col_leg.button("View CIS Threat Legend", width='stretch'):
            show_cis_legend()

        ar_warn = svc.get_cached_geojson()[3] or {}
        oos_warn = svc.get_cached_geojson()[4] or {}
        active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))

        crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
        with svc.SessionLocal() as dbtmp:
            from src.database import ElasticEvent
            recent_siem = dbtmp.query(ElasticEvent).filter(
                ElasticEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
            ).all()

        intel = svc.get_executive_grid_intel(active_nws, crime_data)

        critical_siem_hits = len([e for e in recent_siem if e.severity == "CRITICAL"])
        if critical_siem_hits > 0:
            siem_penalty = min(critical_siem_hits * 3, 20)
            intel['current_cyber_pts'] += siem_penalty
            intel['evidence_log'].append(f"**SIEM Telemetry:** Detected {critical_siem_hits} CRITICAL internal alerts via Elastic, resulting in a +{siem_penalty} pt risk penalty.")

        color_map = {"GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107", "ORANGE": "#fd7e14", "RED": "#dc3545"}
        name_map = {"GREEN": "GREEN (LOW)", "BLUE": "BLUE (GUARDED)", "YELLOW": "YELLOW (ELEVATED)", "ORANGE": "ORANGE (HIGH)", "RED": "RED (SEVERE)"}

        risk_color = color_map.get(intel['unified_risk'].upper(), "#28a745")
        display_risk = name_map.get(intel['unified_risk'].upper(), "UNKNOWN")

        st.markdown(f"""
        <div style='text-align: center; padding: 20px; background-color: #1e1e1e; border-radius: 10px; border: 2px solid {risk_color}; margin-bottom: 20px;'>
            <h3 style='margin:0; color: #a0a0a0;'>GLOBAL THREAT POSTURE (CIS STANDARD)</h3>
            <h1 style='margin:0; font-size: 3rem; color: {risk_color};'>{display_risk}</h1>
            <p style='margin:0; color: #a0a0a0;'>Last Updated: {intel['timestamp']}</p>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("View 14-Day CIS Alert Level Trend", expanded=True):
            history = svc.get_historical_threat_scores(14)
            if not history:
                st.info("Gathering baseline telemetry. Graph will populate tomorrow.")
            else:
                dates = [h.record_date for h in history]
                cyber_pts = [h.cyber_points for h in history]
                phys_pts = [h.physical_points for h in history]

                if dates and dates[-1].date() == datetime.utcnow().date():
                    cyber_pts[-1] = intel['current_cyber_pts']
                    phys_pts[-1] = intel['current_phys_pts']

                chart_data = pd.DataFrame({
                    "Date": dates,
                    "Cyber CIS Score": cyber_pts,
                    "Physical CIS Score": phys_pts
                }).set_index("Date")
                st.line_chart(chart_data, color=["#00b4d8", "#ff9f1c"])

                st.caption(f"**Cyber:** {intel['current_cyber_pts']} ({intel['cyber_score']}) | **Physical:** {intel['current_phys_pts']} ({intel['physical_score']}) | **Unified:** {intel['unified_risk']}")

                col_ref1, col_ref2, col_ref3, col_ref4, col_ref5 = st.columns(5)
                with col_ref1:
                    st.markdown("<div style='background-color:#28a745;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>GREEN<br>-8 to -5</div>", unsafe_allow_html=True)
                with col_ref2:
                    st.markdown("<div style='background-color:#007bff;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>BLUE<br>-4 to -2</div>", unsafe_allow_html=True)
                with col_ref3:
                    st.markdown("<div style='background-color:#ffc107;padding:5px;border-radius:5px;text-align:center;color:black;font-size:12px;'>YELLOW<br>-1 to +2</div>", unsafe_allow_html=True)
                with col_ref4:
                    st.markdown("<div style='background-color:#fd7e14;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>ORANGE<br>+3 to +5</div>", unsafe_allow_html=True)
                with col_ref5:
                    st.markdown("<div style='background-color:#dc3545;padding:5px;border-radius:5px;text-align:center;color:white;font-size:12px;'>RED<br>+6 to +8</div>", unsafe_allow_html=True)

        st.divider()

        col_phys, col_cyber = st.columns(2)
        with col_phys:
            st.subheader("Physical & Perimeter (1 Mile)")
            st.info(f"**Risk Level: {intel['physical_score']}**")
            st.write(intel['physical_brief'])

            phys_sources = intel.get('raw_phys_articles', [])
            if phys_sources:
                with st.expander("View Contributing Physical Intelligence"):
                    for src in phys_sources[:15]:
                        st.markdown(f"- [{src.title}]({src.link}) <small>({src.source})</small>", unsafe_allow_html=True)

            if intel.get("recent_crimes"):
                st.markdown("** Grid-Relevant Perimeter Incidents:**")
                for c in intel["recent_crimes"][:5]:
                    st.caption(f" **{c.get('fbi_category', 'Incident')}:** {c['raw_title']} ({c['distance_miles']} mi) - *{c['timestamp']}*")
                if len(intel["recent_crimes"]) > 5:
                    st.caption(f"...and {len(intel['recent_crimes']) - 5} more (See Threat Telemetry).")

        with col_cyber:
            st.subheader("Cyber & SCADA (48 Hours)")
            st.warning(f"**Risk Level: {intel['cyber_score']}**")
            st.write(intel['cyber_brief'])

            with st.expander("View CIS Macroscopic Variables"):
                st.markdown("**Formula:** `Severity = (Criticality + Lethality) - (System + Network Countermeasures)`")
                st.markdown(f"**Current Aggregate Score:** `{intel['cis_cyber_score']}`")
                st.divider()
                for log in intel.get('evidence_log', []):
                    st.markdown(log)

            cyber_sources = intel.get('raw_cyber_articles', [])
            if cyber_sources:
                with st.expander("View Contributing Cyber Intelligence"):
                    for src in cyber_sources[:15]:
                        tag = "APT" if getattr(src, 'is_apt_related', False) else "Ransomware" if getattr(src, 'is_ransomware', False) else ""
                        st.markdown(f"- **{tag}** [{src.title}]({src.link}) <small>({src.source})</small>", unsafe_allow_html=True)
        st.divider()
        st.subheader("Dynamic Scoring Overview")
        st.caption("AI-generated synthesis of all live telemetry detailing the exact reasoning behind the current threat score.")

        c_score_btn, c_score_space = st.columns([1, 3])
        is_scoring_cooling = check_cooldown("ai_scoring_report", 60)

        if c_score_btn.button("Generating..." if is_scoring_cooling else "Generate Scoring Rationale", disabled=not perms["can_trigger_ai"] or is_scoring_cooling, width="stretch", type="primary"):
            apply_cooldown("ai_scoring_report")
            with st.spinner("Analyzing threat weights and compiling expansive scoring rationale..."):
                from src.utils.llm import generate_dynamic_scoring_report
                with svc.SessionLocal() as session:
                    rep = generate_dynamic_scoring_report(session, intel)
                st.session_state.scored_overview = rep
                st.session_state.scored_overview_risk = intel['unified_risk']

        if "scored_overview" in st.session_state:
            if st.session_state.get("scored_overview_risk") != intel['unified_risk']:
                st.warning(f"The Executive Threat Matrix posture has shifted to **{intel['unified_risk']}** since this rationale was generated. Please regenerate the report to reflect the latest telemetry.")

            with st.container(border=True):
                st.markdown(st.session_state.scored_overview)

        st.divider()
        st.subheader("Dispatch Intelligence Report")
        col_email, col_btn = st.columns([3, 1])
        default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
        target_email = col_email.text_input("Recipient Email Address", value=default_email, label_visibility="collapsed")

        if col_btn.button("Send AI Scoring Report", width='stretch', type="primary", disabled=not perms["can_dispatch_report"]):
            if target_email:
                with st.spinner("Generating AI Analysis and Transmitting..."):
                    from src.utils.llm import generate_dynamic_scoring_report
                    from src.utils.mailer import send_alert_email

                    rep = st.session_state.get("scored_overview")
                    if not rep or st.session_state.get("scored_overview_risk") != intel['unified_risk']:
                        with svc.SessionLocal() as session:
                            rep = generate_dynamic_scoring_report(session, intel)
                        st.session_state.scored_overview = rep
                        st.session_state.scored_overview_risk = intel['unified_risk']

                    def md_to_html(md):
                        md = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', md)
                        lines = md.split('\n')
                        html_lines = []
                        in_ul = False

                        for line in lines:
                            stripped = line.strip()
                            if not stripped:
                                if in_ul:
                                    html_lines.append("</ul>");
                                    in_ul = False
                                html_lines.append("<br>")
                                continue

                            if stripped.startswith('### '):
                                if in_ul:
                                    html_lines.append("</ul>");
                                    in_ul = False
                                html_lines.append(f"<h4 style='color:#34495e; margin-top:15px; margin-bottom:5px;'>{stripped[4:]}</h4>")
                            elif stripped.startswith('## '):
                                if in_ul:
                                    html_lines.append("</ul>");
                                    in_ul = False
                                html_lines.append(f"<h3 style='color:#2c3e50; border-bottom:1px solid #ecf0f1; padding-bottom:5px; margin-top:20px;'>{stripped[3:]}</h3>")
                            elif stripped.startswith('# '):
                                if in_ul:
                                    html_lines.append("</ul>");
                                    in_ul = False
                                html_lines.append(f"<h2 style='color:#2980b9; margin-top:20px;'>{stripped[2:]}</h2>")
                            elif stripped.startswith('- ') or stripped.startswith('* '):
                                if not in_ul:
                                    html_lines.append("<ul style='margin-top:5px; padding-left:20px;'>");
                                    in_ul = True
                                html_lines.append(f"<li style='margin-bottom:8px;'>{stripped[2:]}</li>")
                            elif re.match(r'^\d+\.\s', stripped):
                                if not in_ul:
                                    html_lines.append("<ul style='margin-top:5px; padding-left:20px; list-style-type:decimal;'>");
                                    in_ul = True
                                content = re.sub(r'^\d+\.\s', '', stripped)
                                html_lines.append(f"<li style='margin-bottom:8px;'>{content}</li>")
                            else:
                                if in_ul:
                                    html_lines.append("</ul>");
                                    in_ul = False
                                html_lines.append(f"<p style='margin-top:0; margin-bottom:10px; line-height:1.6;'>{stripped}</p>")

                        if in_ul:
                            html_lines.append("</ul>")
                        return "".join(html_lines)

                    formatted_content = md_to_html(rep)

                    email_color_map = {
                        "GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107",
                        "ORANGE": "#fd7e14", "RED": "#dc3545"
                    }
                    uni_color = email_color_map.get(intel['unified_risk'].upper(), "#333333")
                    cyb_color = email_color_map.get(intel['cyber_score'].upper(), "#333333")
                    phy_color = email_color_map.get(intel['physical_score'].upper(), "#333333")

                    html_body = f"""
                    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; color: #333;">

                        <table width="100%" cellpadding="15" cellspacing="0" style="margin-bottom: 25px; text-align: center; background: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px;">
                            <tr>
                                <th colspan="2" style="background-color: {uni_color}; color: #ffffff; border-radius: 8px 8px 0 0; padding: 15px; font-size: 22px; font-weight: bold; letter-spacing: 1px;">
                                    UNIFIED THREAT POSTURE: {intel['unified_risk']}
                                </th>
                            </tr>
                            <tr>
                                <td width="50%" style="border-right: 1px solid #e0e0e0;">
                                    <span style="font-size: 11px; color: #7f8c8d; text-transform: uppercase; font-weight: bold;">Cyber & SCADA Risk</span><br>
                                    <strong style="font-size: 20px; color: {cyb_color};">{intel['cyber_score']}</strong>
                                </td>
                                <td width="50%">
                                    <span style="font-size: 11px; color: #7f8c8d; text-transform: uppercase; font-weight: bold;">Physical & Perimeter Risk</span><br>
                                    <strong style="font-size: 20px; color: {phy_color};">{intel['physical_score']}</strong>
                                </td>
                            </tr>
                        </table>

                        <div style="background-color: #f8f9fa; padding: 25px; border-radius: 8px; border-left: 5px solid #2980b9;">
                            {formatted_content}
                        </div>

                        <p style="text-align: center; color: #7f8c8d; font-size: 12px; margin-top: 20px;">Generated dynamically by NOC Intelligence Fusion Center</p>
                    </div>
                    """

                    success, msg = send_alert_email(f"Executive Threat Posture: {intel['unified_risk']}", html_body, recipient_override=target_email, is_html=True)
                    if success:
                        st.success(f"Report dispatched to {target_email}")
                    else:
                        st.error(f"SMTP Error: {msg}")
            else:
                st.warning("Please enter a recipient email address.")

    with dash_tabs[2]:
        col_title, col_admin_btn = st.columns([4, 1])

        with col_title:
            st.subheader("Internal Asset Risk Dashboard")
            st.caption("Active correlation of internal assets against OSINT telemetry (Auto-updates every 6 hours).")

        with col_admin_btn:
            if st.session_state.current_role == "admin":
                is_snap_cooling = check_cooldown("force_internal_snap", 30)
                if st.button("Processing..." if is_snap_cooling else "Force Generate", type="primary", width='stretch', disabled=is_snap_cooling):
                    apply_cooldown("force_internal_snap")
                    with st.spinner("Calculating matrices..."):
                        svc.generate_and_save_internal_risk_snapshot()
                        time.sleep(0.5)
                        safe_rerun()

        with svc.SessionLocal() as dbtmp:
            from src.database import InternalRiskSnapshot
            snapshots = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).limit(28).all()

        if not snapshots:
            st.info("Internal Risk matrices are currently calculating. Please check back in a few minutes.")
            if st.button("Trigger Manual Calculation"):
                svc.generate_and_save_internal_risk_snapshot()
                st.success("Generated! Refreshing...")
                time.sleep(1)
                safe_rerun()
        else:
            latest = snapshots[0]

            hw_data = json.loads(latest.hw_data_json)
            sw_data = json.loads(latest.sw_data_json)

            color_map = {"GREEN": "#28a745", "BLUE": "#007bff", "YELLOW": "#ffc107", "ORANGE": "#fd7e14", "RED": "#dc3545"}
            name_map = {"GREEN": "GREEN (LOW)", "BLUE": "BLUE (GUARDED)", "YELLOW": "YELLOW (ELEVATED)", "ORANGE": "ORANGE (HIGH)", "RED": "RED (SEVERE)"}

            safe_risk_level = str(latest.risk_level).upper()
            score_color = color_map.get(safe_risk_level, "#6c757d")
            display_risk = name_map.get(safe_risk_level, "UNKNOWN")

            st.markdown(f"""
            <div style='text-align: center; padding: 20px; background-color: #1e1e1e; border-radius: 10px; border: 2px solid {score_color}; margin-bottom: 20px;'>
                <h3 style='margin:0; color: #a0a0a0;'>INTERNAL ASSET POSTURE (CIS STANDARD)</h3>
                <h1 style='margin:0; font-size: 3rem; color: {score_color};'>{display_risk} [{latest.score}]</h1>
                <p style='margin:0; color: #a0a0a0;'>Analyzed {latest.total_assets} total assets against OSINT feeds.</p>
                <p style='margin:0; color: #a0a0a0; font-size: 0.9em; margin-top: 10px;'><i>Last Updated: {format_local_time(latest.timestamp)}</i></p>
            </div>
            """, unsafe_allow_html=True)

            c1, c2, c3 = st.columns(3)
            c1.metric("Total Asset Footprint", latest.total_assets)
            c2.metric("Total OSINT Correlations", latest.total_osint_hits)
            c3.metric("Critical OSINT Hits", latest.critical_osint_hits, delta_color="inverse")
            st.divider()

            st.markdown("###  Historical Threat Trend")

            df_chart = pd.DataFrame([{"Time": s.timestamp, "CIS Risk Score": s.score} for s in snapshots])
            df_chart.set_index("Time", inplace=True)
            df_chart.sort_index(inplace=True)

            st.line_chart(df_chart, width='stretch', color="#dc3545")
            st.divider()

            st.markdown("###  Hardware Assets")
            with st.expander("View Hardware Inventory & OSINT Correlations", expanded=True):
                at_risk_hw = [h for h in hw_data if h['OSINT Threat Matches'] > 0]

                if at_risk_hw:
                    df_hw = pd.DataFrame(at_risk_hw)
                    st.warning(f"Detected {len(at_risk_hw)} hardware assets actively exposed to recent OSINT intelligence.")
                    st.dataframe(df_hw, width="stretch", hide_index=True)
                elif len(hw_data) > 0:
                    st.success("All tracked hardware assets are currently clear of recent OSINT correlations.")
                else:
                    st.info("No hardware assets loaded. Go to Settings -> Internal Assets to import your inventory.")

            st.divider()

            st.markdown("###  Software Assets")
            with st.expander("View At-Risk Software", expanded=True):
                if sw_data:
                    df_sw = pd.DataFrame(sw_data)
                    st.warning(f"Detected {len(df_sw)} software assets actively exposed to recent OSINT intelligence.")
                    st.dataframe(df_sw, width="stretch", hide_index=True)
                else:
                    st.success("All tracked software assets are currently clear of recent OSINT correlations.")

    with dash_tabs[3]:
        st.subheader("Executive Unified Risk Brief")
        st.caption("AI-generated synthesis of Global OSINT Threats and Internal Asset Vulnerabilities. Auto-updates every 2 hours.")

        col_btn, _ = st.columns([1, 4])
        is_brief_cooling = check_cooldown("unified_brief", 60)

        if col_btn.button("Generating..." if is_brief_cooling else "Force Refresh Brief", disabled=not perms["can_trigger_ai"] or is_brief_cooling, type="primary"):
            apply_cooldown("unified_brief")
            with st.spinner("Synthesizing Pre-Calculated Global and Internal telemetry..."):
                from src.database import InternalRiskSnapshot
                with svc.SessionLocal() as dbtmp:
                    latest_internal = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()

                ar_warn = svc.get_cached_geojson()[3] or {}
                oos_warn = svc.get_cached_geojson()[4] or {}
                active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
                crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
                global_intel = svc.get_executive_grid_intel(active_nws, crime_data)

                with svc.SessionLocal() as session:
                    brief_text = generate_unified_risk_brief(session, global_intel, latest_internal)

                svc.save_global_config({
                    "unified_brief": brief_text,
                    "unified_brief_time": datetime.utcnow()
                })
                time.sleep(0.5)
                safe_rerun()

        st.divider()

        if sys_config and getattr(sys_config, 'unified_brief', None):
            local_b_time = format_local_time(sys_config.unified_brief_time) if sys_config.unified_brief_time else "Unknown"

            with st.container(border=True):
                st.caption(f" **Last Auto-Generated:** {local_b_time}")
                st.markdown(sys_config.unified_brief)

            st.divider()

            st.subheader("Broadcast Executive Brief")
            c_em1, c_em2 = st.columns([3, 1])
            default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
            ub_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="ub_recip")

            if c_em2.button("Transmit Brief", type="primary", width='stretch'):
                if not ub_recipients:
                    st.error("Please enter at least one recipient email.")
                else:
                    with st.spinner("Converting formatting and transmitting..."):
                        from src.database import InternalRiskSnapshot
                        current_global = None
                        current_internal = None

                        with svc.SessionLocal() as dbtmp:
                            latest_internal = dbtmp.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
                            if latest_internal:
                                current_internal = latest_internal.risk_level

                            ar_warn, oos_warn, _ = svc.get_cached_geojson()[3:6]
                            active_nws = len(ar_warn.get("features", [])) + len(oos_warn.get("features", []))
                            crime_data = svc.get_recent_crimes(max_distance=1.0, grid_only=True, hours_back=24)
                            global_intel = svc.get_executive_grid_intel(active_nws, crime_data)
                            current_global = global_intel.get('unified_risk')

                        formatted_html = svc.generate_unified_brief_email_html(
                            local_b_time, sys_config.unified_brief,
                            global_risk=current_global,
                            internal_risk=current_internal
                        )
                        from src.utils.mailer import send_alert_email
                        success, msg = send_alert_email("Executive Unified Risk Brief", formatted_html, recipient_override=ub_recipients, is_html=True)
                        if success:
                            st.success("Brief successfully transmitted!")
                        else:
                            st.error(f"SMTP Error: {msg}")
        else:
            st.info("Brief is currently being generated by the background scheduler. Please check back shortly or click Force Refresh.")
