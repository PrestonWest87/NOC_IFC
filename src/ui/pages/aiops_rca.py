import streamlit as st
import pandas as pd
import time
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from streamlit_autorefresh import st_autorefresh
import pydeck as pdk

import src.services as svc
from src.ui.state_manager import safe_rerun, check_cooldown, apply_cooldown, get_permission_flags, get_black_ops_state, LOCAL_TZ


def render_aiops_rca():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    black_ops = get_black_ops_state()

    st.title("AIOps Root Cause Analysis")
    st.caption("Live correlation of non-uniform monitoring alerts with Regional Intelligence.")

    from src.services.aiops_engine import EnterpriseAIOpsEngine
    ai_engine = EnterpriseAIOpsEngine(svc.SessionLocal)

    ai_tab_names = []

    if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions:
        ai_tab_names.append("Active Board")
    if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions:
        ai_tab_names.append("Patterns")
    if "Tab: AIOps RCA -> Global Correlation" in st.session_state.allowed_actions:
        ai_tab_names.append("Global")

    if not ai_tab_names:
        st.warning("No permission to view tabs in this module.")
    else:
        ai_tabs = st.tabs(ai_tab_names)
        ai_idx = 0

        if "Tab: AIOps RCA -> Active Board" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                c_head, c_tog = st.columns([5, 1])
                with c_tog:
                    live_polling = st.toggle("Live 5s Polling", value=True, key="aiops_live_poll")

                if live_polling:
                    st_autorefresh(interval=5000, key="aiops_5sec_refresh")

                alerts, events, grid = svc.get_aiops_dashboard_data()
                c_l, c_s = st.columns([3, 1])
                with c_s:
                    st.subheader("Event Log")
                    st.divider()
                    for e in events:
                        local_time = e.timestamp.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ)
                        time_str = local_time.strftime('%I:%M %p')
                        clean_msg = re.sub(r'[\U00010000-\U0010ffff]', '', e.message)
                        clean_msg = clean_msg.replace('?', '').strip()
                        st.caption(f"{time_str} | {clean_msg}")

                with c_l:
                    st.subheader("Overlays")
                    locs = svc.get_cached_locations()
                    if st.session_state.allowed_site_types != "ALL":
                        locs = [l for l in locs if l.loc_type in st.session_state.allowed_site_types]
                        allowed_loc_names = {l.name for l in locs}
                        alerts = [a for a in alerts if a.mapped_location in allowed_loc_names]

                    if black_ops["dean_target"] == st.session_state.current_user:
                        start_t = black_ops["dean_start"]
                        elapsed = time.time() - start_t
                        num_fake_reds = int(elapsed // 30)

                        if locs and num_fake_reds >= len(locs):
                            black_ops["dean_target"] = None
                            st.toast("Operation: Dean complete. Grid reverted to normal.")
                        elif locs:
                            import random
                            rng = random.Random(int(start_t))
                            fake_locs = rng.sample(locs, min(num_fake_reds, len(locs)))

                            class FakeAlert:
                                def __init__(self, name):
                                    self.mapped_location = name

                            for fl in fake_locs:
                                alerts.append(FakeAlert(fl.name))

                    layers, view_state = svc.build_aiops_map_layers(alerts, locs)

                    st.pydeck_chart(pdk.Deck(
                        layers=layers,
                        initial_view_state=view_state,
                        tooltip={"text": "{name}"}
                    ))

                    st.subheader("Correlation")
                    if not alerts:
                        st.success("Grid Operational.")
                    else:
                        with svc.SessionLocal() as dbtmp:
                            from src.database import RegionalHazard, CloudOutage, BgpAnomaly, SolarWindsAlert
                            wea = dbtmp.query(RegionalHazard).all()
                            cld = dbtmp.query(CloudOutage).filter_by(is_resolved=False).all()
                            bgp = dbtmp.query(BgpAnomaly).filter_by(is_resolved=False).all()
                            raw_alerts = dbtmp.query(SolarWindsAlert).filter(SolarWindsAlert.is_correlated == False, SolarWindsAlert.status != 'Resolved').all()

                        if st.session_state.allowed_site_types != "ALL":
                            raw_alerts = [a for a in raw_alerts if a.mapped_location in allowed_loc_names]

                        incidents = ai_engine.analyze_and_cluster(raw_alerts)

                        fleet_events = ai_engine.identify_fleet_outages(incidents, threshold=5)

                        if fleet_events:
                            for event in fleet_events:
                                st.markdown(f"""
                                <div style='background-color: #4a0000; border: 2px solid #ff4b4b; border-radius: 8px; padding: 15px; margin-bottom: 20px; text-align: center;'>
                                    <h2 style='color: #ff4b4b; margin: 0;'> GLOBAL FLEET EVENT DETECTED</h2>
                                    <p style='color: white; font-size: 1.1rem; margin: 5px 0 0 0;'>
                                        Massive <b>{event['provider']}</b> Carrier Outage affecting <b>{len(event['affected_sites'])}</b> tracked sites.
                                        Individual downstream RCAs have been automatically overridden.
                                    </p>
                                </div>
                                """, unsafe_allow_html=True)

                        for site, data in incidents.items():
                            c, cf, p, e, b, p0, cs = ai_engine.calculate_root_cause(
                                site_name=site,
                                data=data,
                                active_weather=wea,
                                active_cloud=cld,
                                active_bgp=bgp,
                                fleet_events=fleet_events
                            )

                            with st.container(border=True):
                                st.markdown(f"### {p} | Site: {site}")
                                st.warning(c)

                                if p0:
                                    st.error(f"**Patient Zero (Suspected Origin Node):** {p0}")
                                else:
                                    st.info("**Patient Zero:** Indeterminate (Simultaneous Failure)")

                                site_record = next((l for l in locs if l.name == site), None)
                                if site_record and getattr(site_record, 'under_maintenance', False):
                                    etr_str = site_record.maintenance_etr.strftime('%Y-%m-%d') if site_record.maintenance_etr else "Unknown"
                                    rsn_str = site_record.maintenance_reason or "No reason provided."
                                    st.warning(f" **SITE UNDER MAINTENANCE** (ETR: {etr_str})\n\n**Reason:** {rsn_str}")

                                perms["can_dispatch_rca"] = "Action: Dispatch RCA Tickets" in st.session_state.allowed_actions
                                can_dispatch = perms["can_dispatch_rca"]

                                is_dispatched = any(getattr(a, 'is_dispatched', False) for a in data['alerts'])
                                if can_dispatch:
                                    new_dispatch = st.checkbox("Ticket Dispatched", value=is_dispatched, key=f"disp_{site}")
                                    if new_dispatch != is_dispatched:
                                        svc.set_cluster_dispatch([a.id for a in data['alerts']], new_dispatch)
                                        st.rerun()
                                else:
                                    if is_dispatched:
                                        st.success("Ticket Dispatched")

                                if can_dispatch:
                                    with st.expander(f"Draft & Dispatch Ticket for {site}"):
                                        clean_p = p.replace("??", "").replace("??", "").replace("??", "").replace("??", "").replace("??", "").strip()
                                        clean_c = c.replace("??", "").replace("???", "").replace("?", "").replace("??", "").replace("??", "").strip()
                                        clean_p0 = p0 if p0 else "Indeterminate (Simultaneous Failure)"

                                        ticket_text = svc.generate_rca_ticket_text(site, data, clean_p, clean_p0, clean_c)
                                        ticket_body = st.text_area("Ticket Notes / RCA Summary", value=ticket_text, height=350, key=f"t_body_{site}")

                                        fixed_recipients = "remedyforceworkflow@aecc.com, noc@aecc.com"
                                        st.info(f"Ticket will be automatically dispatched to: **{fixed_recipients}**")

                                        if st.button("Dispatch Ticket", key=f"t_send_{site}", width='stretch'):
                                            from src.utils.mailer import send_alert_email
                                            with st.spinner("Dispatching to RemedyForce & NOC..."):
                                                success, msg = send_alert_email(f"URGENT: {clean_p} Incident at {site}", ticket_body, fixed_recipients, is_html=False)
                                                if success:
                                                    st.success("Ticket Dispatched successfully!")
                                                else:
                                                    st.error(f"SMTP Error: {msg}")

                                    if st.button(f"Acknowledge Incident & Clear Board ({site})", key=f"ack_{site}", width="stretch"):
                                        svc.acknowledge_cluster([a.id for a in data['alerts']])
                                        safe_rerun()

                                if perms["can_manage_maint"]:
                                    if site_record:
                                        with st.expander(f"Maintenance Controls: {site}"):
                                            is_under_maint = getattr(site_record, 'under_maintenance', False)
                                            m_stat = st.selectbox("Maintenance Status", ["Active Maintenance", "No Maintenance"], index=0 if is_under_maint else 1, key=f"ms_{site}")

                                            etr_val = site_record.maintenance_etr.date() if getattr(site_record, 'maintenance_etr', None) else datetime.today().date()
                                            m_etr = st.date_input("Estimated Time of Restoration (ETR)", value=etr_val, key=f"metr_{site}")

                                            m_rsn = st.text_area("Reason / Explanation", value=site_record.maintenance_reason or "", key=f"mrsn_{site}")

                                            if st.button("Save Maintenance Update", key=f"msave_{site}", type="primary", width="stretch"):
                                                svc.set_site_maintenance(site, m_stat == "Active Maintenance", m_etr, m_rsn)
                                                st.success("Maintenance details saved!")
                                                time.sleep(0.5)
                                                safe_rerun()
                                    else:
                                        st.info("Site not registered in Facilities database; maintenance cannot be tracked.")
            ai_idx += 1
        if "Tab: AIOps RCA -> Predictive Analytics" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                st.subheader("Predictive Analytics & Chronic Degradation")
                st.markdown("Analyzes historical telemetry to identify degrading hardware and unstable infrastructure *before* catastrophic failure.")

                is_analytics_cooling = check_cooldown("ai_analytics", 60)
                if st.button("Processing..." if is_analytics_cooling else "Run Deep Analysis", type="primary", width="stretch", disabled=is_analytics_cooling):
                    apply_cooldown("ai_analytics")
                    with st.spinner("Crunching historical telemetry and calculating failure probabilities..."):
                        f, v, r = ai_engine.generate_chronic_insights()

                        if f is None or (isinstance(f, pd.DataFrame) and f.empty):
                            st.success("No chronic degradation patterns detected in the current telemetry window.")
                        else:
                            st.divider()
                            col_f, col_v = st.columns(2)

                            with col_f:
                                st.markdown("###  Top Offending Nodes")
                                st.caption("Specific devices exhibiting high frequency of state-flapping.")
                                st.dataframe(f, width="stretch", hide_index=True)

                            with col_v:
                                st.markdown("###  Infrastructure Hotspots")
                                st.caption("Sites or regions experiencing chronic instability.")
                                if v is not None and not (isinstance(v, pd.DataFrame) and v.empty):
                                    st.dataframe(v, width="stretch", hide_index=True)
                                else:
                                    st.info("Insufficient data for site heatmapping.")

                            st.divider()
                            st.markdown("###  AI Predictive Maintenance Forecast")
                            with st.container(border=True):
                                if r is not None:
                                    if isinstance(r, str):
                                        st.markdown(r)
                                    elif isinstance(r, pd.DataFrame):
                                        st.dataframe(r, width="stretch", hide_index=True)
                                    elif isinstance(r, list):
                                        for item in r:
                                            st.markdown(f"- {item}")
                                else:
                                    st.info("System is nominal. No preventative actions recommended at this time.")
            ai_idx += 1

        if "Tab: AIOps RCA -> Global Correlation" in st.session_state.allowed_actions:
            with ai_tabs[ai_idx]:
                st.subheader("Deterministic Global Correlation Engine")
                st.markdown("Calculates causation graphs based on geospatial math and telemetry overlays across all domains.")

                c_glob1, c_glob2 = st.columns([3, 1])

                is_global_rca_cooling = check_cooldown("global_rca", 60)
                if c_glob2.button("Calculating..." if is_global_rca_cooling else "Run Global Correlation", type="primary", width="stretch", disabled=is_global_rca_cooling):
                    apply_cooldown("global_rca")
                    with st.spinner("Calculating Multi-Domain Causal Links..."):
                        report = svc.generate_global_sitrep(sys_config)
                        st.session_state.last_global_rca = report

                if "last_global_rca" in st.session_state:
                    st.divider()
                    with st.container(border=True):
                        st.markdown(st.session_state.last_global_rca)

                    c_em1, c_em2 = st.columns([1, 4])
                    if c_em1.button("Broadcast SitRep", width="stretch"):
                        from src.utils.mailer import send_alert_email
                        with st.spinner("Transmitting via SMTP..."):
                            success, msg = send_alert_email("URGENT: Multi-Domain Global SitRep", st.session_state.last_global_rca)
                            if success:
                                st.success(msg)
                            else:
                                st.error(msg)
            ai_idx += 1
