import streamlit as st
import pandas as pd
from datetime import datetime, timedelta

import src.services as svc
from src.utils.llm import call_llm, generate_siem_triage_summary, generate_elastic_dsl
from src.ui.state_manager import safe_rerun, check_cooldown, apply_cooldown, get_permission_flags, LOCAL_TZ


def render_threat_hunting():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    ai_enabled = sys_config.is_active if sys_config else False

    st.title("Active Threat Hunting & Detection Engineering")
    st.markdown("Automated IOC extraction, 1-Click OSINT Pivoting, and LLM-assisted YARA/SIEM generation.")

    th_tab_names = []

    if "Tab: Threat Hunting -> Global IOC Matrix" in st.session_state.allowed_actions:
        th_tab_names.append("Live Global IOC Matrix")
    if "Tab: Threat Hunting -> Deep Hunt Builder" in st.session_state.allowed_actions:
        th_tab_names.append("Deep Hunt & Detection Builder")
    if "Tab: Reporting -> Elastic SIEM Report" in st.session_state.allowed_actions:
        th_tab_names.append("Elastic SIEM Report")

    if not th_tab_names:
        st.warning("No permission to view tabs in this module.")
    else:
        th_tabs = st.tabs(th_tab_names)
        th_idx = 0

        if "Tab: Threat Hunting -> Global IOC Matrix" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Global Indicators of Compromise (Last 72 Hours)")

                ioc_data = svc.get_iocs(days_back=3)
                if not ioc_data:
                    st.info("No active IOCs extracted in the last 72 hours.")
                else:
                    for ioc in ioc_data:
                        ioc["OSINT Pivot"] = svc.get_osint_pivot_link(ioc["Type"], ioc["Indicator"])

                    df = pd.DataFrame(ioc_data)
                    all_types = sorted(list(set(df["Type"].tolist())))
                    default_types = [t for t in all_types if t in ["IPv4", "SHA256", "Domain", "CVE", "MITRE ATT&CK"]]

                    filter_type = st.multiselect("Filter by Threat Type", all_types, default=default_types if default_types else all_types)
                    filtered_df = df[df["Type"].isin(filter_type)]

                    st.dataframe(
                        filtered_df, width="stretch", hide_index=True,
                        column_config={
                            "Source Article": st.column_config.LinkColumn("Source Intel"),
                            "OSINT Pivot": st.column_config.LinkColumn("Investigate ", display_text="Open Tool"),
                            "Context": st.column_config.TextColumn("Context Snippet", width="large")
                        }
                    )
                    st.download_button(
                        label="Export Hunting Targets (CSV)",
                        data=filtered_df.drop(columns=["OSINT Pivot"]).to_csv(index=False).encode('utf-8'),
                        file_name=f"Hunt_Targets_{datetime.now(LOCAL_TZ).strftime('%Y%m%d')}.csv", mime='text/csv', width="stretch"
                    )
            th_idx += 1

        if "Tab: Threat Hunting -> Deep Hunt Builder" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Targeted LLM Deep Hunt & Detection Engine")
                with st.form("manual_hunt_form"):
                    hunt_target = st.text_input("Target Entity (e.g., 'Volt Typhoon', 'Ivanti Connect Secure')")
                    hunt_depth = st.slider("Historical Depth (Days)", min_value=7, max_value=90, value=30)

                    is_hunt_cooling = check_cooldown("deep_hunt", 60)
                    if st.form_submit_button("Compiling..." if is_hunt_cooling else "Compile Detection Package", type="primary", disabled=not perms["can_trigger_ai"] or is_hunt_cooling, width="stretch"):
                        apply_cooldown("deep_hunt")
                        if not hunt_target:
                            st.error("Please enter a target entity.")
                        elif not ai_enabled:
                            st.error("AI Engine is currently disabled in settings.")
                        else:
                            with st.spinner(f"Scanning the last {hunt_depth} days of telemetry for '{hunt_target}'..."):
                                target_arts = svc.search_articles_for_hunting(hunt_target, hunt_depth)
                                if not target_arts:
                                    st.warning(f"No intelligence found matching '{hunt_target}'.")
                                else:
                                    st.success(f"Found {len(target_arts)} distinct reports. Synthesizing...")
                                    hunt_context = "\n\n".join([f"Source: {a.source}\nTitle: {a.title}\nContent: {a.summary[:400]}" for a in target_arts])

                                    sys_prompt = f"""You are an elite Cyber Threat Detection Engineer. Analyze the reports regarding '{hunt_target}'.
                                    Output EXACTLY:
                                    ### 1. Threat Overview & MITRE TTPs
                                    ### 2. Known Vulnerabilities & Infrastructure
                                    ### 3. Splunk / SIEM Hunt Queries
                                    ### 4. YARA Detection Stub"""

                                    ai_hunt_result = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": hunt_context}], sys_config, temperature=0.1)
                                    if ai_hunt_result:
                                        st.divider()
                                        st.markdown(f"##  Detection Package: {hunt_target.upper()}")
                                        st.markdown(ai_hunt_result)
                                        st.divider()
                                        st.markdown("###  Reference Intel")
                                        for a in target_arts:
                                            st.markdown(f"- [{a.title}]({a.link})")
            th_idx += 1

        if "Tab: Reporting -> Elastic SIEM Report" in st.session_state.allowed_actions:
            with th_tabs[th_idx]:
                st.subheader("Advanced SIEM Fusion & Hunt")
                st.caption("Live, bi-directional telemetry hunt utilizing local AI-assisted query generation.")

                t_dash, t_hunt, t_ai = st.tabs(["Rolling Cache (Fast)", "Live Hunt (API)", "AI Query Builder"])

                with t_dash:
                    c_sync, c_space = st.columns([1, 4])
                    if c_sync.button("Sync Local Cache", width='stretch', type="primary", key="sync_es_cache"):
                        with st.spinner("Polling Elastic Stack..."):
                            from src.elastic_worker import sync_elastic_telemetry, purge_stale_elastic_data
                            sync_elastic_telemetry(hours_back=24)
                            purge_stale_elastic_data(hours_to_keep=72)
                            st.rerun()

                    with svc.SessionLocal() as dbtmp:
                        from src.database import ElasticEvent
                        raw_events = dbtmp.query(ElasticEvent).filter(
                            ElasticEvent.timestamp >= datetime.utcnow() - timedelta(hours=24)
                        ).all()

                    if not raw_events:
                        st.success("No high-severity SIEM alerts logged locally in the last 24 hours.")
                    else:
                        import plotly.express as px

                        df = pd.DataFrame([{
                            "Time": e.timestamp, "Severity": e.severity,
                            "Category": e.event_category, "IP": e.source_ip, "Message": e.message
                        } for e in raw_events])

                        c1, c2, c3 = st.columns(3)
                        c1.metric("Local High/Crit Alerts", len(df))
                        c2.metric("Unique Threat IPs", df['IP'].nunique())
                        c3.metric("Critical Density", f"{int((len(df[df['Severity'] == 'CRITICAL']) / len(df)) * 100)}%")

                        st.dataframe(df.sort_values('Time', ascending=False), hide_index=True, use_container_width=True)

                with t_hunt:
                    st.markdown("###  Live Elastic Hunt")

                    hc1, hc2, hc3 = st.columns(3)
                    hunt_index = hc1.selectbox("Target Index", ["*", "logs-*", ".ds-winlogbeat-*", ".ds-logs-cisco_umbrella*", ".ds-logs-network_traffic*", ".ds-logs-system.security*"])
                    hunt_limit = hc2.number_input("Result Limit (Protect RAM)", min_value=10, max_value=500, value=50)
                    hunt_term = hc3.text_input("Quick Keyword Search", value="")

                    if st.button("Execute Live Hunt", type="primary", use_container_width=True):
                        with st.spinner("Executing query against cluster..."):
                            from src.elastic_worker import execute_live_query

                            if hunt_term:
                                query_body = {"query": {"query_string": {"query": f"*{hunt_term}*"}}, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]}
                            else:
                                query_body = {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]}

                            results = execute_live_query(index_pattern=hunt_index, query_body=query_body, size=hunt_limit)

                            if isinstance(results, dict) and "error" in results:
                                st.error(f"Elastic Error: {results['error']}")
                            elif not results:
                                st.warning("0 Results Found.")
                            else:
                                flat_results = []
                                for r in results:
                                    src = r.get('_source', {})
                                    flat_results.append({
                                        "Time": src.get('@timestamp', ''),
                                        "Severity": src.get('log', {}).get('level', src.get('event', {}).get('severity', 'UNKNOWN')),
                                        "Message": src.get('message', src.get('event', {}).get('original', 'N/A')),
                                        "Source IP": src.get('source', {}).get('ip', 'N/A')
                                    })

                                st.session_state.last_hunt_results = flat_results
                                st.dataframe(flat_results, use_container_width=True)

                    if hasattr(st.session_state, 'last_hunt_results') and st.session_state.last_hunt_results:
                        if st.button("AI Triage & Summarize Results", use_container_width=True):
                            with st.spinner("Analyzing telemetry payload with local model..."):
                                with svc.SessionLocal() as session:
                                    ai_text = generate_siem_triage_summary(session, st.session_state.last_hunt_results)
                                st.info(ai_text)

                with t_ai:
                    st.markdown("###  Natural Language to Elastic DSL")
                    st.caption("Tell the AI what you want to find, and it will generate the perfect JSON query for Elastic.")

                    nl_query = st.text_area("What are you looking for?", placeholder="e.g., Show me all failed Windows logins from outside the US in the last 2 hours.", height=100)

                    if st.button("Generate Query", type="primary"):
                        if not nl_query:
                            st.warning("Enter a prompt first.")
                        else:
                            with st.spinner("Translating intent to Elastic DSL..."):
                                with svc.SessionLocal() as session:
                                    raw_json = generate_elastic_dsl(session, nl_query)

                                st.code(raw_json, language="json")
                                st.success("Query Generated! Copy this and use it in Kibana, or pass it to a custom Live Hunt API call.")
            th_idx += 1
