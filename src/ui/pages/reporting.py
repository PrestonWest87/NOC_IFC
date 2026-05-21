import streamlit as st
import time
from datetime import datetime, timedelta

import src.services as svc
from src.ui.state_manager import (
    safe_rerun, check_cooldown, apply_cooldown,
    format_local_time, get_permission_flags, LOCAL_TZ
)


def render_reporting():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    ai_enabled = sys_config.is_active if sys_config else False

    current_user_obj = svc.get_user_by_username(st.session_state.current_user)

    st.title("Intelligence Reporting & Briefings")

    rc_tab_names = []

    if "Tab: Reporting -> Daily Fusion" in st.session_state.allowed_actions:
        rc_tab_names.append("Daily Fusion Briefing")
    if "Tab: Reporting -> Report Builder" in st.session_state.allowed_actions:
        rc_tab_names.append("Custom Report Builder")
    if "Tab: Reporting -> Shared Library" in st.session_state.allowed_actions:
        rc_tab_names.append("Shared Library")

    if not rc_tab_names:
        st.warning("No permission to view tabs in this module.")
    else:
        tabs = st.tabs(rc_tab_names)
        tab_idx = 0

        if "Tab: Reporting -> Daily Fusion" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Daily Master Fusion Report")
                st.markdown("AI-synthesized situational report covering Cyber, Vulnerabilities, Physical Hazards, and Cloud Infrastructure.")

                yesterday_local = (datetime.now(LOCAL_TZ) - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
                yesterday_str = yesterday_local.strftime('%Y-%m-%d')
                all_reports = svc.get_all_daily_briefings()
                has_yesterday = any(r.report_date.strftime('%Y-%m-%d') == yesterday_str for r in all_reports)

                col1, col2 = st.columns([3, 1])
                with col2:
                    if not has_yesterday:
                        is_report_cooling = check_cooldown("gen_report", 300)
                        if st.button("Compiling Data..." if is_report_cooling else "Generate Yesterday's Report", width="stretch", type="primary", disabled=not perms["can_trigger_ai"] or is_report_cooling):
                            if not ai_enabled:
                                st.error("AI is disabled.")
                            else:
                                apply_cooldown("gen_report")
                                with st.spinner("Processing massive datasets..."):
                                    from src.utils.llm import generate_daily_fusion_report
                                    with svc.SessionLocal() as session:
                                        date_obj, report_markdown = generate_daily_fusion_report(session)
                                    if report_markdown:
                                        svc.save_daily_briefing(date_obj, report_markdown)
                                        st.success("Report Generated!")
                                        time.sleep(1)
                                        safe_rerun()
                    else:
                        st.success("Latest report is ready for review.")

                st.divider()

                if not all_reports:
                    st.info("No historical reports found. Click the generation button above to synthesize your first shift briefing.")
                else:
                    report_options = {r.report_date.strftime('%A, %B %d, %Y'): r for r in all_reports}
                    c_sel, c_space = st.columns([2, 3])
                    selected_date = c_sel.selectbox("Select Historical Briefing", options=list(report_options.keys()), index=0)
                    selected_report = report_options[selected_date]

                    with st.container(border=True):
                        st.markdown(selected_report.content)

                    st.divider()
                    st.subheader("Broadcast Report")
                    st.caption("Send this report via email. Markdown formatting will be natively converted to HTML and emojis will be preserved.")

                    c_em1, c_em2 = st.columns([3, 1])
                    default_email = sys_config.smtp_recipient if sys_config and sys_config.smtp_recipient else ""
                    report_recipients = c_em1.text_input("Recipient Email(s)", value=default_email, key="report_recip")

                    if c_em2.button("Transmit Report", type="primary", width='stretch'):
                        if not report_recipients:
                            st.error("Please enter at least one recipient email.")
                        else:
                            with st.spinner("Converting formatting and transmitting report..."):
                                formatted_html = svc.generate_daily_report_email_html(selected_date, selected_report.content)
                                from src.utils.mailer import send_alert_email
                                success, msg = send_alert_email(f"Daily Fusion Report - {selected_date}", formatted_html, recipient_override=report_recipients, is_html=True)
                                if success:
                                    st.success("Report successfully transmitted!")
                                else:
                                    st.error(f"SMTP Error: {msg}")
            tab_idx += 1

        if "Tab: Reporting -> Report Builder" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Custom Intel Report Builder")
                if "generated_report" not in st.session_state:
                    st.session_state.generated_report = None

                c_s, c_l = st.columns([3, 1])
                sq = c_s.text_input("Search Articles")
                sl = c_l.selectbox("Limit", [20, 50, 100])

                res = svc.search_articles(sq, sl)

                if res:
                    amap = {f"[{a.published_date.strftime('%Y-%m-%d')}] {a.title}": a for a in res}
                    sels = st.multiselect("Select Articles:", options=list(amap.keys()))

                    st.divider()
                    cm1, cm2 = st.columns(2)
                    aname = cm1.text_input("Analyst", value=current_user_obj.full_name or st.session_state.current_user)
                    cinfo = cm2.text_input("Contact", value=current_user_obj.contact_info or "")
                    obj = st.text_area("AI Objective", value="Generate an exhaustive technical report.")

                    is_rep_cooling = check_cooldown("gen_report_custom", 60)
                    if st.button("Synthesizing..." if is_rep_cooling else "Generate Report", type="primary", disabled=not perms["can_trigger_ai"] or is_rep_cooling, width="stretch"):
                        apply_cooldown("gen_report_custom")
                        if not sels:
                            st.error("Select at least one article.")
                        else:
                            arts = [amap[t] for t in sels]
                            with st.spinner("Synthesizing Intelligence..."):
                                from src.utils.llm import build_custom_intel_report
                                with svc.SessionLocal() as session:
                                    md = build_custom_intel_report(arts, obj, session)
                                if md:
                                    now = datetime.now(LOCAL_TZ).strftime("%A, %B %d, %Y at %I:%M %p %Z")
                                    st.session_state.generated_report = f"#  NOC Report\n**Date:** {now}\n**Analyst:** {aname}\n\n---\n\n{md}"
                                    st.success("Complete!")

                if st.session_state.generated_report:
                    st.divider()
                    st.markdown(st.session_state.generated_report)
                    sv_t = st.text_input("Report Title", value=f"Report - {datetime.now(LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}")
                    if st.button("Save to Library", width="stretch"):
                        svc.save_custom_report(sv_t, st.session_state.current_user, st.session_state.generated_report)
                        st.success("Saved!")
            tab_idx += 1

        if "Tab: Reporting -> Shared Library" in st.session_state.allowed_actions:
            with tabs[tab_idx]:
                st.subheader("Organization Shared Library")
                reps = svc.get_saved_reports()
                if not reps:
                    st.info("No reports saved yet.")
                else:
                    for r in reps:
                        with st.expander(f" **{r.title}** | {format_local_time(r.created_at)}"):
                            st.markdown(r.content)
                            if st.button("Delete", key=f"del_lib_{r.id}", width="stretch"):
                                svc.delete_record("SavedReport", r.id)
                                safe_rerun()
            tab_idx += 1
