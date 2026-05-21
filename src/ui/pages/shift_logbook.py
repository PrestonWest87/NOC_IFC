import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import src.services as svc
from src.ui.state_manager import (
    safe_rerun, check_cooldown, apply_cooldown,
    format_local_time, get_permission_flags, LOCAL_TZ
)


def render_shift_logbook():
    perms = get_permission_flags()
    sys_config = svc.get_cached_config()
    ai_enabled = sys_config.is_active if sys_config else False

    current_user_obj = svc.get_user_by_username(st.session_state.current_user)

    st.title("NOC Running Shift Log & Calendar")
    st.markdown("Incident-based running log isolated by operational role. Logs are aggregated into an automated shift summary upon handoff.")

    @st.dialog("Shift Log Details")
    def open_log_modal(log_entry):
        is_del = getattr(log_entry, 'is_deleted', False)
        if is_del:
            st.error("THIS LOG HAS BEEN SOFT-DELETED AND OMITTED FROM SUMMARIES.")

        st.markdown(f"**Analyst:** {log_entry.analyst} | **Role:** {log_entry.author_role.upper()}")
        st.markdown(f"**Date:** {format_local_time(log_entry.created_at)}")
        st.markdown(f"**Shift:** {log_entry.shift_period}")
        st.divider()
        st.markdown(log_entry.content)

        st.divider()

        if not is_del:
            if st.button("Soft Delete Log", type="primary", width='stretch'):
                with svc.SessionLocal() as session:
                    from src.database import ShiftLogEntry
                    db_log = session.query(ShiftLogEntry).get(log_entry.id)
                    if db_log:
                        db_log.is_deleted = True
                        session.commit()
                st.rerun()
        else:
            if st.session_state.current_role == "admin":
                if st.button("Restore Log", width='stretch'):
                    with svc.SessionLocal() as session:
                        from src.database import ShiftLogEntry
                        db_log = session.query(ShiftLogEntry).get(log_entry.id)
                        if db_log:
                            db_log.is_deleted = False
                            session.commit()
                    st.rerun()

    st.subheader("Log Active Incident / Update")
    c_entry, c_aiops = st.columns([2, 1])

    with c_aiops:
        st.write("**AIOps Telemetry Integration**")
        st.caption("Pulls active outages and automatically calculates the duration of the event.")
        if st.button("Auto-Draft Active Outages", width="stretch"):
            alerts, events, grid = svc.get_aiops_dashboard_data()
            from src.services.aiops_engine import EnterpriseAIOpsEngine
            ai_engine = EnterpriseAIOpsEngine(svc.SessionLocal)

            if not alerts:
                st.success("No active AIOps infrastructure incidents.")
            else:
                incidents = ai_engine.analyze_and_cluster(alerts)
                lines = []
                for site, data in incidents.items():
                    p0 = data['patient_zero']
                    duration = datetime.utcnow() - p0.received_at
                    hours, remainder = divmod(int(duration.total_seconds()), 3600)
                    mins, _ = divmod(remainder, 60)
                    dur_str = f"{hours}h {mins}m" if hours > 0 else f"{mins}m"

                    lines.append(f"AIOps Auto-Log: {site} offline (Origin: {p0.node_name}). Down for {dur_str}.")

                if "aiops_draft" not in st.session_state:
                    st.session_state.aiops_draft = ""
                st.session_state.aiops_draft += "\n".join(lines) + "\n\n"
                safe_rerun()

    with c_entry:
        with st.form("incident_entry_form", clear_on_submit=True):
            c_sh1, c_sh2 = st.columns(2)

            user_shift = getattr(current_user_obj, 'default_shift', 'No Shift')
            custom_shift_date = None

            if user_shift == "No Shift":
                shift_val = c_sh1.date_input("Active Shift Date", value=datetime.now(LOCAL_TZ).date())
                shift_period = f"Date: {shift_val.strftime('%Y-%m-%d')}"
                custom_shift_date = shift_val
            else:
                shift_choices = ["Morning", "Afternoon", "Night"]
                default_idx = shift_choices.index(user_shift) if user_shift in shift_choices else 0
                shift_period = c_sh1.selectbox("Active Shift", shift_choices, index=default_idx)

            analyst_name = c_sh2.text_input("Analyst", value=current_user_obj.full_name or st.session_state.current_user)

            default_text = st.session_state.get("aiops_draft", "")
            incident_notes = st.text_area("Incident Update / Running Notes", value=default_text, height=120, placeholder="Logged circuit flap on MAIN-1, dispatched ticket #12345...")

            if st.form_submit_button("Append to Running Log", type="primary", disabled=not perms["can_submit_log"], width="stretch"):
                if incident_notes.strip():
                    svc.save_shift_log(analyst_name, st.session_state.current_role, shift_period, incident_notes.strip(), custom_date=custom_shift_date)
                    if "aiops_draft" in st.session_state:
                        del st.session_state.aiops_draft
                    st.success("Incident appended to shift log!")
                    time.sleep(0.5)
                    safe_rerun()
                else:
                    st.error("Cannot submit empty log.")

    st.divider()

    st.subheader("Daily Persistent Summaries")
    st.caption("Auto-generated executive handoffs for the Morning Shift and the entire Day. These persist until overwritten.")

    eom_key = f"latest_eom_{st.session_state.current_role}"
    eod_key = f"latest_eod_{st.session_state.current_role}"

    with st.expander("End of Morning Report", expanded=False):
        if st.button("Generate Morning Report", key="gen_eom", type="primary", disabled=not ai_enabled):
            with st.spinner("Synthesizing morning shift logs..."):
                today_start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                utc_start = today_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                utc_end = utc_start

                morn_logs = [l for l in svc.get_shift_logs(st.session_state.current_role, utc_start, utc_end) if "Morning" in l.shift_period and not getattr(l, 'is_deleted', False)]

                if not morn_logs:
                    st.warning("No active morning logs found for today.")
                else:
                    log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.analyst}: {l.content}" for l in morn_logs])
                    sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the Morning shift. Write a concise, professional End of Morning Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."

                    from src.utils.llm import call_llm
                    summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)
                    if summary:
                        st.session_state[eom_key] = {
                            "timestamp": datetime.now(LOCAL_TZ).strftime('%B %d, %Y at %I:%M %p %Z'),
                            "content": summary
                        }
                        with svc.SessionLocal() as session:
                            from src.database import ShiftLogEntry
                            new_log = ShiftLogEntry(
                                analyst=current_user_obj.full_name or st.session_state.current_user,
                                author_role=st.session_state.current_role,
                                shift_period="Morning (06:00 - 14:30)",
                                content=f" **AUTO-GENERATED MORNING HANDOFF REPORT:**\n\n{summary}"
                            )
                            session.add(new_log)
                            session.commit()
                        st.success("Morning report generated and appended to the shift log!")

        if eom_key in st.session_state:
            st.caption(f" **Last Generated:** {st.session_state[eom_key]['timestamp']}")
            st.markdown(st.session_state[eom_key]['content'])

    with st.expander("End of Day Report", expanded=False):
        if st.button("Generate End of Day Report", key="gen_eod", type="primary", disabled=not ai_enabled):
            with st.spinner("Synthesizing all logs for the day..."):
                today_start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
                utc_start = today_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                utc_end = utc_start

                day_logs = [l for l in svc.get_shift_logs(st.session_state.current_role, utc_start, utc_end) if not getattr(l, 'is_deleted', False)]

                if not day_logs:
                    st.warning("No active logs found for today.")
                else:
                    log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.shift_period} | {l.analyst}: {l.content}" for l in day_logs])
                    sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the entire day. Write a comprehensive, professional End of Day Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."

                    from src.utils.llm import call_llm
                    summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)
                    if summary:
                        st.session_state[eod_key] = {
                            "timestamp": datetime.now(LOCAL_TZ).strftime('%B %d, %Y at %I:%M %p %Z'),
                            "content": summary
                        }
                        with svc.SessionLocal() as session:
                            from src.database import ShiftLogEntry
                            new_log = ShiftLogEntry(
                                analyst=current_user_obj.full_name or st.session_state.current_user,
                                author_role=st.session_state.current_role,
                                shift_period="Afternoon/Evening (11:30 - 20:00)",
                                content=f" **AUTO-GENERATED END OF DAY REPORT:**\n\n{summary}"
                            )
                            session.add(new_log)
                            session.commit()
                        st.success("End of Day report generated and appended to the shift log!")

        if eod_key in st.session_state:
            st.caption(f" **Last Generated:** {st.session_state[eod_key]['timestamp']}")
            st.markdown(st.session_state[eod_key]['content'])

    if st.session_state.current_role == "admin":
        with st.expander("Admin: Retroactive End of Day Report", expanded=False):
            st.caption("Generate a missing End of Day report for a previous day and inject it into that day's log.")
            c_ret1, c_ret2 = st.columns(2)
            retro_date = c_ret1.date_input("Select Previous Date", value=datetime.now(LOCAL_TZ).date() - timedelta(days=1), key="retro_eod_date")
            retro_role = c_ret2.selectbox("Target Role", [r.name for r in svc.get_all_roles()], key="retro_eod_role")

            if st.button("Generate Retroactive EOD Report", key="gen_retro_eod", type="primary", disabled=not ai_enabled, width='stretch'):
                with st.spinner(f"Synthesizing logs for {retro_date}..."):
                    retro_dt_start = datetime.combine(retro_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
                    retro_dt_end = retro_dt_start + timedelta(days=1)

                    retro_logs = [l for l in svc.get_shift_logs(retro_role, retro_dt_start, retro_dt_end) if not getattr(l, 'is_deleted', False)]

                    if not retro_logs:
                        st.warning(f"No active logs found for {retro_date} under the {retro_role} role.")
                    else:
                        log_text = "\n".join([f"[{format_local_time(l.created_at)}] {l.shift_period} | {l.analyst}: {l.content}" for l in retro_logs])
                        sys_prompt = "You are a NOC Shift Supervisor. Read the following chronologically ordered running log for the entire day. Write a comprehensive, professional End of Day Shift Handoff Summary combining the key incidents, ongoing outages, and resolutions. Do NOT use pleasantries. Format with markdown."

                        from src.utils.llm import call_llm
                        retro_summary = call_llm([{"role": "system", "content": sys_prompt}, {"role": "user", "content": log_text}], sys_config)

                        if retro_summary:
                            target_local = datetime.combine(retro_date, datetime.max.time()).replace(tzinfo=LOCAL_TZ)
                            target_utc = target_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

                            with svc.SessionLocal() as session:
                                from src.database import ShiftLogEntry
                                new_log = ShiftLogEntry(
                                    analyst=current_user_obj.full_name or st.session_state.current_user,
                                    author_role=retro_role,
                                    shift_date=target_utc,
                                    shift_period="Afternoon/Evening (11:30 - 20:00)",
                                    content=f" **RETROACTIVE END OF DAY REPORT:**\n\n{retro_summary}",
                                    created_at=target_utc
                                )
                                session.add(new_log)
                                session.commit()
                            st.success(f"Retroactive EOD report generated and appended to the {retro_date} shift log!")

    st.subheader("Aggregated Executive Summaries")
    st.caption("Compiles historical shift logs into comprehensive Weekly or Monthly executive overviews using Map-Reduce AI.")

    c_agg1, c_agg2, c_agg3 = st.columns([2, 2, 1.5])
    agg_period = c_agg1.selectbox("Select Reporting Period", ["Current Week", "Previous Week", "Current Month", "Previous Month"], label_visibility="collapsed")

    if st.session_state.current_role == "admin":
        available_roles = ["All"] + [r.name for r in svc.get_all_roles()]
        agg_target_role = c_agg2.selectbox("Target Role", available_roles, key="agg_target_role", label_visibility="collapsed")
    else:
        agg_target_role = st.session_state.current_role
        c_agg2.text_input("Target Role", value=agg_target_role.upper(), disabled=True, label_visibility="collapsed")

    is_agg_cooling = check_cooldown("ai_agg_summary", 60)
    if c_agg3.button("Generating..." if is_agg_cooling else "Generate Summary", width="stretch", type="primary", disabled=not ai_enabled or is_agg_cooling):
        apply_cooldown("ai_agg_summary")
        with st.spinner(f"Reading historical logs and synthesizing {agg_period} summary for {agg_target_role.upper()}..."):
            today = datetime.now(LOCAL_TZ).date()

            if agg_period == "Current Week":
                start_dt = today - timedelta(days=today.weekday())
                end_dt = start_dt + timedelta(days=6)
            elif agg_period == "Previous Week":
                start_dt = today - timedelta(days=today.weekday()) - timedelta(weeks=1)
                end_dt = start_dt + timedelta(days=6)
            elif agg_period == "Current Month":
                start_dt = today.replace(day=1)
                next_month = start_dt.replace(day=28) + timedelta(days=4)
                end_dt = next_month - timedelta(days=next_month.day)
            elif agg_period == "Previous Month":
                last_day_prev_month = today.replace(day=1) - timedelta(days=1)
                start_dt = last_day_prev_month.replace(day=1)
                end_dt = last_day_prev_month

            utc_start = datetime.combine(start_dt, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            utc_end = datetime.combine(end_dt, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None) + timedelta(days=1)

            raw_logs = svc.get_shift_logs(agg_target_role, utc_start, utc_end)
            valid_logs = [l for l in raw_logs if not getattr(l, 'is_deleted', False)]

            if not valid_logs:
                st.warning(f"No valid {agg_target_role.upper()} logs found for {agg_period} ({start_dt.strftime('%m/%d')} - {end_dt.strftime('%m/%d')}).")
            else:
                from src.utils.llm import generate_aggregated_shift_summary
                with svc.SessionLocal() as session:
                    summary = generate_aggregated_shift_summary(session, valid_logs, agg_period, agg_target_role)
                st.session_state[f"agg_summary_{agg_period.replace(' ', '_')}_{agg_target_role}"] = summary

    state_key = f"agg_summary_{agg_period.replace(' ', '_')}_{agg_target_role}"
    if state_key in st.session_state:
        with st.container(border=True):
            st.markdown(st.session_state[state_key])

    st.divider()

    st.subheader("Shift Log Explorer")

    if "log_view_mode" not in st.session_state:
        st.session_state.log_view_mode = "Day View"
    if "selected_log_date" not in st.session_state:
        st.session_state.selected_log_date = datetime.now(LOCAL_TZ).date()

    c_mode1, c_mode2 = st.columns([1, 4])
    view_selection = c_mode1.radio("Layout", ["Day View", "Week View"], horizontal=True, label_visibility="collapsed")

    if view_selection != st.session_state.log_view_mode:
        st.session_state.log_view_mode = view_selection
        safe_rerun()

    st.divider()

    if st.session_state.log_view_mode == "Day View":
        c_nav1, c_nav2, c_nav3 = st.columns([1, 2, 1])
        if c_nav1.button("Previous Day", width='stretch'):
            st.session_state.selected_log_date -= timedelta(days=1)
            safe_rerun()

        new_date = c_nav2.date_input("Select Date", value=st.session_state.selected_log_date, label_visibility="collapsed")
        if new_date != st.session_state.selected_log_date:
            st.session_state.selected_log_date = new_date
            safe_rerun()

        is_today = st.session_state.selected_log_date >= datetime.now(LOCAL_TZ).date()
        if c_nav3.button("Next Day ", width='stretch', disabled=is_today):
            st.session_state.selected_log_date += timedelta(days=1)
            safe_rerun()

        st.markdown(f"<h4 style='text-align: center;'>Logs for {st.session_state.selected_log_date.strftime('%A, %B %d, %Y')}</h4>", unsafe_allow_html=True)

        dt_start = datetime.combine(st.session_state.selected_log_date, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        dt_end = dt_start

        raw_day_logs = svc.get_shift_logs(st.session_state.current_role, dt_start, dt_end)

        day_logs = [l for l in raw_day_logs if not getattr(l, 'is_deleted', False) or st.session_state.current_role == "admin"]

        if not day_logs:
            st.info(f"No active shift logs recorded for {st.session_state.selected_log_date.strftime('%m/%d/%Y')}.")
        else:
            ch1, ch2, ch3, ch4, ch5 = st.columns([1.2, 1, 1.5, 6, 1.2])
            ch1.markdown("**Time**")
            ch2.markdown("**Shift**")
            ch3.markdown("**Analyst**")
            ch4.markdown("**Log Message**")
            ch5.markdown("**Action**")
            st.divider()

            for l in day_logs:
                is_del = getattr(l, 'is_deleted', False)
                local_time = format_local_time(l.created_at).split(' ')[1]
                shift_abbr = "Morning" if "Morning" in l.shift_period else "Evening"
                preview_text = l.content.replace('\n', ' ')

                c1, c2, c3, c4, c5 = st.columns([1.2, 1, 1.5, 6, 1.2])
                c1.caption(local_time)
                c2.caption(shift_abbr)
                c3.caption(l.analyst)

                display_msg = preview_text[:250] + "..." if len(preview_text) > 250 else preview_text

                if is_del:
                    display_msg = f"<span style='color: #dc3545;'><s>{display_msg}</s> (DELETED)</span>"

                c4.markdown(f"<span style='font-size: 0.9rem;'>{display_msg}</span>", unsafe_allow_html=True)

                if c5.button("Expand", key=f"btn_day_{l.id}", width='stretch'):
                    open_log_modal(l)

                st.markdown("<hr style='margin: 0.3rem 0; opacity: 0.3;'/>", unsafe_allow_html=True)

    elif st.session_state.log_view_mode == "Week View":
        if "week_offset" not in st.session_state:
            st.session_state.week_offset = 0

        c_nav1, c_nav2, c_nav3 = st.columns([1, 2, 1])
        if c_nav1.button("Previous Week", width='stretch'):
            st.session_state.week_offset -= 1
            safe_rerun()

        today = datetime.now(LOCAL_TZ).date()
        target_week_start = today - timedelta(days=today.weekday()) + timedelta(weeks=st.session_state.week_offset)
        target_week_end = target_week_start + timedelta(days=6)

        c_nav2.markdown(f"<h4 style='text-align: center; margin-top: 0;'>Week of {target_week_start.strftime('%B %d, %Y')}</h4>", unsafe_allow_html=True)

        if c_nav3.button("Next Week ", width='stretch', disabled=(st.session_state.week_offset >= 0)):
            st.session_state.week_offset += 1
            safe_rerun()

        dt_start = datetime.combine(target_week_start, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        dt_end = datetime.combine(target_week_end, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

        week_logs = svc.get_shift_logs(st.session_state.current_role, dt_start, dt_end)

        days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        cal_cols = st.columns(7)

        for i, col in enumerate(cal_cols):
            current_day_date = target_week_start + timedelta(days=i)
            with col:
                if st.button(f"{days_of_week[i][:3]}\n{current_day_date.strftime('%m/%d')}", key=f"day_btn_{i}", width='stretch'):
                    st.session_state.selected_log_date = current_day_date
                    st.session_state.log_view_mode = "Day View"
                    safe_rerun()

                day_logs = [l for l in week_logs if l.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(LOCAL_TZ).date() == current_day_date and (not getattr(l, 'is_deleted', False) or st.session_state.current_role == "admin")]

                if not day_logs:
                    st.caption("<div style='text-align: center; color: gray;'>No entries</div>", unsafe_allow_html=True)
                else:
                    for l in day_logs:
                        shift_abbr = "Morn" if "Morning" in l.shift_period else "Eve"
                        local_time = format_local_time(l.created_at).split(' ')[1]

                        if st.button(f"{local_time} | {shift_abbr}", key=f"btn_wk_{l.id}", help="Click to read full log", width='stretch'):
                            open_log_modal(l)

    if st.session_state.current_role == "admin":
        st.divider()
        st.subheader("Admin Log Export Utility")

        c_exp1, c_exp2, c_exp3 = st.columns([2, 1, 1])
        available_roles = ["All"] + [r.name for r in svc.get_all_roles()]

        exp_role = c_exp1.selectbox("Role Filter", available_roles, key="exp_role")
        exp_start = c_exp2.date_input("Start Date", value=datetime.now(LOCAL_TZ).date() - timedelta(days=7), key="exp_start")
        exp_end = c_exp3.date_input("End Date", value=datetime.now(LOCAL_TZ).date(), key="exp_end")

        dt_start_exp = datetime.combine(exp_start, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        dt_end_exp = datetime.combine(exp_end, datetime.min.time()).replace(tzinfo=LOCAL_TZ).astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

        exp_logs = [l for l in svc.get_shift_logs(exp_role, dt_start_exp, dt_end_exp) if not getattr(l, 'is_deleted', False)]

        if exp_logs:
            export_data = pd.DataFrame([{
                "Local_Time": format_local_time(l.created_at),
                "Analyst": l.analyst,
                "Role": l.author_role.upper(),
                "Shift_Period": l.shift_period,
                "Content": l.content
            } for l in exp_logs])

            st.download_button(
                label="Download CSV Export",
                data=export_data.to_csv(index=False).encode('utf-8'),
                file_name=f"NOC_ShiftLogs_{exp_role.upper()}_{exp_start.strftime('%Y%m%d')}.csv",
                mime="text/csv",
                width="stretch",
                type="primary"
            )
        else:
            st.info("No logs match the current export criteria.")
