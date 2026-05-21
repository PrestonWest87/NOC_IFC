import streamlit as st
import src.services as svc

def trigger_browser_notifications():
    if "notified_alerts" not in st.session_state:
        st.session_state.notified_alerts = set()

    try:
        g_locs = svc.get_cached_locations()
        g_spc_d1, g_spc_d2, g_spc_d3, g_ar_data, g_oos_data = svc.get_cached_geojson()

        global_alerts = svc.get_filtered_notification_alerts(
            st.session_state.current_user, g_ar_data, g_oos_data, g_locs
        )

        new_alerts = []
        for alert in global_alerts:
            alert_key = f"{alert['Event']}_{alert['Affected Area']}_{alert['Expires']}"
            if alert_key not in st.session_state.notified_alerts:
                new_alerts.append(alert)
                st.session_state.notified_alerts.add(alert_key)

        if new_alerts:
            js_notifications = ""
            for idx, na in enumerate(new_alerts):
                clean_event = na['Event'].replace('"', '')
                clean_area = na['Affected Area'].replace('"', '')
                title = f"NWS Alert: {clean_event}"
                body = f"Affected: {clean_area}"
                js_notifications += f'setTimeout(() => {{new Notification("{title}", {{body: "{body}"}}); }}, {idx * 500});\n'

            js_wrapper = f"""
            <script>
                if ("Notification" in window && Notification.permission === "granted") {{
                    {js_notifications}
                }}
            </script>
            """
            st.components.v1.html(js_wrapper, height=0, width=0)
    except Exception:
        pass
