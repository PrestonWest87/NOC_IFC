import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


class AuthorizationApiTests(unittest.TestCase):
    def setUp(self):
        from src.api.main import app

        self.client = TestClient(app)
        self.token_patch = patch("src.api.auth_guard.svc.get_user_by_token")
        self.get_user = self.token_patch.start()

    def tearDown(self):
        self.token_patch.stop()
        self.client.close()

    def test_action_denial_is_structured_403_and_does_not_call_email_sender(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="analyst", role="analyst",
            allowed_pages=["Reporting & Briefings"], allowed_actions=[], allowed_site_types=[],
        )
        with patch("src.utils.mailer.send_alert_email") as send_email:
            response = self.client.post(
                "/api/v1/email/send",
                headers={"Authorization": "Bearer token"},
                json={"to": "noc@example.com", "subject": "test", "html_body": "body"},
            )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["code"], "permission_denied")
        self.assertEqual(response.json()["detail"]["permission"], "Action: Send Email")
        send_email.assert_not_called()

    def test_action_grant_allows_email_send_and_admin_override(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="dispatcher", role="analyst",
            allowed_pages=[], allowed_actions=["Action: Send Email"], allowed_site_types=[],
        )
        with patch("src.utils.mailer.send_alert_email", return_value=(True, "sent")) as send_email:
            response = self.client.post(
                "/api/v1/email/send",
                headers={"Authorization": "Bearer token"},
                json={"to": "noc@example.com", "subject": "test", "html_body": "body"},
            )
        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once()

        self.get_user.return_value = SimpleNamespace(
            id=1, username="admin", role="admin",
            allowed_pages=[], allowed_actions=[], allowed_site_types=[],
        )
        with patch("src.utils.mailer.send_alert_email", return_value=(True, "sent")) as send_email:
            response = self.client.post(
                "/api/v1/email/send",
                headers={"Authorization": "Bearer admin-token"},
                json={"to": "noc@example.com", "subject": "test", "html_body": "body"},
            )
        self.assertEqual(response.status_code, 200)
        send_email.assert_called_once()

    def test_page_denial_is_structured_403(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="viewer", role="viewer",
            allowed_pages=["Reporting & Briefings"], allowed_actions=[], allowed_site_types=[],
        )
        response = self.client.get("/api/v1/dashboard/metrics", headers={"Authorization": "Bearer token"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["scope"], "page")
        self.assertEqual(response.json()["detail"]["permission"], "Global Dashboards")

    def test_missing_session_is_structured_401(self):
        self.get_user.return_value = None
        response = self.client.get("/api/v1/dashboard/metrics")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"]["code"], "unauthenticated")

    def test_application_settings_write_requires_its_specific_action(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="analyst", role="analyst",
            allowed_pages=["Settings & Admin"],
            allowed_actions=["Tab: Settings -> Application Settings"],
            allowed_site_types=[],
        )
        response = self.client.patch(
            "/api/v1/application-settings/scheduler/jobs/rss_fetch",
            headers={"Authorization": "Bearer token"},
            json={"schedule": {"schedule_type": "interval", "every_value": 10, "unit": "minutes", "enabled": True}},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["permission"], "Action: Manage Scheduler Settings")

        response = self.client.put(
            "/api/v1/application-settings/risk-scoring",
            headers={"Authorization": "Bearer token"},
            json={"global_risk_offset": 2},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["permission"], "Action: Adjust Risk Scoring Overrides")

    def test_settings_tab_grants_allow_scoped_facility_and_rss_read_views(self):
        self.get_user.return_value = SimpleNamespace(
            id=30, username="testuser", role="toc",
            allowed_pages=["Settings & Admin"],
            allowed_actions=[
                "Tab: Settings -> Facility Locations",
                "Tab: Settings -> RSS Sources",
            ],
            allowed_site_types=["HQ"],
        )
        with patch("src.api.routes.settings.svc.get_cached_locations", return_value=[
            {"name": "Main Office", "loc_type": "HQ"},
            {"name": "Remote Yard", "loc_type": "Field Office"},
        ]), patch("src.api.routes.settings.svc.get_admin_lists", return_value=(
            [{"word": "outage"}], [{"name": "Feed", "url": "https://example.test/rss"}],
            [{"username": "private-user"}],
        )):
            facilities = self.client.get(
                "/api/v1/settings/facilities", headers={"Authorization": "Bearer toc-token"}
            )
            rss = self.client.get(
                "/api/v1/settings/rss", headers={"Authorization": "Bearer toc-token"}
            )

        self.assertEqual(facilities.status_code, 200)
        self.assertEqual([row["name"] for row in facilities.json()], ["Main Office"])
        self.assertEqual(rss.status_code, 200)
        self.assertEqual(set(rss.json()), {"keywords", "feeds"})
        self.assertEqual(rss.json()["keywords"], [{"word": "outage"}])

        self.get_user.return_value.allowed_actions = []
        denied = self.client.get(
            "/api/v1/settings/facilities", headers={"Authorization": "Bearer toc-token"}
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"]["permission"], "Tab: Settings -> Facility Locations")

    def test_recovery_email_request_explains_missing_reviewer_and_queues_notice_when_available(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="admin", role="admin",
            allowed_pages=["Settings & Admin"], allowed_actions=[], allowed_site_types=[],
        )
        with patch("src.api.routes.auth.svc.submit_email_change_request", return_value=41), patch(
            "src.api.routes.auth.svc.get_recovery_reviewer_emails", return_value=[]
        ):
            response = self.client.post(
                "/api/v1/auth/request-recovery-email",
                headers={"Authorization": "Bearer admin-token"},
                json={"email": "admin@example.com"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "pending_approval")
        self.assertIn("no other verified recovery-email reviewer", response.json()["message"])
        self.assertIn("DEFAULT_ADMIN_EMAIL", response.json()["message"])

        with patch("src.api.routes.auth.svc.submit_email_change_request", return_value=42), patch(
            "src.api.routes.auth.svc.get_recovery_reviewer_emails", return_value=["reviewer@example.com"]
        ), patch("src.api.routes.auth._send_account_recovery_notice") as send_notice:
            response = self.client.post(
                "/api/v1/auth/request-recovery-email",
                headers={"Authorization": "Bearer admin-token"},
                json={"email": "admin@example.com"},
            )
        self.assertEqual(response.status_code, 200)
        send_notice.assert_called_once()

    def test_recovery_queue_is_permission_based_for_user_admin_reviewers(self):
        self.get_user.return_value = SimpleNamespace(
            id=20, username="user-admin", role="user-admin",
            allowed_pages=["Settings & Admin"],
            allowed_actions=["Tab: Settings -> Users & Roles", "Action: Review Account Recovery Requests"],
            allowed_site_types=[],
        )
        with patch("src.api.routes.user_admin.svc.list_password_reset_requests", return_value=[]):
            response = self.client.get(
                "/api/v1/user-admin/recovery-requests",
                headers={"Authorization": "Bearer reviewer-token"},
            )
        self.assertEqual(response.status_code, 200)

        self.get_user.return_value = SimpleNamespace(
            id=21, username="analyst", role="analyst",
            allowed_pages=["Settings & Admin"], allowed_actions=["Tab: Settings -> Users & Roles"], allowed_site_types=[],
        )
        response = self.client.get(
            "/api/v1/user-admin/recovery-requests",
            headers={"Authorization": "Bearer analyst-token"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"]["permission"], "Action: Review Account Recovery Requests")

    def test_non_aiops_user_cannot_open_websocket(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="reporter", role="analyst",
            allowed_pages=["Reporting & Briefings"], allowed_actions=[], allowed_site_types=[],
        )
        with self.assertRaises(WebSocketDisconnect) as error:
            with self.client.websocket_connect("/ws?token=token"):
                pass
        self.assertEqual(error.exception.code, 1008)

    def test_aiops_page_without_active_board_tab_cannot_open_websocket(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="correlation-only", role="analyst",
            allowed_pages=["AIOps RCA"],
            allowed_actions=["Tab: AIOps RCA -> Global Correlation"],
            allowed_site_types=["HQ"],
        )
        with self.assertRaises(WebSocketDisconnect) as error:
            with self.client.websocket_connect("/ws?token=token"):
                pass
        self.assertEqual(error.exception.code, 1008)

    def test_websocket_commands_require_action_and_allowed_grants_are_echoed(self):
        self.get_user.return_value = SimpleNamespace(
            id=10, username="operator", role="analyst",
            allowed_pages=["AIOps RCA"],
            allowed_actions=["Tab: AIOps RCA -> Active Board"], allowed_site_types=["HQ"],
        )
        with self.client.websocket_connect("/ws?token=token") as websocket:
            websocket.send_json({"type": "RCA_UPDATE"})
            denied = websocket.receive_json()
            self.assertEqual(denied["code"], "permission_denied")

        self.get_user.return_value = SimpleNamespace(
            id=10, username="operator", role="analyst",
            allowed_pages=["AIOps RCA"],
            allowed_actions=["Tab: AIOps RCA -> Active Board", "Action: Dispatch RCA Tickets"],
            allowed_site_types=["HQ"],
        )
        with patch("src.api.main.svc.user_can_access_site", return_value=True), patch(
            "src.api.main.svc.get_cached_locations", return_value=[]
        ):
            with self.client.websocket_connect("/ws?token=token") as websocket:
                websocket.send_json({"type": "RCA_UPDATE"})
                echoed = websocket.receive_json()
                self.assertEqual(echoed["type"], "RCA_UPDATE")

    def test_aiops_payload_filters_events_by_structured_site_not_message_text(self):
        from src.services import filter_aiops_payload_for_user

        user = SimpleNamespace(role="analyst", allowed_site_types=["SCADA"])
        locations = [
            {"name": "North Plant", "loc_type": "SCADA"},
            {"name": "South Plant", "loc_type": "POWER_SUPPLIES"},
        ]
        payload = {
            "alerts": [
                {"mapped_location": "North Plant"},
                {"mapped_location": "South Plant"},
            ],
            "events": [
                {"site_name": "North Plant", "message": "allowed event"},
                {"site_name": "South Plant", "message": "restricted event"},
                {"site_name": None, "message": "Mentions North Plant but is unscoped"},
            ],
            "grid": [],
        }

        filtered = filter_aiops_payload_for_user(payload, user, locations=locations)

        self.assertEqual(filtered["alerts"], [{"mapped_location": "North Plant"}])
        self.assertEqual(filtered["events"], [{"site_name": "North Plant", "message": "allowed event"}])


if __name__ == "__main__":
    unittest.main()
