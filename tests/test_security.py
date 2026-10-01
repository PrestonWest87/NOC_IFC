import unittest
import re
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from starlette.requests import Request


class SecurityUnitTests(unittest.TestCase):
    def test_bearer_token_is_preferred(self):
        request = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/v1/dashboard/metrics",
            "headers": [(b"authorization", b"Bearer header-token")],
            "query_string": b"token=query-token",
        })
        from src.api.auth_guard import token_from_request

        self.assertEqual(token_from_request(request), "header-token")

    def test_query_token_remains_supported_for_legacy_clients(self):
        request = Request({
            "type": "http",
            "method": "GET",
            "path": "/api/v1/dashboard/metrics",
            "headers": [],
            "query_string": b"token=query-token",
        })
        from src.api.auth_guard import token_from_request

        self.assertEqual(token_from_request(request), "query-token")

    def test_private_llm_endpoint_is_blocked_by_default(self):
        from src.api.routes.llm import _safe_llm_endpoint

        self.assertFalse(_safe_llm_endpoint("http://127.0.0.1:11434/v1"))
        self.assertFalse(_safe_llm_endpoint("file:///etc/passwd"))

    def test_admin_dependency_rejects_non_admin(self):
        from fastapi import HTTPException
        from src.api.auth_guard import require_admin

        with self.assertRaises(HTTPException) as error:
            require_admin(SimpleNamespace(role="analyst"))
        self.assertEqual(error.exception.status_code, 403)

    def test_admin_has_page_and_action_override(self):
        from src.api.auth_guard import has_page_permission, require_action

        admin = SimpleNamespace(role="admin", allowed_pages=[], allowed_actions=[])
        self.assertTrue(has_page_permission(admin, "Settings & Admin"))
        self.assertIs(require_action("Action: Dispatch Exec Report")(admin), admin)

    def test_non_admin_page_and_action_are_denied_without_grants(self):
        from fastapi import HTTPException
        from src.api.auth_guard import has_page_permission, require_action

        analyst = SimpleNamespace(role="analyst", allowed_pages=["Reporting & Briefings"], allowed_actions=[])
        self.assertFalse(has_page_permission(analyst, "Settings & Admin"))
        with self.assertRaises(HTTPException):
            require_action("Action: Dispatch Exec Report")(analyst)

    def test_permission_denials_use_machine_readable_code_and_required_grant(self):
        from fastapi import HTTPException
        from src.api.auth_guard import require_action, require_page

        analyst = SimpleNamespace(role="analyst", allowed_pages=[], allowed_actions=[])
        for dependency in (require_action("Action: Send Email"), require_page("Settings & Admin")):
            with self.assertRaises(HTTPException) as error:
                dependency(analyst)
            self.assertEqual(error.exception.status_code, 403)
            self.assertEqual(error.exception.detail["code"], "permission_denied")
            self.assertTrue(error.exception.detail["permission"])

    def test_permission_catalog_contains_sensitive_settings_grants(self):
        from src.core.permissions import ACTION_KEYS, TAB_KEYS

        for key in (
            "Action: Generate Reports", "Action: Send Email",
            "Action: Adjust Risk Scoring Overrides", "Action: Manage Scheduler Settings",
            "Action: Manage Users", "Action: Review Account Recovery Requests",
            "Action: Approve Recovery Email Changes",
        ):
            self.assertIn(key, ACTION_KEYS)
        self.assertIn("Tab: Settings -> Application Settings", TAB_KEYS)

    def test_frontend_permission_keys_exist_in_canonical_catalog(self):
        from src.core.permissions import ACTION_KEYS, PAGE_KEYS, TAB_KEYS

        frontend = Path(__file__).resolve().parents[1] / "web" / "src"
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in frontend.rglob("*.ts*")
        )
        referenced = set(re.findall(r'"((?:Action|Tab): [^"]+)"', source))
        self.assertEqual(referenced - set(ACTION_KEYS) - set(TAB_KEYS), set())
        route_config = (frontend / "utils" / "routeConfig.ts").read_text(encoding="utf-8")
        page_labels = set(re.findall(r'"(/[^\"]*)":\s*"([^\"]+)"', route_config))
        self.assertTrue({label for _, label in page_labels}.issubset(set(PAGE_KEYS)))

    def test_restricted_aiops_payload_is_filtered_before_delivery(self):
        from src.services import filter_aiops_payload_for_user

        user = SimpleNamespace(role="analyst", allowed_site_types=["HQ"])
        locations = [
            {"name": "HQ West", "loc_type": "HQ"},
            {"name": "Field Alpha", "loc_type": "Field Office"},
        ]
        payload = {
            "type": "dashboard_update",
            "alerts": [
                {"id": 1, "mapped_location": "HQ West"},
                {"id": 2, "mapped_location": "Field Alpha"},
            ],
            "events": [
                {"site_name": "HQ West", "message": "HQ West alert"},
                {"site_name": "Field Alpha", "message": "Field Alpha alert"},
                {"site_name": None, "message": "Unmapped event"},
            ],
            "grid": [
                {"affected_area": "HQ West"},
                {"affected_area": "Field Alpha"},
            ],
            "alert_count": 2,
        }
        result = filter_aiops_payload_for_user(payload, user, locations=locations)
        self.assertEqual([row["id"] for row in result["alerts"]], [1])
        self.assertEqual([row["message"] for row in result["events"]], ["HQ West alert"])
        self.assertEqual([row["affected_area"] for row in result["grid"]], ["HQ West"])
        self.assertEqual(result["alert_count"], 1)

    def test_report_search_parser_supports_delimiters_and_phrases(self):
        from src.services import parse_search_terms

        self.assertEqual(
            parse_search_terms('APT29, "critical infrastructure"; ransomware'),
            ["APT29", "critical infrastructure", "ransomware"],
        )
        with self.assertRaises(ValueError):
            parse_search_terms('"unclosed phrase')


if __name__ == "__main__":
    unittest.main()
