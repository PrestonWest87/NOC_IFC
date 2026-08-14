import unittest
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
