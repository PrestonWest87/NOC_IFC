"""Small stdlib checks for the Python/C# route comparison helper."""

import unittest

from compare_api_routes import compare_specs


class ApiRouteComparisonTests(unittest.TestCase):
    def test_normalizes_parameter_names_and_ignores_retired_feature_routes(self):
        python = {"paths": {
            "/api/v1/users/{username}": {"get": {}, "put": {}},
            "/api/v1/dashboard/articles/feedback": {"post": {}},
        }}
        csharp = {"paths": {
            "/api/v1/users/{name}": {"get": {}, "put": {}},
        }}

        missing, extra, retired = compare_specs(python, csharp)

        self.assertEqual(set(), missing)
        self.assertEqual(set(), extra)
        self.assertEqual({("post", "/api/v1/dashboard/articles/feedback")}, retired)

    def test_reports_missing_and_extra_operations(self):
        python = {"paths": {"/api/v1/a": {"get": {}}, "/api/v1/b": {"post": {}}}}
        csharp = {"paths": {"/api/v1/a": {"get": {}}, "/api/v1/c": {"delete": {}}}}

        missing, extra, retired = compare_specs(python, csharp)

        self.assertEqual({("post", "/api/v1/b")}, missing)
        self.assertEqual({("delete", "/api/v1/c")}, extra)
        self.assertEqual(set(), retired)


if __name__ == "__main__":
    unittest.main()
