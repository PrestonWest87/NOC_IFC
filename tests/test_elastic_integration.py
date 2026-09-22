import unittest
from unittest.mock import Mock, patch


class ElasticIntegrationTests(unittest.TestCase):
    def test_client_is_lazy_and_uses_configured_tls(self):
        from src.workers import elastic_worker

        with patch.object(elastic_worker, "es", None), patch.object(
            elastic_worker, "Elasticsearch", return_value="client"
        ) as constructor:
            self.assertEqual(elastic_worker._get_client(), "client")

        options = constructor.call_args.kwargs
        self.assertTrue(options["verify_certs"])
        self.assertIn("request_timeout", options)

    def test_sync_normalizes_string_severity_and_composite_ids(self):
        from src.workers import elastic_worker

        class Query:
            def filter(self, *_args):
                return self

            def first(self):
                return None

        class Session:
            def __init__(self):
                self.rows = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def query(self, *_args):
                return Query()

            def add(self, row):
                self.rows.append(row)

            def commit(self):
                pass

        client = Mock()
        client.search.return_value = {
            "hits": {
                "hits": [{
                    "_id": "event-1",
                    "_index": "logs-2026.09.21",
                    "_source": {
                        "event": {"severity": "3", "original": "test event"},
                        "@timestamp": "2026-09-21T12:00:00Z",
                    },
                }]
            }
        }
        session = Session()
        with patch.object(elastic_worker, "es", client), patch.object(elastic_worker, "SessionLocal", return_value=session):
            result = elastic_worker.sync_elastic_telemetry(hours_back=1)

        self.assertEqual(result, {"status": "ok", "imported": 1})
        self.assertEqual(session.rows[0].id, "logs-2026.09.21:event-1")
        self.assertEqual(session.rows[0].severity, "HIGH")

    def test_live_query_rejects_invalid_input_without_calling_elastic(self):
        from src.workers import elastic_worker

        client = Mock()
        with patch.object(elastic_worker, "es", client):
            self.assertEqual(
                elastic_worker.execute_live_query(index_pattern="bad pattern"),
                {"error": "Invalid Elasticsearch index pattern."},
            )
            self.assertEqual(
                elastic_worker.execute_live_query(size=0),
                {"error": "Invalid Elasticsearch result size."},
            )
            self.assertEqual(
                elastic_worker.execute_live_query(query_body=[]),
                {"error": "Invalid Elasticsearch query."},
            )
            self.assertFalse(client.search.called)

    def test_live_query_does_not_mutate_caller_query(self):
        from src.workers import elastic_worker

        client = Mock()
        client.search.return_value = {"hits": {"hits": []}}
        query = {"query": {"match_all": {}}}
        with patch.object(elastic_worker, "es", client):
            self.assertEqual(elastic_worker.execute_live_query(query_body=query, size=7), [])
        self.assertEqual(query, {"query": {"match_all": {}}})
        self.assertEqual(client.search.call_args.kwargs["body"]["size"], 7)


if __name__ == "__main__":
    unittest.main()
