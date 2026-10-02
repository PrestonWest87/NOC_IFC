import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.models.schema import CloudOutage, CrimeIncident, CveItem, RegionalHazard
from src.workers import cloud_worker, crime_worker, cve_worker, infra_worker


class _BatchQuery:
    def __init__(self, session, model):
        self.session = session
        self.model = model
        if isinstance(model, type):
            self.table_name = model.__tablename__
        else:
            self.table_name = model.property.columns[0].table.name
        self.filters = []
        self.all_calls = 0

    def filter(self, *criteria):
        self.filters.extend(criteria)
        return self

    def filter_by(self, **criteria):
        self.filters.append(criteria)
        return self

    def all(self):
        self.all_calls += 1
        if self.table_name == RegionalHazard.__tablename__:
            return self.session.existing_hazards
        if self.table_name == CveItem.__tablename__:
            return [("CVE-2026-0001",)]
        if self.table_name == CloudOutage.__tablename__:
            return []
        if self.table_name == CrimeIncident.__tablename__:
            return [("existing-crime",)]
        return []

    def first(self):
        return None

    def delete(self, **_kwargs):
        return 0


class _BatchSession:
    def __init__(self, existing_hazards=()):
        self.existing_hazards = list(existing_hazards)
        self.queries = []
        self.added = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def query(self, model):
        query = _BatchQuery(self, model)
        self.queries.append(query)
        return query

    def add(self, item):
        self.added.append(item)

    def add_all(self, items):
        self.added.extend(items)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass


class WorkerBatchingTests(unittest.TestCase):
    def test_cve_worker_queries_only_ids_in_the_current_feed(self):
        session = _BatchSession()
        response = Mock()
        response.json.return_value = {"vulnerabilities": [
            {"cveID": "CVE-2026-0001", "dateAdded": "2026-09-01"},
            {"cveID": "CVE-2026-0002", "dateAdded": "2026-09-02"},
            {"cveID": "CVE-2026-0003", "dateAdded": "2026-09-03"},
        ]}

        with patch.object(cve_worker, "SessionLocal", return_value=session), patch.object(
            cve_worker.requests, "get", return_value=response
        ):
            cve_worker.fetch_cisa_kev()

        cve_queries = [query for query in session.queries if query.table_name == CveItem.__tablename__]
        self.assertEqual(len(cve_queries), 1)
        self.assertEqual([row.cve_id for row in session.added], ["CVE-2026-0002", "CVE-2026-0003"])

    def test_crime_worker_batch_store_uses_one_lookup(self):
        session = _BatchSession()
        incidents = [
            CrimeIncident(id="existing-crime"),
            CrimeIncident(id="new-crime-1"),
            CrimeIncident(id="new-crime-1"),
            CrimeIncident(id="new-crime-2"),
        ]

        added = crime_worker._store_crime_batch(session, incidents)

        self.assertEqual(added, 2)
        self.assertEqual(len(session.queries), 1)
        self.assertEqual([row.id for row in session.added], ["new-crime-1", "new-crime-2"])
        self.assertEqual(session.commits, 1)

    def test_nws_worker_loads_existing_hazards_in_one_query(self):
        existing = RegionalHazard(hazard_id="existing-alert", updated_at=datetime(2026, 1, 1))
        session = _BatchSession(existing_hazards=[existing])
        response = Mock(status_code=200)
        response.json.return_value = {"features": [
            {"properties": {"id": "existing-alert", "event": "Wind", "headline": "Wind", "severity": "Severe"}},
            {"properties": {"id": "new-alert", "event": "Flood", "headline": "Flood", "severity": "Moderate"}},
        ]}

        with patch.object(infra_worker, "SessionLocal", return_value=session), patch.object(
            infra_worker.requests, "get", return_value=response
        ):
            infra_worker.fetch_nws_alerts_for_region("AR", "nws_ar")

        hazard_queries = [query for query in session.queries if query.model is RegionalHazard]
        self.assertEqual(len(hazard_queries), 1)
        self.assertEqual(len(session.added), 2)  # GeoJSON cache and one new hazard.
        self.assertEqual(sum(isinstance(row, RegionalHazard) for row in session.added), 1)
        self.assertIsNotNone(existing.updated_at)

    def test_cloud_worker_batches_existing_outage_lookup_per_provider(self):
        session = _BatchSession()
        current_time = datetime.now(timezone.utc).replace(tzinfo=None).timetuple()
        entries = [
            {"published_parsed": current_time, "title": "AWS US-East incident one", "link": "https://status.test/1", "summary": "US-East"},
            {"published_parsed": current_time, "title": "AWS US-East incident two", "link": "https://status.test/2", "summary": "US-East"},
        ]

        with patch.object(cloud_worker, "CLOUD_FEEDS", {"AWS": "https://status.test/feed"}), patch.object(
            cloud_worker, "_fetch_single_feed", return_value=("AWS", "feed-body", None)
        ), patch.object(cloud_worker.feedparser, "parse", return_value=SimpleNamespace(entries=entries)), patch.object(
            cloud_worker, "SessionLocal", return_value=session
        ):
            cloud_worker.fetch_cloud_outages()

        outage_queries = [query for query in session.queries if query.table_name == CloudOutage.__tablename__]
        self.assertEqual(len(outage_queries), 2)  # One batch lookup and one purge query.
        self.assertEqual(outage_queries[0].all_calls, 1)
        self.assertEqual(sum(isinstance(row, CloudOutage) for row in session.added), 2)

    def test_cloud_worker_updates_duplicate_new_candidate_without_an_extra_insert(self):
        session = _BatchSession()
        current_time = datetime.now(timezone.utc).replace(tzinfo=None).timetuple()
        entries = [
            {"published_parsed": current_time, "title": "AWS US-East incident", "link": "https://status.test/1", "summary": "US-East outage reported"},
            {"published_parsed": current_time, "title": "AWS US-East incident", "link": "https://status.test/2", "summary": "US-East outage resolved"},
        ]

        with patch.object(cloud_worker, "CLOUD_FEEDS", {"AWS": "https://status.test/feed"}), patch.object(
            cloud_worker, "_fetch_single_feed", return_value=("AWS", "feed-body", None)
        ), patch.object(cloud_worker.feedparser, "parse", return_value=SimpleNamespace(entries=entries)), patch.object(
            cloud_worker, "SessionLocal", return_value=session
        ):
            cloud_worker.fetch_cloud_outages()

        inserted = [row for row in session.added if isinstance(row, CloudOutage)]
        self.assertEqual(len(inserted), 1)
        self.assertTrue(inserted[0].is_resolved)


if __name__ == "__main__":
    unittest.main()
