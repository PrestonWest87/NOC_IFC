import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import scheduler
from src.models.schema import Base, CloudOutage


class SchedulerMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)

    def tearDown(self):
        self.engine.dispose()

    def test_cloud_outage_retention_keeps_recent_and_older_unresolved_rows(self):
        now = datetime.utcnow()
        rows = [
            CloudOutage(provider="resolved-old", is_resolved=True, updated_at=now - timedelta(hours=25)),
            CloudOutage(provider="resolved-recent", is_resolved=True, updated_at=now - timedelta(hours=12)),
            CloudOutage(provider="unresolved-recent", is_resolved=False, updated_at=now - timedelta(days=13)),
            CloudOutage(provider="unresolved-old", is_resolved=False, updated_at=now - timedelta(days=15)),
        ]
        with self.sessions() as session:
            session.add_all(rows)
            session.commit()

        with patch.object(scheduler, "SessionLocal", self.sessions), patch.object(scheduler, "engine", self.engine):
            scheduler.run_database_maintenance()

        with self.sessions() as session:
            remaining = {row.provider for row in session.query(CloudOutage).all()}
        self.assertEqual(remaining, {"resolved-recent", "unresolved-recent"})


if __name__ == "__main__":
    unittest.main()
