import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import services
from src.models.schema import Base, MonitoredLocation, SolarWindsAlert


class NeedsDispatchServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.sessions = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.session_patch = patch.object(services, "SessionLocal", self.sessions)
        self.session_patch.start()
        with self.sessions() as session:
            session.add(MonitoredLocation(name="NOC-1", lat=34.0, lon=-92.0))
            session.add_all([
                SolarWindsAlert(
                    id=1, node_name="router-1", status="Active", mapped_location="NOC-1",
                    is_correlated=False, is_dispatched=True,
                ),
                SolarWindsAlert(
                    id=2, node_name="router-2", status="Active", mapped_location="NOC-1",
                    is_correlated=False, is_dispatched=False,
                ),
                SolarWindsAlert(
                    id=3, node_name="router-3", status="Resolved", mapped_location="NOC-1",
                    is_correlated=False, is_dispatched=True,
                ),
                SolarWindsAlert(
                    id=4, node_name="router-4", status="Active", mapped_location="NOC-1",
                    is_correlated=True, is_dispatched=True,
                ),
            ])
            session.commit()

    def tearDown(self):
        self.session_patch.stop()
        self.engine.dispose()

    def test_needs_dispatch_is_persisted_only_for_current_active_uncorrelated_alerts(self):
        updated = services.set_site_needs_dispatch("NOC-1", True, modified_by="dispatcher")
        self.assertEqual(updated, 2)

        with self.sessions() as session:
            alerts = {alert.id: alert for alert in session.query(SolarWindsAlert).all()}
            self.assertTrue(alerts[1].needs_dispatch)
            self.assertTrue(alerts[2].needs_dispatch)
            self.assertFalse(alerts[1].is_dispatched)
            self.assertFalse(alerts[2].is_dispatched)
            self.assertFalse(alerts[3].needs_dispatch)
            self.assertFalse(alerts[4].needs_dispatch)
            location = session.query(MonitoredLocation).filter_by(name="NOC-1").one()
            self.assertEqual(location.status_modified_by, "dispatcher")
            self.assertIsNotNone(location.status_modified_at)

        self.assertEqual(services.set_site_needs_dispatch("NOC-1", False, modified_by="dispatcher"), 2)
        with self.sessions() as session:
            alerts = {alert.id: alert for alert in session.query(SolarWindsAlert).all()}
            self.assertFalse(alerts[1].needs_dispatch)
            self.assertFalse(alerts[2].needs_dispatch)

    def test_needs_dispatch_cannot_be_set_without_an_active_alert(self):
        with self.sessions() as session:
            session.add(MonitoredLocation(name="NOC-2", lat=35.0, lon=-93.0))
            session.commit()

        with self.assertRaisesRegex(ValueError, "requires at least one active site alert"):
            services.set_site_needs_dispatch("NOC-2", True, modified_by="dispatcher")


if __name__ == "__main__":
    unittest.main()
