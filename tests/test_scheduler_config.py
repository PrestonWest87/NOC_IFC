import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import services as svc
from src.core.scheduler_registry import JOB_REGISTRY, default_schedule, validate_schedule
from src.models.schema import Base, SchedulerJobConfig, SystemConfig


class SchedulerConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.session_patch = patch.object(svc, "SessionLocal", self.session_factory)
        self.session_patch.start()

    def tearDown(self):
        self.session_patch.stop()
        self.engine.dispose()

    def test_registry_exposes_defaults_and_validates_job_specific_bounds(self):
        defaults = default_schedule("rss_fetch")
        self.assertEqual(defaults["every_value"], 5)
        self.assertEqual(validate_schedule("rss_fetch", {**defaults, "every_value": 10})["every_value"], 10)
        with self.assertRaises(ValueError):
            validate_schedule("rss_fetch", {**defaults, "every_value": 1})
        with self.assertRaises(ValueError):
            validate_schedule("tiered_alert_escalation", {
                **default_schedule("tiered_alert_escalation"), "enabled": False,
            })
        with self.assertRaises(ValueError):
            validate_schedule("global_brief", {
                **default_schedule("global_brief"), "run_at": "25:99",
            })

    def test_persisted_change_increments_worker_revision(self):
        initial = svc.get_scheduler_settings()
        self.assertEqual(initial["revision"], 0)
        changed = svc.save_scheduler_setting(
            "rss_fetch", {**default_schedule("rss_fetch"), "every_value": 10}, "admin", None
        )
        self.assertEqual(changed["revision"], 1)
        current = svc.get_scheduler_settings()
        self.assertEqual(current["revision"], 1)
        self.assertEqual(current["applied_revision"], 0)
        rss = next(job for job in current["jobs"] if job["key"] == "rss_fetch")
        self.assertEqual(rss["schedule"]["every_value"], 10)
        svc.mark_scheduler_revision_applied(1)
        self.assertEqual(svc.get_scheduler_settings()["applied_revision"], 1)
        with self.session_factory() as db:
            self.assertEqual(db.query(SchedulerJobConfig).count(), 1)
            self.assertEqual(db.query(SystemConfig).one().scheduler_revision, 1)

    def test_registry_functions_are_unique_and_have_valid_defaults(self):
        self.assertTrue(JOB_REGISTRY)
        for key, job in JOB_REGISTRY.items():
            validated = validate_schedule(key, default_schedule(key))
            self.assertEqual(validated["schedule_type"], job["schedule_type"])

        backup = default_schedule("database_backup")
        self.assertEqual(backup["schedule_type"], "weekly")
        self.assertEqual(backup["weekday"], "sunday")
        self.assertEqual(backup["run_at"], "00:00")
        self.assertEqual(backup["timezone"], "America/Chicago")
        with self.assertRaisesRegex(ValueError, "cannot be disabled"):
            validate_schedule("database_backup", {**backup, "enabled": False})


if __name__ == "__main__":
    unittest.main()
