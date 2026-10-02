import unittest
from unittest.mock import patch

from src.core.scheduler_registry import JOB_REGISTRY, default_schedule
from src import scheduler


class SchedulerReloadTests(unittest.TestCase):
    def setUp(self):
        scheduler.schedule.clear()
        scheduler._loaded_scheduler_revision = 10

    def tearDown(self):
        scheduler.schedule.clear()
        scheduler._loaded_scheduler_revision = None

    def test_worker_reschedules_managed_jobs_when_revision_changes(self):
        settings = {key: default_schedule(key) for key in JOB_REGISTRY}
        settings["rss_fetch"]["every_value"] = 10
        snapshot = (11, 10, settings, [])
        with patch.object(scheduler, "_get_scheduler_snapshot", return_value=snapshot), patch(
            "src.services.mark_scheduler_revision_applied"
        ) as mark_applied:
            scheduler._reload_scheduler_if_changed()
        mark_applied.assert_called_once_with(11)

        rss_job = next(
            job for job in scheduler.schedule.get_jobs("noc-managed")
            if "rss_fetch" in job.tags
        )
        self.assertEqual(rss_job.interval, 10)
        self.assertEqual(rss_job.unit, "minutes")
        self.assertEqual(scheduler._loaded_scheduler_revision, 11)

    def test_disabled_noncritical_job_is_not_registered(self):
        settings = {key: default_schedule(key) for key in JOB_REGISTRY}
        settings["rss_fetch"]["enabled"] = False
        scheduler._register_configured_jobs(settings)
        keys = {tag for job in scheduler.schedule.get_jobs("noc-managed") for tag in job.tags}
        self.assertNotIn("rss_fetch", keys)
        self.assertIn("tiered_alert_escalation", keys)


if __name__ == "__main__":
    unittest.main()
