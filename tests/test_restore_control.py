import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import restore_control
from src.core import ui_restore


class RestoreControlTests(unittest.TestCase):
    def test_restore_gate_blocks_new_api_writers_and_publishes_status_capability(self):
        with tempfile.TemporaryDirectory(prefix="noc-restore-control-") as directory, patch.object(
            restore_control, "application_data_dir", return_value=Path(directory)
        ):
            self.assertTrue(restore_control.begin_api_request())
            restore_control.end_api_request()
            self.assertTrue(restore_control.begin_api_background_writer())
            restore_control.end_api_background_writer()

            restore_id = restore_control.begin_restore("stage-" + "a" * 32 + ".nocbackup", "test-admin")
            self.assertTrue(restore_control.maintenance_requested())
            self.assertFalse(restore_control.begin_api_request())
            self.assertFalse(restore_control.begin_api_background_writer())
            self.assertEqual(restore_control.api_activity(), {
                "active_requests": 0,
                "active_background_writers": 0,
            })

            restore_control.publish_process_status("worker", "paused")
            worker = restore_control.process_status("worker", restore_id)
            self.assertIsNotNone(worker)
            self.assertEqual(worker["state"], "paused")
            self.assertEqual(restore_control.restore_status(restore_id)["state"], "quiescing")

            restore_control.update_restore(restore_id, "restoring", "Installing snapshot", percent=50)
            restore_control.finish_restore(restore_id, "complete", "Restore completed", result={"table_count": 36})
            self.assertFalse(restore_control.maintenance_requested())
            status = restore_control.restore_status(restore_id)
            self.assertEqual(status["state"], "complete")
            self.assertEqual(status["percent"], 100)
            self.assertEqual(status["result"], {"table_count": 36})

    def test_only_one_restore_can_enter_shared_maintenance_mode(self):
        with tempfile.TemporaryDirectory(prefix="noc-restore-control-") as directory, patch.object(
            restore_control, "application_data_dir", return_value=Path(directory)
        ):
            restore_control.begin_restore("stage-" + "b" * 32 + ".nocbackup", "admin")
            with self.assertRaises(restore_control.RestoreInProgressError):
                restore_control.begin_restore("stage-" + "c" * 32 + ".nocbackup", "admin")

    def test_ui_restore_waits_for_fresh_idle_worker_and_webhook_acknowledgements(self):
        with tempfile.TemporaryDirectory(prefix="noc-restore-control-") as directory, patch.object(
            restore_control, "application_data_dir", return_value=Path(directory)
        ):
            restore_id = restore_control.begin_restore("stage-" + "d" * 32 + ".nocbackup", "admin")
            restore_control.publish_process_status("worker", "paused")
            restore_control.publish_process_status("webhook", "paused")

            ui_restore._wait_for_writers(restore_id)

            restore_control.publish_process_status("webhook", "draining", active=1)
            with patch.object(ui_restore, "QUIESCE_TIMEOUT_SECONDS", 0.01):
                with self.assertRaisesRegex(TimeoutError, "did not all become idle"):
                    ui_restore._wait_for_writers(restore_id)


if __name__ == "__main__":
    unittest.main()
