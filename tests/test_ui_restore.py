import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.core import restore_control, ui_restore


class UIRestoreTests(unittest.TestCase):
    def test_restore_waits_for_all_writer_acknowledgements_then_reports_completion(self):
        with tempfile.TemporaryDirectory(prefix="noc-ui-restore-") as directory, patch.object(
            restore_control, "application_data_dir", return_value=Path(directory)
        ):
            restore_id = restore_control.begin_restore("stage-" + ("e" * 32) + ".nocbackup", "admin")
            restore_control.publish_process_status("worker", "paused")
            restore_control.publish_process_status("webhook", "paused")
            result = {
                "backup_created_at": "2026-10-02T00:00:00Z",
                "table_count": 36,
                "model_restored": True,
                "credentials_invalidated": {"sessions": 2},
                "pre_restore_backup": "safety.nocbackup",
            }
            with patch("src.core.backup_manager.get_staged_backup_path", return_value=Path(directory) / "staged.nocbackup"), patch(
                "src.core.backup_manager.restore_backup", return_value=result
            ) as restore, patch("src.core.db.init_db") as init_db, patch(
                "src.services.logic.force_reload_scorer"
            ):
                ui_restore._run_restore(restore_id)
            restore.assert_called_once_with(Path(directory) / "staged.nocbackup", maintenance_confirmed=True)
            init_db.assert_called_once()
            self.assertFalse(restore_control.maintenance_requested())
            status = restore_control.restore_status(restore_id)
            self.assertEqual(status["state"], "complete")
            self.assertEqual(status["percent"], 100)
            self.assertEqual(status["result"]["table_count"], 36)


if __name__ == "__main__":
    unittest.main()
