import io
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from src.core import backup_manager
from src.core.config import settings
from src.models.schema import (
    AccountAuditEvent,
    Base,
    EmailChangeRequest,
    PasswordResetRequest,
    PasswordResetToken,
    RegistrationInvite,
    User,
    UserSession,
)


class BackupManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="noc-backup-test-")
        self.root = Path(self.temp.name)
        self.backup_dir = self.root / "backups"
        self.model_path = self.root / "models" / "ml_model.pkl"
        self.key = bytes(range(32))
        self.key_patch = patch.object(
            settings, "backup_encryption_keys", json.dumps({"test-key": self.key.hex()})
        )
        self.active_patch = patch.object(settings, "backup_encryption_active_key_id", "test-key")
        self.limit_patch = patch.object(settings, "backup_max_bytes", 8 * 1024 * 1024)
        self.key_patch.start()
        self.active_patch.start()
        self.limit_patch.start()

    def tearDown(self):
        self.limit_patch.stop()
        self.active_patch.stop()
        self.key_patch.stop()
        self.temp.cleanup()

    def create_database(self, path: Path, username: str, extension_secret: str = "extension-secret"):
        engine = create_engine(f"sqlite:///{path}")
        Base.metadata.create_all(engine)
        now = datetime.utcnow()
        with Session(engine) as db:
            user = User(
                username=username,
                password_hash="hashed-password",
                role="admin",
                session_token=f"legacy-{username}-session",
                account_type="individual",
                is_active=True,
            )
            db.add(user)
            db.flush()
            db.add(UserSession(user_id=user.id, token=f"session-{username}"))
            db.add(RegistrationInvite(
                username=f"pending-{username}", role="analyst", token_hash=f"invite-{username}",
                created_by=username, created_at=now, expires_at=now + timedelta(days=1),
                email=f"{username}@example.test", email_normalized=f"{username}@example.test",
            ))
            request = PasswordResetRequest(
                user_id=user.id, identifier_hash=f"identifier-{username}", requester_ip="192.0.2.1",
                status="approved", requested_at=now, reviewed_by_id=user.id, reviewed_at=now,
            )
            db.add(request)
            db.flush()
            db.add(PasswordResetToken(
                request_id=request.id, user_id=user.id, token_hash=f"reset-{username}",
                created_at=now, expires_at=now + timedelta(hours=1),
            ))
            db.add(EmailChangeRequest(
                user_id=user.id,
                requested_email=f"new-{username}@example.test",
                requested_email_normalized=f"new-{username}@example.test",
                status="pending_verification",
                requested_at=now,
                reviewed_by_id=user.id,
                reviewed_at=now,
                verification_token_hash=f"email-verification-{username}",
                verification_expires_at=now + timedelta(hours=1),
            ))
            db.add(AccountAuditEvent(
                actor_user_id=user.id,
                subject_user_id=user.id,
                event_type="test_history",
                event_detail={"preserve": True},
                created_at=now,
            ))
            db.commit()
        engine.dispose()
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE custom_extension_data (secret TEXT NOT NULL)")
            connection.execute("INSERT INTO custom_extension_data(secret) VALUES (?)", (extension_secret,))
        return path

    def test_full_snapshot_encrypts_all_sqlite_tables_and_model_then_validates(self):
        database = self.create_database(self.root / "source.sqlite", "archived-user")
        self.model_path.parent.mkdir(parents=True)
        self.model_path.write_bytes(b"serialized-ml-model" * 100_000)

        backup = backup_manager.create_backup(
            "manual", database_path=database, model_path=self.model_path,
            backup_dir=self.backup_dir,
        )
        encrypted_path = self.backup_dir / backup["filename"]
        encrypted_bytes = encrypted_path.read_bytes()
        self.assertTrue(encrypted_bytes.startswith(backup_manager.BACKUP_MAGIC))
        self.assertNotIn(b"extension-secret", encrypted_bytes)
        self.assertNotIn(b"hashed-password", encrypted_bytes)
        encrypted_db = sqlite3.connect(encrypted_path)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                encrypted_db.execute("SELECT name FROM sqlite_master").fetchall()
        finally:
            encrypted_db.close()

        validation = backup_manager.validate_backup(encrypted_path)
        manifest = validation["manifest"]
        self.assertGreaterEqual(manifest["database"]["table_count"], len(Base.metadata.tables))
        self.assertIn("custom_extension_data", manifest["database"]["tables"])
        self.assertTrue(validation["summary"]["model_included"])
        self.assertEqual(validation["summary"]["backup_kind"], "manual")

    def test_authentication_rejects_tampered_or_unavailable_keys(self):
        database = self.create_database(self.root / "tamper.sqlite", "tamper-user")
        backup = backup_manager.create_backup(database_path=database, backup_dir=self.backup_dir)
        path = self.backup_dir / backup["filename"]
        with patch.object(settings, "backup_encryption_keys", json.dumps({"other-key": (b"o" * 32).hex()})), patch.object(
            settings, "backup_encryption_active_key_id", "other-key"
        ):
            with self.assertRaisesRegex(backup_manager.BackupError, "key required"):
                backup_manager.validate_backup(path)
        data = bytearray(path.read_bytes())
        data[-1] ^= 0x01
        path.write_bytes(data)
        with self.assertRaisesRegex(backup_manager.BackupError, "authentication failed"):
            backup_manager.validate_backup(path)

    def test_scheduled_retention_keeps_three_and_never_prunes_manual_backups(self):
        database = self.create_database(self.root / "retention.sqlite", "retention-user")
        manual = backup_manager.create_backup(database_path=database, backup_dir=self.backup_dir)
        for _ in range(4):
            backup_manager.create_backup("scheduled", database_path=database, backup_dir=self.backup_dir)

        records = backup_manager.list_backups(backup_dir=self.backup_dir)
        self.assertEqual(sum(item["kind"] == "scheduled" for item in records), 3)
        self.assertIn(manual["filename"], {item["filename"] for item in records})
        with self.assertRaisesRegex(backup_manager.BackupError, "retention policy"):
            scheduled = next(item for item in records if item["kind"] == "scheduled")
            backup_manager.delete_backup(scheduled["id"], backup_dir=self.backup_dir)

    def test_legacy_pre_restore_backup_can_be_relabelled_from_authenticated_manifest(self):
        database = self.create_database(self.root / "legacy-safety.sqlite", "legacy-safety-user")
        safety = backup_manager.create_backup(
            "manual", reason="pre-restore safety snapshot", database_path=database,
            backup_dir=self.backup_dir,
        )
        current_path = self.backup_dir / safety["filename"]
        match = backup_manager._BACKUP_FILENAME.fullmatch(current_path.name)
        legacy_name = backup_manager._backup_filename(
            "manual", datetime.strptime(match.group(2), "%Y%m%dT%H%M%SZ").replace(tzinfo=backup_manager.timezone.utc),
            match.group(3), category="manual",
        )
        current_path.rename(self.backup_dir / legacy_name)

        relabelled = backup_manager.relabel_legacy_pre_restore_backup(
            legacy_name, backup_dir=self.backup_dir,
        )

        self.assertEqual(relabelled, safety["filename"])
        self.assertEqual(backup_manager.list_backups(backup_dir=self.backup_dir)[0]["kind"], "pre-restore")

    def test_stage_upload_validates_before_persisting_and_can_be_removed(self):
        database = self.create_database(self.root / "stage.sqlite", "stage-user")
        backup = backup_manager.create_backup(database_path=database, backup_dir=self.backup_dir)
        package = self.backup_dir / backup["filename"]

        staged = backup_manager.stage_uploaded_backup(io.BytesIO(package.read_bytes()), backup_dir=self.backup_dir)

        self.assertEqual(staged["table_count"], backup["table_count"])
        self.assertEqual(len(backup_manager.list_staged_backups(backup_dir=self.backup_dir)), 1)
        backup_manager.delete_staged_backup(staged["stage_id"], backup_dir=self.backup_dir)
        self.assertEqual(backup_manager.list_staged_backups(backup_dir=self.backup_dir), [])

    def test_offline_restore_migrates_database_and_invalidates_outstanding_credentials(self):
        source = self.create_database(self.root / "archive.sqlite", "restored-user", "all-table-data")
        current = self.create_database(self.root / "current.sqlite", "current-user", "current-data")
        self.model_path.parent.mkdir(parents=True)
        self.model_path.write_bytes(b"restored-model")
        backup = backup_manager.create_backup(
            database_path=source, model_path=self.model_path, backup_dir=self.backup_dir,
        )
        package = self.backup_dir / backup["filename"]
        self.model_path.write_bytes(b"current-model")
        staged_dir = self.backup_dir / "staged"
        staged_dir.mkdir()
        (staged_dir / f"stage-{'a' * 32}.nocbackup").write_bytes(b"staged-one")
        (staged_dir / f"stage-{'b' * 32}.nocbackup").write_bytes(b"staged-two")

        with self.assertRaisesRegex(backup_manager.BackupError, "stopping API, worker, and webhook"):
            backup_manager.restore_backup(
                package, database_path=current, model_path=self.model_path, backup_dir=self.backup_dir,
            )

        result = backup_manager.restore_backup(
            package,
            maintenance_confirmed=True,
            database_path=current,
            model_path=self.model_path,
            backup_dir=self.backup_dir,
        )

        self.assertEqual(result["status"], "restored")
        self.assertTrue(result["model_restored"])
        self.assertTrue(result["pre_restore_backup"])
        self.assertEqual(result["staged_packages_cleared"], 2)
        self.assertEqual(backup_manager.list_staged_backups(backup_dir=self.backup_dir), [])
        safety_record = next(
            item for item in backup_manager.list_backups(backup_dir=self.backup_dir)
            if item["filename"] == result["pre_restore_backup"]
        )
        self.assertEqual(safety_record["kind"], "pre-restore")
        self.assertEqual(self.model_path.read_bytes(), b"restored-model")
        with sqlite3.connect(current) as connection:
            self.assertEqual(connection.execute("SELECT username, session_token FROM users").fetchone(), ("restored-user", None))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM user_sessions").fetchone()[0], 0)
            self.assertIsNotNone(connection.execute("SELECT revoked_at FROM registration_invites").fetchone()[0])
            self.assertIsNotNone(connection.execute("SELECT used_at FROM password_reset_tokens").fetchone()[0])
            email_request = connection.execute(
                "SELECT status, verification_token_hash, verification_expires_at FROM email_change_requests"
            ).fetchone()
            self.assertEqual(email_request, ("invalidated", None, None))
            self.assertEqual(connection.execute("SELECT secret FROM custom_extension_data").fetchone()[0], "all-table-data")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM account_audit_events").fetchone()[0], 1)
        self.assertTrue((self.backup_dir / result["pre_restore_backup"]).is_file())

    def test_restore_install_failure_rolls_back_database_and_model(self):
        source = self.create_database(self.root / "rollback-source.sqlite", "archive-user", "archive-data")
        current = self.create_database(self.root / "rollback-current.sqlite", "live-user", "live-data")
        self.model_path.parent.mkdir(parents=True)
        self.model_path.write_bytes(b"archive-model")
        backup = backup_manager.create_backup(
            database_path=source, model_path=self.model_path, backup_dir=self.backup_dir,
        )
        self.model_path.write_bytes(b"live-model")
        original_fsync = backup_manager._fsync_directory
        calls = 0

        def fail_after_swap(directory):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("simulated directory sync failure")
            original_fsync(directory)

        with patch.object(backup_manager, "_fsync_directory", side_effect=fail_after_swap):
            with self.assertRaisesRegex(backup_manager.BackupError, "rolled back"):
                backup_manager.restore_backup(
                    self.backup_dir / backup["filename"],
                    maintenance_confirmed=True,
                    database_path=current,
                    model_path=self.model_path,
                    backup_dir=self.backup_dir,
                )

        with sqlite3.connect(current) as connection:
            self.assertEqual(connection.execute("SELECT username FROM users").fetchone()[0], "live-user")
            self.assertEqual(connection.execute("SELECT secret FROM custom_extension_data").fetchone()[0], "live-data")
        self.assertEqual(self.model_path.read_bytes(), b"live-model")

    def test_failed_database_replace_restores_the_consistent_pre_restore_snapshot(self):
        source = self.create_database(self.root / "replace-source.sqlite", "archive-user", "archive-data")
        current = self.create_database(self.root / "replace-current.sqlite", "live-user", "live-data")
        backup = backup_manager.create_backup(database_path=source, backup_dir=self.backup_dir)
        original_replace = backup_manager.os.replace
        failed_once = False

        def fail_new_database_once(source_path, destination_path):
            nonlocal failed_once
            if Path(destination_path) == current and not failed_once:
                failed_once = True
                raise OSError("simulated atomic database replacement failure")
            original_replace(source_path, destination_path)

        with patch.object(backup_manager.os, "replace", side_effect=fail_new_database_once):
            with self.assertRaisesRegex(backup_manager.BackupError, "rolled back"):
                backup_manager.restore_backup(
                    self.backup_dir / backup["filename"],
                    maintenance_confirmed=True,
                    database_path=current,
                    model_path=self.model_path,
                    backup_dir=self.backup_dir,
                )

        with sqlite3.connect(current) as connection:
            self.assertEqual(connection.execute("SELECT username FROM users").fetchone()[0], "live-user")
            self.assertEqual(connection.execute("SELECT secret FROM custom_extension_data").fetchone()[0], "live-data")

    def test_key_rotation_keeps_old_backups_decryptable(self):
        database = self.create_database(self.root / "rotation.sqlite", "rotation-user")
        old_key = self.key
        backup = backup_manager.create_backup(database_path=database, backup_dir=self.backup_dir)
        new_key = bytes(reversed(range(32)))
        with patch.object(
            settings, "backup_encryption_keys",
            json.dumps({"test-key": old_key.hex(), "rotated-key": new_key.hex()}),
        ), patch.object(settings, "backup_encryption_active_key_id", "rotated-key"):
            self.assertEqual(
                backup_manager.validate_backup(self.backup_dir / backup["filename"])["manifest"]["backup_kind"],
                "manual",
            )
            rotated = backup_manager.create_backup(database_path=database, backup_dir=self.backup_dir)
            self.assertTrue(backup_manager.validate_backup(self.backup_dir / rotated["filename"]))


if __name__ == "__main__":
    unittest.main()
