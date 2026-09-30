import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import services as svc
from src.models.schema import FailedLoginAttempt, SystemConfig


class FailedLoginAlertTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        SystemConfig.__table__.create(bind=self.engine)
        FailedLoginAttempt.__table__.create(bind=self.engine)
        self.session_factory = sessionmaker(bind=self.engine)
        self.session_patch = patch.object(svc, "SessionLocal", self.session_factory)
        self.session_patch.start()

        with self.session_factory() as db:
            db.add(SystemConfig(
                failed_login_alert_enabled=True,
                failed_login_alert_recipients="security@example.com, noc@example.com",
                failed_login_alert_threshold=3,
                failed_login_alert_window_minutes=5,
                smtp_enabled=True,
                smtp_server="smtp.example.com",
                smtp_sender="noc@example.com",
            ))
            db.commit()

    def tearDown(self):
        self.session_patch.stop()
        self.engine.dispose()

    def test_threshold_alert_includes_submitted_usernames_and_throttles_window(self):
        self.assertIsNone(svc.record_failed_login_attempt("alice", "192.0.2.10"))
        self.assertIsNone(svc.record_failed_login_attempt("admin", "192.0.2.11"))

        alert = svc.record_failed_login_attempt("root", "192.0.2.12")
        self.assertIsNotNone(alert)
        self.assertEqual(alert["threshold"], 3)
        self.assertEqual(alert["window_minutes"], 5)
        self.assertEqual(alert["recipients"], "security@example.com, noc@example.com")
        self.assertEqual(
            [attempt["username"] for attempt in alert["attempts"]],
            ["alice", "admin", "root"],
        )
        self.assertEqual(
            [attempt["source_ip"] for attempt in alert["attempts"]],
            ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
        )

        self.assertIsNone(svc.record_failed_login_attempt("guest", "192.0.2.13"))

    def test_alert_can_fire_again_after_the_configured_window(self):
        for username in ("one", "two", "three"):
            alert = svc.record_failed_login_attempt(username)

        self.assertIsNotNone(alert)
        with self.session_factory() as db:
            config = db.query(SystemConfig).first()
            config.failed_login_alert_last_sent = datetime.utcnow() - timedelta(minutes=6)
            db.commit()

        alert = svc.record_failed_login_attempt("four")
        self.assertIsNotNone(alert)
        self.assertEqual([attempt["username"] for attempt in alert["attempts"]], ["one", "two", "three", "four"])

    def test_recipient_lists_are_normalized_and_validated(self):
        self.assertEqual(
            svc._normalize_failed_login_alert_recipients(
                " security@example.com; NOC@example.com\nsecurity@example.com "
            ),
            "security@example.com, NOC@example.com",
        )
        with self.assertRaises(ValueError):
            svc._normalize_failed_login_alert_recipients("not-an-email")

    def test_admin_config_saves_and_validates_alert_settings(self):
        svc.save_global_config({
            "failed_login_alert_enabled": True,
            "failed_login_alert_recipients": "security@example.com; noc@example.com",
            "failed_login_alert_threshold": 4,
            "failed_login_alert_window_minutes": 10,
        }, allow_system_fields=False)

        with self.session_factory() as db:
            config = db.query(SystemConfig).first()
            self.assertTrue(config.failed_login_alert_enabled)
            self.assertEqual(
                config.failed_login_alert_recipients,
                "security@example.com, noc@example.com",
            )
            self.assertEqual(config.failed_login_alert_threshold, 4)
            self.assertEqual(config.failed_login_alert_window_minutes, 10)

        with self.assertRaises(ValueError):
            svc.save_global_config({
                "failed_login_alert_enabled": True,
                "failed_login_alert_recipients": "",
            }, allow_system_fields=False)

    def test_alert_email_body_contains_each_submitted_username(self):
        from src.api.routes.auth import _send_failed_login_alert

        alert = {
            "recipients": "security@example.com, noc@example.com",
            "threshold": 2,
            "window_minutes": 5,
            "triggered_at": "2026-09-29T12:00:00Z",
            "attempts": [
                {"username": "not-a-user", "source_ip": "192.0.2.10", "attempted_at": "2026-09-29T11:59:00Z"},
                {"username": "admin", "source_ip": "192.0.2.11", "attempted_at": "2026-09-29T12:00:00Z"},
            ],
        }
        with patch("src.utils.mailer.send_alert_email", return_value=(True, "sent")) as send_email:
            _send_failed_login_alert(alert)

        body = send_email.call_args.kwargs["body"]
        self.assertIn('"not-a-user"', body)
        self.assertIn('"admin"', body)
        self.assertEqual(
            send_email.call_args.kwargs["recipient_override"],
            "security@example.com, noc@example.com",
        )

    def test_alert_recipient_list_is_only_returned_to_administrators(self):
        from src.api.routes.settings import get_config

        with self.session_factory() as db:
            analyst_config = get_config(db, SimpleNamespace(role="analyst"))
            admin_config = get_config(db, SimpleNamespace(role="admin"))

        self.assertEqual(analyst_config["failed_login_alert_recipients"], "")
        self.assertEqual(
            admin_config["failed_login_alert_recipients"],
            "security@example.com, noc@example.com",
        )


if __name__ == "__main__":
    unittest.main()
