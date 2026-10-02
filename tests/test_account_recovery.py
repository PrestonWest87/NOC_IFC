import unittest
import re
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src import services as svc
from src.models.schema import (
    Base, EmailChangeRequest, PasswordResetRequest, PasswordResetToken, Role,
    User, UserSession,
)


class AccountRecoveryTests(unittest.TestCase):
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
        with self.session_factory() as db:
            db.add_all([
                Role(name="admin", allowed_pages=[], allowed_actions=[], allowed_site_types=["HQ"]),
                Role(name="analyst", allowed_pages=["Global Dashboards"], allowed_actions=[], allowed_site_types=["HQ"]),
                Role(name="viewer", allowed_pages=["Global Dashboards"], allowed_actions=[], allowed_site_types=["HQ"]),
            ])
            db.add(User(
                username="admin", password_hash=svc.hash_password("admin-password-123"),
                role="admin", account_type="individual", is_active=True,
                email="security@example.com", email_normalized="security@example.com",
                email_verified_at=datetime.utcnow(),
            ))
            db.add(User(
                username="alice", password_hash=svc.hash_password("alice-password-123"),
                role="analyst", account_type="individual", is_active=True,
            ))
            db.commit()

    def tearDown(self):
        self.session_patch.stop()
        self.engine.dispose()

    def test_display_accounts_may_omit_email_and_invites_require_email(self):
        user_id = svc.create_display_account(
            "wall-screen", "wall-screen-password", "viewer", "HQ Wall Screen"
        )
        with self.session_factory() as db:
            display = db.query(User).filter_by(id=user_id).one()
            self.assertEqual(display.account_type, "display")
            self.assertIsNone(display.email)
            self.assertTrue(display.is_active)
        directory = {row["username"]: row for row in svc.get_user_directory()}
        self.assertEqual(directory["wall-screen"]["email_status"], "exempt")
        self.assertEqual(directory["alice"]["email_status"], "missing")

        with self.assertRaises(ValueError):
            svc.create_registration_invite("bob", "", "analyst", "admin")

    def test_invitation_binds_email_and_registration_verifies_it(self):
        raw_token, _ = svc.create_registration_invite(
            "bob", "Bob.Example@example.com", "analyst", "admin"
        )
        invite = svc.get_registration_invite(raw_token)
        self.assertEqual(invite["email"], "Bob.Example@example.com")
        user, token = svc.complete_registration(
            raw_token, "bob-password-123", "Bob Example", "Analyst", "", "No Shift"
        )
        self.assertEqual(user.account_type, "individual")
        self.assertEqual(user.email_normalized, "bob.example@example.com")
        self.assertIsNotNone(user.email_verified_at)
        self.assertTrue(token)

    def test_resending_invitation_invalidates_previous_link(self):
        first, _ = svc.create_registration_invite("resend-user", "resend@example.com", "analyst", "admin")
        second, _ = svc.create_registration_invite("resend-user", "resend@example.com", "analyst", "admin")
        self.assertIsNone(svc.get_registration_invite(first))
        self.assertIsNotNone(svc.get_registration_invite(second))
        self.assertEqual(len(svc.get_pending_registration_invites()), 1)

    def test_recovery_email_requires_review_and_mailbox_verification(self):
        request_id = svc.submit_email_change_request(2, "alice.recovery@example.com")
        pending = svc.list_email_change_requests()
        self.assertEqual(pending[0]["id"], request_id)
        approved = svc.review_email_change_request(request_id, 1, True, "Identity confirmed")
        self.assertEqual(approved["status"], "pending_verification")
        with self.session_factory() as db:
            user = db.query(User).filter_by(username="alice").one()
            self.assertIsNone(user.email)
            row = db.query(EmailChangeRequest).filter_by(id=request_id).one()
            self.assertNotEqual(row.verification_token_hash, approved["token"])

        self.assertTrue(svc.verify_recovery_email(approved["token"]))
        self.assertFalse(svc.verify_recovery_email(approved["token"]))
        with self.session_factory() as db:
            user = db.query(User).filter_by(username="alice").one()
            self.assertEqual(user.email_normalized, "alice.recovery@example.com")
            self.assertIsNotNone(user.email_verified_at)

    def test_recovery_email_http_workflow_notifies_approver_and_verifies_mailbox(self):
        from fastapi.testclient import TestClient
        from src.api.main import app

        token_users = {
            "alice-token": SimpleNamespace(
                id=2, username="alice", role="analyst", allowed_pages=[],
                allowed_actions=[], allowed_site_types=[],
            ),
            "reviewer-token": SimpleNamespace(
                id=1, username="admin", role="admin", allowed_pages=[],
                allowed_actions=[], allowed_site_types=[],
            ),
        }
        with patch.object(svc, "get_user_by_token", side_effect=lambda token: token_users.get(token)), patch(
            "src.api.main.init_db"
        ), patch("src.api.routes.auth._send_account_recovery_notice") as reviewer_notice, patch(
            "src.api.routes.user_admin._send_email"
        ) as verification_email:
            with TestClient(app) as client:
                submitted = client.post(
                    "/api/v1/auth/request-recovery-email",
                    headers={"Authorization": "Bearer alice-token"},
                    json={"email": "alice.recovery@example.com"},
                )
                self.assertEqual(submitted.status_code, 200)
                self.assertEqual(submitted.json()["status"], "pending_approval")
                reviewer_notice.assert_called_once()

                with self.session_factory() as db:
                    request = db.query(EmailChangeRequest).filter_by(user_id=2).one()
                    request_id = request.id
                    self.assertEqual(request.status, "pending_review")
                    self.assertIsNone(db.query(User).filter_by(id=2).one().email)

                approved = client.post(
                    f"/api/v1/user-admin/email-change-requests/{request_id}/decision",
                    headers={"Authorization": "Bearer reviewer-token"},
                    json={"approve": True, "reason": "Verified account owner"},
                )
                self.assertEqual(approved.status_code, 200)
                self.assertEqual(approved.json()["status"], "pending_verification")
                verification_email.assert_called_once()
                email_body = verification_email.call_args.args[1]
                match = re.search(r"token=([A-Za-z0-9_-]+)", email_body)
                self.assertIsNotNone(match)
                raw_token = match.group(1)

                verified = client.get(f"/api/v1/auth/verify-recovery-email?token={raw_token}")
                self.assertEqual(verified.status_code, 200)
                self.assertEqual(verified.json()["status"], "verified")

        with self.session_factory() as db:
            alice = db.query(User).filter_by(id=2).one()
            request = db.query(EmailChangeRequest).filter_by(id=request_id).one()
            self.assertEqual(alice.email, "alice.recovery@example.com")
            self.assertEqual(alice.email_normalized, "alice.recovery@example.com")
            self.assertIsNotNone(alice.email_verified_at)
            self.assertEqual(request.status, "completed")

    def test_email_change_denial_keeps_account_email_unchanged(self):
        request_id = svc.submit_email_change_request(2, "alice.recovery@example.com")
        result = svc.review_email_change_request(request_id, 1, False, "Could not verify requester")
        self.assertEqual(result["status"], "denied")
        with self.session_factory() as db:
            user = db.query(User).filter_by(username="alice").one()
            request = db.query(EmailChangeRequest).filter_by(id=request_id).one()
            self.assertIsNone(user.email)
            self.assertEqual(request.status, "denied")

    def test_recovery_reviewers_cannot_approve_their_own_requests(self):
        self.assertEqual(
            svc.get_recovery_reviewer_emails(
                "Action: Approve Recovery Email Changes", exclude_user_id=1
            ),
            [],
        )
        self.assertEqual(
            svc.get_recovery_reviewer_emails(
                "Action: Approve Recovery Email Changes", exclude_user_id=2
            ),
            ["security@example.com"],
        )
        email_request_id = svc.submit_email_change_request(1, "admin-recovery@example.com")
        with self.assertRaises(ValueError):
            svc.review_email_change_request(email_request_id, 1, True)

        svc.submit_password_reset_request("admin", "192.0.2.18")
        reset_request_id = next(
            item["id"] for item in svc.list_password_reset_requests()
            if item["username"] == "admin"
        )
        with self.assertRaises(ValueError):
            svc.review_password_reset_request(reset_request_id, 1, True)

    def test_password_reset_requires_approval_expires_and_revokes_sessions(self):
        with self.session_factory() as db:
            alice = db.query(User).filter_by(username="alice").one()
            alice.email = "alice@example.com"
            alice.email_normalized = "alice@example.com"
            alice.email_verified_at = datetime.utcnow()
            alice.session_token = "legacy-session"
            db.add(UserSession(user_id=alice.id, token="current-session"))
            db.commit()

        result = svc.submit_password_reset_request("alice", "192.0.2.15")
        self.assertTrue(result["accepted"])
        self.assertIn("security@example.com", result["notify"])
        pending = svc.list_password_reset_requests()
        request_id = pending[0]["id"]
        approved = svc.review_password_reset_request(request_id, 1, True, "Verified by phone")
        self.assertEqual(approved["status"], "approved")
        self.assertNotEqual(approved["token"], approved["token"][::-1])
        self.assertTrue(svc.complete_password_reset(approved["token"], "new-password-123"))
        self.assertFalse(svc.complete_password_reset(approved["token"], "replayed-password-123"))

        with self.session_factory() as db:
            alice = db.query(User).filter_by(username="alice").one()
            self.assertIsNone(alice.session_token)
            self.assertEqual(db.query(UserSession).filter_by(user_id=alice.id).count(), 0)
            token_row = db.query(PasswordResetToken).filter_by(request_id=request_id).one()
            request = db.query(PasswordResetRequest).filter_by(id=request_id).one()
            self.assertIsNotNone(token_row.used_at)
            self.assertEqual(request.status, "completed")

    def test_password_reset_denial_does_not_issue_token(self):
        request_result = svc.submit_password_reset_request("alice", "192.0.2.20")
        request_id = svc.list_password_reset_requests()[0]["id"]
        result = svc.review_password_reset_request(request_id, 1, False, "Not verified")
        self.assertEqual(result["status"], "denied")
        with self.session_factory() as db:
            self.assertEqual(db.query(PasswordResetToken).count(), 0)
            self.assertEqual(db.query(PasswordResetRequest).filter_by(id=request_id).one().status, "denied")
        self.assertTrue(request_result["accepted"])

    def test_expired_password_reset_token_is_rejected(self):
        with self.session_factory() as db:
            user = User(
                username="bob", password_hash=svc.hash_password("bob-password-123"),
                role="analyst", account_type="individual", is_active=True,
                email="bob@example.com", email_normalized="bob@example.com",
                email_verified_at=datetime.utcnow(),
            )
            db.add(user)
            db.commit()
        svc.submit_password_reset_request("bob", "192.0.2.30")
        request_id = svc.list_password_reset_requests()[0]["id"]
        approved = svc.review_password_reset_request(request_id, 1, True)
        with self.session_factory() as db:
            token = db.query(PasswordResetToken).filter_by(request_id=request_id).one()
            token.expires_at = datetime.utcnow() - timedelta(minutes=1)
            db.commit()
        self.assertFalse(svc.complete_password_reset(approved["token"], "expired-reset-password"))

    def test_sign_in_and_throttled_activity_are_durable(self):
        old_activity = datetime.utcnow() - timedelta(minutes=10)
        with self.session_factory() as db:
            alice = db.query(User).filter_by(username="alice").one()
            alice.last_activity_at = old_activity
            db.add(UserSession(user_id=alice.id, token="activity-session"))
            db.commit()

        refreshed = svc.get_user_by_token("activity-session")
        self.assertIsNotNone(refreshed.last_activity_at)
        self.assertGreater(refreshed.last_activity_at, old_activity)
        first_activity = refreshed.last_activity_at
        svc.get_user_by_token("activity-session")
        with self.session_factory() as db:
            alice = db.query(User).filter_by(username="alice").one()
            self.assertEqual(alice.last_activity_at, first_activity)

        signed_in, _token = svc.authenticate_user("alice", "alice-password-123")
        self.assertIsNotNone(signed_in.last_login_at)

    def test_display_account_reset_requires_administrator_assistance(self):
        user_id = svc.create_display_account(
            "wall-screen", "wall-screen-password", "viewer", "Wall Screen"
        )
        with self.session_factory() as db:
            user = db.query(User).filter_by(id=user_id).one()
            user.email = "screen@example.com"
            user.email_normalized = "screen@example.com"
            user.email_verified_at = datetime.utcnow()
            db.commit()
        request = svc.submit_password_reset_request("wall-screen", "192.0.2.25")
        request_id = svc.list_password_reset_requests()[0]["id"]
        with self.assertRaises(ValueError):
            svc.review_password_reset_request(request_id, 1, True)
        self.assertTrue(svc.force_reset_pwd("wall-screen", "screen-reset-password"))


if __name__ == "__main__":
    unittest.main()
