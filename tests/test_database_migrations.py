import os
import unittest
from unittest.mock import patch

from sqlalchemy import Column, MetaData, Table, create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.core import db as core_db
from src.models.schema import AccountAuditEvent, EmailChangeRequest, Role, SystemConfig, User


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.session_factory = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        self.engine_patch = patch.object(core_db, "engine", self.engine)
        self.session_patch = patch.object(core_db, "SessionLocal", self.session_factory)
        self.engine_patch.start()
        self.session_patch.start()

    def tearDown(self):
        self.session_patch.stop()
        self.engine_patch.stop()
        self.engine.dispose()

    def test_upgrade_adds_optional_email_and_seeded_roles_without_regranting_on_restart(self):
        with self.engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY, username VARCHAR UNIQUE, password_hash VARCHAR,
                    role VARCHAR, session_token VARCHAR, full_name VARCHAR, job_title VARCHAR,
                    contact_info VARCHAR, default_shift VARCHAR DEFAULT 'No Shift', theme VARCHAR DEFAULT 'standard'
                )
            """))
            connection.execute(text("""
                CREATE TABLE roles (
                    id INTEGER PRIMARY KEY, name VARCHAR UNIQUE, allowed_pages JSON, allowed_actions JSON
                )
            """))
            connection.execute(text("""
                CREATE TABLE registration_invites (
                    id INTEGER PRIMARY KEY, username VARCHAR NOT NULL, role VARCHAR NOT NULL,
                    token_hash VARCHAR NOT NULL UNIQUE, created_by VARCHAR NOT NULL,
                    created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, used_at DATETIME
                )
            """))
            connection.execute(text("""
                CREATE TABLE timeline_events (
                    id INTEGER PRIMARY KEY, timestamp DATETIME, source VARCHAR,
                    event_type VARCHAR, message VARCHAR
                )
            """))
            connection.execute(text(
                "INSERT INTO users (id, username, password_hash, role, full_name) "
                "VALUES (1, 'legacy-person', 'unused', 'analyst', 'Legacy Person')"
            ))
            connection.execute(text(
                "INSERT INTO roles (id, name, allowed_pages, allowed_actions) "
                "VALUES (1, 'analyst', '[]', '[\"Action: Trigger AI Functions\", \"Action: Dispatch Exec Report\"]')"
            ))
            connection.execute(text(
                "INSERT INTO roles (id, name, allowed_pages, allowed_actions) "
                "VALUES (2, 'reporter', '[\"Reporting & Briefings\"]', '[\"Action: Trigger AI Functions\"]')"
            ))
            connection.execute(text(
                "INSERT INTO registration_invites (id, username, role, token_hash, created_by, created_at, expires_at) "
                "VALUES (1, 'pending', 'analyst', 'legacy-hash', 'admin', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ))

        legacy_config = Table("system_config", MetaData())
        for column in SystemConfig.__table__.columns:
            if column.name not in {"permission_catalog_version", "scheduler_revision", "scheduler_applied_revision"}:
                legacy_config.append_column(Column(
                    column.name,
                    column.type,
                    primary_key=column.primary_key,
                    nullable=True,
                ))
        legacy_config.create(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO system_config (id) VALUES (1)"))

        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()

        with self.session_factory() as session:
            user = session.query(User).filter_by(username="legacy-person").one()
            self.assertEqual(user.account_type, "individual")
            self.assertIsNone(user.email)
            self.assertTrue(user.is_active)
            self.assertIsNotNone(user.created_at)
            self.assertIsNone(user.last_login_at)
            migrated_event = session.execute(text("PRAGMA table_info(timeline_events)")).all()
            migrated_event_columns = {row[1]: row[2] for row in migrated_event}
            self.assertEqual(migrated_event_columns["site_name"], "VARCHAR(255)")
            user_columns = {row[1]: row[2] for row in session.execute(text("PRAGMA table_info(users)")).all()}
            self.assertEqual(user_columns["email_verified_at"], "TIMESTAMP")
            invite = session.query(core_db.Base.metadata.tables["registration_invites"]).filter_by(id=1).one()
            self.assertEqual(invite.email, "")
            self.assertIsNotNone(invite.used_at)
            analyst = session.query(Role).filter_by(name="analyst").one()
            self.assertNotIn("Action: Dispatch Exec Report", analyst.allowed_actions)
            self.assertNotIn("Action: Generate Reports", analyst.allowed_actions)
            reporter = session.query(Role).filter_by(name="reporter").one()
            self.assertNotIn("Action: Trigger AI Functions", reporter.allowed_actions)
            self.assertIn("Action: Generate Reports", reporter.allowed_actions)
            self.assertIsNotNone(session.query(SystemConfig).one().permission_catalog_version)

            analyst.allowed_actions = []
            analyst.allowed_pages = ["Global Dashboards"]
            session.commit()

        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()

        with self.session_factory() as session:
            analyst = session.query(Role).filter_by(name="analyst").one()
            self.assertEqual(analyst.allowed_actions, [])
            self.assertEqual(analyst.allowed_pages, ["Global Dashboards"])

    def test_fresh_database_seeds_roles_and_application_config(self):
        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()
        with self.session_factory() as session:
            roles = {role.name: role for role in session.query(Role).all()}
            self.assertTrue({"admin", "analyst", "viewer", "user-admin"}.issubset(roles))
            self.assertNotIn("Action: Send Email", roles["analyst"].allowed_actions)
            self.assertNotIn("Action: Adjust Risk Scoring Overrides", roles["analyst"].allowed_actions)
            self.assertEqual(roles["user-admin"].allowed_site_types, [])
            self.assertEqual(session.query(SystemConfig).one().permission_catalog_version, 1)

    def test_default_admin_email_bootstraps_existing_admin_and_resolves_pending_request(self):
        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()

        with self.session_factory() as session:
            admin = User(
                username="admin", password_hash="already-hashed", role="admin",
                account_type="individual", is_active=True,
            )
            session.add(admin)
            session.flush()
            pending = EmailChangeRequest(
                user_id=admin.id,
                requested_email="security@example.com",
                requested_email_normalized="security@example.com",
                status="pending_review",
            )
            session.add(pending)
            session.commit()
            pending_id = pending.id

        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}), patch.object(
            core_db.settings, "default_admin_email", "security@example.com"
        ):
            core_db.init_db()

        with self.session_factory() as session:
            admin = session.query(User).filter_by(username="admin").one()
            pending = session.query(EmailChangeRequest).filter_by(id=pending_id).one()
            audit = session.query(AccountAuditEvent).filter_by(
                event_type="bootstrap_recovery_email_configured", subject_user_id=admin.id
            ).one()
            self.assertEqual(admin.email, "security@example.com")
            self.assertEqual(admin.email_normalized, "security@example.com")
            self.assertIsNotNone(admin.email_verified_at)
            self.assertEqual(pending.status, "completed")
            self.assertIsNotNone(pending.verified_at)
            self.assertIsNone(pending.verification_token_hash)
            self.assertEqual(audit.event_detail["source"], "DEFAULT_ADMIN_EMAIL")


if __name__ == "__main__":
    unittest.main()
