import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from sqlalchemy import Column, Integer, MetaData, Table, create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from migrations.schema_v1 import Base as LegacySchemaBase
from src.core import db as core_db
from src.core.migration_runner import run_migrations
from src.models.schema import (
    AccountAuditEvent, EmailChangeRequest, MonitoredLocation, Role, SystemConfig, User,
)


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
            revision = session.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            self.assertEqual(revision, "20261002_0002")
            self.assertIn("revoked_at", {column["name"] for column in inspect(self.engine).get_columns("registration_invites")})

    def test_pre_alembic_schema_upgrade_preserves_existing_application_rows(self):
        LegacySchemaBase.metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO users "
                "(id, username, password_hash, role, account_type, is_active, created_at, email, email_normalized) "
                "VALUES (41, 'legacy-admin', 'existing-hash', 'admin', 'individual', 1, "
                "'2025-01-02 03:04:05', 'admin@example.com', 'admin@example.com')"
            ))
            connection.execute(text(
                "INSERT INTO articles (id, title, link, summary, published_date, source, score, category) "
                "VALUES (51, 'Legacy article', 'https://example.test/legacy', 'kept row', "
                "'2025-01-02 03:04:05', 'legacy feed', 72.5, 'Cyber')"
            ))
            connection.execute(text(
                "INSERT INTO monitored_locations (id, name, lat, lon, priority) "
                "VALUES (61, 'Legacy site', 34.0, -92.0, 'P2-High')"
            ))
            connection.execute(text(
                "INSERT INTO registration_invites "
                "(id, username, role, token_hash, created_by, created_at, expires_at, "
                "email, email_normalized, account_type) VALUES "
                "(71, 'invitee', 'analyst', 'legacy-token-hash', 'legacy-admin', "
                "'2025-01-02 03:04:05', '2030-01-02 03:04:05', "
                "'invitee@example.com', 'invitee@example.com', 'individual')"
            ))

        run_migrations(self.engine)

        with self.engine.connect() as connection:
            self.assertEqual(
                connection.execute(text(
                    "SELECT username, password_hash, email_normalized FROM users WHERE id = 41"
                )).one(),
                ("legacy-admin", "existing-hash", "admin@example.com"),
            )
            self.assertEqual(
                connection.execute(text(
                    "SELECT title, link, score FROM articles WHERE id = 51"
                )).one(),
                ("Legacy article", "https://example.test/legacy", 72.5),
            )
            self.assertEqual(
                connection.execute(text(
                    "SELECT name, priority FROM monitored_locations WHERE id = 61"
                )).one(),
                ("Legacy site", "P2-High"),
            )
            migrated_invite = connection.execute(text(
                "SELECT username, email, revoked_at FROM registration_invites WHERE id = 71"
            )).one()
            self.assertEqual(migrated_invite, ("invitee", "invitee@example.com", None))
            self.assertEqual(
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one(),
                "20261002_0002",
            )

        self.assertIn(
            "revoked_at",
            {column["name"] for column in inspect(self.engine).get_columns("registration_invites")},
        )

    def test_unknown_older_schema_fails_closed_without_losing_existing_rows(self):
        with self.engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE system_config (id INTEGER PRIMARY KEY, llm_endpoint VARCHAR)"
            ))
            connection.execute(text(
                "INSERT INTO system_config (id, llm_endpoint) VALUES (91, 'https://legacy.example.test/v1')"
            ))

        with self.assertRaisesRegex(RuntimeError, "missing explicit column definitions"):
            run_migrations(self.engine)

        with self.engine.connect() as connection:
            self.assertEqual(
                connection.execute(text(
                    "SELECT id, llm_endpoint FROM system_config WHERE id = 91"
                )).one(),
                (91, "https://legacy.example.test/v1"),
            )
            self.assertIsNone(connection.execute(text(
                "SELECT version_num FROM alembic_version"
            )).first())

    def test_fresh_install_uses_frozen_baseline_not_runtime_model_metadata(self):
        future_table = Table(
            "post_v1_model_table",
            core_db.Base.metadata,
            Column("id", Integer, primary_key=True),
        )
        try:
            with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
                core_db.init_db()
            self.assertFalse(inspect(self.engine).has_table(future_table.name))
        finally:
            core_db.Base.metadata.remove(future_table)

    def test_partial_legacy_column_groups_are_completed(self):
        legacy_tables = []
        for model, omitted in (
            (SystemConfig, {"baseline_override_phys"}),
            (MonitoredLocation, {"status_modified_at", "last_auto_ticket"}),
        ):
            table = Table(model.__tablename__, MetaData())
            for column in model.__table__.columns:
                if column.name not in omitted:
                    table.append_column(Column(
                        column.name, column.type,
                        primary_key=column.primary_key,
                        nullable=True,
                    ))
            legacy_tables.append(table)
        for table in legacy_tables:
            table.create(self.engine)

        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO system_config (id, baseline_override_cyber) VALUES (1, 2.5)"
            ))
            connection.execute(text(
                "INSERT INTO monitored_locations (id, name, lat, lon, loc_type, status_modified_by) "
                "VALUES (1, 'legacy-site', 1.0, 2.0, 'NOC', 'legacy')"
            ))

        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()

        with self.engine.connect() as connection:
            config_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(system_config)"))}
            location_columns = {row[1] for row in connection.execute(text("PRAGMA table_info(monitored_locations)"))}
        self.assertIn("baseline_override_phys", config_columns)
        self.assertIn("status_modified_at", location_columns)
        self.assertIn("last_auto_ticket", location_columns)

    def test_startup_at_head_performs_no_schema_ddl(self):
        with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
            core_db.init_db()

        statements = []

        def record_mutation(_connection, _cursor, statement, _parameters, _context, _executemany):
            normalized = statement.lstrip().upper()
            if normalized.startswith((
                "CREATE TABLE", "CREATE INDEX", "ALTER TABLE", "DROP TABLE", "DROP INDEX",
                "INSERT", "UPDATE", "DELETE",
            )):
                statements.append(statement)

        event.listen(self.engine, "before_cursor_execute", record_mutation)
        try:
            with patch.dict(os.environ, {"DEFAULT_ADMIN_PASSWORD": ""}):
                core_db.init_db()
        finally:
            event.remove(self.engine, "before_cursor_execute", record_mutation)

        self.assertEqual(statements, [])

    def test_migration_runner_serializes_first_start_for_shared_sqlite_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_url = f"sqlite:///{Path(temp_dir) / 'shared.db'}"
            engines = [create_engine(database_url, poolclass=NullPool) for _ in range(2)]
            errors = []

            def migrate(engine):
                try:
                    run_migrations(engine)
                except Exception as exc:  # captured for assertion in the test thread
                    errors.append(exc)

            threads = [threading.Thread(target=migrate, args=(engine,)) for engine in engines]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)

            try:
                self.assertTrue(all(not thread.is_alive() for thread in threads))
                self.assertEqual(errors, [])
                with engines[0].connect() as connection:
                    revision = connection.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalar_one()
                self.assertEqual(revision, "20261002_0002")
            finally:
                for engine in engines:
                    engine.dispose()

    def test_database_url_rejects_postgresql(self):
        with self.assertRaisesRegex(RuntimeError, "Only SQLite databases are supported"):
            core_db.validate_database_url("postgresql://user:pass@localhost/noc")

    def test_legacy_duplicate_recovery_emails_fail_without_recording_success(self):
        legacy_users = Table("users", MetaData())
        for column in User.__table__.columns:
            legacy_users.append_column(Column(
                column.name, column.type,
                primary_key=column.primary_key,
                nullable=True,
            ))
        legacy_users.create(self.engine)
        with self.engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO users (id, email_normalized) VALUES "
                "(1, 'duplicate@example.com'), (2, 'duplicate@example.com')"
            ))

        with self.assertRaisesRegex(RuntimeError, "duplicate email groups must be resolved"):
            core_db.init_db()

        with self.engine.connect() as connection:
            version_table = connection.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='alembic_version'"
            )).first()
            self.assertIsNotNone(version_table)
            version = connection.execute(text("SELECT version_num FROM alembic_version")).first()
            self.assertIsNone(version)

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
