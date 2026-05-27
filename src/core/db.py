import time
import random
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from src.models import Base
from src.core.config import DATABASE_URL

logger = logging.getLogger(__name__)

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30}
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-16000")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA mmap_size=268435456")
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Dependency injection helper yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    time.sleep(random.uniform(0.1, 1.5))
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.error(f"Schema generation error: {e}")

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE roles ADD COLUMN allowed_site_types JSON"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE solarwinds_alerts ADD COLUMN is_dispatched BOOLEAN DEFAULT 0"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN district VARCHAR DEFAULT 'Central'"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE shift_logs ADD COLUMN author_role VARCHAR DEFAULT 'analyst'"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN baseline_override_cyber FLOAT DEFAULT 0.0"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN baseline_override_phys FLOAT DEFAULT 0.0"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN under_maintenance BOOLEAN DEFAULT 0"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN maintenance_etr DATETIME"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN maintenance_reason TEXT"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS user_weather_prefs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username VARCHAR,
                    alert_type VARCHAR
                )
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_user_weather_prefs_username ON user_weather_prefs (username)"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE shift_logs ADD COLUMN is_deleted BOOLEAN DEFAULT 0"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN unified_brief TEXT"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN unified_brief_time DATETIME"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN default_shift VARCHAR DEFAULT 'No Shift'"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE crime_incidents ADD COLUMN is_alert_dispatched BOOLEAN DEFAULT 0"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN last_global_risk VARCHAR"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN last_internal_risk VARCHAR"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN last_risk_alert_time DATETIME"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN sys_countermeasures INTEGER DEFAULT 3"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN net_countermeasures INTEGER DEFAULT 3"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE solarwinds_alerts ADD COLUMN is_ticketed BOOLEAN DEFAULT 0"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN last_auto_ticket DATETIME"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN last_escalation_ticket DATETIME"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN last_auto_dispatch DATETIME"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN last_escalation_dispatch DATETIME"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN status_modified_by VARCHAR"))
            conn.execute(text("ALTER TABLE monitored_locations ADD COLUMN status_modified_at DATETIME"))
    except Exception:
        pass

    session = SessionLocal()
    try:
        from src.models.schema import Role, User
        all_pages = [
            "Global Dashboards", "Threat Telemetry", "Regional Grid",
            "Threat Hunting & IOCs", "AIOps RCA", "Shift Logbook",
            "Reporting & Briefings", "Settings & Admin"
        ]

        all_actions = [
            "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score",
            "Action: Trigger AI Functions", "Action: Manually Sync Data", "Action: Dispatch Exec Report",
            "Action: Submit Shift Log", "Action: Dispatch RCA Tickets", "Action: Manage Site Maintenance",
            "Tab: Dashboards -> Operational", "Tab: Dashboards -> Global Risk", "Tab: Dashboards -> Internal Risk",
            "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV",
            "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Perimeter Crime",
            "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
            "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
            "Tab: Threat Hunting -> Global IOC Matrix", "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: Reporting -> Elastic SIEM Report",
            "Tab: AIOps RCA -> Active Board", "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
            "Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History",
            "Tab: Reporting -> Daily Fusion", "Tab: Reporting -> Report Builder", "Tab: Reporting -> Shared Library",
            "Tab: Settings -> Facility Locations", "Tab: Settings -> RSS Sources", "Tab: Settings -> ML Training",
            "Tab: Settings -> AI & SMTP", "Tab: Settings -> Users & Roles", "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone"
        ]

        admin_role = session.query(Role).filter_by(name="admin").first()
        if not admin_role:
            session.add(Role(name="admin", allowed_pages=all_pages, allowed_actions=all_actions))
        else:
            admin_role.allowed_pages = all_pages
            admin_role.allowed_actions = all_actions

        analyst_role = session.query(Role).filter_by(name="analyst").first()
        if not analyst_role:
            session.add(Role(name="analyst", allowed_pages=all_pages[:-1], allowed_actions=all_actions))
        else:
            analyst_role.allowed_pages = all_pages[:-1]
            analyst_role.allowed_actions = all_actions

        if not session.query(User).first():
            import bcrypt
            hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
            session.add(User(
                username="admin",
                password_hash=hashed,
                role="admin",
                full_name="Preston",
                job_title="Network Operations Analyst",
                contact_info="NOC Desk"
            ))

        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database initialization error: {e}")
    finally:
        session.close()
