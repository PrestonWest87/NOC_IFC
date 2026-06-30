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

    # FIXED: Loops over each alteration individually so already existing columns don't block countermeasures
    risk_alert_alterations = [
        "ALTER TABLE system_config ADD COLUMN last_global_risk VARCHAR",
        "ALTER TABLE system_config ADD COLUMN last_internal_risk VARCHAR",
        "ALTER TABLE system_config ADD COLUMN last_risk_alert_time DATETIME",
        "ALTER TABLE system_config ADD COLUMN sys_countermeasures INTEGER DEFAULT 3",
        "ALTER TABLE system_config ADD COLUMN net_countermeasures INTEGER DEFAULT 3"
    ]
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for stmt in risk_alert_alterations:
            try:
                conn.execute(text(stmt))
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

    # FIXED: Loops over each calculation offset/override statement individually to handle pre-existing table runs safely
    scoring_alterations = [
        "ALTER TABLE system_config ADD COLUMN scoring_mode VARCHAR DEFAULT 'auto'",
        "ALTER TABLE system_config ADD COLUMN cyber_criticality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN cyber_lethality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN physical_criticality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN physical_lethality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN internal_criticality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN internal_lethality_override INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN global_risk_offset INTEGER DEFAULT 0",
        "ALTER TABLE system_config ADD COLUMN internal_risk_offset INTEGER DEFAULT 0"
    ]
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for stmt in scoring_alterations:
            try:
                conn.execute(text(stmt))
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

    # Seed default RSS feeds (adds if missing, safe for existing DBs)
    try:
        from src.models.schema import FeedSource
        session2 = SessionLocal()
        default_feeds = [
            ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
            ("https://krebsonsecurity.com/feed/", "Krebs on Security"),
            ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
            ("https://feeds.a.dj.com/rss/RSSWorldNews.xml", "WSJ World News"),
            ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "CISA Advisories"),
            ("https://www.darkreading.com/rss.xml", "Dark Reading"),
            ("https://therecord.media/feed/", "The Record"),
        ]
        added = 0
        for url, name in default_feeds:
            if not session2.query(FeedSource).filter_by(url=url).first():
                session2.add(FeedSource(url=url, name=name, is_active=True))
                added += 1
        if added:
            session2.commit()
            logger.info(f"Added {added} default RSS feed sources.")
        session2.close()
    except Exception as e:
        logger.warning(f"Could not seed default feeds: {e}")

    from src.models.schema import Keyword
    session3 = SessionLocal()
    default_keywords = [
        ("ransomware", 90), ("breach", 85), ("data breach", 85), ("zero-day", 85),
        ("exploit", 80), ("infrastructure", 80), ("malware", 80), ("outage", 80),
        ("vulnerability", 75), ("ddos", 75), ("phishing", 75), ("backdoor", 75),
        ("attack", 70), ("cve", 70), ("cyberattack", 70), ("hack", 70),
        ("threat", 60), ("cyber", 55), ("security", 55), ("hacker", 60),
        ("espionage", 75), ("apt", 80), ("nation-state", 75),
        ("supply chain", 70), ("rce", 80), ("botnet", 75),
        ("trojan", 70), ("spyware", 70), ("wiper", 75),
        ("data exfiltration", 80), ("lateral movement", 70),
        ("privilege escalation", 70), ("cobalt strike", 80),
        ("critical infrastructure", 70), ("power grid", 65),
        ("disruption", 60), ("degraded", 50), ("bgp", 55),
        ("submarine cable", 60), ("intrusion", 60),
        ("ransomware gang", 85), ("lockbit", 85), ("blackcat", 85),
        ("clop", 80), ("alphv", 80), ("conti", 80),
        ("solarwinds", 70), ("log4j", 80), ("log4shell", 85),
        ("cisa", 60), ("fbi", 55), ("nsa", 55),
        ("nato", 50), ("intelligence", 50), ("sanctions", 50),
        ("disinformation", 50), ("deepfake", 50),
        ("ai", 40), ("artificial intelligence", 45),
        ("machine learning", 40), ("drone", 45), ("uav", 45),
        ("missile", 50), ("military", 45), ("defense", 40),
        ("pipeline", 50), ("energy", 40), ("financial", 35),
        ("cryptocurrency", 35), ("bitcoin", 30),
    ]
    try:
        added_kw = 0
        for word, weight in default_keywords:
            if not session3.query(Keyword).filter_by(word=word).first():
                session3.add(Keyword(word=word, weight=weight))
                added_kw += 1
        if added_kw:
            session3.commit()
            logger.info(f"Seeded {added_kw} default keywords.")
        session3.close()
    except Exception as e:
        logger.warning(f"Could not seed default keywords: {e}")

    try:
        from src.services import rescore_all_articles
        rescored = rescore_all_articles()
        logger.info(f"Rescored {rescored} existing articles with new keywords.")
    except Exception as e:
        logger.warning(f"Could not rescore articles: {e}")
