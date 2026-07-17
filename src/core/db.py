import time
import random
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import text
from src.models import Base
from src.core.config import DATABASE_URL

logger = logging.getLogger(__name__)

engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,
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
    # Run column migration first so API queries don't fail on stale schema
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN alerted_eq_ids TEXT DEFAULT '[]'"))
    except Exception:
        pass

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

    for _col in [
        "status_modified_by VARCHAR",
        "status_modified_at DATETIME",
        "last_auto_ticket DATETIME",
        "last_escalation_ticket DATETIME",
        "last_auto_dispatch DATETIME",
        "last_escalation_dispatch DATETIME",
    ]:
        try:
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                conn.execute(text(f"ALTER TABLE monitored_locations ADD COLUMN {_col}"))
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
            conn.execute(text("ALTER TABLE system_config ADD COLUMN global_brief TEXT"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN global_brief_time DATETIME"))
    except Exception:
        pass

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN internal_brief TEXT"))
            conn.execute(text("ALTER TABLE system_config ADD COLUMN internal_brief_time DATETIME"))
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

    for _col in [
        "is_ticketed BOOLEAN DEFAULT 0",
        "acknowledged_by VARCHAR",
        "acknowledged_at DATETIME",
        "dispatched_by VARCHAR",
        "dispatched_at DATETIME",
    ]:
        try:
            with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
                conn.execute(text(f"ALTER TABLE solarwinds_alerts ADD COLUMN {_col}"))
        except Exception:
            pass

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

    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN llm_context_window INTEGER DEFAULT 128000"))
    except Exception:
        pass

    # Migrate priority from Integer to String
    try:
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(
                "UPDATE monitored_locations SET priority = CASE "
                "WHEN priority = '1' OR priority = 1 THEN 'P1-Critical' "
                "WHEN priority = '2' OR priority = 2 THEN 'P2-High' "
                "WHEN priority = '3' OR priority = 3 THEN 'P3-Moderate' "
                "WHEN priority = '4' OR priority = 4 THEN 'P4-Low' "
                "WHEN priority = '5' OR priority = 5 THEN 'P5-Planning' "
                "ELSE 'P3-Moderate' END "
                "WHERE priority IS NOT NULL AND CAST(priority AS INTEGER) = priority"
            ))
    except Exception:
        pass

    session = SessionLocal()
    try:
        from src.models.schema import Role, User
        all_pages = [
            "Global Dashboards", "Threat Telemetry", "Regional Grid",
            "Threat Hunting & IOCs", "AIOps RCA", "Shift Logbook",
            "Reporting & Briefings", "Settings & Admin",
            "Keyword Analysis"
        ]

        all_actions = [
            "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score",
            "Action: Trigger AI Functions", "Action: Manually Sync Data", "Action: Dispatch Exec Report",
            "Action: Submit Shift Log", "Action: Dispatch RCA Tickets", "Action: Manage Site Maintenance",
            "Tab: Dashboards -> Operational", "Tab: Dashboards -> Global Risk", "Tab: Dashboards -> Internal Risk", "Tab: Dashboards -> Unified Brief",
            "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV",
            "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Perimeter Crime",
            "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash",
            "Tab: Regional Grid -> Hazard Analytics", "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", "Tab: Regional Grid -> Atmos Weather",
            "Tab: Threat Hunting -> Global IOC Matrix", "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: Reporting -> Elastic SIEM Report",
            "Tab: AIOps RCA -> Active Board", "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
            "Tab: Shift Log -> Active Shift", "Tab: Shift Log -> History",
            "Tab: Reporting -> Daily Fusion", "Tab: Reporting -> Report Builder", "Tab: Reporting -> Shared Library",
            "Tab: Settings -> Facility Locations", "Tab: Settings -> Internal Assets", "Tab: Settings -> RSS Sources", "Tab: Settings -> ML Training",
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

        import os
        admin_pw = os.environ.get("DEFAULT_ADMIN_PASSWORD", "").strip()
        if admin_pw and not session.query(User).first():
            import bcrypt
            hashed = bcrypt.hashpw(admin_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            session.add(User(
                username="admin",
                password_hash=hashed,
                role="admin",
                full_name="Administrator",
                job_title="System Admin",
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
        from src.models.schema import SystemConfig
        session_cfg = SessionLocal()
        if not session_cfg.query(SystemConfig).first():
            session_cfg.add(SystemConfig(is_active=False))
            session_cfg.commit()
            logger.info("Created default SystemConfig.")
        session_cfg.close()
    except Exception as e:
        logger.warning(f"Could not seed default SystemConfig: {e}")

    # Seed dummy internal assets for testing (only if empty)
    try:
        from src.models.schema import HardwareAsset, SoftwareAsset
        session_assets = SessionLocal()

        if session_assets.query(HardwareAsset).count() == 0:
            dummy_hw = [
                HardwareAsset(ip_address="10.0.1.10", asset_name="FW-CORE-01", operating_system="PAN-OS", os_vendor="Palo Alto Networks", os_product="PA-5260", os_version="11.1.2", host_type="Firewall", instances=1, critical_instances=1, vulnerabilities=3, critical_vulnerabilities=1, severe_vulnerabilities=1, exploit_count=1, raw_risk_score=85.0, risk_score=85.0),
                HardwareAsset(ip_address="10.0.1.20", asset_name="FW-BRANCH-01", operating_system="PAN-OS", os_vendor="Palo Alto Networks", os_product="PA-460", os_version="11.0.4", host_type="Firewall", instances=1, critical_instances=0, vulnerabilities=2, critical_vulnerabilities=0, severe_vulnerabilities=1, exploit_count=0, raw_risk_score=45.0, risk_score=45.0),
                HardwareAsset(ip_address="10.0.1.30", asset_name="RTR-CORE-01", operating_system="IOS-XE", os_vendor="Cisco", os_product="Catalyst 9300", os_version="17.9.4", host_type="Router", instances=1, critical_instances=0, vulnerabilities=4, critical_vulnerabilities=2, severe_vulnerabilities=1, exploit_count=1, raw_risk_score=72.0, risk_score=72.0),
                HardwareAsset(ip_address="10.0.1.40", asset_name="SW-DIST-01", operating_system="IOS-XE", os_vendor="Cisco", os_product="Catalyst 9500", os_version="17.6.3", host_type="Switch", instances=1, critical_instances=0, vulnerabilities=2, critical_vulnerabilities=0, severe_vulnerabilities=1, exploit_count=0, raw_risk_score=35.0, risk_score=35.0),
                HardwareAsset(ip_address="10.0.1.50", asset_name="SW-ACCESS-01", operating_system="IOS", os_vendor="Cisco", os_product="Catalyst 2960", os_version="15.2(2)E", host_type="Switch", instances=1, critical_instances=0, vulnerabilities=1, critical_vulnerabilities=0, severe_vulnerabilities=0, exploit_count=0, raw_risk_score=15.0, risk_score=15.0),
                HardwareAsset(ip_address="10.0.2.10", asset_name="SRV-DC-01", operating_system="Windows Server 2022", os_vendor="Microsoft", os_product="Windows Server", os_version="21H2", host_type="Server", instances=1, critical_instances=1, vulnerabilities=8, critical_vulnerabilities=3, severe_vulnerabilities=2, exploit_count=2, raw_risk_score=92.0, risk_score=92.0),
                HardwareAsset(ip_address="10.0.2.20", asset_name="SRV-DC-02", operating_system="Windows Server 2022", os_vendor="Microsoft", os_product="Windows Server", os_version="21H2", host_type="Server", instances=1, critical_instances=1, vulnerabilities=8, critical_vulnerabilities=3, severe_vulnerabilities=2, exploit_count=2, raw_risk_score=90.0, risk_score=90.0),
                HardwareAsset(ip_address="10.0.2.30", asset_name="SRV-APP-01", operating_system="Ubuntu 22.04 LTS", os_vendor="Canonical", os_product="Ubuntu", os_version="22.04", host_type="Server", instances=1, critical_instances=0, vulnerabilities=5, critical_vulnerabilities=1, severe_vulnerabilities=2, exploit_count=1, raw_risk_score=65.0, risk_score=65.0),
                HardwareAsset(ip_address="10.0.2.40", asset_name="SRV-DB-01", operating_system="Red Hat Enterprise Linux 9", os_vendor="Red Hat", os_product="RHEL", os_version="9.3", host_type="Server", instances=1, critical_instances=1, vulnerabilities=3, critical_vulnerabilities=1, severe_vulnerabilities=1, exploit_count=0, raw_risk_score=55.0, risk_score=55.0),
                HardwareAsset(ip_address="10.0.3.10", asset_name="UPS-IDF-01", operating_system="Network Management Card", os_vendor="APC", os_product="APC UPS", os_version="6.2.0", host_type="UPS", instances=1, critical_instances=0, vulnerabilities=1, critical_vulnerabilities=0, severe_vulnerabilities=0, exploit_count=0, raw_risk_score=20.0, risk_score=20.0),
                HardwareAsset(ip_address="10.0.3.20", asset_name="HVAC-CTRL-01", operating_system="BACnet", os_vendor="Honeywell", os_product="Tridium Niagara", os_version="4.12", host_type="HVAC", instances=1, critical_instances=0, vulnerabilities=2, critical_vulnerabilities=1, severe_vulnerabilities=0, exploit_count=0, raw_risk_score=40.0, risk_score=40.0),
                HardwareAsset(ip_address="10.0.4.10", asset_name="RTU-SITE-01", operating_system="RTOS", os_vendor="Schneider Electric", os_product="Modicon M340", os_version="3.20", host_type="RTU", instances=1, critical_instances=1, vulnerabilities=2, critical_vulnerabilities=1, severe_vulnerabilities=1, exploit_count=1, raw_risk_score=78.0, risk_score=78.0),
                HardwareAsset(ip_address="10.0.4.20", asset_name="PLC-PROCESS-01", operating_system="ControlLogix", os_vendor="Rockwell Automation", os_product="Allen-Bradley ControlLogix", os_version="33.011", host_type="SCADA", instances=1, critical_instances=1, vulnerabilities=3, critical_vulnerabilities=2, severe_vulnerabilities=1, exploit_count=1, raw_risk_score=88.0, risk_score=88.0),
                HardwareAsset(ip_address="10.0.5.10", asset_name="WLC-CAMPUS-01", operating_system="AireOS", os_vendor="Cisco", os_product="Catalyst 9800", os_version="17.9.3", host_type="Wireless Controller", instances=1, critical_instances=0, vulnerabilities=3, critical_vulnerabilities=1, severe_vulnerabilities=1, exploit_count=0, raw_risk_score=50.0, risk_score=50.0),
                HardwareAsset(ip_address="10.0.5.20", asset_name="AP-LOBBY-01", operating_system="IOS-XE", os_vendor="Cisco", os_product="Catalyst 9130", os_version="17.6.3", host_type="Access Point", instances=1, critical_instances=0, vulnerabilities=1, critical_vulnerabilities=0, severe_vulnerabilities=0, exploit_count=0, raw_risk_score=10.0, risk_score=10.0),
            ]
            session_assets.add_all(dummy_hw)
            session_assets.commit()
            logger.info("Seeded %d dummy hardware assets.", len(dummy_hw))

        if session_assets.query(SoftwareAsset).count() == 0:
            dummy_sw = [
                SoftwareAsset(name="Windows Server 2022"),
                SoftwareAsset(name="Windows 11 Enterprise"),
                SoftwareAsset(name="Windows 10 Pro"),
                SoftwareAsset(name="Microsoft SQL Server 2022"),
                SoftwareAsset(name="Microsoft Exchange Server 2019"),
                SoftwareAsset(name="Microsoft Office LTSC 2024"),
                SoftwareAsset(name="Microsoft Defender for Endpoint"),
                SoftwareAsset(name="Active Directory Domain Services"),
                SoftwareAsset(name="Palo Alto PAN-OS"),
                SoftwareAsset(name="Cisco IOS-XE"),
                SoftwareAsset(name="Cisco IOS"),
                SoftwareAsset(name="VMware vSphere 8"),
                SoftwareAsset(name="VMware ESXi 8"),
                SoftwareAsset(name="Ubuntu 22.04 LTS"),
                SoftwareAsset(name="Red Hat Enterprise Linux 9"),
                SoftwareAsset(name="Apache HTTP Server 2.4"),
                SoftwareAsset(name="nginx 1.24"),
                SoftwareAsset(name="OpenSSH 9.3"),
                SoftwareAsset(name="OpenSSL 3.1"),
                SoftwareAsset(name="Google Chrome 125"),
                SoftwareAsset(name="Mozilla Firefox 126"),
                SoftwareAsset(name="Fortinet FortiGate 7.4"),
                SoftwareAsset(name="SolarWinds Orion 2024"),
                SoftwareAsset(name="Docker Engine 26"),
                SoftwareAsset(name="Kubernetes 1.30"),
                SoftwareAsset(name="PostgreSQL 16"),
                SoftwareAsset(name="Redis 7.2"),
                SoftwareAsset(name="BIND 9.18"),
                SoftwareAsset(name="Tridium Niagara 4.12"),
                SoftwareAsset(name="Wireshark 4.2"),
            ]
            session_assets.add_all(dummy_sw)
            session_assets.commit()
            logger.info("Seeded %d dummy software assets.", len(dummy_sw))

        session_assets.close()
    except Exception as e:
        logger.warning(f"Could not seed dummy assets: {e}")

    try:
        from src.services import rescore_all_articles
        rescored = rescore_all_articles()
        logger.info(f"Rescored {rescored} existing articles with new keywords.")
    except Exception as e:
        logger.warning(f"Could not rescore articles: {e}")
