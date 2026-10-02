"""Idempotent application data setup that runs after schema migrations."""

import logging
import os
import re
from datetime import datetime

import bcrypt

from src.core.config import settings
from src.core.permissions import ADMIN_ACTIONS, PAGE_KEYS, TAB_CATALOG
from src.models.schema import (
    AccountAuditEvent,
    EmailChangeRequest,
    FeedSource,
    HardwareAsset,
    Keyword,
    MonitoredLocation,
    Role,
    SoftwareAsset,
    SystemConfig,
    User,
)

logger = logging.getLogger(__name__)

DEFAULT_FEEDS = (
    ("https://feeds.feedburner.com/TheHackersNews", "The Hacker News"),
    ("https://krebsonsecurity.com/feed/", "Krebs on Security"),
    ("https://www.bleepingcomputer.com/feed/", "BleepingComputer"),
    ("https://feeds.a.dj.com/rss/RSSWorldNews.xml", "WSJ World News"),
    ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "CISA Advisories"),
    ("https://www.darkreading.com/rss.xml", "Dark Reading"),
    ("https://therecord.media/feed/", "The Record"),
)

DEFAULT_KEYWORDS = (
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
)

def _demo_hardware_assets():
    return (
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
    )

DEMO_SOFTWARE_ASSETS = (
    "Windows Server 2022", "Windows 11 Enterprise", "Windows 10 Pro",
    "Microsoft SQL Server 2022", "Microsoft Exchange Server 2019",
    "Microsoft Office LTSC 2024", "Microsoft Defender for Endpoint",
    "Active Directory Domain Services", "Palo Alto PAN-OS", "Cisco IOS-XE",
    "Cisco IOS", "VMware vSphere 8", "VMware ESXi 8", "Ubuntu 22.04 LTS",
    "Red Hat Enterprise Linux 9", "Apache HTTP Server 2.4", "nginx 1.24",
    "OpenSSH 9.3", "OpenSSL 3.1", "Google Chrome 125", "Mozilla Firefox 126",
    "Fortinet FortiGate 7.4", "SolarWinds Orion 2024", "Docker Engine 26",
    "Kubernetes 1.30", "PostgreSQL 16", "Redis 7.2", "BIND 9.18",
    "Tridium Niagara 4.12", "Wireshark 4.2",
)


def _seed_roles_and_admin(session):
    site_types = ["NOC", "SOC", "Data Center", "Field Office", "HQ", "Remote Site", "Cloud"]
    site_types.extend(
        value for (value,) in session.query(MonitoredLocation.loc_type).distinct().all()
        if value
    )
    site_types = list(dict.fromkeys(site_types))
    tabs_by_key = {
        tab["key"]: group
        for group, tabs in TAB_CATALOG.items()
        for tab in tabs
    }
    operational_pages = [page for page in PAGE_KEYS if page != "Settings & Admin"]
    analyst_actions = [
        "Action: Pin Articles", "Action: Boost Threat Score", "Action: Manually Sync Data",
        "Action: Submit Shift Log", "Action: Dispatch RCA Tickets",
        "Action: Acknowledge RCA Alerts", "Action: Manage Site Maintenance",
        "Action: Generate Risk Snapshot", "Action: Run RCA Analysis",
    ]
    analyst_actions.extend(key for key, group in tabs_by_key.items() if group != "settings")
    settings_user_tab = "Tab: Settings -> Users & Roles"

    admin_role = session.query(Role).filter_by(name="admin").first()
    if not admin_role:
        admin_role = Role(name="admin")
        session.add(admin_role)
    if admin_role.allowed_pages != list(PAGE_KEYS):
        admin_role.allowed_pages = list(PAGE_KEYS)
    if admin_role.allowed_actions != list(ADMIN_ACTIONS):
        admin_role.allowed_actions = list(ADMIN_ACTIONS)
    if admin_role.allowed_site_types != site_types:
        admin_role.allowed_site_types = site_types

    if not session.query(Role).filter_by(name="analyst").first():
        session.add(Role(
            name="analyst", allowed_pages=operational_pages,
            allowed_actions=analyst_actions, allowed_site_types=site_types,
        ))
    if not session.query(Role).filter_by(name="viewer").first():
        session.add(Role(
            name="viewer", allowed_pages=["Global Dashboards", "Regional Grid"],
            allowed_actions=[
                "Tab: Dashboards -> Operational",
                "Tab: Regional Grid -> Geospatial Map",
            ], allowed_site_types=site_types,
        ))
    if not session.query(Role).filter_by(name="user-admin").first():
        session.add(Role(
            name="user-admin", allowed_pages=["Settings & Admin"],
            allowed_actions=[
                settings_user_tab,
                "Action: Manage Users",
                "Action: Review Account Recovery Requests",
                "Action: Approve Recovery Email Changes",
            ], allowed_site_types=[],
        ))

    config = session.query(SystemConfig).first()
    if not config:
        config = SystemConfig()
        session.add(config)
        session.flush()

    if int(config.permission_catalog_version or 0) < 1:
        analyst_role = session.query(Role).filter_by(name="analyst").first()
        if analyst_role:
            analyst_role.allowed_pages = operational_pages
            analyst_role.allowed_actions = analyst_actions
            analyst_role.allowed_site_types = site_types
        for role in session.query(Role).filter(Role.name.notin_(["admin", "analyst"])).all():
            current_actions = list(role.allowed_actions or [])
            if "Action: Trigger AI Functions" in current_actions:
                current_actions = [key for key in current_actions if key != "Action: Trigger AI Functions"]
                current_actions.append("Action: Generate Reports")
            role.allowed_actions = list(dict.fromkeys(current_actions))
            if not role.allowed_site_types and role.name != "user-admin":
                role.allowed_site_types = site_types
        config.permission_catalog_version = 1

    admin_email = settings.default_admin_email.strip()
    email_valid = bool(re.fullmatch(
        r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}",
        admin_email,
    ))
    normalized_admin_email = admin_email.casefold() if email_valid else None
    admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "").strip()
    if admin_password and not session.query(User.id).first():
        hashed = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        now = datetime.utcnow()
        session.add(User(
            username="admin", password_hash=hashed, role="admin", account_type="individual",
            is_active=True, email=admin_email if email_valid else None,
            email_normalized=normalized_admin_email,
            email_verified_at=now if email_valid else None, created_at=now,
            full_name="Administrator", job_title="System Admin", contact_info="NOC Desk",
        ))

    # Trusted bootstrap configuration can verify an existing email-less admin.
    if email_valid:
        bootstrap_admin = session.query(User).filter_by(username="admin").first()
        if bootstrap_admin and not bootstrap_admin.email_verified_at:
            existing_normalized = str(
                bootstrap_admin.email_normalized or bootstrap_admin.email or ""
            ).strip().casefold()
            duplicate = session.query(User.id).filter(
                User.email_normalized == normalized_admin_email,
                User.id != bootstrap_admin.id,
            ).first()
            if duplicate:
                logger.warning("DEFAULT_ADMIN_EMAIL bootstrap skipped because the address belongs to another account")
            elif existing_normalized and existing_normalized != normalized_admin_email:
                logger.warning("DEFAULT_ADMIN_EMAIL bootstrap skipped because admin has a different unverified address")
            else:
                now = datetime.utcnow()
                bootstrap_admin.email = admin_email
                bootstrap_admin.email_normalized = normalized_admin_email
                bootstrap_admin.email_verified_at = now
                pending_requests = session.query(EmailChangeRequest).filter(
                    EmailChangeRequest.user_id == bootstrap_admin.id,
                    EmailChangeRequest.status.in_(["pending_review", "pending_verification"]),
                ).all()
                for request in pending_requests:
                    if request.requested_email_normalized == normalized_admin_email:
                        request.status = "completed"
                        request.reviewed_at = now
                        request.verified_at = now
                        request.verification_token_hash = None
                        request.verification_expires_at = None
                        request.decision_reason = "Completed by trusted DEFAULT_ADMIN_EMAIL bootstrap configuration."
                    else:
                        request.status = "denied"
                        request.reviewed_at = now
                        request.verification_token_hash = None
                        request.verification_expires_at = None
                        request.decision_reason = "Superseded by trusted DEFAULT_ADMIN_EMAIL bootstrap configuration."
                session.add(AccountAuditEvent(
                    subject_user_id=bootstrap_admin.id,
                    event_type="bootstrap_recovery_email_configured",
                    event_detail={"source": "DEFAULT_ADMIN_EMAIL"},
                    created_at=now,
                ))


def _seed_feeds(session_factory):
    with session_factory() as session:
        urls = [url for url, _ in DEFAULT_FEEDS]
        existing = {
            url for (url,) in session.query(FeedSource.url).filter(FeedSource.url.in_(urls)).all()
        }
        missing = [
            FeedSource(url=url, name=name, is_active=True)
            for url, name in DEFAULT_FEEDS if url not in existing
        ]
        if missing:
            session.add_all(missing)
            session.commit()
            logger.info("Added %d default RSS feed sources.", len(missing))


def _seed_keywords(session_factory):
    with session_factory() as session:
        words = [word for word, _ in DEFAULT_KEYWORDS]
        existing = {
            word for (word,) in session.query(Keyword.word).filter(Keyword.word.in_(words)).all()
        }
        missing = [Keyword(word=word, weight=weight) for word, weight in DEFAULT_KEYWORDS if word not in existing]
        if missing:
            session.add_all(missing)
            session.commit()
            logger.info("Seeded %d default keywords.", len(missing))


def _seed_demo_assets(session_factory):
    if not settings.demo_seed_data:
        return
    with session_factory() as session:
        if not session.query(HardwareAsset.id).first():
            hardware_assets = _demo_hardware_assets()
            session.add_all(hardware_assets)
            session.commit()
            logger.info("Seeded %d dummy hardware assets.", len(hardware_assets))
        if not session.query(SoftwareAsset.id).first():
            session.add_all([SoftwareAsset(name=name) for name in DEMO_SOFTWARE_ASSETS])
            session.commit()
            logger.info("Seeded %d dummy software assets.", len(DEMO_SOFTWARE_ASSETS))


def ensure_bootstrap_data(session_factory) -> None:
    """Create missing default data without replacing operator customizations."""
    try:
        with session_factory() as session:
            _seed_roles_and_admin(session)
            session.commit()
    except Exception:
        logger.exception("Database bootstrap data initialization failed")

    try:
        _seed_feeds(session_factory)
    except Exception:
        logger.exception("Could not seed default feeds")

    try:
        _seed_keywords(session_factory)
    except Exception:
        logger.exception("Could not seed default keywords")

    try:
        with session_factory() as session:
            if not session.query(SystemConfig.id).first():
                session.add(SystemConfig(is_active=False))
                session.commit()
                logger.info("Created default SystemConfig.")
    except Exception:
        logger.exception("Could not seed default SystemConfig")

    try:
        _seed_demo_assets(session_factory)
    except Exception:
        logger.exception("Could not seed demo assets")

    if os.environ.get("RESCORE_ON_STARTUP", "false").lower() in {"1", "true", "yes"}:
        try:
            from src.services import rescore_all_articles

            rescored = rescore_all_articles()
            logger.info("Rescored %d existing articles with new keywords.", rescored)
        except Exception:
            logger.exception("Could not rescore articles")
    else:
        logger.info("Skipping startup article rescore; run maintenance rescore explicitly when required.")
