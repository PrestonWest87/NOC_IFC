import os
import bcrypt
import time
import random
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON, event
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

# Enforce SQLite connection string
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/noc_fusion.db").strip().strip('"').strip("'")
if not DATABASE_URL.startswith("sqlite"):
    DATABASE_URL = "sqlite:////app/data/noc_fusion.db"

# --- OPTIMIZED SQLITE ENGINE CONFIGURATION ---
engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False, "timeout": 30} 
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    # Write-Ahead Logging for high-concurrency (simultaneous reads/writes)
    cursor.execute("PRAGMA journal_mode=WAL")
    # Reduces sync overhead to disk, vastly improving write speeds
    cursor.execute("PRAGMA synchronous=NORMAL")
    # Dedicate 64MB of RAM to the DB cache
    cursor.execute("PRAGMA cache_size=-64000") 
    # Process complex queries and temporary tables in RAM, not on disk
    cursor.execute("PRAGMA temp_store=MEMORY")
    # Use Memory-Mapped I/O for lightning-fast dashboard reads
    cursor.execute("PRAGMA mmap_size=3000000000") 
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ==========================================
# CORE SYSTEM MODELS
# ==========================================

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="analyst", index=True)
    session_token = Column(String, nullable=True, index=True) 
    full_name = Column(String, nullable=True)
    job_title = Column(String, nullable=True)
    contact_info = Column(String, nullable=True)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    allowed_pages = Column(JSON) 
    allowed_actions = Column(JSON, default=list) 

class SavedReport(Base):
    __tablename__ = "saved_reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    author = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class FeedSource(Base):
    __tablename__ = "feed_sources"
    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, unique=True, index=True)
    name = Column(String)
    is_active = Column(Boolean, default=True)

class Keyword(Base):
    __tablename__ = "keywords"
    id = Column(Integer, primary_key=True, index=True)
    word = Column(String, unique=True, index=True)
    weight = Column(Integer, default=10)

class SystemConfig(Base):
    __tablename__ = "system_config"
    id = Column(Integer, primary_key=True, index=True)
    llm_endpoint = Column(String, default="https://api.openai.com/v1")
    llm_api_key = Column(String, default="")
    llm_model_name = Column(String, default="gpt-4o-mini")
    is_active = Column(Boolean, default=False)
    tech_stack = Column(Text, default="SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco")
    monitored_asns = Column(String, default="AS701, AS7922, AS3356") 
    rolling_summary = Column(Text, nullable=True)
    rolling_summary_time = Column(DateTime, nullable=True)
    smtp_server = Column(String, nullable=True)
    smtp_port = Column(Integer, default=587)
    smtp_username = Column(String, nullable=True)
    smtp_password = Column(String, nullable=True)
    smtp_sender = Column(String, nullable=True)
    smtp_recipient = Column(String, nullable=True)
    smtp_enabled = Column(Boolean, default=False)


# ==========================================
# INTELLIGENCE & THREAT MODELS
# ==========================================

class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    link = Column(String, unique=True, index=True)
    summary = Column(Text)
    published_date = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    score = Column(Float, default=0.0, index=True)
    category = Column(String, default="General", index=True)
    keywords_found = Column(JSON)
    is_bubbled = Column(Boolean, default=False)
    story_group = Column(String, nullable=True) 
    human_feedback = Column(Integer, default=0) 
    ai_bluf = Column(Text, nullable=True)
    is_pinned = Column(Boolean, default=False, index=True)

class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"
    id = Column(Integer, primary_key=True, index=True)
    article_id = Column(Integer, index=True)
    indicator_type = Column(String, index=True)
    indicator_value = Column(String, index=True)
    context = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)

class CveItem(Base):
    __tablename__ = "cve_items"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    vendor = Column(String, index=True)
    product = Column(String, index=True)
    vulnerability_name = Column(String)
    date_added = Column(DateTime, index=True)
    description = Column(Text)
    required_action = Column(Text)
    due_date = Column(String)

class DailyBriefing(Base):
    __tablename__ = "daily_briefings"
    id = Column(Integer, primary_key=True, index=True)
    report_date = Column(DateTime, unique=True, index=True)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


# ==========================================
# GRID, WEATHER & AIOps MODELS
# ==========================================

class RegionalHazard(Base):
    __tablename__ = "regional_hazards"
    id = Column(Integer, primary_key=True, index=True)
    hazard_id = Column(String, unique=True, index=True)
    hazard_type = Column(String) 
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    location = Column(String)
    updated_at = Column(DateTime, index=True)

class RegionalOutage(Base):
    __tablename__ = "regional_outages"
    id = Column(Integer, primary_key=True, index=True)
    outage_type = Column(String, index=True) 
    provider = Column(String) 
    description = Column(Text)
    affected_area = Column(String)
    lat = Column(Float, nullable=True)
    lon = Column(Float, nullable=True)
    radius_km = Column(Float, default=10.0) 
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False, index=True)

class CloudOutage(Base):
    __tablename__ = "cloud_outages"
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String, index=True) 
    service = Column(String) 
    title = Column(String)
    description = Column(Text)
    link = Column(String)
    is_resolved = Column(Boolean, default=False, index=True)
    updated_at = Column(DateTime, index=True)

class BgpAnomaly(Base):
    __tablename__ = "bgp_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    asn = Column(String, index=True)
    event_type = Column(String) 
    description = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False, index=True)

class SolarWindsAlert(Base):
    __tablename__ = "solarwinds_alerts"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True)
    severity = Column(String)
    node_name = Column(String, index=True)
    ip_address = Column(String)
    status = Column(String, index=True)
    sw_timestamp = Column(String)
    details = Column(Text)
    node_link = Column(String)
    raw_payload = Column(JSON, nullable=True) 
    mapped_location = Column(String, nullable=True, index=True) 
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True, index=True)
    is_correlated = Column(Boolean, default=False, index=True)
    ai_root_cause = Column(Text, nullable=True)
    device_type = Column(String, default="Unknown", index=True)
    event_category = Column(String, default="Unknown")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True) 
    event_type = Column(String, index=True) 
    message = Column(String)

class NodeAlias(Base):
    __tablename__ = "node_aliases"
    id = Column(Integer, primary_key=True, index=True)
    node_pattern = Column(String, unique=True, index=True)
    mapped_location_name = Column(String, index=True) 
    confidence_score = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False, index=True)

class MonitoredLocation(Base):
    __tablename__ = "monitored_locations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    loc_type = Column(String, default="General", index=True)
    priority = Column(Integer, default=3, index=True)
    current_spc_risk = Column(String, default="None")
    last_updated = Column(DateTime, default=datetime.utcnow)

class CrimeIncident(Base):
    __tablename__ = "crime_incidents"
    id = Column(String, primary_key=True, index=True)
    category = Column(String)
    raw_title = Column(String)
    timestamp = Column(DateTime, index=True)
    distance_miles = Column(Float)
    severity = Column(String)
    lat = Column(Float)
    lon = Column(Float)


# ==========================================
# INITIALIZATION & SEEDING
# ==========================================

def init_db():
    # Minor sleep mitigates docker-compose DB container race conditions
    time.sleep(random.uniform(0.1, 1.5))
    
    # Safely create all models natively through SQLAlchemy
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        print(f"Schema generation error: {e}")
    
    # Seed Initial Data
    session = SessionLocal()
    try:
        all_pages = [
            "🌐 Operational Dashboard", 
            "📊 Executive Dashboard", 
            "📰 Daily Fusion Report",
            "📡 Threat Telemetry", 
            "🚨 Crime Intelligence",
            "🎯 Threat Hunting & IOCs",
            "⚡ AIOps RCA", 
            "📑 Report Center", 
            "⚙️ Settings & Admin"
        ]
        
        # EXACT match to descriptive strings deployed in app.py UI
        all_actions = [
            "Action: Pin Articles", "Action: Train ML Model", "Action: Boost Threat Score", 
            "Action: Trigger AI Functions", "Action: Manually Sync Data",
            "Action: Dispatch Exec Report",
            "Tab: Threat Telemetry -> RSS Triage", "Tab: Threat Telemetry -> CISA KEV", 
            "Tab: Threat Telemetry -> Cloud Services", "Tab: Threat Telemetry -> Regional Grid",
            "Tab: Regional Grid -> Geospatial Map", "Tab: Regional Grid -> Executive Dash", "Tab: Regional Grid -> Hazard Analytics", 
            "Tab: Regional Grid -> Location Matrix", "Tab: Regional Grid -> Weather Alerts Log", 
            "Tab: Regional Grid -> Manage Locations", "Tab: Threat Hunting -> Global IOC Matrix", 
            "Tab: Threat Hunting -> Deep Hunt Builder", "Tab: AIOps RCA -> Active Board", 
            "Tab: AIOps RCA -> Predictive Analytics", "Tab: AIOps RCA -> Global Correlation",
            "Tab: Report Center -> Report Builder", "Tab: Report Center -> Shared Library",
            "Tab: Settings -> RSS Sources", "Tab: Settings -> ML Training", "Tab: Settings -> AI & SMTP", 
            "Tab: Settings -> Users & Roles", "Tab: Settings -> Backup & Restore", "Tab: Settings -> Danger Zone"
        ]

        admin_role = session.query(Role).filter_by(name="admin").first()
        if not admin_role:
            session.add(Role(name="admin", allowed_pages=all_pages, allowed_actions=all_actions))
        else:
            # Auto-heals existing admin roles
            admin_role.allowed_pages = all_pages
            admin_role.allowed_actions = all_actions
            
        analyst_role = session.query(Role).filter_by(name="analyst").first()
        if not analyst_role:
            session.add(Role(name="analyst", allowed_pages=all_pages[:-1], allowed_actions=all_actions))
        else:
            analyst_role.allowed_pages = all_pages[:-1]
            analyst_role.allowed_actions = all_actions
            
        if not session.query(User).first():
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
        print(f"Database initialization error: {e}")
    finally:
        session.close() # Ensures connection is cleanly returned to the pool
