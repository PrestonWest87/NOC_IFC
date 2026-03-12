import os
import bcrypt
import time
import random
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/rss_db")

engine = create_engine(
    DATABASE_URL, pool_size=20, max_overflow=30, pool_pre_ping=True, pool_recycle=3600
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="analyst")
    session_token = Column(String, nullable=True) 
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
    created_at = Column(DateTime, default=datetime.utcnow)

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

class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    link = Column(String, unique=True, index=True)
    summary = Column(Text)
    published_date = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String)
    score = Column(Float, default=0.0, index=True)
    category = Column(String, default="General", index=True)
    keywords_found = Column(JSON)
    is_bubbled = Column(Boolean, default=False)
    story_group = Column(String, nullable=True) 
    human_feedback = Column(Integer, default=0) 
    ai_bluf = Column(Text, nullable=True)
    is_pinned = Column(Boolean, default=False)

class ExtractedIOC(Base):
    __tablename__ = "extracted_iocs"
    id = Column(Integer, primary_key=True, index=True)
    article_id = Column(Integer, index=True)
    indicator_type = Column(String, index=True)
    indicator_value = Column(String, index=True)
    context = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)

class SystemConfig(Base):
    __tablename__ = "system_config"
    id = Column(Integer, primary_key=True, index=True)
    llm_endpoint = Column(String, default="https://api.openai.com/v1")
    llm_api_key = Column(String, default="")
    llm_model_name = Column(String, default="gpt-4o-mini")
    is_active = Column(Boolean, default=False)
    tech_stack = Column(Text, default="SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco")
    monitored_asns = Column(String, default="AS701, AS7922, AS3356") # BGP Monitoring Targets
    rolling_summary = Column(Text, nullable=True)
    rolling_summary_time = Column(DateTime, nullable=True)
    smtp_server = Column(String, nullable=True)
    smtp_port = Column(Integer, default=587)
    smtp_username = Column(String, nullable=True)
    smtp_password = Column(String, nullable=True)
    smtp_sender = Column(String, nullable=True)
    smtp_recipient = Column(String, nullable=True)
    smtp_enabled = Column(Boolean, default=False)

class CveItem(Base):
    __tablename__ = "cve_items"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    vendor = Column(String)
    product = Column(String)
    vulnerability_name = Column(String)
    date_added = Column(DateTime)
    description = Column(Text)
    required_action = Column(Text)
    due_date = Column(String)

class RegionalHazard(Base):
    __tablename__ = "regional_hazards"
    id = Column(Integer, primary_key=True, index=True)
    hazard_id = Column(String, unique=True, index=True)
    hazard_type = Column(String) 
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    location = Column(String)
    updated_at = Column(DateTime)

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
    is_resolved = Column(Boolean, default=False)

class BgpAnomaly(Base):
    __tablename__ = "bgp_anomalies"
    id = Column(Integer, primary_key=True, index=True)
    asn = Column(String, index=True)
    event_type = Column(String) 
    description = Column(Text)
    detected_at = Column(DateTime, default=datetime.utcnow)
    is_resolved = Column(Boolean, default=False)

class CloudOutage(Base):
    __tablename__ = "cloud_outages"
    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String) 
    service = Column(String) 
    title = Column(String)
    description = Column(Text)
    link = Column(String)
    is_resolved = Column(Boolean, default=False)
    updated_at = Column(DateTime)
    
class DailyBriefing(Base):
    __tablename__ = "daily_briefings"
    id = Column(Integer, primary_key=True, index=True)
    report_date = Column(DateTime, unique=True, index=True)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class MonitoredLocation(Base):
    __tablename__ = "monitored_locations"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    lat = Column(Float)
    lon = Column(Float)
    loc_type = Column(String, default="General")
    priority = Column(Integer, default=3)
    current_spc_risk = Column(String, default="None")
    last_updated = Column(DateTime, default=datetime.utcnow)

class NodeAlias(Base):
    __tablename__ = "node_aliases"
    id = Column(Integer, primary_key=True, index=True)
    node_pattern = Column(String, unique=True, index=True)
    mapped_location_name = Column(String) 
    confidence_score = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)

class SolarWindsAlert(Base):
    __tablename__ = "solarwinds_alerts"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, index=True)
    severity = Column(String)
    node_name = Column(String, index=True)
    ip_address = Column(String)
    status = Column(String)
    sw_timestamp = Column(String)
    details = Column(Text)
    node_link = Column(String)
    raw_payload = Column(JSON, nullable=True) 
    mapped_location = Column(String, nullable=True) 
    received_at = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at = Column(DateTime, nullable=True)
    is_correlated = Column(Boolean, default=False)
    ai_root_cause = Column(Text, nullable=True)
    device_type = Column(String, default="Unknown")
    event_category = Column(String, default="Unknown")

class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String) 
    event_type = Column(String) 
    message = Column(String)

def init_db():
    time.sleep(random.uniform(0.1, 2.0))
    
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        pass
    
    migrations = [
        "CREATE TABLE IF NOT EXISTS regional_outages (id SERIAL PRIMARY KEY, outage_type VARCHAR, provider VARCHAR, description TEXT, affected_area VARCHAR, lat FLOAT, lon FLOAT, radius_km FLOAT DEFAULT 10.0, detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_resolved BOOLEAN DEFAULT FALSE);",
        "CREATE INDEX IF NOT EXISTS ix_regional_outages_type ON regional_outages (outage_type);",
        "CREATE TABLE IF NOT EXISTS bgp_anomalies (id SERIAL PRIMARY KEY, asn VARCHAR, event_type VARCHAR, description TEXT, detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_resolved BOOLEAN DEFAULT FALSE);",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS monitored_asns VARCHAR DEFAULT 'AS701, AS7922, AS3356';",
        "ALTER TABLE solarwinds_alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;",
        "CREATE TABLE IF NOT EXISTS timeline_events (id SERIAL PRIMARY KEY, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, source VARCHAR, event_type VARCHAR, message VARCHAR);",
        "ALTER TABLE solarwinds_alerts ADD COLUMN IF NOT EXISTS raw_payload JSON;",
        "ALTER TABLE solarwinds_alerts ADD COLUMN IF NOT EXISTS mapped_location VARCHAR;",
        "ALTER TABLE solarwinds_alerts ADD COLUMN IF NOT EXISTS device_type VARCHAR DEFAULT 'Unknown';",
        "ALTER TABLE solarwinds_alerts ADD COLUMN IF NOT EXISTS event_category VARCHAR DEFAULT 'Unknown';",
        "ALTER TABLE articles ADD COLUMN IF NOT EXISTS story_group VARCHAR;",
        "ALTER TABLE articles ADD COLUMN IF NOT EXISTS ai_bluf TEXT;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS tech_stack TEXT DEFAULT 'SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco';",
        "ALTER TABLE articles ADD COLUMN IF NOT EXISTS is_pinned BOOLEAN DEFAULT FALSE;",
        "ALTER TABLE roles ADD COLUMN IF NOT EXISTS allowed_actions JSON DEFAULT '[]'::json;",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS session_token VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS rolling_summary TEXT;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS rolling_summary_time TIMESTAMP;",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR;",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title VARCHAR;",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS contact_info VARCHAR;",
        "ALTER TABLE articles ADD COLUMN IF NOT EXISTS category VARCHAR DEFAULT 'General';",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_server VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_port INTEGER DEFAULT 587;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_username VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_password VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_sender VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_recipient VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN IF NOT EXISTS smtp_enabled BOOLEAN DEFAULT FALSE;",
        "CREATE INDEX IF NOT EXISTS ix_articles_published_date ON articles (published_date);",
        "CREATE INDEX IF NOT EXISTS ix_articles_score ON articles (score);",
        "CREATE INDEX IF NOT EXISTS ix_articles_category ON articles (category);",
        "CREATE TABLE IF NOT EXISTS extracted_iocs (id SERIAL PRIMARY KEY, article_id INTEGER, indicator_type VARCHAR, indicator_value VARCHAR, context TEXT, detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
        "CREATE INDEX IF NOT EXISTS ix_extracted_iocs_article_id ON extracted_iocs (article_id);",
        "CREATE TABLE IF NOT EXISTS monitored_locations (id SERIAL PRIMARY KEY, name VARCHAR UNIQUE, lat FLOAT, lon FLOAT, loc_type VARCHAR DEFAULT 'General', priority INTEGER DEFAULT 3, current_spc_risk VARCHAR DEFAULT 'None', last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP);",
        "CREATE TABLE IF NOT EXISTS solarwinds_alerts (id SERIAL PRIMARY KEY, event_type VARCHAR, severity VARCHAR, node_name VARCHAR, ip_address VARCHAR, status VARCHAR, sw_timestamp VARCHAR, details TEXT, node_link VARCHAR, raw_payload JSON, mapped_location VARCHAR, received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_correlated BOOLEAN DEFAULT FALSE, ai_root_cause TEXT);",
        "CREATE TABLE IF NOT EXISTS node_aliases (id SERIAL PRIMARY KEY, node_pattern VARCHAR UNIQUE, mapped_location_name VARCHAR, confidence_score FLOAT DEFAULT 0.0, is_verified BOOLEAN DEFAULT FALSE);"
    ]
    
    for sql in migrations:
        with engine.connect() as conn:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                conn.rollback()
            
    session = SessionLocal()
    
    all_pages = [
        "🌐 Operational Dashboard", 
        "📰 Daily Fusion Report",
        "📡 Threat Telemetry", 
        "🎯 Threat Hunting & IOCs",
        "⚡ AIOps RCA", 
        "📑 Report Center", 
        "⚙️ Settings & Admin"
    ]
    all_actions = [
        "action_pin", "action_train_ml", "action_boost_threat", "action_trigger_ai", "action_sync_data",
        "tab_tt_rss", "tab_tt_kev", "tab_tt_cloud", "tab_tt_infra",
        "tab_rc_build", "tab_rc_lib"
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
        
    session.commit()

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
        
    session.close()