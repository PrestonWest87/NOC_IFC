import os
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/rss_db")

engine = create_engine(
    DATABASE_URL,
    pool_size=20,          # Allow up to 20 concurrent threads to write at the same time
    max_overflow=30,       # Allow an extra 30 overflow connections during massive spikes
    pool_pre_ping=True,    # Automatically test and drop dead connections 
    pool_recycle=3600      # Force-refresh connections every hour to prevent memory leaks
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
    # --- EFFICIENCY UPGRADE: Indexing ---
    published_date = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String)
    score = Column(Float, default=0.0, index=True)
    # ------------------------------------
    keywords_found = Column(JSON)
    is_bubbled = Column(Boolean, default=False)
    story_group = Column(String, nullable=True) 
    human_feedback = Column(Integer, default=0) 
    ai_bluf = Column(Text, nullable=True)
    is_pinned = Column(Boolean, default=False)

class SystemConfig(Base):
    __tablename__ = "system_config"
    id = Column(Integer, primary_key=True, index=True)
    llm_endpoint = Column(String, default="https://api.openai.com/v1")
    llm_api_key = Column(String, default="")
    llm_model_name = Column(String, default="gpt-4o-mini")
    is_active = Column(Boolean, default=False)
    tech_stack = Column(Text, default="SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco")
    rolling_summary = Column(Text, nullable=True)
    rolling_summary_time = Column(DateTime, nullable=True)

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

def init_db():
    Base.metadata.create_all(bind=engine)
    
    migrations = [
        "ALTER TABLE articles ADD COLUMN story_group VARCHAR;",
        "ALTER TABLE articles ADD COLUMN ai_bluf TEXT;",
        "ALTER TABLE system_config ADD COLUMN tech_stack TEXT DEFAULT 'SolarWinds, Cisco SD-WAN, Microsoft Office, Verizon, Cisco';",
        "ALTER TABLE articles ADD COLUMN is_pinned BOOLEAN DEFAULT FALSE;",
        "ALTER TABLE roles ADD COLUMN allowed_actions JSON DEFAULT '[]'::json;",
        "ALTER TABLE users ADD COLUMN session_token VARCHAR;",
        "ALTER TABLE system_config ADD COLUMN rolling_summary TEXT;",
        "ALTER TABLE system_config ADD COLUMN rolling_summary_time TIMESTAMP;",
        "ALTER TABLE users ADD COLUMN full_name VARCHAR;",
        "ALTER TABLE users ADD COLUMN job_title VARCHAR;",
        "ALTER TABLE users ADD COLUMN contact_info VARCHAR;",
        "CREATE INDEX IF NOT EXISTS ix_articles_published_date ON articles (published_date);",
        "CREATE INDEX IF NOT EXISTS ix_articles_score ON articles (score);"
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
        "📑 Report Center", 
        "⚙️ Settings & Admin"
    ]
    all_actions = [
        "action_pin", "action_train_ml", "action_boost_threat", 
        "action_trigger_ai", "action_sync_data",
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
        print("✅ Default admin created.")
        
    session.close()