import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@db:5432/rss_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

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
    published_date = Column(DateTime, default=datetime.utcnow)
    source = Column(String)
    score = Column(Float, default=0.0)
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
    
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE articles ADD COLUMN story_group VARCHAR;"))
            conn.commit()
        except Exception:
            pass 
        try:
            conn.execute(text("ALTER TABLE articles ADD COLUMN ai_bluf TEXT;"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE system_config ADD COLUMN tech_stack TEXT DEFAULT 'SolarWinds, Docker, Nginx Proxy Manager, Home Assistant, Checkmk, Python, Windows';"))
            conn.commit()
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE articles ADD COLUMN is_pinned BOOLEAN DEFAULT FALSE;"))
            conn.commit()
        except Exception:
            pass