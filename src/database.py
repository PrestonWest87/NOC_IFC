import os
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float, Boolean, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Article(Base):
    __tablename__ = "articles"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    link = Column(String, unique=True, index=True)
    summary = Column(Text)
    published_date = Column(DateTime, default=datetime.utcnow)
    source = Column(String)
    score = Column(Float, default=0.0)
    keywords_found = Column(JSON)
    is_bubbled = Column(Boolean, default=False)
    human_feedback = Column(Integer, default=0) # 0=None, 1=Dismiss, 2=Confirm

class FeedSource(Base):
    __tablename__ = "feed_sources"
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True)
    name = Column(String)
    is_active = Column(Boolean, default=True)

class Keyword(Base):
    __tablename__ = "keywords"
    id = Column(Integer, primary_key=True)
    word = Column(String, unique=True)
    weight = Column(Integer)

# --- New Table for LLM Configuration ---
class LLMSettings(Base):
    __tablename__ = "llm_settings"
    id = Column(Integer, primary_key=True)
    provider = Column(String, default="Local (Ollama)") # "Local (Ollama)", "OpenAI", or "Gemini"
    model_name = Column(String, default="llama3")
    api_key = Column(String, nullable=True)
    base_url = Column(String, default="http://host.docker.internal:11434/v1") 

def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Seed default data if empty
    session = SessionLocal()
    if session.query(FeedSource).count() == 0:
        session.add(FeedSource(url="https://feeds.feedburner.com/TheHackersNews", name="Hacker News"))
        session.add(FeedSource(url="https://www.bleepingcomputer.com/feed/", name="BleepingComputer"))
    
    if session.query(Keyword).count() == 0:
        session.add(Keyword(word="critical", weight=50))
        session.add(Keyword(word="rce", weight=60))
        session.add(Keyword(word="vulnerability", weight=40))
        
    # Initialize default LLM settings
    if session.query(LLMSettings).count() == 0:
        session.add(LLMSettings())
    
    session.commit()
    session.close()