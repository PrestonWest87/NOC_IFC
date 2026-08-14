import sys
import os
import logging
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    database_url: str = "sqlite:////app/data/noc_fusion.db"
    demo_seed_data: bool = False
    log_level: str = "INFO"
    elastic_url: str = "https://localhost:9200"
    elastic_api_key: str = "your_read_only_api_key"
    crime_alert_sms: str | None = None
    crime_alert_email: str | None = None
    risk_alert_recipients: str = ""
    webhook_hmac_secret: str | None = None
    webhook_signature_header: str = "X-SolarWinds-Signature"
    webhook_timestamp_header: str = "X-SolarWinds-Timestamp"
    webhook_replay_window_seconds: int = 300
    webhook_max_body_bytes: int = 1048576
    websocket_max_message_bytes: int = 65536
    allow_private_llm_endpoints: bool = False
    cors_origins: str = "http://localhost:8501,http://localhost:5173"
    allow_unsigned_webhooks: bool = False
    public_app_url: str = "http://localhost:8501"
    registration_invite_ttl_hours: int = 72

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()

DATABASE_URL = settings.database_url
ELASTIC_URL = settings.elastic_url
ELASTIC_API_KEY = settings.elastic_api_key
CRIME_ALERT_SMS = settings.crime_alert_sms
CRIME_ALERT_EMAIL = settings.crime_alert_email
RISK_ALERT_RECIPIENTS = settings.risk_alert_recipients


def setup_logging(level=None):
    if level is None:
        level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
        level = getattr(logging, level_name, logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
