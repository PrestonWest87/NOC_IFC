import sys
import logging
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    database_url: str = "sqlite:////app/data/noc_fusion.db"
    elastic_url: str = "https://localhost:9200"
    elastic_api_key: str = "your_read_only_api_key"
    crime_alert_sms: str | None = None
    crime_alert_email: str | None = None
    risk_alert_recipients: str = ""

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


def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
