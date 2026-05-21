import os
import sys
import logging
from dotenv import load_dotenv

load_dotenv()

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////app/data/noc_fusion.db").strip().strip('"').strip("'")
if not DATABASE_URL.startswith("sqlite"):
    DATABASE_URL = "sqlite:////app/data/noc_fusion.db"

# Elastic
ELASTIC_URL = os.getenv("ELASTIC_URL", "https://localhost:9200")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "your_read_only_api_key")

# Crime alerts
CRIME_ALERT_SMS = os.getenv("CRIME_ALERT_SMS")
CRIME_ALERT_EMAIL = os.getenv("CRIME_ALERT_EMAIL")

# Risk alert recipients
RISK_ALERT_RECIPIENTS = os.getenv("RISK_ALERT_RECIPIENTS", "")


def setup_logging(level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
