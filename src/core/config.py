"""Load configuration used by host-side migration and backup tools."""

from pydantic import Field
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """Pydantic-managed settings retained for offline database maintenance."""
    database_url: str = "sqlite:////app/data/noc_fusion.db"
    demo_seed_data: bool = False
    default_admin_email: str = ""
    backup_encryption_keys: str = ""
    backup_encryption_active_key_id: str = "primary"
    backup_max_bytes: int = Field(default=10737418240, gt=0, le=107374182400)

    class Config:
        """Load the local dotenv file and ignore unrelated environment names."""
        env_file = ".env"
        extra = "ignore"


settings = Settings()

DATABASE_URL = settings.database_url
