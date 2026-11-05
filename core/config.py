import os
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Honeypot-System v2.0 Global Configuration.
    Supports dynamic overrides via environment variables and .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Decoy Service Ports
    SSH_PORT: int = 2222
    HTTP_PORT: int = 8080
    FTP_PORT: int = 2121
    TELNET_PORT: int = 2323
    API_PORT: int = 9090
    HOST: str = "0.0.0.0"

    # Persistence & Storage
    DB_PATH: str = "data/honeypot.db"
    RECORDINGS_DIR: str = "recordings"

    # Active Defense Mechanisms
    TARPIT_ENABLED: bool = True
    TARPIT_BYTE_RATE: int = 10  # Bytes per second to throttle automated crawlers
    MALICIOUS_IP_THRESHOLD: int = 5  # Threshold before adding IP to high-confidence blocklist

    # Sensor Identification
    SENSOR_NAME: str = "honeypot-node-01"

    def ensure_directories(self) -> None:
        """Ensure runtime directories for databases and session recordings exist."""
        db_dir = Path(self.DB_PATH).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        rec_dir = Path(self.RECORDINGS_DIR)
        rec_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()

