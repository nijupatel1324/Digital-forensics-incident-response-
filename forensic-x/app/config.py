"""
FORENSIC-X — Configuration
app/config.py

Central settings class powered by Pydantic-Settings.
All values are read from environment variables / .env file.
"""

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application-wide configuration.
    Values are loaded from environment variables (or .env).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────
    APP_NAME: str = "FORENSIC-X"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    APP_DEBUG: bool = True
    APP_BASE_URL: str = "http://localhost:8000"

    # ── Security ─────────────────────────────────────────────
    SECRET_KEY: str = "CHANGE_ME_TO_A_RANDOM_64_CHAR_HEX_STRING"
    JWT_SECRET: str = "CHANGE_ME_TO_ANOTHER_RANDOM_64_CHAR_HEX_STRING"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    CORS_ORIGINS: str = "http://localhost:8000,http://localhost:3000"

    # ── Database ─────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://forensicx:password@localhost:5432/forensicx_db"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    DATABASE_ECHO: bool = False

    # ── Redis ─────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None

    # ── Admin Bootstrap ──────────────────────────────────────
    ADMIN_EMAIL: str = "admin@forensicx.local"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "CHANGE_ME_STRONG_ADMIN_PASSWORD"
    ADMIN_FULL_NAME: str = "System Administrator"

    # ── File Storage ─────────────────────────────────────────
    EVIDENCE_UPLOAD_DIR: str = "./evidence_store"
    REPORTS_DIR: str = "./reports_store"
    MAX_UPLOAD_SIZE_MB: int = 500
    ALLOWED_EVIDENCE_EXTENSIONS: str = (
        ".log,.evtx,.pcap,.cap,.csv,.json,.xml,.txt,.zip,"
        ".tar,.gz,.pdf,.png,.jpg,.jpeg,.bmp,.tiff"
    )

    # ── Email ─────────────────────────────────────────────────
    SMTP_HOST: str = "smtp.example.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = "noreply@forensicx.local"
    SMTP_FROM_NAME: str = "FORENSIC-X Platform"
    SMTP_TLS: bool = True

    # ── Rate Limiting ─────────────────────────────────────────
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_API: str = "100/minute"
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 15

    # ── MFA ──────────────────────────────────────────────────
    MFA_ISSUER_NAME: str = "FORENSIC-X"
    MFA_ENABLED: bool = False

    # ── Logging ───────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    LOG_FILE: str = "./logs/forensicx.log"

    # ── Detection Engine ──────────────────────────────────────
    DETECTION_BRUTE_FORCE_THRESHOLD: int = 5
    DETECTION_BRUTE_FORCE_WINDOW_SECONDS: int = 300
    DETECTION_ENABLED: bool = True

    # ── Threat Intel ─────────────────────────────────────────
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    THREAT_INTEL_ENABLED: bool = False

    # ── Derived helpers ───────────────────────────────────────

    @property
    def allowed_hosts_list(self) -> List[str]:
        return [h.strip() for h in self.ALLOWED_HOSTS.split(",")]

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def allowed_extensions_set(self) -> set:
        return {
            ext.strip().lower()
            for ext in self.ALLOWED_EVIDENCE_EXTENSIONS.split(",")
        }

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def evidence_upload_path(self) -> Path:
        p = Path(self.EVIDENCE_UPLOAD_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def reports_path(self) -> Path:
        p = Path(self.REPORTS_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def logs_path(self) -> Path:
        p = Path(self.LOG_FILE).parent
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache()
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()

# Convenience alias used throughout the app
settings = get_settings()

def get_settings_uncached() -> Settings:
    """Return a fresh Settings instance (used in tests)."""
    return Settings()
