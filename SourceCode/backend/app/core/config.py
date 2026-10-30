"""
Configuration settings for XGuard backend.
Supports environment variable overrides and sensible local defaults.
"""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "XGuard Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Cross-Origin Resource Sharing
    CORS_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://localhost:5173",
        "chrome-extension://*"
    ]

    # Database
    DATABASE_URL: str = "sqlite:///./threatguard.db"

    # Security & Scanning Defaults
    DEFAULT_PROTECTION_MODE: str = "balanced"  # balanced, strict, learning
    SCAN_TIMEOUT_SECONDS: float = 3.5
    RATE_LIMIT_PER_MINUTE: int = 120
    MAX_REDIRECT_HOPS: int = 5

    # Threat Intelligence Adapters
    URLHAUS_API_ENABLED: bool = True
    URLHAUS_TIMEOUT_SECONDS: float = 2.0

    # AI Chatbot LLM Configuration (Optional external provider)
    GROQ_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    LLM_MODEL: str = "llama-3.1-8b-instant"


settings = Settings()
