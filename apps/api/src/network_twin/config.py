"""Configuration management using Pydantic Settings."""


from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Application configuration with strict validation and safe defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_prefix="NTWIN_",
    )

    app_name: str = "Protocol-Aware Network Digital Twin & Security Verification Engine"
    app_version: str = "0.1.0"
    schema_version: str = "1.0.0"
    environment: str = Field(
        default="development", description="development, testing, staging, or production"
    )
    debug: bool = False

    # Server settings
    host: str = "127.0.0.1"
    port: int = 8000
    api_prefix: str = "/api/v1"

    # CORS settings - restricted development defaults
    cors_allowed_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Database settings (Optional in Phase 00)
    database_url: str | None = None
    require_database: bool = False

    # Engine connection and execution settings
    engine_socket_path: str | None = None
    engine_binary_path: str | None = None
    require_engine: bool = False
    data_dir: str = "data"

    # Security limits
    max_request_body_bytes: int = 50 * 1024 * 1024  # 50 MB limit for PCAP uploads


settings = AppSettings()
