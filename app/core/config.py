from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./phishscope.db"
    jwt_secret: str = "dev-only-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_days: int = 30

    virustotal_api_key: str = ""
    urlscan_api_key: str = ""
    phishtank_app_key: str = ""
    urlhaus_auth_key: str = ""
    safe_browsing_api_key: str = ""

    http_timeout_seconds: float = 4.0
    ti_cache_ttl_hours: int = 24
    analysis_dedup_hours: int = 24

    n8n_webhook_url: str = ""
    n8n_webhook_secret: str = ""

    rate_limit_analyze: str = "30/minute"


settings = Settings()
