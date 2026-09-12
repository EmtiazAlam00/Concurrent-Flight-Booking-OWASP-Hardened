from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    env: str = Field("local", alias="SKYLOCK_ENV")

    database_url: str = Field(
        "postgresql+asyncpg://skylock_app:skylock_app@localhost:5432/skylock",
        alias="DATABASE_URL",
    )
    # Migrations run as the owner role so they can REVOKE from the app role.
    migration_database_url: str | None = Field(None, alias="MIGRATION_DATABASE_URL")
    redis_url: str = Field("redis://localhost:6379/0", alias="REDIS_URL")

    jwt_secret: str = Field(
        "dev-only-insecure-secret-change-me-0000000000000000", alias="JWT_SECRET"
    )
    jwt_algorithm: str = "HS256"
    access_token_ttl_seconds: int = Field(600, alias="ACCESS_TOKEN_TTL_SECONDS")
    refresh_token_ttl_seconds: int = Field(1_209_600, alias="REFRESH_TOKEN_TTL_SECONDS")
    login_max_failures: int = Field(5, alias="LOGIN_MAX_FAILURES")
    login_lockout_seconds: int = Field(900, alias="LOGIN_LOCKOUT_SECONDS")

    hold_ttl_seconds: int = Field(600, alias="HOLD_TTL_SECONDS")
    hold_sweep_interval_seconds: int = Field(30, alias="HOLD_SWEEP_INTERVAL_SECONDS")
    max_active_holds_per_user: int = Field(6, alias="MAX_ACTIVE_HOLDS_PER_USER")

    dashboard_enabled: bool = Field(True, alias="DASHBOARD_ENABLED")
    dashboard_user: str = Field("dash", alias="DASHBOARD_USER")
    dashboard_password: str = Field("dash-dev-password", alias="DASHBOARD_PASSWORD")

    rate_limit_enabled: bool = Field(True, alias="RATE_LIMIT_ENABLED")
    payment_provider: str = Field("fake", alias="PAYMENT_PROVIDER")

    # Idempotency records are replayable for this long after completion.
    idempotency_ttl_seconds: int = 24 * 3600

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
