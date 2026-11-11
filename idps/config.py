"""Runtime settings for the IDPS, overridable with IDPS_* environment variables."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDPS_")

    interface: str = "eth0"
    model_path: str = "models/model.joblib"
    block_ttl_seconds: int = 900
    confidence_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    # Log what would be blocked instead of touching nftables.
    dry_run: bool = True
    # IPs that must never be blocked (gateway, DNS, SOC host, analyst).
    allowlist: list[str] = Field(default_factory=list)


def get_settings() -> Settings:
    return Settings()
