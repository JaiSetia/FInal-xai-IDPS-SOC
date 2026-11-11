"""SOC API settings, overridable with IDPS_SOC_* environment variables."""

from functools import lru_cache
from typing import Annotated

from pydantic import Field, IPvAnyNetwork, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MIN_SECRET_LENGTH = 32

SEVERITIES = ("low", "medium", "high", "critical")

# Base severity per predicted class (matched case-insensitively). Anything not listed gets
# `default_severity`. Override with IDPS_SOC_SEVERITY_BY_CLASS='{"Bot": "critical"}'.
DEFAULT_SEVERITY_BY_CLASS = {
    "portscan": "low",
    "dos": "high", "ddos": "critical", "bot": "high", "infiltration": "critical",
    "heartbleed": "critical", "web attack": "high", "ftp-patator": "medium",
    "ssh-patator": "medium", "brute force": "medium", "sql injection": "high", "xss": "medium",
}


class SocSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDPS_SOC_")

    # SQLite for local development; PostgreSQL in deployment, e.g.
    # postgresql+psycopg://user:pass@host/idps
    database_url: str = "sqlite:///./soc.db"
    # Signs login tokens. Required: there is deliberately no default, so a forgotten
    # setting can't leave the SOC running with a guessable key.
    # Generate one with: python -c "import secrets; print(secrets.token_urlsafe(48))"
    jwt_secret: SecretStr
    access_token_minutes: int = Field(default=30, ge=5, le=24 * 60)
    # Failed logins allowed per (username, client IP) before a lockout, and per client IP.
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_max_failures_per_ip: int = Field(default=20, ge=1, le=1000)
    login_lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)
    # Severity = base severity of the class, lowered one level when the model is unsure.
    severity_by_class: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_SEVERITY_BY_CLASS))
    default_severity: str = "medium"
    low_confidence_below: float = Field(default=0.6, ge=0, le=1)
    # Maximum simultaneous /ws/alerts connections, and each one's queue of unsent alerts
    # (a client that falls this far behind is disconnected rather than slowing ingest).
    ws_max_connections: int = Field(default=50, ge=1, le=10_000)
    ws_queue_size: int = Field(default=200, ge=1, le=100_000)
    # Serve /docs and /openapi.json. Off by default: they would be the only unauthenticated
    # routes besides /health and /auth/login.
    enable_docs: bool = False
    # Addresses and networks the SOC must never ask a sensor to block: the gateways, DNS servers,
    # the SOC host, the sensors and the analysts' machines. REQUIRED for blocking: while it is
    # empty, every block request is refused (503), so a forgotten setting fails closed.
    # From the environment: IDPS_SOC_BLOCK_ALLOWLIST=10.10.1.1,10.10.2.1,192.168.1.0/24
    block_allowlist: Annotated[list[IPvAnyNetwork], NoDecode] = Field(default_factory=list)
    # Attack world map. GeoLite2 City database path (free MaxMind account needed); without it,
    # public addresses can't be placed. geo_demo gives lab (private) addresses made-up,
    # clearly labelled locations for demonstrations. home_* is where the protected site is.
    geoip_db: str | None = None
    geo_demo: bool = False
    home_lat: float | None = Field(default=None, ge=-90, le=90)
    home_lon: float | None = Field(default=None, ge=-180, le=180)
    home_label: str = Field(default="Protected site", max_length=64)
    # SOC assistant (Claude). Needs Anthropic credentials in the API's environment
    # (ANTHROPIC_API_KEY); without them the assistant is switched off and the rest works.
    assistant_model: str = "claude-opus-5-5"
    assistant_effort: str = Field(default="medium", pattern="^(low|medium|high|xhigh|max)$")
    # Cost and abuse limits: messages per user per 10 minutes, and turns per conversation.
    assistant_rate_per_10min: int = Field(default=20, ge=1, le=1000)
    assistant_max_turns: int = Field(default=30, ge=1, le=200)
    # Replies running at once across all users (each holds a model call open).
    assistant_max_concurrent: int = Field(default=4, ge=1, le=100)
    # Browser origins allowed to call the API (the dashboard's dev server by default).
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"])

    @field_validator("jwt_secret")
    @classmethod
    def _secret_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_SECRET_LENGTH:
            raise ValueError(f"IDPS_SOC_JWT_SECRET must be at least {MIN_SECRET_LENGTH} characters")
        return value

    @field_validator("severity_by_class", mode="before")
    @classmethod
    def _normalise_severity_map(cls, value: object) -> object:
        if isinstance(value, dict):
            value = {str(k).strip().casefold(): v for k, v in value.items()}
            bad = {v for v in value.values() if v not in SEVERITIES}
            if bad:
                raise ValueError(f"severities must be one of {SEVERITIES}, got {sorted(bad)}")
        return value

    @field_validator("default_severity")
    @classmethod
    def _default_severity_valid(cls, value: str) -> str:
        if value not in SEVERITIES:
            raise ValueError(f"default_severity must be one of {SEVERITIES}")
        return value

    @field_validator("block_allowlist", mode="before")
    @classmethod
    def _split_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


@lru_cache
def get_settings() -> SocSettings:
    return SocSettings()
