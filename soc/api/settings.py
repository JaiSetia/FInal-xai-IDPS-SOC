"""SOC API settings, overridable with IDPS_SOC_* environment variables."""

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, IPvAnyNetwork, SecretStr, field_validator, model_validator
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
    # Families of rule (Suricata) alerts, see idps/rules/eve.py; "Rule match" gets default_severity.
    "scan": "low", "malware": "high", "exploit": "high", "policy": "low",
}


# Integration secrets can come from a file instead of the environment: IDPS_SOC_<NAME>_FILE=path
# (Docker/Kubernetes secrets). Blank values (docker compose passes "" for an unset ${VAR:-}) mean
# "not set" for every integration setting.
SECRET_FIELDS = ("webhook_url", "webhook_secret", "slack_webhook_url", "smtp_password",
                 "abuseipdb_key")
INTEGRATION_PREFIXES = ("notify_", "webhook_", "slack_", "smtp_", "email_", "syslog_",
                        "abuseipdb_")
_EMAIL = re.compile(r"^[^@\s<>,;\"]+@[^@\s<>,;\"]+$")


class SocSettings(BaseSettings):
    # hide_input_in_errors: a rejected value (an address list, a URL, a secret) is never echoed
    # into the validation error, which ends up in logs.
    model_config = SettingsConfigDict(env_prefix="IDPS_SOC_", hide_input_in_errors=True)

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
    # Dry-run "would block" records older than this are deleted (see routes/blocks.py). Real
    # blocks are never pruned.
    would_block_retention_days: int = Field(default=7, ge=1, le=365)
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

    # --- Integrations (docs/soc.md, "Integrations") -----------------------------------------
    # Every channel is optional and configured ONLY here (environment or *_FILE secret files),
    # never through the API; the API never returns or logs these values.
    # Base address of the dashboard, for links to an alert in notifications (blank: no link).
    public_url: str | None = None
    notify_enabled: bool = True  # kill switch for every channel
    # Notify for new alerts at or above this severity (a channel's own *_MIN_SEVERITY overrides).
    notify_min_severity: str = "high"
    # DEV/LAB ONLY. Webhook destinations must be https and public; these let a lab test use a
    # local receiver. (Slack and webhook URLs go through the same check.)
    notify_allow_private: bool = False
    notify_allow_http: bool = False
    notify_queue_size: int = Field(default=500, ge=1, le=100_000)  # per channel
    notify_max_attempts: int = Field(default=3, ge=1, le=6)
    notify_backoff_seconds: float = Field(default=1.0, ge=0, le=60)  # doubles each retry
    notify_rate_per_minute: int = Field(default=20, ge=1, le=10_000)  # per channel, then a digest
    notify_dedupe_seconds: int = Field(default=300, ge=0, le=86_400)  # 0 = off
    notify_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    # Generic webhook: JSON POST, optional HMAC-SHA256 of the body in X-IDPS-Signature.
    webhook_url: SecretStr | None = None
    webhook_secret: SecretStr | None = None
    webhook_min_severity: str | None = None
    webhook_include_rules: bool = True
    # Slack incoming webhook.
    slack_webhook_url: SecretStr | None = None
    slack_min_severity: str | None = None
    slack_include_rules: bool = True
    # Email over SMTP. smtp_security "none" is for a local test receiver only.
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)  # 465 for ssl, else 587
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_to: Annotated[list[str], NoDecode] = Field(default_factory=list)
    email_min_severity: str | None = None
    email_include_rules: bool = True
    # Syslog/CEF export for a SIEM. Every alert by default (low and up), no dedupe, no rate limit
    # (a SIEM wants the whole stream); blocks are sent too.
    syslog_host: str | None = None
    syslog_port: int = Field(default=514, ge=1, le=65535)
    syslog_protocol: Literal["udp", "tcp", "tls"] = "udp"
    syslog_ca_file: str | None = None  # TLS: CA that signed the receiver's certificate
    syslog_min_severity: str = "low"
    syslog_include_rules: bool = True
    syslog_include_blocks: bool = True
    syslog_idle_seconds: float = Field(default=60, gt=0, le=3600)  # reconnect a TCP/TLS link idle this long
    syslog_rate_per_minute: int = Field(default=0, ge=0, le=1_000_000)  # 0 = unlimited
    # AbuseIPDB reputation of an alert's source address (looked up only when an analyst opens
    # it). This sends that public IP to a third party; see docs/soc.md.
    abuseipdb_key: SecretStr | None = None
    abuseipdb_cache_hours: float = Field(default=24, gt=0, le=24 * 30)
    abuseipdb_timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    abuseipdb_max_per_minute: int = Field(default=30, ge=1, le=10_000)  # uncached lookups
    abuseipdb_max_per_day: int = Field(default=900, ge=1, le=1_000_000)  # free tier: 1000

    @property
    def smtp_port_effective(self) -> int:
        return self.smtp_port or (465 if self.smtp_security == "ssl" else 587)

    @model_validator(mode="before")
    @classmethod
    def _integration_inputs(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        for key in list(data):
            blank = isinstance(data[key], str) and not data[key].strip()
            if blank and (key.startswith(INTEGRATION_PREFIXES) or key == "public_url"):
                del data[key]  # blank = unset (the default applies)
        for name in SECRET_FIELDS:
            path = os.environ.get(f"IDPS_SOC_{name.upper()}_FILE", "").strip()
            if path and name not in data:
                try:
                    value = Path(path).read_text(encoding="utf-8").strip()
                except OSError as exc:  # never echo the path's content; the path is not secret
                    raise ValueError(f"IDPS_SOC_{name.upper()}_FILE cannot be read") from exc
                if value:
                    data[name] = value
        return data

    @field_validator("notify_min_severity", "syslog_min_severity", "webhook_min_severity",
                     "slack_min_severity", "email_min_severity")
    @classmethod
    def _severity_name(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip().casefold()
            if value not in SEVERITIES:
                raise ValueError(f"severity must be one of {SEVERITIES}")
        return value

    @field_validator("public_url")
    @classmethod
    def _public_url(cls, value: str | None) -> str | None:
        if value is not None:
            value = value.strip().rstrip("/")
            if not re.match(r"^https?://[^\s/?#]+(/[^\s?#]*)?$", value):
                raise ValueError("IDPS_SOC_PUBLIC_URL must be an http(s) address without a query")
        return value

    @field_validator("smtp_to", mode="before")
    @classmethod
    def _split_recipients(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("smtp_to")
    @classmethod
    def _recipients_valid(cls, value: list[str]) -> list[str]:
        if len(value) > 20 or not all(_EMAIL.match(v) for v in value):
            raise ValueError("IDPS_SOC_SMTP_TO must be up to 20 plain email addresses")
        return value

    @field_validator("smtp_from")
    @classmethod
    def _sender_valid(cls, value: str | None) -> str | None:
        if value is not None and not _EMAIL.match(value.strip()):
            raise ValueError("IDPS_SOC_SMTP_FROM must be a plain email address")
        return None if value is None else value.strip()

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

    @field_validator("geoip_db", "home_lat", "home_lon", mode="before")
    @classmethod
    def _blank_is_unset(cls, value: object) -> object:
        # docker compose passes "" for an unset ${VAR:-}: that means "not configured".
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("home_label", mode="before")
    @classmethod
    def _blank_label_is_default(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return "Protected site"
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
