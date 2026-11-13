"""Database tables. Auth tables are here; the SOC data tables follow below them."""

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from soc.api.db import Base, UtcDateTime


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    ANALYST = "analyst"  # triage alerts, confirm or reject actions, manage cases
    ADMIN = "admin"  # everything an analyst can do, plus users, sensors and policy


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=False, length=16))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Bumped on password change or disable: every token issued before it stops working.
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class SensorToken(Base):
    """API token a sensor uses to send alerts. Only a SHA-256 of the token is stored."""

    __tablename__ = "sensor_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


# --- SOC data tables ---------------------------------------------------------------------

class Severity(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


class AlertStatus(enum.StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class CaseStatus(enum.StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class ActionKind(enum.StrEnum):
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"


class ActionStatus(enum.StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    EXECUTED = "executed"
    FAILED = "failed"


class BlockSource(enum.StrEnum):
    AUTO = "auto"
    ANALYST = "analyst"


def _enum(cls: type[enum.Enum]) -> Enum:
    return Enum(cls, native_enum=False, length=24, values_callable=lambda e: [m.value for m in e])


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    status: Mapped[CaseStatus] = mapped_column(_enum(CaseStatus), default=CaseStatus.OPEN,
                                               index=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class CaseNote(Base):
    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(ForeignKey("cases.id"), index=True)
    author_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class Alert(Base):
    """One detection reported by a sensor. BENIGN flows are never stored."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_src_ip", "src_ip"), Index("ix_alerts_dst_ip", "dst_ip"),
        # The class-by-day heatmap (metrics.class_per_day) scans a week of alerts by these.
        Index("ix_alerts_received_class_anomaly", "received_at", "predicted_class",
              "anomaly_score"))

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    received_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    # Flow identity (idps.features.ID_COLUMNS); start_ms and end_ms are epoch milliseconds.
    src_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[int] = mapped_column(Integer)
    start_ms: Mapped[int] = mapped_column(BigInteger)
    end_ms: Mapped[int] = mapped_column(BigInteger)
    predicted_class: Mapped[str] = mapped_column(String(64), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[Severity] = mapped_column(_enum(Severity), index=True)
    explanation: Mapped[dict] = mapped_column(JSON)
    status: Mapped[AlertStatus] = mapped_column(_enum(AlertStatus), default=AlertStatus.NEW,
                                                index=True)
    case_id: Mapped[int | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)


class Block(Base):
    """An IP block reported by a sensor. Active until unblocked or past expires_at."""

    __tablename__ = "blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[BlockSource] = mapped_column(_enum(BlockSource))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    unblocked_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


class Action(Base):
    """An action requested of a sensor. Assistant proposals start pending; analysts confirm."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[ActionKind] = mapped_column(_enum(ActionKind))
    params: Mapped[dict] = mapped_column(JSON)
    reason: Mapped[str] = mapped_column(String(500), default="")
    proposed_by: Mapped[str] = mapped_column(String(16))  # "user" or "assistant"
    proposed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    status: Mapped[ActionStatus] = mapped_column(_enum(ActionStatus), index=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    decided_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)


class AuditEntry(Base):
    """Who did what. One row per mutating request (ingest: one per batch)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    actor_type: Mapped[str] = mapped_column(String(16))  # "user" or "sensor"
    actor_name: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(128), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class AssistantConversation(Base):
    """One analyst's chat with the SOC assistant. `messages` is the exact Messages API history
    (thinking and tool blocks included), sent back unchanged on the next turn."""

    __tablename__ = "assistant_conversations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    title: Mapped[str] = mapped_column(String(120), default="")
    messages: Mapped[list] = mapped_column(JSON, default=list)
    user_turns: Mapped[int] = mapped_column(Integer, default=0)
    # Set while a reply is running, so a second message can't race it (cleared when saved).
    busy_since: Mapped[datetime | None] = mapped_column(UtcDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)


class WouldBlock(Base):
    """A block a dry-run sensor decided on but did not apply. Kept apart from `blocks` on purpose:
    nothing here is in the firewall, so it never counts as an active block."""

    __tablename__ = "would_blocks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    reason: Mapped[str] = mapped_column(String(500), default="")
    source: Mapped[BlockSource] = mapped_column(_enum(BlockSource))
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow, index=True)
    ttl_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)


class SensorStatus(Base):
    """The latest status report of each sensor (one row per sensor, overwritten). `last_seen_at`
    is set by the server; the sensor's own clock (`sent_at` inside the payload) is not trusted."""

    __tablename__ = "sensor_status"

    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensor_tokens.id"), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON)
    last_seen_at: Mapped[datetime] = mapped_column(UtcDateTime, default=utcnow)
