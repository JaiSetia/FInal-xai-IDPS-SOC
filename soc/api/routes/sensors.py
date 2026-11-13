"""Sensor status: each sensor reports what it is doing; the dashboard lists it."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser, Sensor
from soc.api.db import get_db
from soc.api.models import SensorStatus, SensorToken

log = logging.getLogger("soc.api")
router = APIRouter(tags=["sensors"])
_warned_bad_row = False

ONLINE_SECONDS = 120  # a sensor not heard from for this long shows offline
MAX_ALLOWLIST = 100
MAX_SENSORS = 500
_COUNT = Field(ge=0, le=2**53)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ModelInfo(StrictModel):
    name: str = Field(max_length=64)
    checksum_ok: bool


class PolicyInfo(StrictModel):
    confidence_threshold: float = Field(ge=0, le=1)
    min_flows: int = Field(ge=1, le=1_000_000)
    window_seconds: float = Field(gt=0, le=1e7)
    min_alert_confidence: float = Field(ge=0, le=1)
    block_ttl_seconds: int = Field(ge=1, le=10_000_000)
    unblock_grace_seconds: int = Field(ge=0, le=31_536_000)  # = the sensor's own cap
    max_analyst_blocks: int = Field(ge=1, le=10_000_000)


class HeartbeatInfo(StrictModel):
    enabled: bool
    ok: bool


class Counters(StrictModel):
    flows: int = _COUNT
    alerts: int = _COUNT
    blocked: int = _COUNT
    would_block: int = _COUNT


_UNIT = {"ge": 0, "le": 1}


class MethodFaithfulness(StrictModel):
    mean_drop: float = Field(ge=-1, le=1)
    # null: random removal changed nothing; negative: deleting the explanation raised confidence
    ratio_to_random: float | None = Field(ge=-1e9, le=1e9)
    label_flip_rate: float = Field(**_UNIT)
    share_flows_beating_random: float = Field(**_UNIT)


class Faithfulness(StrictModel):
    """The model's explanation-faithfulness result (model level, from an offline report)."""

    model: str = Field(min_length=1, max_length=64)
    model_matches: bool
    # "digest": compared by the bundle's sha256; "name": only the algorithm name (weak match,
    # also what older sensors/reports give)
    model_check: Literal["digest", "name"] | None = None
    flows: int = Field(ge=1, le=10_000_000)
    top_k: int = Field(ge=1, le=1_000)
    random_mean_drop: float = Field(ge=-1, le=1)
    methods: dict[Literal["shap", "lime"], MethodFaithfulness] = Field(min_length=1)


class StatusReport(StrictModel):
    """POST /sensor/status. Every field is bounded: a sensor can't make the SOC store a big blob."""

    dry_run: bool
    blocking_enabled: bool
    interface: str | None = Field(default=None, max_length=64)
    mode: Literal["live", "replay"]
    model: ModelInfo
    policy: PolicyInfo
    allowlist: list[Annotated[str, Field(max_length=64)]] = Field(max_length=MAX_ALLOWLIST)
    # How many entries the sensor really has (the list above is cut at MAX_ALLOWLIST).
    allowlist_total: int | None = Field(default=None, ge=0, le=10_000_000)
    outbox_pending: int = Field(ge=0, le=100_000_000)
    shap_p95_ms: float | None = Field(default=None, ge=0, le=1e9)
    heartbeat: HeartbeatInfo
    counters: Counters
    faithfulness: Faithfulness | None = None  # absent from older sensors
    sensor_version: str | None = Field(default=None, max_length=32)
    sent_at: datetime | None = None


class StatusAck(BaseModel):
    last_seen_at: datetime


class SensorStatusOut(BaseModel):
    sensor_id: int
    name: str
    revoked: bool
    last_seen_at: datetime | None
    online: bool
    status: StatusReport | None


class SensorsStatus(BaseModel):
    soc_allowlist: list[str]
    sensors: list[SensorStatusOut]


@router.post("/sensor/status", response_model=StatusAck)
def post_status(report: StatusReport, sensor: Sensor, db: Annotated[Session, Depends(get_db)]):
    """Overwrite this sensor's status. `last_seen_at` is the server's clock, not the sensor's.
    Not audited: it arrives every 30 s and would bury the audit log."""
    now = datetime.now(UTC)
    payload = report.model_dump(mode="json")
    for attempt in (1, 2):
        row = db.get(SensorStatus, sensor.id)
        if row is None:
            db.add(SensorStatus(sensor_id=sensor.id, payload=payload, last_seen_at=now))
        else:
            row.payload, row.last_seen_at = payload, now
        try:
            db.commit()
            break
        except IntegrityError:  # two first reports at once: the other won, update its row
            db.rollback()
            if attempt == 2:
                raise
    return StatusAck(last_seen_at=now)


@router.get("/sensors/status", response_model=SensorsStatus)
def sensors_status(user: AnyUser, request: Request, db: Annotated[Session, Depends(get_db)]):
    """Every sensor with its latest report. Never includes tokens or their hashes."""
    global _warned_bad_row
    now = datetime.now(UTC)
    rows = db.execute(
        select(SensorToken, SensorStatus)
        .outerjoin(SensorStatus, SensorStatus.sensor_id == SensorToken.id)
        .order_by(SensorToken.id).limit(MAX_SENSORS))
    out = []
    for token, status in rows:
        parsed = None
        if status is not None:
            try:
                parsed = StatusReport.model_validate(status.payload)
            except ValidationError:  # a row written under an older schema: show it as unknown
                if not _warned_bad_row:
                    _warned_bad_row = True
                    log.warning("the stored status of sensor %d no longer validates; showing "
                                "none until it reports again", token.id)
        seen = status.last_seen_at if status else None
        out.append(SensorStatusOut(
            sensor_id=token.id, name=token.name, revoked=token.revoked, last_seen_at=seen,
            online=bool(seen and not token.revoked
                        and now - seen <= timedelta(seconds=ONLINE_SECONDS)),
            status=parsed))
    allowlist = [str(net) for net in request.app.state.settings.block_allowlist]
    return SensorsStatus(soc_allowlist=allowlist, sensors=out)
