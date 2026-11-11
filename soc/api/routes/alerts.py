"""Alert ingest (sensors) and alert triage (analysts)."""

import json
from datetime import datetime
from typing import Annotated, Any, Self

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser, Sensor
from soc.api.common import (
    Cursor,
    IPAddress,
    Limit,
    Page,
    audit,
    derive_severity,
    get_or_404,
    paginate,
)
from soc.api.db import get_db
from soc.api.models import Alert, AlertStatus, Severity

router = APIRouter(tags=["alerts"])

MAX_BATCH = 500
MAX_EXPLANATION_BYTES = 16 * 1024
MAX_MS = 4_102_444_800_000  # year 2100; catches seconds/microseconds mix-ups


class FeatureContribution(BaseModel):
    model_config = ConfigDict(extra="ignore")

    feature: str = Field(min_length=1, max_length=64)
    value: float | None = Field(default=None, allow_inf_nan=False)
    contribution: float | None = Field(default=None, allow_inf_nan=False)


class ExplanationIn(BaseModel):
    """The idps.explain record format. Typed here so the dashboard can trust its shape;
    unknown keys are dropped."""

    model_config = ConfigDict(extra="ignore")

    method: str | None = Field(default=None, max_length=16)
    predicted_class: str | None = Field(default=None, max_length=64)
    confidence: float | None = Field(default=None, allow_inf_nan=False)
    base_value: float | None = Field(default=None, allow_inf_nan=False)
    output_space: str | None = Field(default=None, max_length=32)
    top_features: list[FeatureContribution] = Field(default_factory=list, max_length=50)


class AlertIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src_ip: IPAddress
    src_port: StrictInt = Field(ge=0, le=65535)
    dst_ip: IPAddress
    dst_port: StrictInt = Field(ge=0, le=65535)
    protocol: StrictInt = Field(ge=0, le=255)
    start_ms: StrictInt = Field(ge=0, le=MAX_MS)
    end_ms: StrictInt = Field(ge=0, le=MAX_MS)
    predicted_class: str = Field(min_length=1, max_length=64)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    anomaly_score: float | None = Field(default=None, allow_inf_nan=False)
    explanation: ExplanationIn = Field(default_factory=ExplanationIn)

    @field_validator("predicted_class")
    @classmethod
    def _strip(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("predicted_class must not be blank")
        return value

    @field_validator("explanation", mode="before")
    @classmethod
    def _explanation_size(cls, value: object) -> object:
        if not isinstance(value, dict):
            raise ValueError("explanation must be a JSON object")  # noqa: TRY004  pydantic needs ValueError
        try:
            size = len(json.dumps(value, separators=(",", ":"), allow_nan=False).encode())
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError("explanation must be plain JSON") from exc
        if size > MAX_EXPLANATION_BYTES:
            raise ValueError(f"explanation is {size} bytes; the limit is {MAX_EXPLANATION_BYTES}")
        return value

    @model_validator(mode="after")
    def _start_before_end(self) -> Self:
        if self.start_ms > self.end_ms:
            raise ValueError("start_ms must not be after end_ms")
        return self


class AlertBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alerts: list[AlertIn] = Field(min_length=1, max_length=MAX_BATCH)


class IngestResult(BaseModel):
    accepted: int
    skipped_benign: int
    ids: list[int]


class AlertOut(BaseModel):
    """An alert without its explanation (lists and the live feed); see AlertDetail."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    sensor_id: int
    received_at: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    start_ms: int
    end_ms: int
    predicted_class: str
    confidence: float
    anomaly_score: float | None
    severity: Severity
    status: AlertStatus
    case_id: int | None


class AlertDetail(AlertOut):
    explanation: dict[str, Any]


class AlertPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AlertStatus


@router.post("/ingest/alerts", response_model=IngestResult, status_code=201)
def ingest_alerts(batch: AlertBatch, sensor: Sensor, request: Request,
                  db: Annotated[Session, Depends(get_db)]):
    settings = request.app.state.settings
    rows, skipped = [], 0
    for item in batch.alerts:
        if item.predicted_class.casefold() == "benign":
            skipped += 1  # BENIGN is never stored
            continue
        rows.append(Alert(
            sensor_id=sensor.id,
            severity=derive_severity(settings, item.predicted_class, item.confidence),
            **item.model_dump()))
    db.add_all(rows)
    audit(db, sensor, "ingest_alerts", f"sensor:{sensor.name}",
          {"received": len(batch.alerts), "stored": len(rows), "skipped_benign": skipped})
    db.commit()
    request.app.state.broadcaster.publish_many(
        [AlertOut.model_validate(r).model_dump(mode="json") for r in rows])
    return IngestResult(accepted=len(rows), skipped_benign=skipped, ids=[r.id for r in rows])


@router.get("/alerts", response_model=Page[AlertOut])
def list_alerts(
    user: AnyUser, db: Annotated[Session, Depends(get_db)],
    severity: Annotated[list[Severity] | None, Query(max_length=4)] = None,
    predicted_class: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    ip: Annotated[IPAddress | None, Query(description="matches source or destination")] = None,
    status: Annotated[AlertStatus | None, Query()] = None,
    since: datetime | None = None, until: datetime | None = None,
    limit: Limit = 50, cursor: Cursor = None,
):
    for moment in (since, until):
        if moment is not None and moment.tzinfo is None:
            raise HTTPException(422, "since/until must include a timezone, e.g. 2026-01-01T00:00:00Z")
    query = select(Alert).order_by(Alert.id.desc()).limit(limit + 1)
    if severity:
        query = query.where(Alert.severity.in_(severity))
    if predicted_class:
        query = query.where(Alert.predicted_class == predicted_class)
    if ip:
        query = query.where(or_(Alert.src_ip == ip, Alert.dst_ip == ip))
    if status:
        query = query.where(Alert.status == status)
    if since:
        query = query.where(Alert.received_at >= since)
    if until:
        query = query.where(Alert.received_at <= until)
    if cursor:
        query = query.where(Alert.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[AlertOut](items=[AlertOut.model_validate(r) for r in rows],
                          next_cursor=next_cursor)


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, user: AnyUser, db: Annotated[Session, Depends(get_db)]):
    return AlertDetail.model_validate(get_or_404(db, Alert, alert_id, "alert"))


@router.patch("/alerts/{alert_id}", response_model=AlertDetail)
def patch_alert(alert_id: int, body: AlertPatch, user: AnyUser,
                db: Annotated[Session, Depends(get_db)]):
    alert = get_or_404(db, Alert, alert_id, "alert")
    old = alert.status
    alert.status = body.status
    audit(db, user, "alert_status", f"alert:{alert.id}",
          {"from": old.value, "to": body.status.value})
    db.commit()
    return AlertDetail.model_validate(alert)
