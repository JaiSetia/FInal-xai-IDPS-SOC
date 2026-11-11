"""Blocks reported by sensors, and the list of blocks for the dashboard."""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser, Sensor
from soc.api.common import Cursor, IPAddress, Limit, Page, audit, paginate
from soc.api.db import get_db
from soc.api.models import Alert, Block, BlockSource

router = APIRouter(tags=["blocks"])

MAX_EVENTS = 100
MAX_TTL_SECONDS = 30 * 24 * 3600


def active_clause(now: datetime):
    return and_(Block.unblocked_at.is_(None),
                or_(Block.expires_at.is_(None), Block.expires_at > now))


class BlockEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: Literal["blocked", "unblocked"]
    ip: IPAddress
    reason: str = Field(default="", max_length=500)
    ttl_seconds: int | None = Field(default=None, ge=1, le=MAX_TTL_SECONDS)
    expires_at: datetime | None = None
    alert_id: int | None = Field(default=None, ge=1, le=2**62)
    source: BlockSource = BlockSource.AUTO

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.ttl_seconds is not None and self.expires_at is not None:
            raise ValueError("give ttl_seconds or expires_at, not both")
        if self.event == "unblocked" and (self.ttl_seconds or self.expires_at):
            raise ValueError("an unblock event has no ttl_seconds or expires_at")
        return self


class BlockBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[BlockEvent] = Field(min_length=1, max_length=MAX_EVENTS)


class BlockIngestResult(BaseModel):
    blocked: int
    unblocked: int  # active blocks that were closed (0 if the IP wasn't blocked)


class BlockOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sensor_id: int
    ip: str
    reason: str
    source: BlockSource
    alert_id: int | None
    blocked_at: datetime
    expires_at: datetime | None
    unblocked_at: datetime | None
    active: bool = False


def block_out(block: Block, now: datetime) -> BlockOut:
    out = BlockOut.model_validate(block)
    out.active = block.unblocked_at is None and (block.expires_at is None
                                                 or block.expires_at > now)
    return out


@router.post("/ingest/blocks", response_model=BlockIngestResult, status_code=201)
def ingest_blocks(batch: BlockBatch, sensor: Sensor, db: Annotated[Session, Depends(get_db)]):
    now = datetime.now(UTC)
    alert_ids = {e.alert_id for e in batch.events if e.alert_id is not None}
    if alert_ids:
        found = set(db.scalars(select(Alert.id).where(Alert.id.in_(alert_ids))))
        if alert_ids - found:
            raise HTTPException(422, f"unknown alert_id(s): {sorted(alert_ids - found)}")
    blocked = unblocked = 0
    for ev in batch.events:
        active = list(db.scalars(select(Block).where(
            Block.sensor_id == sensor.id, Block.ip == ev.ip, active_clause(now))))
        if ev.event == "blocked":
            expires = ev.expires_at or (now + timedelta(seconds=ev.ttl_seconds)
                                        if ev.ttl_seconds else None)
            if expires is not None and expires <= now:
                raise HTTPException(422, "expires_at is in the past")
            if active:  # already blocked: just refresh the existing record
                active[0].expires_at, active[0].reason = expires, ev.reason
            else:
                db.add(Block(sensor_id=sensor.id, ip=ev.ip, reason=ev.reason, source=ev.source,
                             alert_id=ev.alert_id, blocked_at=now, expires_at=expires))
            blocked += 1
        else:
            for b in active:
                b.unblocked_at = now
            unblocked += len(active)
    audit(db, sensor, "ingest_blocks", f"sensor:{sensor.name}",
          {"events": len(batch.events), "blocked": blocked, "unblocked": unblocked})
    db.commit()
    return BlockIngestResult(blocked=blocked, unblocked=unblocked)


@router.get("/blocks", response_model=Page[BlockOut])
def list_blocks(user: AnyUser, db: Annotated[Session, Depends(get_db)],
                active: Annotated[bool | None, Query()] = None,
                ip: Annotated[IPAddress | None, Query()] = None,
                limit: Limit = 50, cursor: Cursor = None):
    now = datetime.now(UTC)
    query = select(Block).order_by(Block.id.desc()).limit(limit + 1)
    if active is True:
        query = query.where(active_clause(now))
    elif active is False:
        query = query.where(~active_clause(now))
    if ip:
        query = query.where(Block.ip == ip)
    if cursor:
        query = query.where(Block.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[BlockOut](items=[block_out(b, now) for b in rows], next_cursor=next_cursor)
