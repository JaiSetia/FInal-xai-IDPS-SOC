"""Sensor status: each sensor reports what it is doing; the dashboard lists it."""

import copy
import ipaddress
import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Request
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    ValidationError,
    model_validator,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser, Sensor
from soc.api.common import audit, plain_text
from soc.api.db import get_db
from soc.api.models import Role, SensorStatus, SensorToken

log = logging.getLogger("soc.api")
router = APIRouter(tags=["sensors"])
_warned_bad_row = False

ONLINE_SECONDS = 120  # a sensor not heard from for this long shows offline
MAX_ALLOWLIST = 100
MAX_SENSORS = 500
_COUNT = Field(ge=0, le=2**53)
MAX_AUDIT_ENTRIES = 20  # allowlist entries named (added / removed) in one audit row
AUDIT_WINDOW_SECONDS = 600.0  # at most one audit row per sensor per field per this long


def _clock() -> float:
    return time.monotonic()  # tests replace this to move the throttle's clock


def _network(value: str) -> str:
    """An allowlist entry must be an IP address or network; stored normalised (10.1.1.1/32)."""
    if "%" in value:
        raise ValueError("zone IDs are not accepted")
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise ValueError("allowlist entries must be IP addresses or networks") from None


Network = Annotated[str, Field(max_length=64), AfterValidator(_network)]
Text = Annotated[str, AfterValidator(plain_text)]  # no control / direction-override characters


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class ModelInfo(StrictModel):
    name: Text = Field(max_length=64)
    checksum_ok: StrictBool


class PolicyInfo(StrictModel):
    confidence_threshold: float = Field(ge=0, le=1)
    min_flows: StrictInt = Field(ge=1, le=1_000_000)
    window_seconds: float = Field(gt=0, le=1e7)
    min_alert_confidence: float = Field(ge=0, le=1)
    block_ttl_seconds: StrictInt = Field(ge=1, le=10_000_000)
    unblock_grace_seconds: StrictInt = Field(ge=0, le=31_536_000)  # = the sensor's own cap
    max_analyst_blocks: StrictInt = Field(ge=1, le=10_000_000)


class HeartbeatInfo(StrictModel):
    enabled: StrictBool
    ok: StrictBool


class Counters(StrictModel):
    flows: StrictInt = _COUNT
    alerts: StrictInt = _COUNT
    blocked: StrictInt = _COUNT
    would_block: StrictInt = _COUNT


_UNIT = {"ge": 0, "le": 1}


class MethodFaithfulness(StrictModel):
    mean_drop: float = Field(ge=-1, le=1)
    # null: random removal changed nothing; negative: deleting the explanation raised confidence
    ratio_to_random: float | None = Field(ge=-1e9, le=1e9)
    label_flip_rate: float = Field(**_UNIT)
    share_flows_beating_random: float = Field(**_UNIT)


class Faithfulness(StrictModel):
    """The model's explanation-faithfulness result (model level, from an offline report)."""

    model: Text = Field(min_length=1, max_length=64)
    model_matches: StrictBool
    # "digest": compared by the bundle's sha256; "name": only the algorithm name (weak match,
    # also what older sensors/reports give)
    model_check: Literal["digest", "name"] | None = None
    flows: StrictInt = Field(ge=1, le=10_000_000)
    top_k: StrictInt = Field(ge=1, le=1_000)
    random_mean_drop: float = Field(ge=-1, le=1)
    methods: dict[Literal["shap", "lime"], MethodFaithfulness] = Field(min_length=1)


class StatusReport(StrictModel):
    """POST /sensor/status. Every field is bounded: a sensor can't make the SOC store a big blob."""

    dry_run: StrictBool
    blocking_enabled: StrictBool
    interface: Text | None = Field(default=None, max_length=64)
    mode: Literal["live", "replay"]
    model: ModelInfo
    policy: PolicyInfo
    allowlist: list[Network] = Field(max_length=MAX_ALLOWLIST)
    # How many entries the sensor really has (the list above is cut at MAX_ALLOWLIST).
    allowlist_total: StrictInt | None = Field(default=None, ge=0, le=10_000_000)
    outbox_pending: StrictInt = Field(ge=0, le=100_000_000)
    shap_p95_ms: float | None = Field(default=None, ge=0, le=1e9)
    heartbeat: HeartbeatInfo
    counters: Counters
    faithfulness: Faithfulness | None = None  # absent from older sensors
    sensor_version: Text | None = Field(default=None, max_length=32)
    sent_at: datetime | None = None

    @model_validator(mode="after")
    def _total_covers_the_list(self):
        if (self.allowlist_total is not None and self.allowlist is not None
                and self.allowlist_total < len(self.allowlist)):
            raise ValueError("allowlist_total is smaller than the allowlist it counts")
        return self


class StatusAck(BaseModel):
    last_seen_at: datetime


class StatusOut(StatusReport):
    """What GET /sensors/status shows. Analysts get it without the allowlist and the block policy
    (together they tell an attacker exactly what to stay under and who to impersonate); both are
    then null. `allowlist_total` stays."""

    policy: PolicyInfo | None = None
    allowlist: list[str] | None = None


class SensorStatusOut(BaseModel):
    sensor_id: int
    name: str
    revoked: bool
    last_seen_at: datetime | None
    online: bool
    status: StatusOut | None


class SensorsStatus(BaseModel):
    redacted: bool  # true for non-admins: soc_allowlist, allowlist and policy are withheld
    soc_allowlist: list[str] | None
    sensors: list[SensorStatusOut]


def _normalised(entry: str) -> str:
    try:
        return _network(entry)
    except ValueError:
        return entry  # an entry that no longer parses stays as it was


# What a change of is worth an audit row. Scalars are logged as [old, new].
SCALAR_FIELDS = ("dry_run", "blocking_enabled", "mode", "model")


def status_changes(old: dict | None, new: dict) -> dict:
    """The audited differences between two status payloads ({} if none; `old` None = first)."""
    if old is None:
        return {}
    changes: dict = {}
    for key in SCALAR_FIELDS:
        if old.get(key) != new.get(key):
            changes[key] = [old.get(key), new.get(key)]
    old_policy, new_policy = old.get("policy") or {}, new.get("policy") or {}
    policy = {k: [old_policy.get(k), new_policy.get(k)]
              for k in sorted(set(old_policy) | set(new_policy))
              if old_policy.get(k) != new_policy.get(k)}
    if policy:
        changes["policy"] = policy
    # Rows stored before entries were normalised hold "10.10.1.1"; the same address is not a change.
    old_list = [_normalised(e) for e in old.get("allowlist") or []]
    new_list = new.get("allowlist") or []
    old_total, new_total = old.get("allowlist_total"), new.get("allowlist_total")
    if set(old_list) != set(new_list) or old_total != new_total:
        added = sorted(set(new_list) - set(old_list))
        removed = sorted(set(old_list) - set(new_list))
        changes["allowlist"] = {
            "count": [len(old_list), len(new_list)], "total": [old_total, new_total],
            "added": added[:MAX_AUDIT_ENTRIES], "removed": removed[:MAX_AUDIT_ENTRIES],
            "more": max(len(added) - MAX_AUDIT_ENTRIES, 0) + max(len(removed) - MAX_AUDIT_ENTRIES, 0)}
    was = (old.get("faithfulness") or {}).get("model_matches")
    now = (new.get("faithfulness") or {}).get("model_matches")
    if was != now:
        changes["faithfulness.model_matches"] = [was, now]
    return changes


FIELD_KEYS = {"dry_run": ("dry_run",), "blocking_enabled": ("blocking_enabled",),
              "mode": ("mode",), "model": ("model",), "policy": ("policy",),
              "allowlist": ("allowlist", "allowlist_total")}


class SensorAuditState:
    """What was last written to the audit log per sensor, so a flapping setting cannot flood it.

    Per (sensor, field): at most one row per AUDIT_WINDOW_SECONDS. A change inside the window is
    not lost: the baseline (the last AUDITED value) stays, so the first post after the window
    compares against it and logs one row old -> latest, with `folded` saying how many changes it
    absorbed. In memory (the API is one process); after a restart the stored status is the
    baseline."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.baseline: dict[int, dict] = {}
        self.last_at: dict[tuple[int, str], float] = {}
        self.folded: dict[tuple[int, str], int] = {}


def audit_details(state: SensorAuditState, sensor_id: int, previous: dict, new: dict,
                  now: float) -> dict | None:
    """The details of the audit row to write for this report, or None (nothing changed, or
    everything that changed is inside its window)."""
    with state.lock:
        baseline = state.baseline.get(sensor_id)
        baseline = copy.deepcopy(previous if baseline is None else baseline)
        vs_baseline = status_changes(baseline, new)
        this_post = status_changes(previous, new)  # real changes since the previous report
        emitted: dict = {}
        folded: dict = {}
        for field, change in vs_baseline.items():
            key = (sensor_id, field)
            last = state.last_at.get(key)
            if last is None or now - last >= AUDIT_WINDOW_SECONDS:
                emitted[field] = change
                state.last_at[key] = now
                if n := state.folded.pop(key, 0):
                    folded[field] = n
                if field == "faithfulness.model_matches":
                    baseline["faithfulness"] = {
                        "model_matches": (new.get("faithfulness") or {}).get("model_matches")}
                else:
                    for k in FIELD_KEYS[field]:
                        baseline[k] = copy.deepcopy(new.get(k))
        for field in this_post:  # a change of this post that is not written now is folded
            if field not in emitted:
                key = (sensor_id, field)
                state.folded[key] = state.folded.get(key, 0) + 1
        state.baseline[sensor_id] = baseline
    if not emitted:
        return None
    return {"changed": emitted, **({"folded": folded} if folded else {})}


@router.post("/sensor/status", response_model=StatusAck)
def post_status(report: StatusReport, sensor: Sensor, request: Request,
                db: Annotated[Session, Depends(get_db)]):
    """Overwrite this sensor's status. `last_seen_at` is the server's clock, not the sensor's.
    Audited only on the first report and when something that matters changed (mode, policy,
    allowlist, model ...), at most once per field per AUDIT_WINDOW_SECONDS, not on every 30 s post."""
    audit_state: SensorAuditState = request.app.state.sensor_audit
    now = datetime.now(UTC)
    payload = report.model_dump(mode="json")
    for attempt in (1, 2):
        row = db.get(SensorStatus, sensor.id)
        target = f"sensor:{sensor.name}"
        if row is None:
            db.add(SensorStatus(sensor_id=sensor.id, payload=payload, last_seen_at=now))
            with audit_state.lock:  # the first report is the baseline (and is always logged)
                audit_state.baseline[sensor.id] = copy.deepcopy(payload)
            audit(db, sensor, "sensor_status_first", target,
                  {"mode": payload["mode"], "dry_run": payload["dry_run"],
                   "blocking_enabled": payload["blocking_enabled"]})
        else:
            details = audit_details(audit_state, sensor.id, row.payload, payload, _clock())
            if details:
                audit(db, sensor, "sensor_status_changed", target, details)
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
    """Every sensor with its latest report. Never includes tokens or their hashes. Non-admins get
    `redacted: true`: no SOC allowlist, and no allowlist or policy in a sensor's status; a revoked
    sensor's status is withheld from them altogether."""
    global _warned_bad_row
    admin = user.role == Role.ADMIN
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
                parsed = StatusOut.model_validate(status.payload)
                if not admin:
                    parsed = None if token.revoked else parsed.model_copy(
                        update={"policy": None, "allowlist": None})
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
    allowlist = ([str(net) for net in request.app.state.settings.block_allowlist]
                 if admin else None)
    return SensorsStatus(redacted=not admin, soc_allowlist=allowlist, sensors=out)
