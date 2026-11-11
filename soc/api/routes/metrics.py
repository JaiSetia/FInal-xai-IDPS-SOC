"""Dashboard metrics and the topology data for the map."""

from datetime import UTC, datetime, timedelta
from typing import Annotated

import numpy as np
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from soc.api.auth import AnyUser
from soc.api.db import get_db
from soc.api.models import SEVERITY_RANK, Alert, AlertStatus, Block, Severity
from soc.api.routes.blocks import active_clause

router = APIRouter(tags=["metrics"])

MAX_HOURS = 24 * 30
MAX_TOPOLOGY_EDGES = 1000
# Bounded work per request, however many alerts arrive (e.g. during a flood):
MAX_CLASSES = 25  # classes listed in by_class; the rest are summed as "(other)"
LATENCY_SAMPLE = 20_000  # latency percentiles use the newest alerts only
Hours = Annotated[int, Query(ge=1, le=MAX_HOURS)]


class Bucket(BaseModel):
    start: datetime
    count: int


class TopSource(BaseModel):
    ip: str
    count: int


class LatencyStats(BaseModel):
    p50_ms: float | None
    p95_ms: float | None
    samples: int


class MetricsSummary(BaseModel):
    hours: int
    since: datetime
    bucket_seconds: int
    alerts_total: int
    alerts_per_bucket: list[Bucket]
    by_class: dict[str, int]
    by_severity: dict[str, int]
    top_sources: list[TopSource]
    triaged: int
    false_positives: int
    false_positive_rate: float | None
    detection_latency: LatencyStats
    active_blocks: int


@router.get("/metrics/summary", response_model=MetricsSummary)
def metrics_summary(user: AnyUser, db: Annotated[Session, Depends(get_db)], hours: Hours = 24):
    now = datetime.now(UTC)
    since = now - timedelta(hours=hours)
    in_window = Alert.received_at >= since

    def grouped(column):
        rows = db.execute(select(column, func.count()).where(in_window).group_by(column))
        return {str(getattr(k, "value", k)): n for k, n in rows}

    by_class_all = sorted(grouped(Alert.predicted_class).items(), key=lambda kv: (-kv[1], kv[0]))
    by_class = dict(by_class_all[:MAX_CLASSES])
    if len(by_class_all) > MAX_CLASSES:
        by_class["(other)"] = sum(n for _, n in by_class_all[MAX_CLASSES:])
    by_severity = {s.value: 0 for s in Severity} | grouped(Alert.severity)
    by_status = grouped(Alert.status)
    top = db.execute(select(Alert.src_ip, func.count().label("n")).where(in_window)
                     .group_by(Alert.src_ip).order_by(func.count().desc(), Alert.src_ip).limit(10))

    # Hourly buckets up to 3 days, daily beyond, aligned to the bucket size. One indexed
    # COUNT per bucket (at most 72 + 30), so the cost doesn't grow with the number of alerts.
    step = 3600 if hours <= 72 else 86400
    first = int(since.timestamp()) // step * step
    series = []
    for t in range(first, int(now.timestamp()) + 1, step):
        lo, hi = datetime.fromtimestamp(t, UTC), datetime.fromtimestamp(t + step, UTC)
        n = db.scalar(select(func.count()).select_from(Alert).where(
            in_window, Alert.received_at >= lo, Alert.received_at < hi)) or 0
        series.append(Bucket(start=lo, count=n))
    # Detection latency from a bounded sample of the newest alerts in the window.
    latencies = [max(received.timestamp() * 1000 - end_ms, 0.0)  # clock skew -> 0
                 for received, end_ms in db.execute(
                     select(Alert.received_at, Alert.end_ms).where(in_window)
                     .order_by(Alert.id.desc()).limit(LATENCY_SAMPLE))]

    triaged = sum(n for s, n in by_status.items() if s != AlertStatus.NEW.value)
    fp = by_status.get(AlertStatus.FALSE_POSITIVE.value, 0)
    p50, p95 = (float(np.percentile(latencies, q)) for q in (50, 95)) if latencies else (None,) * 2
    return MetricsSummary(
        hours=hours, since=since, bucket_seconds=step, alerts_total=sum(by_class.values()),
        alerts_per_bucket=series, by_class=by_class, by_severity=by_severity,
        top_sources=[TopSource(ip=ip, count=n) for ip, n in top],
        triaged=triaged, false_positives=fp,
        false_positive_rate=fp / triaged if triaged else None,
        detection_latency=LatencyStats(p50_ms=p50, p95_ms=p95, samples=len(latencies)),
        active_blocks=db.scalar(select(func.count()).select_from(Block)
                                .where(active_clause(now))) or 0)


# --- topology ---------------------------------------------------------------------------

class TopologyNode(BaseModel):
    ip: str
    alert_count: int
    max_severity: Severity


class TopologyEdge(BaseModel):
    src: str
    dst: str
    count: int
    max_severity: Severity


class Topology(BaseModel):
    hours: int
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


def _max_sev(a: Severity | None, b: Severity) -> Severity:
    return b if a is None or SEVERITY_RANK[b] > SEVERITY_RANK[a] else a


@router.get("/topology", response_model=Topology)
def topology(user: AnyUser, db: Annotated[Session, Depends(get_db)], hours: Hours = 1):
    since = datetime.now(UTC) - timedelta(hours=hours)
    # Aggregated and cut in SQL, so a flood of distinct pairs doesn't load into memory.
    rank = case(*[(Alert.severity == sev, r) for sev, r in SEVERITY_RANK.items()], else_=0)
    rows = db.execute(
        select(Alert.src_ip, Alert.dst_ip, func.count().label("n"), func.max(rank))
        .where(Alert.received_at >= since).group_by(Alert.src_ip, Alert.dst_ip)
        .order_by(func.count().desc(), Alert.src_ip, Alert.dst_ip).limit(MAX_TOPOLOGY_EDGES))
    by_rank = {r: sev for sev, r in SEVERITY_RANK.items()}
    top = [((src, dst), (n, by_rank[int(r or 0)])) for src, dst, n, r in rows]
    nodes: dict[str, list] = {}
    for (src, dst), (n, sev) in top:
        for ip in {src, dst}:  # a self-edge counts once
            node = nodes.setdefault(ip, [0, None])
            node[0] += n
            node[1] = _max_sev(node[1], sev)
    return Topology(
        hours=hours,
        nodes=[TopologyNode(ip=ip, alert_count=n, max_severity=s)
               for ip, (n, s) in sorted(nodes.items(), key=lambda kv: (-kv[1][0], kv[0]))],
        edges=[TopologyEdge(src=s, dst=d, count=n, max_severity=sev)
               for (s, d), (n, sev) in top])
