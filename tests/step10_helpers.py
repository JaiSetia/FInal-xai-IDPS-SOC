"""Shared helpers for the step 10 tests (migrations, backup, retention)."""

import json
import os
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from conftest import TEST_SECRET
from sqlalchemy import text
from sqlalchemy.orm import Session

from soc.api.db import Base, init_db, make_engine
from soc.api.models import (
    Action,
    ActionKind,
    ActionStatus,
    Alert,
    AlertStatus,
    AssistantConversation,
    AuditEntry,
    Block,
    BlockSource,
    Case,
    CaseNote,
    CaseStatus,
    ModelVersion,
    Role,
    SensorStatus,
    SensorToken,
    Severity,
    User,
    WouldBlock,
)
from soc.api.settings import SocSettings

PG_URL = os.environ.get("IDPS_TEST_DATABASE_URL", "")
ON_PG = bool(PG_URL) and not PG_URL.startswith("sqlite")
needs_pg = pytest.mark.skipif(not ON_PG, reason="IDPS_TEST_DATABASE_URL is not set")


def wipe_pg() -> None:
    engine = sa.create_engine(PG_URL)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    engine.dispose()


@pytest.fixture
def pg_engine():
    """An empty (wiped) PostgreSQL database."""
    if not ON_PG:
        pytest.skip("IDPS_TEST_DATABASE_URL is not set")
    wipe_pg()
    engine = make_engine(PG_URL)
    yield engine
    engine.dispose()


@pytest.fixture(params=["sqlite", pytest.param("pg", marks=needs_pg)])
def any_engine(request, tmp_path):
    """An empty database, on SQLite and (when configured) PostgreSQL."""
    if request.param == "sqlite":
        engine = make_engine(f"sqlite:///{tmp_path / 'any.db'}")
    else:
        wipe_pg()
        engine = make_engine(PG_URL)
    yield engine
    engine.dispose()


def migrated(engine):
    init_db(engine)
    return engine


def settings(**kw) -> SocSettings:
    return SocSettings(jwt_secret=TEST_SECRET, **kw)


def tables_in(engine) -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def populate(engine, now=None) -> None:
    """Every table with at least one row, including SQL NULL vs JSON null and odd floats."""
    now = now or datetime(2026, 3, 4, 5, 6, 7, 123456, tzinfo=UTC)
    with Session(engine) as db:
        admin = User(username="admin", password_hash="x" * 60, role=Role.ADMIN, created_at=now)
        analyst = User(username="ana", password_hash="y" * 60, role=Role.ANALYST, disabled=True,
                       token_version=3, created_at=now)
        s1 = SensorToken(name="s1", token_hash="a" * 64, created_at=now)
        s2 = SensorToken(name="s2", token_hash="b" * 64, revoked=True, created_at=now)
        db.add_all([admin, analyst, s1, s2])
        db.flush()
        case = Case(title="case é中", status=CaseStatus.INVESTIGATING,
                    created_by_id=admin.id, created_at=now, updated_at=now)
        db.add(case)
        db.flush()
        db.add(CaseNote(case_id=case.id, author_id=analyst.id, text="note \"q\" \n line2",
                        created_at=now))

        def alert(**kw):
            base = dict(sensor_id=s1.id, received_at=now, src_ip="1.2.3.4", src_port=1,
                        dst_ip="5.6.7.8", dst_port=2, protocol=6, start_ms=1_700_000_000_000,
                        end_ms=2**40, predicted_class="DoS", confidence=0.123456789012,
                        severity=Severity.HIGH, explanation={"x": [1.5, None], "u": "ü"},
                        status=AlertStatus.NEW)
            a = Alert(**(base | kw))
            db.add(a)
            return a

        a1 = alert(features={"f1": 1.0, "f2": None}, model_sha256="c" * 64, model_version="v1",
                   true_class="PortScan", anomaly_score=0.5, source="ml", case_id=case.id,
                   rule=None)
        a2 = alert(features=sa.JSON.NULL, rule=sa.JSON.NULL, source="rule")  # JSON null
        a3 = alert(features=None, rule={"sid": 1}, anomaly_score=None)  # SQL NULL / SQL NULL
        db.flush()
        db.add(Block(sensor_id=s1.id, ip="1.2.3.4", reason="r", source=BlockSource.AUTO,
                     alert_id=a1.id, blocked_at=now, expires_at=now + timedelta(hours=1)))
        db.add(WouldBlock(sensor_id=s2.id, ip="9.9.9.9", reason="w", source=BlockSource.ANALYST,
                          alert_id=a2.id, at=now, ttl_seconds=60))
        db.add(Action(kind=ActionKind.BLOCK_IP, params={"ip": "1.2.3.4"}, reason="x",
                      proposed_by="assistant", proposed_by_user_id=admin.id, sensor_id=s1.id,
                      status=ActionStatus.EXECUTED, created_at=now, decided_by_id=admin.id,
                      decided_at=now, result=None, completed_at=now))  # JSON null result
        db.add(Action(kind=ActionKind.UNBLOCK_IP, params={}, proposed_by="user", sensor_id=s2.id,
                      status=ActionStatus.PENDING, created_at=now))  # SQL NULL result
        db.add(AuditEntry(at=now, actor_type="user", actor_name="admin", action="login",
                          details={"a": {"b": [1, 2, {"c": None}]}}))
        db.add(AssistantConversation(user_id=admin.id, title="t", messages=[{"role": "user"}],
                                     user_turns=1, created_at=now, updated_at=now,
                                     busy_since=now))
        db.add(SensorStatus(sensor_id=s1.id, payload={"cpu": 0.5}, last_seen_at=now))
        db.add(ModelVersion(sensor_id=s1.id, name="m", sha256="d" * 64, version="v1",
                            first_seen=now, last_seen=now))
        db.commit()
    # extra float edge cases and a unicode-heavy row can not be stored in JSON portably; skip


def _norm(value, is_json):
    if is_json:
        return None if value is None else ("json", json.loads(value))
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value


def dump(engine) -> dict[str, list[tuple]]:
    """All rows of every model table in primary-key order; JSON columns as text so SQL NULL and
    JSON null stay distinct."""
    out = {}
    with engine.connect() as conn:
        for table in Base.metadata.sorted_tables:
            cols = list(table.columns)
            flags = [isinstance(c.type, sa.JSON) for c in cols]
            sel = sa.select(*[sa.cast(c, sa.Text) if f else c for c, f in zip(cols, flags)]
                            ).order_by(*table.primary_key.columns)
            out[table.name] = [tuple(_norm(v, f) for v, f in zip(r, flags))
                               for r in conn.execute(sel)]
        conn.rollback()
    return out


@pytest.fixture
def cli_env(monkeypatch):
    """The CLI reads get_settings(): give it a JWT secret and drop the cache around the test."""
    from soc.api.settings import get_settings

    monkeypatch.setenv("IDPS_SOC_JWT_SECRET", "k" * 48)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
