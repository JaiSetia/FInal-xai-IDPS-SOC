"""Database engine and sessions (SQLAlchemy 2)."""

from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import DateTime, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UtcDateTime(TypeDecorator):
    """A timezone-aware UTC datetime. SQLite drops the timezone on storage; this puts it back."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime: use timezone-aware UTC datetimes")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def make_engine(url: str) -> Engine:
    kwargs: dict = {}
    if url.startswith("sqlite"):
        # FastAPI runs sync endpoints in a thread pool, so SQLite must allow that.
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool  # one shared in-memory database (tests)
    return create_engine(url, **kwargs)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """Create missing tables. (Schema migrations are a later step; see docs/soc.md.)"""
    from soc.api import models  # noqa: F401  registers the tables

    Base.metadata.create_all(engine)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request, closed afterwards."""
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
