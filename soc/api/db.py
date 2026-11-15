"""Database engine and sessions (SQLAlchemy 2)."""

from collections.abc import Iterator
from datetime import UTC, datetime

from fastapi import Request
from sqlalchemy import DateTime, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, ProgrammingError
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


def upgrade_schema(engine: Engine) -> list[str]:
    """TEMPORARY, until Alembic (roadmap step 10): add nullable columns that the models have and
    an existing database lacks, with ALTER TABLE ADD COLUMN, and the indexes the models declare
    on those new columns. Idempotent (also when two processes start at once: a "duplicate
    column" answer is fine if the column is there afterwards); returns what it added
    ("table.column"). Only plain nullable columns are added, with no defaults or constraints, and
    nothing is ever dropped, renamed or retyped; those need a real migration."""
    quote = engine.dialect.identifier_preparer.quote
    added: list[str] = []
    for table in Base.metadata.sorted_tables:
        insp = inspect(engine)
        if not insp.has_table(table.name):
            continue
        have = {c["name"] for c in insp.get_columns(table.name)}
        new_cols = []
        for col in table.columns:
            if col.name in have:
                continue
            if not col.nullable or col.primary_key:
                raise RuntimeError(
                    f"{table.name}.{col.name} is missing and is not a nullable column: "
                    "this needs a real migration")
            ddl = f"ALTER TABLE {quote(table.name)} ADD COLUMN {quote(col.name)} " \
                  f"{col.type.compile(dialect=engine.dialect)}"
            try:
                with engine.begin() as conn:  # one transaction each: PostgreSQL aborts on error
                    conn.execute(text(ddl))
            except (OperationalError, ProgrammingError):
                again = {c["name"] for c in inspect(engine).get_columns(table.name)}
                if col.name not in again:
                    raise
                continue  # another process added it first
            added.append(f"{table.name}.{col.name}")
            new_cols.append(col.name)
        if new_cols:
            existing = {i["name"] for i in inspect(engine).get_indexes(table.name)}
            for index in table.indexes:
                if index.name not in existing and {c.name for c in index.columns} & set(new_cols):
                    try:
                        index.create(engine)
                    except (OperationalError, ProgrammingError):
                        names = {i["name"] for i in inspect(engine).get_indexes(table.name)}
                        if index.name not in names:
                            raise
    return added


def init_db(engine: Engine) -> None:
    """Create missing tables, then add missing nullable columns to old ones (upgrade_schema;
    full migrations come with Alembic, see docs/soc.md)."""
    from soc.api import models  # noqa: F401  registers the tables

    Base.metadata.create_all(engine)
    upgrade_schema(engine)


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one session per request, closed afterwards."""
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()
