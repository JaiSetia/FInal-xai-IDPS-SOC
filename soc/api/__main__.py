"""Admin CLI for the SOC API.

    python -m soc.api create-user <username> --role admin|analyst   (asks for the password)
    python -m soc.api create-sensor <name>                           (prints the token once)
    python -m soc.api db upgrade | current | check   [--database-url URL]
    python -m soc.api prune [--dry-run]              [--database-url URL]   (retention, once)
    python -m soc.api backup OUT.jsonl.gz            [--database-url URL]
    python -m soc.api restore IN.jsonl.gz            [--database-url URL]   (empty database only)

--database-url defaults to IDPS_SOC_DATABASE_URL (then the SOC's default). Exit status: 0 ok,
1 refused or failed (one line on stderr), 2 bad usage.
"""

import argparse
import getpass
import os
import sys

from soc.api import auth
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.models import Role
from soc.api.security import PasswordPolicyError
from soc.api.settings import get_settings


def _session():
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_db(engine, settings.auto_migrate)
    return make_session_factory(engine)()


def _create_user(args) -> int:
    password = getpass.getpass(f"Password for {args.username}: ")
    if password != getpass.getpass("Repeat password: "):
        print("passwords don't match", file=sys.stderr)
        return 1
    with _session() as db:
        try:
            auth.create_user(db, args.username, password, Role(args.role))
        except (ValueError, PasswordPolicyError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print(f"created {args.role} {args.username!r}")
    return 0


def _create_sensor(args) -> int:
    with _session() as db:
        try:
            token = auth.create_sensor_token(db, args.name)
        except Exception as exc:  # noqa: BLE001  e.g. duplicate name
            print(f"error: {exc}", file=sys.stderr)
            return 1
    print("Sensor token (shown once; store it in the sensor's IDPS_SOC_SENSOR_TOKEN):")
    print(token)
    return 0


def _url(args) -> str:
    if args.database_url:
        return args.database_url
    from soc.api.settings import SocSettings

    return os.environ.get("IDPS_SOC_DATABASE_URL") or SocSettings.model_fields[
        "database_url"].default


def _engine(args):
    return make_engine(_url(args))


def _guarded(fn):
    """Turn failures into one stderr line and exit status 1 (a shell script's contract). The
    database URL (it holds a password) is never printed."""
    def run(args) -> int:
        from soc.api.backup import BackupError
        from soc.api.migrate import SchemaError

        try:
            return fn(args)
        except (BackupError, SchemaError) as exc:
            print(f"error: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            text = (str(exc).splitlines() or [""])[0][:300]
            print(f"error: {type(exc).__name__}: {text}", file=sys.stderr)
        return 1
    return run


def _db(args) -> int:
    from soc.api import migrate

    engine = _engine(args)
    if args.db_cmd == "upgrade":
        migrate.ensure_schema(engine, auto_migrate=True)  # empty / adopt / upgrade, under the lock
        print(f"database is at {migrate.head_revision()}")
        return 0
    if args.db_cmd == "current":
        with engine.connect() as conn:
            print(migrate.current_revision(conn) or "(none)")
            conn.rollback()
        return 0
    problems = migrate.check(engine)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if not problems:
        print("ok: the database is at head and matches the models")
    return 1 if problems else 0


def _prune(args) -> int:
    from soc.api import migrate, retention
    from soc.api.settings import MIN_SECRET_LENGTH, SocSettings

    url = _url(args)
    # The JWT secret is not needed to prune: a placeholder satisfies the settings model (the
    # retention values still come from the IDPS_SOC_* environment).
    settings = SocSettings(jwt_secret="x" * MIN_SECRET_LENGTH, database_url=url)
    engine = make_engine(url)
    problems = migrate.check(engine)
    if problems:
        raise migrate.SchemaError(
            f"the database is not ready ({problems[0]}): run `python -m soc.api db upgrade` first")
    with make_session_factory(engine)() as db:
        counts: dict[str, int] = {}
        gave_up: list[str] = []
        error = None
        try:
            # pause between batches (as the background runner does): on SQLite each batch holds
            # the write lock, and back-to-back batches would starve the SOC's own writers
            retention.prune(db, settings, dry_run=args.dry_run, counts=counts,
                            pause=retention.PAUSE_SECONDS, problems=gave_up)
            if gave_up:
                error = "; ".join(gave_up)
                print(f"warning: {error}", file=sys.stderr)
        except Exception as exc:
            error = type(exc).__name__ + " (see the message above)"
            raise
        finally:
            if not args.dry_run and sum(counts.values()):
                try:  # what was deleted before a failure is audited too
                    retention._audit(make_session_factory(engine), counts, error)
                except Exception:
                    if error is None:
                        raise  # the prune worked but could not be recorded: say so
                    print("warning: the audit entry could not be written", file=sys.stderr)
    print(("would delete" if args.dry_run else "deleted") + ":")
    for table, n in counts.items():
        print(f"  {table}: {n}")
    return 0


def _backup(args) -> int:
    from soc.api import backup

    engine = _engine(args)
    print(f"backing up {engine.url.render_as_string(hide_password=True)}", file=sys.stderr)
    backup.backup(engine, args.file)
    return 0


def _restore(args) -> int:
    from soc.api import backup

    engine = _engine(args)
    print(f"restoring into {engine.url.render_as_string(hide_password=True)}", file=sys.stderr)
    backup.restore(engine, args.file)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc.api")
    sub = parser.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("create-user")
    u.add_argument("username")
    u.add_argument("--role", choices=[r.value for r in Role], required=True)
    u.set_defaults(fn=_create_user)
    s = sub.add_parser("create-sensor")
    s.add_argument("name")
    s.set_defaults(fn=_create_sensor)
    d = sub.add_parser("db", help="schema migrations")
    d.add_argument("db_cmd", choices=["upgrade", "current", "check"])
    d.set_defaults(fn=_guarded(_db))
    pr = sub.add_parser("prune", help="run the retention policy once")
    pr.add_argument("--dry-run", action="store_true", help="only count what would be deleted")
    pr.set_defaults(fn=_guarded(_prune))
    b = sub.add_parser("backup", help="portable logical backup (gzip JSON lines)")
    b.add_argument("file", metavar="OUT.jsonl.gz")
    b.set_defaults(fn=_guarded(_backup))
    r = sub.add_parser("restore", help="restore a backup into an empty database")
    r.add_argument("file", metavar="IN.jsonl.gz")
    r.set_defaults(fn=_guarded(_restore))
    for cmd in (d, pr, b, r):
        cmd.add_argument("--database-url", default=None,
                         help="SQLAlchemy URL (default: IDPS_SOC_DATABASE_URL)")
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
