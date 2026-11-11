"""Admin CLI for the SOC API.

    python -m soc.api create-user <username> --role admin|analyst   (asks for the password)
    python -m soc.api create-sensor <name>                           (prints the token once)
"""

import argparse
import getpass
import sys

from soc.api import auth
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.models import Role
from soc.api.security import PasswordPolicyError
from soc.api.settings import get_settings


def _session():
    engine = make_engine(get_settings().database_url)
    init_db(engine)
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
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
