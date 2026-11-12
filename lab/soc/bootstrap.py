"""First-start setup of the lab SOC: the admin user and the sensor token.

Run by lab/soc/start.sh with the SOC settings in the environment. Idempotent:
- the admin `LAB_SOC_ADMIN_USER` (default "admin") is created once, with LAB_SOC_ADMIN_PASSWORD;
- a sensor token is created when the shared token file is missing, empty, or holds a token this
  database doesn't know (or has revoked), e.g. after the SOC's data volume was recreated. It is
  written there (0600, via a temporary file) for the sensor container, which mounts the same
  volume read-only. The SOC keeps only its hash.
"""

from __future__ import annotations

import os
import sys
import time

from sqlalchemy import select

from soc.api import auth
from soc.api.db import init_db, make_engine, make_session_factory
from soc.api.models import Role, SensorToken, User
from soc.api.security import PasswordPolicyError, hash_sensor_token
from soc.api.settings import get_settings


def _token_is_valid(db, token_file: str) -> bool:
    try:
        with open(token_file) as fh:
            token = fh.read().strip()
    except FileNotFoundError:
        return False
    if not token:
        return False
    row = db.scalar(select(SensorToken).where(SensorToken.token_hash == hash_sensor_token(token)))
    return row is not None and not row.revoked


def main(token_file: str) -> int:
    user = os.environ.get("LAB_SOC_ADMIN_USER", "admin")
    password = os.environ.get("LAB_SOC_ADMIN_PASSWORD", "")
    engine = make_engine(get_settings().database_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        if db.scalar(select(User).where(User.username == user)) is None:
            try:
                auth.create_user(db, user, password, Role.ADMIN)
            except (ValueError, PasswordPolicyError) as exc:
                print(f"soc: cannot create the admin user: {exc}", file=sys.stderr)
                return 1
            print(f"soc: created admin user {user!r}")
        if not _token_is_valid(db, token_file):
            # A new name each time, so a replaced token never collides with an old sensor.
            name = f"lab-sensor-{int(time.time())}"
            token = auth.create_sensor_token(db, name)
            tmp = f"{token_file}.tmp"
            if os.path.exists(tmp):
                os.unlink(tmp)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(token)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, token_file)
            print(f"soc: created sensor {name!r}; its token is in {token_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
