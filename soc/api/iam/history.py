"""Login history: one row per sign-in attempt. Written by soc.api.auth; a failure to write must
never break a login, so every error here is logged and swallowed."""

import logging
import time

from sqlalchemy.orm import Session

from soc.api.common import strip_unsafe
from soc.api.models import LoginHistory

log = logging.getLogger("soc.iam.history")

# A flood of throttled attempts must not become a flood of rows: one "locked" row per
# (username, address) per minute.
_LOCKED_EVERY = 60.0
_recent_locked: dict[tuple[str, str], float] = {}
_MAX_TRACKED = 10_000


def _clean(text: str, limit: int) -> str:
    try:
        text = strip_unsafe(text)
    except ValueError:  # a NUL
        text = text.replace("\x00", "")
        text = strip_unsafe(text)
    return text[:limit]


def record_login(db: Session, *, username: str, user_id: int | None, success: bool, reason: str,
                 ip: str, user_agent: str | None, mfa_used: bool = False) -> None:
    try:
        if reason == "locked":
            now, key = time.monotonic(), (username[:64], ip)
            if len(_recent_locked) > _MAX_TRACKED:
                _recent_locked.clear()
            if now - _recent_locked.get(key, -_LOCKED_EVERY) < _LOCKED_EVERY:
                return
            _recent_locked[key] = now
        db.add(LoginHistory(username=_clean(username, 64), user_id=user_id, success=success,
                            reason=reason, ip=_clean(ip, 45),
                            user_agent=_clean(user_agent or "", 255), mfa_used=mfa_used))
        db.commit()
    except Exception:  # history is best effort: never break a login
        log.warning("could not record a login attempt", exc_info=True)
        try:
            db.rollback()
        except Exception:
            log.warning("rollback after a failed history write also failed", exc_info=True)
