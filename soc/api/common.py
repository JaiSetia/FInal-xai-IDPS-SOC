"""Small helpers shared by the route modules: audit log, severity, IP checks, pagination."""

import ipaddress
from typing import Annotated, Generic, TypeVar

from fastapi import HTTPException, Query, status
from pydantic import AfterValidator, BaseModel
from sqlalchemy.orm import Session

from soc.api.models import SEVERITY_RANK, AuditEntry, SensorToken, Severity, User
from soc.api.settings import SocSettings

MAX_PAGE = 500
T = TypeVar("T")


# --- audit log -------------------------------------------------------------------------

def audit(db: Session, actor: User | SensorToken, action: str, target: str = "",
          details: dict | None = None) -> None:
    """Add an audit entry to the session. It is committed with the change it describes."""
    if isinstance(actor, User):
        actor_type, name = "user", actor.username
    else:
        actor_type, name = "sensor", actor.name
    db.add(AuditEntry(actor_type=actor_type, actor_name=name, action=action, target=target,
                      details=details or {}))


# --- severity ---------------------------------------------------------------------------

def derive_severity(settings: SocSettings, predicted_class: str, confidence: float) -> Severity:
    """Base severity of the class, lowered one level (never below low) when confidence is low."""
    base = Severity(settings.severity_by_class.get(predicted_class.strip().casefold(),
                                                   settings.default_severity))
    if confidence < settings.low_confidence_below:
        rank = max(SEVERITY_RANK[base] - 1, 0)
        base = next(s for s, r in SEVERITY_RANK.items() if r == rank)
    return base


# --- IP addresses -----------------------------------------------------------------------

MAX_IP_LENGTH = 45  # longest textual IPv6 address with an embedded IPv4 part


def _canonical_ip(value: str) -> str:
    value = value.strip()
    # Error messages never repeat the input: it may be huge or hostile.
    if len(value) > MAX_IP_LENGTH or "%" in value:
        # "%" starts an IPv6 zone ID, which may contain any text (even nft syntax) and has no
        # meaning for a remote host. Refuse it rather than pass it on to a sensor.
        raise ValueError("not a valid IPv4 or IPv6 address (zone IDs aren't accepted)")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("not a valid IPv4 or IPv6 address") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:1.2.3.4 is the same host as 1.2.3.4
    return str(addr)


IPAddress = Annotated[str, AfterValidator(_canonical_ip)]


class BlockingUnavailable(HTTPException):
    """Blocking is switched off by configuration (503). Not a verdict on the address."""

    def __init__(self) -> None:
        super().__init__(status.HTTP_503_SERVICE_UNAVAILABLE,
                         "IDPS_SOC_BLOCK_ALLOWLIST is not set (gateways, DNS, SOC host, sensors, "
                         "analysts); refusing to request any block until it is")


def check_blockable(ip: str, settings: SocSettings) -> None:
    """Raise if the SOC must not ask for `ip` to be blocked.

    422: the address is never blockable (special-purpose or allowlisted).
    503 (BlockingUnavailable): the allowlist isn't configured, so nothing may be blocked.
    """
    addr = ipaddress.ip_address(_canonical_ip(ip))
    if (addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified
            or addr.is_reserved):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            f"{addr} is loopback, multicast, link-local, reserved or unspecified "
                            "and can't be blocked")
    if not settings.block_allowlist:
        raise BlockingUnavailable()
    for net in settings.block_allowlist:
        if addr.version == net.version and addr in net:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                                f"{addr} is in the block allowlist ({net}) and can't be blocked")


# --- pagination -------------------------------------------------------------------------

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE)]
# Keyset cursor: the id of the last item seen. Pages go from newest (highest id) to oldest.
Cursor = Annotated[int | None, Query(ge=1, le=2**62, description="id of the last item seen")]


class Page(BaseModel, Generic[T]):
    items: list[T]
    next_cursor: int | None = None


def paginate(rows: list, limit: int) -> tuple[list, int | None]:
    """`rows` was fetched with limit + 1; return the page and the cursor for the next one."""
    if len(rows) > limit:
        rows = rows[:limit]
        return rows, rows[-1].id
    return rows, None


def get_or_404(db: Session, model, ident: int, what: str):
    obj = db.get(model, ident)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")
    return obj
