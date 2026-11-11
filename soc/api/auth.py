"""Login, current-user and role dependencies, and sensor authentication."""

from collections.abc import Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc.api import security
from soc.api.db import get_db
from soc.api.models import Role, SensorToken, User

router = APIRouter(prefix="/auth", tags=["auth"])
_bearer = HTTPBearer(auto_error=False)

# One message for every login failure, so responses don't reveal whether a username exists.
_LOGIN_FAILED = "incorrect username or password"
_UNAUTHORIZED = HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated",
                              headers={"WWW-Authenticate": "Bearer"})


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=security.MAX_PASSWORD_LENGTH)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserOut(BaseModel):
    id: int
    username: str
    role: Role


def client_ip(request: Request) -> str:
    # The direct peer address. If the API is put behind a reverse proxy, configure the
    # proxy-headers support in uvicorn (--proxy-headers / --forwarded-allow-ips) rather
    # than trusting X-Forwarded-For here, which any client could forge.
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Annotated[Session, Depends(get_db)]):
    settings = request.app.state.settings
    throttle: security.LoginThrottle = request.app.state.login_throttle
    ip = client_ip(request)
    ticket = throttle.begin_attempt(body.username, ip)  # counted as a failure until proven
    if ticket is None:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "too many failed logins; try again later")
    user = db.scalar(select(User).where(User.username == body.username))
    ok = security.verify_password(body.password, user.password_hash if user else None)
    if not ok or user is None or user.disabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, _LOGIN_FAILED)
    throttle.succeeded(body.username, ip, ticket)
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(body.password)
        db.commit()
    minutes = settings.access_token_minutes
    token = security.create_access_token(
        user_id=user.id, token_version=user.token_version,
        secret=settings.jwt_secret.get_secret_value(), minutes=minutes)
    return TokenResponse(access_token=token, expires_in=minutes * 60)


def user_from_token(token: str, request_or_app, db: Session) -> User | None:
    """The active user a token belongs to, or None. Shared by HTTP and WebSocket auth."""
    app = getattr(request_or_app, "app", request_or_app)
    try:
        claims = security.decode_access_token(
            token, secret=app.state.settings.jwt_secret.get_secret_value())
    except security.TokenError:
        return None
    user = db.get(User, int(claims["sub"]))
    if user is None or user.disabled or user.token_version != claims["ver"]:
        return None
    return user


def current_user(request: Request, db: Annotated[Session, Depends(get_db)],
                 creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]) -> User:
    if creds is None or creds.scheme.lower() != "bearer":
        raise _UNAUTHORIZED
    user = user_from_token(creds.credentials, request, db)
    if user is None:
        raise _UNAUTHORIZED
    return user


def require_role(*roles: Role) -> Callable[..., User]:
    """Dependency factory: the current user, who must have one of `roles` (admins always pass)."""
    allowed = set(roles) | {Role.ADMIN}

    def dependency(user: Annotated[User, Depends(current_user)]) -> User:
        if user.role not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not allowed for your role")
        return user

    return dependency


AnyUser = Annotated[User, Depends(require_role(Role.ANALYST))]
AdminUser = Annotated[User, Depends(require_role(Role.ADMIN))]


def current_sensor(db: Annotated[Session, Depends(get_db)],
                   creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
                   ) -> SensorToken:
    """Authenticate a sensor by its API token (Authorization: Bearer idps_sensor_...)."""
    if creds is None or not creds.credentials.startswith(security.SENSOR_TOKEN_PREFIX):
        raise _UNAUTHORIZED
    digest = security.hash_sensor_token(creds.credentials)
    sensor = db.scalar(select(SensorToken).where(SensorToken.token_hash == digest))
    if sensor is None or sensor.revoked or not security.tokens_equal(sensor.token_hash, digest):
        raise _UNAUTHORIZED
    return sensor


Sensor = Annotated[SensorToken, Depends(current_sensor)]


@router.get("/me", response_model=UserOut)
def me(user: AnyUser):
    return UserOut(id=user.id, username=user.username, role=user.role)


# --- helpers used by the CLI and the admin endpoints -------------------------------------

def create_user(db: Session, username: str, password: str, role: Role) -> User:
    if db.scalar(select(User).where(User.username == username)) is not None:
        raise ValueError(f"user {username!r} already exists")
    user = User(username=username, password_hash=security.hash_password(password), role=role)
    db.add(user)
    db.commit()
    return user


def set_password(db: Session, user: User, password: str) -> None:
    user.password_hash = security.hash_password(password)
    user.token_version += 1  # log out every existing session
    db.commit()


def set_disabled(db: Session, user: User, disabled: bool) -> None:
    user.disabled = disabled
    user.token_version += 1
    db.commit()


def create_sensor_token(db: Session, name: str) -> str:
    """Create a sensor and return its token. The token is shown once and never stored."""
    token = security.generate_sensor_token()
    db.add(SensorToken(name=name, token_hash=security.hash_sensor_token(token)))
    db.commit()
    return token
