"""Admin: users, sensors and the audit log. Admins only."""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from soc.api import auth
from soc.api.auth import AdminUser
from soc.api.common import Cursor, Limit, Page, audit, get_or_404, paginate
from soc.api.db import get_db
from soc.api.models import AuditEntry, Role, SensorToken, User
from soc.api.security import PasswordPolicyError

router = APIRouter(prefix="/admin", tags=["admin"])

USERNAME_PATTERN = r"^[A-Za-z0-9._@-]+$"
Username = Annotated[str, Field(min_length=1, max_length=64, pattern=USERNAME_PATTERN)]
Password = Annotated[str, Field(min_length=1, max_length=256)]  # the policy is checked by auth


class UserAdminOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: Role
    disabled: bool
    created_at: datetime


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: Username
    password: Password
    role: Role


class RoleChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role


class PasswordReset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: Password


class SensorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    revoked: bool
    created_at: datetime


class SensorCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=64, pattern=USERNAME_PATTERN)]


class SensorCreated(SensorOut):
    token: str  # shown once; only its hash is stored


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    actor_type: str
    actor_name: str
    action: str
    target: str
    details: dict[str, Any]


def _enabled_admins(db: Session) -> int:
    # FOR UPDATE locks the enabled admin rows until this transaction commits, so two admins
    # demoting or disabling each other at the same moment can't both pass the check
    # (PostgreSQL). SQLite ignores it but allows only one writer at a time anyway.
    return len(db.scalars(select(User.id).where(User.role == Role.ADMIN,
                                                User.disabled.is_(False)).with_for_update()).all())


def _would_remove_last_admin(db: Session, user: User) -> bool:
    return user.role == Role.ADMIN and not user.disabled and _enabled_admins(db) <= 1


_LAST_ADMIN = "refused: this would leave no enabled admin"


# --- users ------------------------------------------------------------------------------

@router.get("/users", response_model=list[UserAdminOut])
def list_users(admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    return [UserAdminOut.model_validate(u) for u in db.scalars(select(User).order_by(User.id))]


@router.post("/users", response_model=UserAdminOut, status_code=201)
def create_user(body: UserCreate, admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    # The audit row is added first so auth.create_user's commit stores both together.
    audit(db, admin, "user_create", f"user:{body.username}", {"role": body.role.value})
    try:
        user = auth.create_user(db, body.username, body.password, body.role)
    except ValueError as exc:  # also PasswordPolicyError, a ValueError subclass
        db.rollback()
        code = 422 if isinstance(exc, PasswordPolicyError) else 409
        raise HTTPException(code, str(exc)) from exc
    return UserAdminOut.model_validate(user)


@router.patch("/users/{user_id}/role", response_model=UserAdminOut)
def change_role(user_id: int, body: RoleChange, admin: AdminUser,
                db: Annotated[Session, Depends(get_db)]):
    user = get_or_404(db, User, user_id, "user")
    if body.role != Role.ADMIN and _would_remove_last_admin(db, user):
        raise HTTPException(409, _LAST_ADMIN)
    old = user.role
    user.role = body.role
    audit(db, admin, "user_role", f"user:{user.username}",
          {"from": old.value, "to": body.role.value})
    db.commit()
    return UserAdminOut.model_validate(user)


def _set_disabled(user_id: int, admin: User, db: Session, disabled: bool) -> UserAdminOut:
    user = get_or_404(db, User, user_id, "user")
    if disabled and _would_remove_last_admin(db, user):
        raise HTTPException(409, _LAST_ADMIN)
    audit(db, admin, "user_disable" if disabled else "user_enable", f"user:{user.username}")
    auth.set_disabled(db, user, disabled)  # also ends the user's sessions; commits
    return UserAdminOut.model_validate(user)


@router.post("/users/{user_id}/disable", response_model=UserAdminOut)
def disable_user(user_id: int, admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    return _set_disabled(user_id, admin, db, True)


@router.post("/users/{user_id}/enable", response_model=UserAdminOut)
def enable_user(user_id: int, admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    return _set_disabled(user_id, admin, db, False)


@router.post("/users/{user_id}/reset-password", response_model=UserAdminOut)
def reset_password(user_id: int, body: PasswordReset, admin: AdminUser,
                   db: Annotated[Session, Depends(get_db)]):
    user = get_or_404(db, User, user_id, "user")
    audit(db, admin, "user_reset_password", f"user:{user.username}")
    try:
        auth.set_password(db, user, body.password)
    except PasswordPolicyError as exc:
        db.rollback()
        raise HTTPException(422, str(exc)) from exc
    return UserAdminOut.model_validate(user)


# --- sensors ----------------------------------------------------------------------------

@router.get("/sensors", response_model=list[SensorOut])
def list_sensors(admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    return [SensorOut.model_validate(s) for s in db.scalars(select(SensorToken)
                                                            .order_by(SensorToken.id))]


@router.post("/sensors", response_model=SensorCreated, status_code=201)
def create_sensor(body: SensorCreate, admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    if db.scalar(select(SensorToken).where(SensorToken.name == body.name)) is not None:
        raise HTTPException(409, f"sensor {body.name!r} already exists")
    audit(db, admin, "sensor_create", f"sensor:{body.name}")
    token = auth.create_sensor_token(db, body.name)  # commits the audit row with it
    sensor = db.scalar(select(SensorToken).where(SensorToken.name == body.name))
    return SensorCreated(**SensorOut.model_validate(sensor).model_dump(), token=token)


@router.post("/sensors/{sensor_id}/revoke", response_model=SensorOut)
def revoke_sensor(sensor_id: int, admin: AdminUser, db: Annotated[Session, Depends(get_db)]):
    sensor = get_or_404(db, SensorToken, sensor_id, "sensor")
    sensor.revoked = True
    audit(db, admin, "sensor_revoke", f"sensor:{sensor.name}")
    db.commit()
    return SensorOut.model_validate(sensor)


# --- audit log --------------------------------------------------------------------------

@router.get("/audit", response_model=Page[AuditOut])
def list_audit(admin: AdminUser, db: Annotated[Session, Depends(get_db)],
               actor: Annotated[str | None, Query(max_length=64)] = None,
               action: Annotated[str | None, Query(max_length=64)] = None,
               limit: Limit = 100, cursor: Cursor = None):
    query = select(AuditEntry).order_by(AuditEntry.id.desc()).limit(limit + 1)
    if actor:
        query = query.where(AuditEntry.actor_name == actor)
    if action:
        query = query.where(AuditEntry.action == action)
    if cursor:
        query = query.where(AuditEntry.id < cursor)
    rows, next_cursor = paginate(list(db.scalars(query)), limit)
    return Page[AuditOut](items=[AuditOut.model_validate(r) for r in rows],
                          next_cursor=next_cursor)
