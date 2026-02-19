# main.py  (single-file FastAPI example like your Questions/Choices code)
# NOTE: For production, replace create_all() with Alembic migrations.

from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import List, Optional, Annotated, Dict, Set
from schemas import MemberOut, MemberUpdateIn

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    WebSocket,
    WebSocketDisconnect,
    status,
    Request
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

import models
from database import engine, SessionLocal

# ----------------------------
# App + Swagger Bearer Auth setup
# ----------------------------
app = FastAPI(title="AptPulse API", version="1.0.0")

bearer_scheme = HTTPBearer(auto_error=False)

def custom_openapi():
    """
    Adds BearerAuth scheme so Swagger shows the 'Authorize' button.
    Secured routes are automatically marked based on dependencies.
    """
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title=app.title,
        version=app.version,
        description="AptPulse backend (FastAPI + Postgres + In-house WebSocket + In-house Calendar)",
        routes=app.routes,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})
    schema["components"]["securitySchemes"]["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "token",
    }
    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = custom_openapi

# DEV ONLY (use Alembic in real deployments)
#models.Base.metadata.create_all(bind=engine)


# ----------------------------
# DB Dependency (same style as your example)
# ----------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


# ----------------------------
# Simple in-house session token (no JWT libs)
# Client sends: Authorization: Bearer <token>
# We store SHA256(token) in refresh_tokens.token_hash (used as session table for beta)
# ----------------------------
SESSION_DAYS = 7
SESSION_RENEW_IF_LT = timedelta(days=2)

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def create_session(db: Session, user_id: int, request: Request, days: int = SESSION_DAYS) -> str:
    raw = secrets.token_urlsafe(32)
    token_hash = _sha256(raw)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=days)

    db_token = models.RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        revoked_at=None,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
        last_used_at=now,
    )
    db.add(db_token)
    db.commit()
    return raw


def _user_is_verified(db: Session, user_id: int) -> bool:
    # Verified if any identity for this user is_verified
    return (
        db.query(models.Identity.id)
        .filter(models.Identity.user_id == user_id, models.Identity.is_verified == True)
        .first()
        is not None
    )


def get_current_user(
    db: db_dependency,
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> models.User:
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")

    token_hash = _sha256(creds.credentials)

    token_row = (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.token_hash == token_hash,
            models.RefreshToken.revoked_at.is_(None),
            models.RefreshToken.expires_at > datetime.now(timezone.utc),
        )
        .first()
    )
    if not token_row:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = (
        db.query(models.User)
        .filter(models.User.id == token_row.user_id, models.User.is_active == True)
        .first()
    )
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Enforce verification globally (prevents unverified users from using app)
    if not _user_is_verified(db, user.id):
        raise HTTPException(status_code=403, detail="Account not verified")

    # update last_used + rolling renewal
    now = datetime.now(timezone.utc)
    token_row.last_used_at = now
    if token_row.expires_at - now < SESSION_RENEW_IF_LT:
        token_row.expires_at = now + timedelta(days=SESSION_DAYS)
    db.commit()

    return user

user_dependency = Annotated[models.User, Depends(get_current_user)]


def require_group_role(db: Session, group_id: int, user_id: int, roles: List[models.GroupRole]):
    membership = (
        db.query(models.GroupMembership)
        .filter(
            models.GroupMembership.group_id == group_id,
            models.GroupMembership.user_id == user_id,
            models.GroupMembership.is_active == True,
        )
        .first()
    )
    if not membership or membership.role not in roles:
        raise HTTPException(status_code=403, detail="Not allowed for this group")
    return membership


def require_premium_or_trial(user: models.User):
    # premium gates for Scheduled Plans + advanced insights
    now = datetime.now(timezone.utc)
    if user.is_premium:
        return
    if user.trial_end_at and user.trial_end_at > now:
        return
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail="Trial expired. Upgrade required for this feature.",
    )


# ----------------------------
# WebSocket Manager (in-house)
# ----------------------------
class WSManager:
    def __init__(self):
        self._user_connections: Dict[int, Set[WebSocket]] = {}

    async def connect(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self._user_connections.setdefault(user_id, set()).add(websocket)

    def disconnect(self, user_id: int, websocket: WebSocket):
        conns = self._user_connections.get(user_id)
        if not conns:
            return
        conns.discard(websocket)
        if not conns:
            self._user_connections.pop(user_id, None)

    async def send_to_user(self, user_id: int, payload: dict):
        conns = self._user_connections.get(user_id, set())
        dead = []
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(user_id, ws)

    async def broadcast_to_users(self, user_ids: List[int], payload: dict):
        for uid in set(user_ids):
            await self.send_to_user(uid, payload)

ws_manager = WSManager()


def _group_member_user_ids(db: Session, group_id: int) -> List[int]:
    rows = (
        db.query(models.GroupMembership.user_id)
        .filter(models.GroupMembership.group_id == group_id, models.GroupMembership.is_active == True)
        .all()
    )
    return [r[0] for r in rows]


async def notify_group(db: Session, group_id: int, notif_type: str, title: str, body: str, data: dict):
    user_ids = _group_member_user_ids(db, group_id)

    # store IN_APP notifications
    for uid in user_ids:
        db.add(
            models.Notification(
                user_id=uid,
                group_id=group_id,
                assignment_id=data.get("assignment_id"),
                channel=models.NotificationChannel.IN_APP,
                status=models.NotificationStatus.QUEUED,
                notif_type=notif_type,
                title=title,
                body=body,
                data=data,
                scheduled_for=datetime.now(timezone.utc),
            )
        )
    db.commit()

    # websocket push
    await ws_manager.broadcast_to_users(
        user_ids,
        payload={
            "type": notif_type,
            "group_id": group_id,
            "title": title,
            "body": body,
            "data": data,
        },
    )


# ----------------------------
# Pydantic Schemas
# ----------------------------
class SignupEmail(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    display_name: Optional[str] = None


class LoginEmail(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class GroupCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class GroupOut(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True


class InviteCreate(BaseModel):
    invitee_email: Optional[EmailStr] = None
    invitee_phone_e164: Optional[str] = None
    expires_in_days: int = 7


class ChoreTypeCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    description: Optional[str] = None


class RotationParticipantIn(BaseModel):
    user_id: int
    position: int = Field(ge=0)


class RotationPlanCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    chore_type_id: int
    timezone: str = "America/Chicago"
    participants: List[RotationParticipantIn]
    first_due_at: Optional[datetime] = None  # if None => now


class AssignmentCompleteIn(BaseModel):
    notes: Optional[str] = None
    photo_url: Optional[str] = None


class ScheduledRuleIn(BaseModel):
    user_id: int
    day_of_week: Optional[int] = Field(default=None, ge=0, le=6)
    day_of_month: Optional[int] = Field(default=None, ge=1, le=31)


class ScheduledPlanCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    chore_type_id: int
    timezone: str = "America/Chicago"
    frequency: models.ScheduleFrequency
    interval_days: Optional[int] = None  # for EVERY_N_DAYS (7/14)
    due_time: str = "09:00"              # "HH:MM"
    rules: List[ScheduledRuleIn]


# ----------------------------
# Password hashing (PBKDF2, no external libs)
# ----------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk_check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()
        return secrets.compare_digest(dk_check, dk_hex)
    except Exception:
        return False


# ----------------------------
# Basic health check
# ----------------------------
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


# ----------------------------
# AUTH APIs (email flow)
# ----------------------------
def _new_one_time_token() -> str:
    return secrets.token_urlsafe(32)

def _token_hash(token: str) -> str:
    return _sha256(token)

class VerifyEmailRequestIn(BaseModel):
    email: EmailStr

class VerifyEmailConfirmIn(BaseModel):
    token: str

class ForgotPasswordIn(BaseModel):
    email: EmailStr

class ResetPasswordIn(BaseModel):
    token: str
    new_password: str = Field(min_length=8)

@app.post("/api/v1/auth/signup/email")
def signup_email(payload: SignupEmail, request: Request, db: db_dependency):
    email = str(payload.email).lower()

    existing = (
        db.query(models.Identity)
        .filter(models.Identity.provider == models.IdentityProvider.EMAIL,
                models.Identity.email == email)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    now = datetime.now(timezone.utc)
    user = models.User(
        display_name=payload.display_name,
        is_active=True,
        trial_end_at=now + timedelta(days=14),
        is_premium=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ident = models.Identity(
        user_id=user.id,
        provider=models.IdentityProvider.EMAIL,
        email=email,
        password_hash=hash_password(payload.password),
        is_verified=False,
        verified_at=None,
    )
    db.add(ident)
    db.commit()
    db.refresh(ident)

    # create verification token (hash stored)
    raw_token = _new_one_time_token()
    db.add(models.EmailVerificationToken(
        identity_id=ident.id,
        token_hash=_token_hash(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        used_at=None,
    ))
    db.commit()

    # DEV: return token for testing. PROD: email it.
    return {"status": "PENDING_VERIFICATION", "verify_token_dev_only": raw_token}


@app.post("/api/v1/auth/login/email", response_model=TokenResponse)
def login_email(payload: LoginEmail, request: Request, db: db_dependency):
    email = str(payload.email).lower()

    ident = (
        db.query(models.Identity)
        .filter(models.Identity.provider == models.IdentityProvider.EMAIL,
                models.Identity.email == email)
        .first()
    )
    if not ident or not ident.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, ident.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not ident.is_verified:
        raise HTTPException(status_code=403, detail="Email not verified")

    token = create_session(db, ident.user_id, request)
    return TokenResponse(access_token=token)

@app.post("/api/v1/auth/verify/email/request")
def request_email_verification(payload: VerifyEmailRequestIn, db: db_dependency):
    email = str(payload.email).lower()

    ident = (
        db.query(models.Identity)
        .filter(models.Identity.provider == models.IdentityProvider.EMAIL,
                models.Identity.email == email)
        .first()
    )

    # avoid enumeration
    if not ident:
        return {"status": "OK"}

    raw_token = _new_one_time_token()
    db.add(models.EmailVerificationToken(
        identity_id=ident.id,
        token_hash=_token_hash(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        used_at=None,
    ))
    db.commit()

    return {"status": "OK", "verify_token_dev_only": raw_token}


@app.post("/api/v1/auth/verify/email/confirm")
def confirm_email_verification(payload: VerifyEmailConfirmIn, db: db_dependency):
    token_hash = _token_hash(payload.token)
    now = datetime.now(timezone.utc)

    row = (
        db.query(models.EmailVerificationToken)
        .filter(
            models.EmailVerificationToken.token_hash == token_hash,
            models.EmailVerificationToken.used_at.is_(None),
            models.EmailVerificationToken.expires_at > now,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    ident = db.query(models.Identity).filter(models.Identity.id == row.identity_id).first()
    if not ident:
        raise HTTPException(status_code=400, detail="Identity not found")

    ident.is_verified = True
    ident.verified_at = now
    row.used_at = now
    db.commit()

    return {"status": "VERIFIED"}


@app.post("/api/v1/auth/password/forgot")
def forgot_password(payload: ForgotPasswordIn, db: db_dependency):
    email = str(payload.email).lower()

    ident = (
        db.query(models.Identity)
        .filter(models.Identity.provider == models.IdentityProvider.EMAIL,
                models.Identity.email == email)
        .first()
    )

    # avoid enumeration
    if not ident:
        return {"status": "OK"}

    raw_token = _new_one_time_token()
    db.add(models.PasswordResetToken(
        identity_id=ident.id,
        token_hash=_token_hash(raw_token),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        used_at=None,
    ))
    db.commit()

    return {"status": "OK", "reset_token_dev_only": raw_token}


@app.post("/api/v1/auth/password/reset")
def reset_password(payload: ResetPasswordIn, db: db_dependency):
    now = datetime.now(timezone.utc)
    token_hash = _token_hash(payload.token)

    row = (
        db.query(models.PasswordResetToken)
        .filter(
            models.PasswordResetToken.token_hash == token_hash,
            models.PasswordResetToken.used_at.is_(None),
            models.PasswordResetToken.expires_at > now,
        )
        .first()
    )
    if not row:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    ident = db.query(models.Identity).filter(models.Identity.id == row.identity_id).first()
    if not ident:
        raise HTTPException(status_code=400, detail="Identity not found")

    ident.password_hash = hash_password(payload.new_password)
    row.used_at = now
    db.commit()

    return {"status": "PASSWORD_UPDATED"}

@app.post("/api/v1/auth/logout")
def logout(
    user: user_dependency,
    db: db_dependency,
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    if not creds or not creds.credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")

    token_hash = _sha256(creds.credentials)
    row = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    if row and row.revoked_at is None:
        row.revoked_at = datetime.now(timezone.utc)
        db.commit()

    return {"status": "OK"}


# ----------------------------
# GROUP APIs
# ----------------------------
@app.post("/api/v1/groups", response_model=GroupOut)
def create_group(payload: GroupCreate, user: user_dependency, db: db_dependency):
    g = models.Group(name=payload.name, created_by_user_id=user.id)
    db.add(g)
    db.commit()
    db.refresh(g)

    m = models.GroupMembership(group_id=g.id, user_id=user.id, role=models.GroupRole.ADMIN, is_active=True)
    db.add(m)
    db.commit()

    return g


@app.post("/api/v1/groups/{group_id}/invite")
def invite_to_group(group_id: int, payload: InviteCreate, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    if not payload.invitee_email and not payload.invitee_phone_e164:
        raise HTTPException(status_code=400, detail="Provide invitee_email or invitee_phone_e164")

    token = secrets.token_urlsafe(24)
    inv = models.Invitation(
        group_id=group_id,
        invited_by_user_id=user.id,
        invitee_email=str(payload.invitee_email).lower() if payload.invitee_email else None,
        invitee_phone_e164=payload.invitee_phone_e164,
        token=token,
        status=models.InviteStatus.PENDING,
        expires_at=datetime.now(timezone.utc) + timedelta(days=payload.expires_in_days),
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)

    return {"invite_token": inv.token, "expires_at": inv.expires_at.isoformat()}
def _user_matches_invite(db: Session, user_id: int, inv: models.Invitation) -> bool:
    if inv.invitee_email:
        return (
            db.query(models.Identity.id)
            .filter(
                models.Identity.user_id == user_id,
                models.Identity.provider == models.IdentityProvider.EMAIL,
                models.Identity.email == inv.invitee_email.lower(),
                models.Identity.is_verified == True,
            )
            .first()
            is not None
        )

    if inv.invitee_phone_e164:
        return (
            db.query(models.Identity.id)
            .filter(
                models.Identity.user_id == user_id,
                models.Identity.provider == models.IdentityProvider.PHONE,
                models.Identity.phone_e164 == inv.invitee_phone_e164,
                models.Identity.is_verified == True,
            )
            .first()
            is not None
        )

    return False


@app.post("/api/v1/groups/join/{invite_token}")
def accept_invite(invite_token: str, user: user_dependency, db: db_dependency):
    inv = db.query(models.Invitation).filter(models.Invitation.token == invite_token).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Invite not found")
    if inv.status != models.InviteStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Invite is {inv.status}")
    if inv.expires_at <= datetime.now(timezone.utc):
        inv.status = models.InviteStatus.EXPIRED
        db.commit()
        raise HTTPException(status_code=400, detail="Invite expired")

    # SECURITY FIX
    if not _user_matches_invite(db, user.id, inv):
        raise HTTPException(status_code=403, detail="This invite is not for your verified account")

    existing = (
        db.query(models.GroupMembership)
        .filter(models.GroupMembership.group_id == inv.group_id,
                models.GroupMembership.user_id == user.id)
        .first()
    )
    if not existing:
        db.add(models.GroupMembership(group_id=inv.group_id, user_id=user.id, role=models.GroupRole.MEMBER, is_active=True))
    else:
        existing.is_active = True

    inv.status = models.InviteStatus.ACCEPTED
    inv.accepted_by_user_id = user.id
    inv.responded_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "JOINED", "group_id": inv.group_id}

# ----------------------------
# CHORE TYPE APIs
# ----------------------------
@app.post("/api/v1/groups/{group_id}/chore-types")
def create_chore_type(group_id: int, payload: ChoreTypeCreate, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    ct = models.ChoreType(
        group_id=group_id,
        name=payload.name,
        description=payload.description,
        is_active=True,
    )
    db.add(ct)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail="Chore type name already exists in this group")

    db.refresh(ct)
    return {"id": ct.id, "name": ct.name, "description": ct.description}


# ----------------------------
# ROTATION PLAN APIs (Round Robin)
# ----------------------------
@app.post("/api/v1/groups/{group_id}/plans/rotation")
def create_rotation_plan(group_id: int, payload: RotationPlanCreate, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    # Validate chore_type belongs to group
    chore = (
        db.query(models.ChoreType)
        .filter(models.ChoreType.id == payload.chore_type_id, models.ChoreType.group_id == group_id)
        .first()
    )
    if not chore:
        raise HTTPException(status_code=404, detail="Chore type not found in this group")

    # Validate participants belong to group
    member_ids = set(_group_member_user_ids(db, group_id))
    for p in payload.participants:
        if p.user_id not in member_ids:
            raise HTTPException(status_code=400, detail=f"user_id {p.user_id} is not a member of the group")

    # Create plan
    plan = models.Plan(
        group_id=group_id,
        chore_type_id=payload.chore_type_id,
        plan_type=models.PlanType.ROTATION,
        name=payload.name,
        is_active=True,
        is_paused=False,
        timezone=payload.timezone,
        rotation_current_index=0,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)

    # Store ordered participants
    for p in payload.participants:
        db.add(models.PlanParticipant(plan_id=plan.id, user_id=p.user_id, position=p.position, is_active=True))
    db.commit()

    # Create first assignment
    due_at = payload.first_due_at or datetime.now(timezone.utc)
    first_assignee = sorted(payload.participants, key=lambda x: x.position)[0].user_id

    assignment = models.Assignment(
        group_id=group_id,
        plan_id=plan.id,
        chore_type_id=payload.chore_type_id,
        assigned_to_user_id=first_assignee,
        due_at=due_at,
        status=models.AssignmentStatus.PENDING,
        source="ROTATION",
    )
    db.add(assignment)
    db.commit()
    db.refresh(assignment)

    return {"plan_id": plan.id, "first_assignment_id": assignment.id, "assigned_to_user_id": first_assignee}


@app.post("/api/v1/assignments/{assignment_id}/complete")
async def complete_assignment(
    assignment_id: int,
    payload: AssignmentCompleteIn,
    user: user_dependency,
    db: db_dependency,
):
    """
    Completes an assignment, writes Completion audit, and if ROTATION plan:
    advances the plan pointer (transaction-safe) + creates the next assignment.
    """
    assignment = (
        db.query(models.Assignment)
        .filter(models.Assignment.id == assignment_id)
        .with_for_update()
        .first()
    )
    if not assignment:
        raise HTTPException(status_code=404, detail="Assignment not found")

    membership = require_group_role(db, assignment.group_id, user.id, roles=[models.GroupRole.ADMIN, models.GroupRole.MEMBER])

    # Optional rule: only assigned user can complete (admins can complete anything)
    if membership.role != models.GroupRole.ADMIN and assignment.assigned_to_user_id and assignment.assigned_to_user_id != user.id:
        raise HTTPException(status_code=403, detail="Only assigned user (or admin) can complete this task")

    if assignment.status != models.AssignmentStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Assignment is {assignment.status}")

    # Mark complete + audit
    assignment.status = models.AssignmentStatus.COMPLETED
    assignment.completed_at = datetime.now(timezone.utc)
    assignment.notes = payload.notes

    completion = models.Completion(
        assignment_id=assignment.id,
        group_id=assignment.group_id,
        plan_id=assignment.plan_id,
        completed_by_user_id=user.id,
        completed_at=datetime.now(timezone.utc),
        notes=payload.notes,
        photo_url=payload.photo_url,
    )
    db.add(completion)

    # Lock plan for rotation advance
    plan = (
        db.query(models.Plan)
        .filter(models.Plan.id == assignment.plan_id)
        .with_for_update()
        .first()
    )

    next_assignment_id = None
    next_user_id = None

    if plan and plan.plan_type == models.PlanType.ROTATION and plan.is_active and not plan.is_paused:
        participants = (
            db.query(models.PlanParticipant)
            .filter(models.PlanParticipant.plan_id == plan.id, models.PlanParticipant.is_active == True)
            .order_by(models.PlanParticipant.position.asc())
            .all()
        )
        if participants:
            n = len(participants)
            plan.rotation_current_index = (plan.rotation_current_index + 1) % n
            next_user_id = participants[plan.rotation_current_index].user_id

            next_assignment = models.Assignment(
                group_id=assignment.group_id,
                plan_id=plan.id,
                chore_type_id=assignment.chore_type_id,
                assigned_to_user_id=next_user_id,
                due_at=datetime.now(timezone.utc),
                status=models.AssignmentStatus.PENDING,
                source="ROTATION",
            )
            db.add(next_assignment)
            db.flush()
            next_assignment_id = next_assignment.id

    db.commit()

    # Notify group + websocket
    title = "Chore completed"
    body = (
        f"User {user.id} completed the chore. Next up: user {next_user_id}"
        if next_user_id
        else f"User {user.id} completed the chore."
    )
    await notify_group(
        db=db,
        group_id=assignment.group_id,
        notif_type="chore_completed",
        title=title,
        body=body,
        data={
            "assignment_id": assignment.id,
            "plan_id": assignment.plan_id,
            "completed_by_user_id": user.id,
            "next_assigned_user_id": next_user_id,
            "next_assignment_id": next_assignment_id,
        },
    )

    return {
        "status": "COMPLETED",
        "assignment_id": assignment.id,
        "next_assigned_user_id": next_user_id,
        "next_assignment_id": next_assignment_id,
    }


# ----------------------------
# SCHEDULED PLAN APIs (Premium/Trial gated)
# ----------------------------
@app.post("/api/v1/groups/{group_id}/plans/scheduled")
def create_scheduled_plan(group_id: int, payload: ScheduledPlanCreate, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])
    require_premium_or_trial(user)

    # Validate chore_type belongs to group
    chore = (
        db.query(models.ChoreType)
        .filter(models.ChoreType.id == payload.chore_type_id, models.ChoreType.group_id == group_id)
        .first()
    )
    if not chore:
        raise HTTPException(status_code=404, detail="Chore type not found in this group")

    plan = models.Plan(
        group_id=group_id,
        chore_type_id=payload.chore_type_id,
        plan_type=models.PlanType.SCHEDULED,
        name=payload.name,
        is_active=True,
        is_paused=False,
        timezone=payload.timezone,
        schedule_frequency=payload.frequency,
        interval_days=payload.interval_days,
        due_time=payload.due_time,
        schedule_config=None,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)

    # store schedule rules
    for r in payload.rules:
        db.add(
            models.ScheduleRule(
                plan_id=plan.id,
                user_id=r.user_id,
                day_of_week=r.day_of_week,
                day_of_month=r.day_of_month,
                rule_config=None,
            )
        )
    member_ids = set(_group_member_user_ids(db, group_id))
    for r in payload.rules:
        if r.user_id not in member_ids:
            raise HTTPException(status_code=400, detail=f"user_id {r.user_id} is not a member of the group")
    db.commit()
 

    # NOTE: actual assignment generation happens via scheduler job (APScheduler) later.
    return {"plan_id": plan.id, "status": "CREATED"}


# ----------------------------
# IN-HOUSE CALENDAR APIs (Assignments are the calendar)
# ----------------------------
@app.get("/api/v1/groups/{group_id}/calendar")
def get_calendar(group_id: int, start: datetime, end: datetime, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN, models.GroupRole.MEMBER])

    items = (
        db.query(models.Assignment)
        .filter(
            models.Assignment.group_id == group_id,
            models.Assignment.due_at >= start,
            models.Assignment.due_at < end,
        )
        .order_by(models.Assignment.due_at.asc())
        .all()
    )

    return [
        {
            "id": a.id,
            "plan_id": a.plan_id,
            "chore_type_id": a.chore_type_id,
            "assigned_to_user_id": a.assigned_to_user_id,
            "due_at": a.due_at.isoformat(),
            "status": a.status,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        }
        for a in items
    ]


# ----------------------------
# INSIGHTS APIs (basic aggregates)
# ----------------------------
@app.get("/api/v1/groups/{group_id}/insights/completions/monthly")
def monthly_completions(group_id: int, year: int, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN, models.GroupRole.MEMBER])

    start = datetime(year, 1, 1, tzinfo=timezone.utc)
    end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)

    rows = (
        db.query(
            func.date_trunc("month", models.Completion.completed_at).label("month"),
            func.count(models.Completion.id).label("count"),
        )
        .filter(
            models.Completion.group_id == group_id,
            models.Completion.completed_at >= start,
            models.Completion.completed_at < end,
        )
        .group_by("month")
        .order_by("month")
        .all()
    )

    return [{"month": r.month.date().isoformat(), "count": int(r.count)} for r in rows]


# ----------------------------
# WEBSOCKET ENDPOINT
# Client connects: ws://host/api/v1/ws?token=<access_token>
# ----------------------------
@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket, token: str):
    db = SessionLocal()
    user_id = None
    try:
        token_hash = _sha256(token)
        token_row = (
            db.query(models.RefreshToken)
            .filter(
                models.RefreshToken.token_hash == token_hash,
                models.RefreshToken.revoked_at.is_(None),
                models.RefreshToken.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )
        if not token_row:
            await websocket.close(code=1008)
            return

        user_id = token_row.user_id
        await ws_manager.connect(user_id, websocket)

        while True:
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if user_id is not None:
            ws_manager.disconnect(user_id, websocket)
        db.close()

def _active_admin_count(db: Session, group_id: int) -> int:
    return (
        db.query(models.GroupMembership.id)
        .filter(
            models.GroupMembership.group_id == group_id,
            models.GroupMembership.is_active == True,
            models.GroupMembership.role == models.GroupRole.ADMIN,
        )
        .count()
    )

@app.get("/api/v1/groups/{group_id}/members", response_model=list[MemberOut])
def list_members(group_id: int, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    rows = (
        db.query(models.GroupMembership, models.User)
        .join(models.User, models.User.id == models.GroupMembership.user_id)
        .filter(models.GroupMembership.group_id == group_id)
        .order_by(models.GroupMembership.joined_at.asc())
        .all()
    )

    return [
        MemberOut(
            user_id=m.user_id,
            display_name=u.display_name,
            role=m.role,
            joined_at=m.joined_at,
            is_active=m.is_active,
        )
        for (m, u) in rows
    ]


@app.patch("/api/v1/groups/{group_id}/members/{member_user_id}")
def update_member(group_id: int, member_user_id: int, payload: MemberUpdateIn, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    m = (
        db.query(models.GroupMembership)
        .filter(models.GroupMembership.group_id == group_id,
                models.GroupMembership.user_id == member_user_id)
        .first()
    )
    if not m:
        raise HTTPException(status_code=404, detail="Member not found")

    # prevent removing/demoting the last admin
    if m.role == models.GroupRole.ADMIN:
        will_deactivate = (payload.is_active is False)
        will_demote = (payload.role == models.GroupRole.MEMBER)
        if (will_deactivate or will_demote) and _active_admin_count(db, group_id) <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove/demote the last admin")

    if payload.role is not None:
        m.role = payload.role
    if payload.is_active is not None:
        m.is_active = payload.is_active

    db.commit()
    return {"status": "UPDATED"}


@app.delete("/api/v1/groups/{group_id}/members/{member_user_id}")
def remove_member(group_id: int, member_user_id: int, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    m = (
        db.query(models.GroupMembership)
        .filter(models.GroupMembership.group_id == group_id,
                models.GroupMembership.user_id == member_user_id,
                models.GroupMembership.is_active == True)
        .first()
    )
    if not m:
        raise HTTPException(status_code=404, detail="Active member not found")

    if m.role == models.GroupRole.ADMIN and _active_admin_count(db, group_id) <= 1:
        raise HTTPException(status_code=400, detail="Cannot remove the last admin")

    m.is_active = False
    db.commit()
    return {"status": "REMOVED"}


@app.get("/api/v1/groups/{group_id}/invites")
def list_invites(group_id: int, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    invs = (
        db.query(models.Invitation)
        .filter(models.Invitation.group_id == group_id)
        .order_by(models.Invitation.created_at.desc())
        .all()
    )

    return [
        {
            "id": i.id,
            "invitee_email": i.invitee_email,
            "invitee_phone_e164": i.invitee_phone_e164,
            "status": i.status,
            "expires_at": i.expires_at.isoformat(),
            "responded_at": i.responded_at.isoformat() if i.responded_at else None,
        }
        for i in invs
    ]


@app.post("/api/v1/groups/{group_id}/invites/{invite_id}/cancel")
def cancel_invite(group_id: int, invite_id: int, user: user_dependency, db: db_dependency):
    require_group_role(db, group_id, user.id, roles=[models.GroupRole.ADMIN])

    inv = (
        db.query(models.Invitation)
        .filter(models.Invitation.group_id == group_id,
                models.Invitation.id == invite_id)
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Invite not found")

    if inv.status != models.InviteStatus.PENDING:
        raise HTTPException(status_code=400, detail=f"Invite is {inv.status}")

    inv.status = models.InviteStatus.CANCELLED
    inv.responded_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "CANCELLED"}
