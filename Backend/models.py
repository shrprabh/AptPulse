# app/models.py
from __future__ import annotations

import enum
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from database import Base


# ----------------------------
# Enums
# ----------------------------

class IdentityProvider(str, enum.Enum):
    EMAIL = "EMAIL"
    GOOGLE = "GOOGLE"
    PHONE = "PHONE"


class GroupRole(str, enum.Enum):
    ADMIN = "ADMIN"
    MEMBER = "MEMBER"


class InviteStatus(str, enum.Enum):
    PENDING = "PENDING"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class PlanType(str, enum.Enum):
    ROTATION = "ROTATION"     # round-robin queue
    SCHEDULED = "SCHEDULED"   # calendar recurrence


class ScheduleFrequency(str, enum.Enum):
    WEEKLY = "WEEKLY"
    BIWEEKLY = "BIWEEKLY"
    MONTHLY = "MONTHLY"
    EVERY_N_DAYS = "EVERY_N_DAYS"


class AssignmentStatus(str, enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    OVERDUE = "OVERDUE"


class NotificationChannel(str, enum.Enum):
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"
    SMS = "SMS"  # optional; stub for beta


class NotificationStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    SENT = "SENT"
    FAILED = "FAILED"
    READ = "READ"


# ----------------------------
# Common mixins
# ----------------------------

class TimestampMixin:
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


# ----------------------------
# Users + Auth
# ----------------------------

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    display_name = Column(String(120), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)

    # 14-day trial enforcement
    trial_end_at = Column(DateTime(timezone=True), nullable=True)
    is_premium = Column(Boolean, default=False, nullable=False)

    # Relationships
    identities = relationship("Identity", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    memberships = relationship("GroupMembership", back_populates="user", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="user", cascade="all, delete-orphan")
    notification_prefs = relationship("NotificationPreference", back_populates="user", cascade="all, delete-orphan")


class Identity(Base, TimestampMixin):
    """
    Stores login identities for a user:
    - EMAIL: email + password_hash + is_verified
    - GOOGLE: provider_user_id (sub) + is_verified
    - PHONE: phone_e164 + is_verified
    """
    __tablename__ = "identities"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(Enum(IdentityProvider, name="identity_provider"), nullable=False, index=True)

    # Email identity
    email = Column(String(320), nullable=True, index=True)
    password_hash = Column(String(255), nullable=True)

    # Phone identity (E.164)
    phone_e164 = Column(String(32), nullable=True, index=True)

    # Google identity (JWT "sub")
    provider_user_id = Column(String(255), nullable=True, index=True)

    is_verified = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="identities")

    __table_args__ = (
        # Must have at least one identifier depending on provider
        CheckConstraint(
            "(provider != 'EMAIL' OR email IS NOT NULL) "
            "AND (provider != 'PHONE' OR phone_e164 IS NOT NULL) "
            "AND (provider != 'GOOGLE' OR provider_user_id IS NOT NULL)",
            name="ck_identity_provider_fields",
        ),
        # Uniqueness per provider
        UniqueConstraint("provider", "email", name="uq_identity_provider_email"),
        UniqueConstraint("provider", "phone_e164", name="uq_identity_provider_phone"),
        UniqueConstraint("provider", "provider_user_id", name="uq_identity_provider_provider_user_id"),
    )


class EmailVerificationToken(Base, TimestampMixin):
    __tablename__ = "email_verification_tokens"

    id = Column(Integer, primary_key=True, index=True)
    identity_id = Column(Integer, ForeignKey("identities.id", ondelete="CASCADE"), nullable=False, index=True)

    token = Column(String(255), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)

    identity = relationship("Identity")


class RefreshToken(Base, TimestampMixin):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Store a HASH of the refresh token for security (don’t store raw token)
    token_hash = Column(String(255), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    revoked_at = Column(DateTime(timezone=True), nullable=True)

    user_agent = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)

    user = relationship("User", back_populates="refresh_tokens")


class OTPCode(Base, TimestampMixin):
    """
    DEV-only phone OTP storage. In production you’d send OTP via SMS gateway.
    Store code_hash (not raw code), enforce expiry/attempt limits.
    """
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    phone_e164 = Column(String(32), nullable=False, index=True)

    code_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)

    attempts = Column(Integer, default=0, nullable=False)

    __table_args__ = (
        Index("ix_otp_phone_active", "phone_e164", "expires_at"),
    )


# ----------------------------
# Groups + Membership + Invites
# ----------------------------

class Group(Base, TimestampMixin):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False, index=True)

    created_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    memberships = relationship("GroupMembership", back_populates="group", cascade="all, delete-orphan")
    invitations = relationship("Invitation", back_populates="group", cascade="all, delete-orphan")

    chore_types = relationship("ChoreType", back_populates="group", cascade="all, delete-orphan")
    plans = relationship("Plan", back_populates="group", cascade="all, delete-orphan")
    assignments = relationship("Assignment", back_populates="group", cascade="all, delete-orphan")


class GroupMembership(Base, TimestampMixin):
    __tablename__ = "group_memberships"

    id = Column(Integer, primary_key=True, index=True)

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    role = Column(Enum(GroupRole, name="group_role"), nullable=False, default=GroupRole.MEMBER)
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)

    group = relationship("Group", back_populates="memberships")
    user = relationship("User", back_populates="memberships")

    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_membership_group_user"),
        Index("ix_membership_group_role", "group_id", "role"),
    )


class Invitation(Base, TimestampMixin):
    __tablename__ = "invitations"

    id = Column(Integer, primary_key=True, index=True)

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    invited_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    # invite target (one of these must be present)
    invitee_email = Column(String(320), nullable=True, index=True)
    invitee_phone_e164 = Column(String(32), nullable=True, index=True)

    token = Column(String(255), nullable=False, unique=True, index=True)
    status = Column(Enum(InviteStatus, name="invite_status"), nullable=False, default=InviteStatus.PENDING, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    accepted_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    responded_at = Column(DateTime(timezone=True), nullable=True)

    group = relationship("Group", back_populates="invitations")

    __table_args__ = (
        CheckConstraint(
            "(invitee_email IS NOT NULL) OR (invitee_phone_e164 IS NOT NULL)",
            name="ck_invitation_has_target",
        ),
        Index("ix_invite_group_status", "group_id", "status"),
    )


# ----------------------------
# Chores + Plans
# ----------------------------

class ChoreType(Base, TimestampMixin):
    __tablename__ = "chore_types"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(120), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    group = relationship("Group", back_populates="chore_types")
    plans = relationship("Plan", back_populates="chore_type", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("group_id", "name", name="uq_choretype_group_name"),
    )


class Plan(Base, TimestampMixin):
    """
    A Plan defines how assignments are produced:
    - ROTATION: ordered participants, round-robin
    - SCHEDULED: recurrence rules generate Assignment rows
    """
    __tablename__ = "plans"

    id = Column(Integer, primary_key=True, index=True)

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    chore_type_id = Column(Integer, ForeignKey("chore_types.id", ondelete="CASCADE"), nullable=False, index=True)

    plan_type = Column(Enum(PlanType, name="plan_type"), nullable=False, index=True)
    name = Column(String(120), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    is_paused = Column(Boolean, default=False, nullable=False)

    # for both types (optional but useful)
    timezone = Column(String(64), nullable=True)  # e.g., "America/Chicago"
    start_at = Column(DateTime(timezone=True), nullable=True)

    # ROTATION-specific state (server advances this)
    rotation_current_index = Column(Integer, default=0, nullable=False)

    # SCHEDULED-specific configuration
    schedule_frequency = Column(Enum(ScheduleFrequency, name="schedule_frequency"), nullable=True, index=True)
    interval_days = Column(Integer, nullable=True)      # for EVERY_N_DAYS (e.g., 7 or 14)
    due_time = Column(String(8), nullable=True)         # "HH:MM" (interpreted in plan timezone)
    schedule_config = Column(JSONB, nullable=True)      # flexible JSON for future rules

    group = relationship("Group", back_populates="plans")
    chore_type = relationship("ChoreType", back_populates="plans")

    participants = relationship("PlanParticipant", back_populates="plan", cascade="all, delete-orphan")
    schedule_rules = relationship("ScheduleRule", back_populates="plan", cascade="all, delete-orphan")
    assignments = relationship("Assignment", back_populates="plan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_plan_group_type_active", "group_id", "plan_type", "is_active"),
    )


class PlanParticipant(Base, TimestampMixin):
    """
    Participants for ROTATION plans (ordered by position).
    For scheduled plans, use ScheduleRule instead.
    """
    __tablename__ = "plan_participants"

    id = Column(Integer, primary_key=True, index=True)

    plan_id = Column(Integer, ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    position = Column(Integer, nullable=False)  # 0..n-1 ordering for round-robin
    is_active = Column(Boolean, default=True, nullable=False)

    plan = relationship("Plan", back_populates="participants")
    user = relationship("User")

    __table_args__ = (
        UniqueConstraint("plan_id", "user_id", name="uq_planparticipant_plan_user"),
        UniqueConstraint("plan_id", "position", name="uq_planparticipant_plan_position"),
        Index("ix_planparticipant_plan_position", "plan_id", "position"),
    )


class ScheduleRule(Base, TimestampMixin):
    """
    Rules for SCHEDULED plans:
    Examples:
    - WEEKLY: user_id + day_of_week (0=Mon..6=Sun)
    - MONTHLY: user_id + day_of_month (1..31)
    - BIWEEKLY: same as weekly + config in schedule_config to define week parity
    - EVERY_N_DAYS: can be encoded in plan.interval_days and schedule_config
    """
    __tablename__ = "schedule_rules"

    id = Column(Integer, primary_key=True, index=True)

    plan_id = Column(Integer, ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    day_of_week = Column(Integer, nullable=True)   # 0..6
    day_of_month = Column(Integer, nullable=True)  # 1..31

    rule_config = Column(JSONB, nullable=True)     # flexible (e.g., biweekly parity)

    plan = relationship("Plan", back_populates="schedule_rules")
    user = relationship("User")

    __table_args__ = (
        CheckConstraint(
            "(day_of_week IS NULL OR (day_of_week >= 0 AND day_of_week <= 6))",
            name="ck_schedule_rule_day_of_week_range",
        ),
        CheckConstraint(
            "(day_of_month IS NULL OR (day_of_month >= 1 AND day_of_month <= 31))",
            name="ck_schedule_rule_day_of_month_range",
        ),
        Index("ix_schedule_rule_plan_user", "plan_id", "user_id"),
    )


# ----------------------------
# Assignments + Completions (Calendar in-house)
# ----------------------------

class Assignment(Base, TimestampMixin):
    """
    Concrete occurrence that appears on the in-house calendar.
    Generated by:
    - rotation completion (optional next assignment creation)
    - scheduled plan generator (APScheduler)
    """
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True, index=True)

    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True)
    chore_type_id = Column(Integer, ForeignKey("chore_types.id", ondelete="CASCADE"), nullable=False, index=True)

    assigned_to_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    due_at = Column(DateTime(timezone=True), nullable=False, index=True)
    status = Column(Enum(AssignmentStatus, name="assignment_status"), nullable=False, default=AssignmentStatus.PENDING, index=True)

    completed_at = Column(DateTime(timezone=True), nullable=True)
    notes = Column(Text, nullable=True)

    # helpful for idempotency
    source = Column(String(32), nullable=True)  # e.g., "SCHEDULED_GENERATOR", "ROTATION"

    group = relationship("Group", back_populates="assignments")
    plan = relationship("Plan", back_populates="assignments")
    chore_type = relationship("ChoreType")
    assigned_to = relationship("User")

    completions = relationship("Completion", back_populates="assignment", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assignment_group_due", "group_id", "due_at"),
        Index("ix_assignment_user_due", "assigned_to_user_id", "due_at"),
        # Helps prevent duplicates from schedulers (tune as needed)
        UniqueConstraint("plan_id", "due_at", "assigned_to_user_id", name="uq_assignment_plan_due_user"),
    )


class Completion(Base, TimestampMixin):
    __tablename__ = "completions"

    id = Column(Integer, primary_key=True, index=True)

    assignment_id = Column(Integer, ForeignKey("assignments.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=False, index=True)
    plan_id = Column(Integer, ForeignKey("plans.id", ondelete="CASCADE"), nullable=False, index=True)

    completed_by_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    completed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    notes = Column(Text, nullable=True)
    photo_url = Column(Text, nullable=True)  # optional

    assignment = relationship("Assignment", back_populates="completions")
    completed_by = relationship("User")
    plan = relationship("Plan")


# ----------------------------
# Notifications (In-app + Email + SMS stub)
# ----------------------------

class NotificationPreference(Base, TimestampMixin):
    __tablename__ = "notification_preferences"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    # Optional group-specific prefs (NULL => global default)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)

    in_app_enabled = Column(Boolean, default=True, nullable=False)
    email_enabled = Column(Boolean, default=True, nullable=False)
    sms_enabled = Column(Boolean, default=False, nullable=False)

    # Optional JSON: quiet hours, reminder offsets, etc.
    prefs = Column(JSONB, nullable=True)

    user = relationship("User", back_populates="notification_prefs")
    group = relationship("Group")


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)

    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)

    assignment_id = Column(Integer, ForeignKey("assignments.id", ondelete="SET NULL"), nullable=True, index=True)

    channel = Column(Enum(NotificationChannel, name="notification_channel"), nullable=False, index=True)
    status = Column(Enum(NotificationStatus, name="notification_status"), nullable=False, default=NotificationStatus.QUEUED, index=True)

    notif_type = Column(String(64), nullable=False, index=True)  # e.g., "REMINDER_24H", "CHORE_COMPLETED"
    title = Column(String(200), nullable=True)
    body = Column(Text, nullable=True)

    # Extra payload for client (websocket/in-app UI)
    data = Column(JSONB, nullable=True)

    scheduled_for = Column(DateTime(timezone=True), nullable=True, index=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    read_at = Column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="notifications")
    group = relationship("Group")
    assignment = relationship("Assignment")

    __table_args__ = (
        Index("ix_notification_user_status", "user_id", "status"),
        # Idempotency helper for reminders (tune based on your scheduler design)
        UniqueConstraint("assignment_id", "channel", "notif_type", name="uq_notification_assignment_channel_type"),
    )


# ----------------------------
# Audit Log (optional but helpful)
# ----------------------------

class AuditLog(Base, TimestampMixin):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    actor_user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id", ondelete="CASCADE"), nullable=True, index=True)

    action = Column(String(80), nullable=False, index=True)        # e.g., "PLAN_CREATED", "ROTATION_ADVANCED"
    entity_type = Column(String(80), nullable=True, index=True)    # e.g., "Plan", "Assignment"
    entity_id = Column(Integer, nullable=True, index=True)

    # "metadata" is reserved by SQLAlchemy Declarative, so map it with a safe attribute name.
    event_metadata = Column("metadata", JSONB, nullable=True)

    actor = relationship("User")
    group = relationship("Group")
