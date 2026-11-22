"""SQLAlchemy models - مرآة phishscope-schema.sql.

على PostgreSQL الـ schema.sql هو صاحب الـ DDL (enums حقيقية + RLS + triggers).
على SQLite (dev) SQLAlchemy بيبني جداول مكافئة (enum كـ VARCHAR+CHECK).
"""
import enum
import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class GUID(sa.types.TypeDecorator):
    """uuid يشتغل على الاتنين: UUID على PG و CHAR(36) على SQLite."""
    impl = sa.CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(sa.CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        return value if dialect.name == "postgresql" else str(value)

    def process_result_value(self, value, dialect):
        return value if value is None or isinstance(value, uuid.UUID) else uuid.UUID(value)


class ScanType(str, enum.Enum):
    url = "url"; email = "email"; sms = "sms"; qr = "qr"; domain = "domain"; ip = "ip"


class ScanStatus(str, enum.Enum):
    pending = "pending"; processing = "processing"; done = "done"; failed = "failed"


class Verdict(str, enum.Enum):
    SAFE = "SAFE"; LOW_RISK = "LOW_RISK"; SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"; MALICIOUS = "MALICIOUS"; INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class Severity(str, enum.Enum):
    low = "low"; medium = "medium"; high = "high"; critical = "critical"


class UserRole(str, enum.Enum):
    user = "user"; analyst = "analyst"; admin = "admin"


class EvidenceSource(str, enum.Enum):
    static_analysis = "static_analysis"; threat_intel = "threat_intel"
    ml_model = "ml_model"; heuristic = "heuristic"; manual = "manual"


class EvidenceState(str, enum.Enum):
    confirmed = "confirmed"; inconclusive = "inconclusive"
    conflicting = "conflicting"; unavailable = "unavailable"


class IocType(str, enum.Enum):
    url = "url"; domain = "domain"; ip = "ip"; email = "email"; hash = "hash"


def _enum(e, name):
    return sa.Enum(e, name=name, native_enum=False, validate_strings=True,
                   create_constraint=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(sa.String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(sa.Text)
    full_name: Mapped[str] = mapped_column(sa.Text, default="")
    role: Mapped[UserRole] = mapped_column(_enum(UserRole, "user_role"), default=UserRole.user)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    failed_logins: Mapped[int] = mapped_column(sa.SmallInteger, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())

    analyses: Mapped[list["Analysis"]] = relationship(back_populates="user")


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[bytes] = mapped_column(sa.LargeBinary(32), unique=True)
    user_agent: Mapped[str | None] = mapped_column(sa.Text)
    ip: Mapped[str | None] = mapped_column(sa.String(45))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"))
    token_hash: Mapped[bytes] = mapped_column(sa.LargeBinary(32), unique=True)
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="SET NULL"))
    input_type: Mapped[ScanType] = mapped_column(_enum(ScanType, "scan_type"))
    raw_input: Mapped[str] = mapped_column(sa.Text)
    normalized_input: Mapped[str] = mapped_column(sa.Text)
    request_hash: Mapped[bytes] = mapped_column(sa.LargeBinary(32), index=True)
    status: Mapped[ScanStatus] = mapped_column(_enum(ScanStatus, "scan_status"), default=ScanStatus.pending, index=True)
    risk_score: Mapped[int | None] = mapped_column(sa.SmallInteger)
    severity: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity"))
    verdict: Mapped[Verdict | None] = mapped_column(_enum(Verdict, "verdict"))
    # على PG العمود ده generated (risk_score >= 80) زي قاعدة معن
    was_blocked: Mapped[bool | None] = mapped_column(sa.Boolean, sa.Computed("risk_score >= 80"))
    redirect_chain: Mapped[list] = mapped_column(sa.JSON, default=list)
    findings: Mapped[list] = mapped_column(sa.JSON, default=list)
    iocs: Mapped[list] = mapped_column(sa.JSON, default=list)
    recommended_action: Mapped[str | None] = mapped_column(sa.Text)
    threat_type: Mapped[str | None] = mapped_column(sa.Text)
    explanation: Mapped[str | None] = mapped_column(sa.Text)
    error_message: Mapped[str | None] = mapped_column(sa.Text)
    processing_ms: Mapped[int | None] = mapped_column(sa.Integer)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now(), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped[User | None] = relationship(back_populates="analyses")
    evidence: Mapped[list["AnalysisEvidence"]] = relationship(back_populates="analysis", cascade="all, delete-orphan")


class AnalysisEvidence(Base):
    __tablename__ = "analysis_evidence"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    source: Mapped[EvidenceSource] = mapped_column(_enum(EvidenceSource, "evidence_source"))
    provider: Mapped[str | None] = mapped_column(sa.String(50))
    evidence_type: Mapped[str] = mapped_column(sa.String(100))
    state: Mapped[EvidenceState] = mapped_column(_enum(EvidenceState, "evidence_state"), default=EvidenceState.confirmed)
    data: Mapped[dict] = mapped_column(sa.JSON)
    weight: Mapped[int] = mapped_column(sa.SmallInteger, default=0)
    content_hash: Mapped[bytes] = mapped_column(sa.LargeBinary(32))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())

    analysis: Mapped[Analysis] = relationship(back_populates="evidence")


class ModelRegistry(Base):
    __tablename__ = "model_registry"
    __table_args__ = (sa.UniqueConstraint("name", "version"),)
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(sa.String(100))
    version: Mapped[str] = mapped_column(sa.String(50))
    task: Mapped[ScanType] = mapped_column(_enum(ScanType, "scan_type"))
    framework: Mapped[str] = mapped_column(sa.String(50))
    artifact_uri: Mapped[str] = mapped_column(sa.Text)
    trained_on: Mapped[str | None] = mapped_column(sa.Text)
    metrics: Mapped[dict] = mapped_column(sa.JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class MLPrediction(Base):
    __tablename__ = "ml_predictions"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="CASCADE"), index=True)
    model_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("model_registry.id"))
    label: Mapped[str] = mapped_column(sa.String(50))
    probability: Mapped[float] = mapped_column(sa.Numeric(5, 4))
    threshold: Mapped[float] = mapped_column(sa.Numeric(5, 4))
    features: Mapped[dict | None] = mapped_column(sa.JSON)
    latency_ms: Mapped[int | None] = mapped_column(sa.Integer)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="SET NULL"))
    original_url: Mapped[str] = mapped_column(sa.Text)
    final_url: Mapped[str | None] = mapped_column(sa.Text)
    was_blocked: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    block_reason: Mapped[str | None] = mapped_column(sa.Text)
    redirect_chain: Mapped[list] = mapped_column(sa.JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class AutoScan(Base):
    __tablename__ = "auto_scans"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(sa.Enum("sms", "email", name="source_type", native_enum=False))
    content: Mapped[str] = mapped_column(sa.Text)
    extracted_urls: Mapped[list] = mapped_column(sa.JSON, default=list)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="SET NULL"))
    verdict: Mapped[Verdict | None] = mapped_column(_enum(Verdict, "verdict"))
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class MessageInbox(Base):
    __tablename__ = "message_inbox"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    alert_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(sa.Text)
    body: Mapped[str] = mapped_column(sa.Text, default="")
    severity: Mapped[Severity | None] = mapped_column(_enum(Severity, "severity"))
    is_read: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())
    read_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"
    provider: Mapped[str] = mapped_column(sa.String(50), primary_key=True)
    indicator: Mapped[str] = mapped_column(sa.Text, primary_key=True)
    indicator_type: Mapped[IocType] = mapped_column(_enum(IocType, "ioc_type"))
    verdict: Mapped[Verdict | None] = mapped_column(_enum(Verdict, "verdict"))
    raw: Mapped[dict | None] = mapped_column(sa.JSON)
    fetched_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), index=True)


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (sa.Index("idx_iocs_value", "type", "value"),)
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="CASCADE"))
    type: Mapped[IocType] = mapped_column(_enum(IocType, "ioc_type"))
    value: Mapped[str] = mapped_column(sa.Text)  # defanged دايماً
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (sa.UniqueConstraint("user_id", "push_token"),)
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"))
    push_token: Mapped[str] = mapped_column(sa.Text)
    platform: Mapped[str] = mapped_column(sa.String(20), default="android")
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())
    last_seen_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="SET NULL"))
    format: Mapped[str] = mapped_column(sa.String(10), default="json")
    storage_uri: Mapped[str | None] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(sa.BigInteger, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(sa.String(100), index=True)
    entity: Mapped[str | None] = mapped_column(sa.String(50))
    entity_id: Mapped[str | None] = mapped_column(sa.String(64))
    ip: Mapped[str | None] = mapped_column(sa.String(45))
    user_agent: Mapped[str | None] = mapped_column(sa.Text)
    metadata_: Mapped[dict] = mapped_column("metadata", sa.JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now(), index=True)


def audit(db, action: str, user_id: uuid.UUID | None = None, entity: str | None = None,
          entity_id: str | None = None, ip: str | None = None, **meta) -> None:
    """Security Audit Logging (متطلب 3). append-only على PG بفضل الـ triggers."""
    db.add(AuditLog(user_id=user_id, action=action, entity=entity,
                    entity_id=entity_id, ip=ip, metadata_=meta))


class AlertPrefs(Base):
    """تفضيلات التنبيه لكل مستخدم (مجاني ودائم: in-app + Telegram + Slack webhook)."""
    __tablename__ = "alert_prefs"
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    threshold: Mapped[int] = mapped_column(sa.SmallInteger, default=70)
    in_app: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    telegram_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True)
    telegram_chat_id: Mapped[str | None] = mapped_column(sa.String(32))
    slack_webhook_url: Mapped[str | None] = mapped_column(sa.Text)
    slack_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    n8n_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[uuid.UUID] = mapped_column(GUID, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(GUID, sa.ForeignKey("analyses.id", ondelete="SET NULL"))
    risk_score: Mapped[int] = mapped_column(sa.SmallInteger)
    verdict: Mapped[str | None] = mapped_column(sa.String(32))
    title: Mapped[str] = mapped_column(sa.Text, default="")
    channels: Mapped[list] = mapped_column(sa.JSON, default=list)  # القنوات اللي اتبعتت فعلاً
    read: Mapped[bool] = mapped_column(sa.Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), server_default=sa.func.now(), index=True)


class TelegramLinkCode(Base):
    """كود ربط تيليجرام: استخدام واحد، صلاحية ١٥ دقيقة."""
    __tablename__ = "telegram_link_codes"
    code: Mapped[str] = mapped_column(sa.String(16), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(GUID, sa.ForeignKey("users.id", ondelete="CASCADE"))
    expires_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
