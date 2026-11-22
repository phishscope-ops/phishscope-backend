"""Pydantic contracts - شكل البيانات الثابت بين التطبيق والباك إند (Data Contracts)."""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import ScanStatus, ScanType, Severity, Verdict


# ---------- auth ----------
class RegisterIn(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=10, max_length=128)
    full_name: str = Field(default="", max_length=200)


class LoginIn(BaseModel):
    email: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class ProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    full_name: str
    role: str
    created_at: datetime


class ProfilePatch(BaseModel):
    full_name: str | None = Field(default=None, max_length=200)
    password: str | None = Field(default=None, min_length=10, max_length=128)


# ---------- analysis ----------
class AnalyzeIn(BaseModel):
    content: str = Field(min_length=1, max_length=20_000)
    # المستخدم مش بيختار النوع (Classification تلقائي)، بس ممكن يحدده يدوي من خيار متقدم
    input_type: ScanType | None = None


class AnalyzeOut(BaseModel):
    analysis_id: uuid.UUID
    status: ScanStatus


class EvidenceOut(BaseModel):
    source: str
    provider: str | None
    evidence_type: str
    state: str
    data: dict
    weight: int


class ResultOut(BaseModel):
    """عقدة الـ Result من دليل الفريق."""
    analysis_id: uuid.UUID
    status: ScanStatus
    input_type: ScanType | None = None
    risk_score: int | None = None
    severity: Severity | None = None
    verdict: Verdict | None = None
    was_blocked: bool | None = None
    findings: list = []
    evidence: list[EvidenceOut] = []
    iocs: list = []
    recommended_actions: list[str] = []
    threat_type: str | None = None
    threat_label: str | None = None
    explanation: str | None = None
    created_at: datetime | None = None
    completed_at: datetime | None = None


class HistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    input_type: ScanType
    status: ScanStatus
    risk_score: int | None
    severity: Severity | None
    verdict: Verdict | None
    threat_type: str | None = None
    created_at: datetime


class HistoryOut(BaseModel):
    items: list[HistoryItem]
    total: int
    page: int
    page_size: int


# ---------- dashboard / inbox / devices ----------
class DashboardStats(BaseModel):
    total_scans: int
    safe_count: int
    suspicious_count: int
    malicious_count: int
    unknown_count: int
    last_30d: int


class InboxItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    alert_id: uuid.UUID | None
    title: str
    body: str
    severity: Severity | None
    is_read: bool
    created_at: datetime


class DeviceIn(BaseModel):
    push_token: str = Field(min_length=10, max_length=512)
    platform: str = Field(default="android", pattern="^(android|ios)$")
