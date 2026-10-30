"""
SQLAlchemy ORM models for XGuard.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey
from app.database.session import Base


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    url = Column(Text, nullable=False)
    hostname = Column(String(255), index=True)
    registered_domain = Column(String(255), index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), index=True)
    predicted_category = Column(String(64), index=True)
    model_probability = Column(Float, nullable=True)
    model_version = Column(String(32), nullable=True)
    evidence_json = Column(Text, default="[]")
    intelligence_json = Column(Text, default="[]")
    checks_completed_json = Column(Text, default="[]")
    checks_failed_json = Column(Text, default="[]")
    recommended_action = Column(String(32))
    scan_duration_ms = Column(Float, default=0.0)
    user_action = Column(String(32), default="pending")  # allowed, warned, blocked, overridden


class RedirectRecord(Base):
    __tablename__ = "redirect_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(64), ForeignKey("scan_records.id", ondelete="CASCADE"), index=True)
    hop_order = Column(Integer, nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255))
    status_code = Column(Integer, nullable=True)
    is_cross_domain = Column(Boolean, default=False)
    resolved_ip = Column(String(64), nullable=True)


class FeedbackRecord(Base):
    __tablename__ = "feedback_records"

    id = Column(String(64), primary_key=True)
    scan_id = Column(String(64), nullable=True, index=True)
    url = Column(Text, nullable=False)
    feedback_type = Column(String(32), nullable=False)
    user_comment = Column(Text, nullable=True)
    consent_status = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class SettingRecord(Base):
    __tablename__ = "user_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False)
