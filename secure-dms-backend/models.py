from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False)

    documents = relationship("Document", back_populates="uploaded_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(50), default="Active")
    created_at = Column(DateTime, default=datetime.utcnow)

    documents = relationship("Document", back_populates="case")


class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    document_type = Column(String(100), default="General")
    blob_path = Column(String(500))
    file_hash = Column(String(64), nullable=False)
    status = Column(String(50), default="Verified")
    uploaded_at = Column(DateTime, default=datetime.utcnow)

    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    case = relationship("Case", back_populates="documents")
    uploaded_by_user = relationship("User", back_populates="documents")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(255), nullable=False)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")

class OTPVerification(Base):
    __tablename__ = "otp_verifications"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), nullable=False, index=True)
    otp_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    attempts = Column(Integer, default=0)
    used = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuthenticationThrottle(Base):
    """Persistent per-email counters for login and OTP abuse protection."""

    __tablename__ = "authentication_throttles"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), unique=True, nullable=False, index=True)
    failed_login_count = Column(Integer, default=0, nullable=False)
    login_window_started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    otp_request_count = Column(Integer, default=0, nullable=False)
    otp_window_started_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class SecurityAlert(Base):
    """An actionable integrity incident, kept separately from normal audit history."""

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False, index=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    alert_type = Column(String(80), nullable=False)
    severity = Column(String(20), default="HIGH", nullable=False)
    status = Column(String(20), default="OPEN", nullable=False)
    details = Column(Text, nullable=False)
    expected_hash = Column(String(64), nullable=True)
    observed_hash = Column(String(64), nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
