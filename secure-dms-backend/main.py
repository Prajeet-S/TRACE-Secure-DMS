import secrets
import smtplib
import hmac
import os
import logging
import zipfile
from io import BytesIO
from urllib.parse import unquote
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv


from fastapi import (
    FastAPI,
    Depends,
    UploadFile,
    File,
    Form,
    HTTPException,
    Query,
    Request
)

from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

from database import engine, get_db, Base
from models import User, Case, Document, AuditLog, OTPVerification, AuthenticationThrottle, SecurityAlert
from blockchain import BlockchainBlock, append_document_block, ensure_blockchain_initialized, verify_blockchain, verify_document_block

from passlib.context import CryptContext
from pydantic import BaseModel, validator
from jose import jwt, ExpiredSignatureError, JWTError

import hashlib
import os
import subprocess
import tempfile

load_dotenv()
logger = logging.getLogger("securedms.security")


# =========================================================
# DATABASE
# =========================================================

Base.metadata.create_all(bind=engine)


# =========================================================
# FASTAPI
# =========================================================

app = FastAPI(
    title="Secure Digital Document Management System",
    description="SIH Secure DMS Backend",
    version="1.0.0"
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


# =========================================================
# SECURITY
# =========================================================

pwd_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    deprecated="auto"
)

SECRET_KEY = os.getenv("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing from .env")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "5"))
LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "15"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
OTP_REQUEST_LIMIT = int(os.getenv("OTP_REQUEST_LIMIT", "3"))
OTP_REQUEST_WINDOW_MINUTES = int(os.getenv("OTP_REQUEST_WINDOW_MINUTES", "15"))
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))
EVENT_GRID_WEBHOOK_SECRET = os.getenv("EVENT_GRID_WEBHOOK_SECRET")
INTEGRITY_ALERT_EMAILS_ENABLED = os.getenv("INTEGRITY_ALERT_EMAILS_ENABLED", "true").lower() == "true"

if ACCESS_TOKEN_EXPIRE_MINUTES <= 0 or MAX_UPLOAD_BYTES <= 0:
    raise RuntimeError("Security timeout and upload-size settings must be positive")

security = HTTPBearer()

# =========================================================
# EMAIL / OTP CONFIGURATION
# =========================================================

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_EMAIL = os.getenv("SMTP_EMAIL")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))

if not SMTP_EMAIL or not SMTP_PASSWORD:
    raise RuntimeError("SMTP_EMAIL and SMTP_PASSWORD are missing from .env")


# =========================================================
# AZURE CONFIGURATION
# =========================================================

AZURE_STORAGE_ACCOUNT = "prajeetstorage1"
AZURE_CONTAINER = "files"


# =========================================================
# REQUEST MODELS
# =========================================================

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: str

    @validator("username")
    def validate_username(cls, value):
        value = value.strip()
        if not 3 <= len(value) <= 100:
            raise ValueError("Username must contain 3 to 100 characters")
        return value

    @validator("email")
    def normalize_email(cls, value):
        value = value.strip().lower()
        if len(value) > 150 or "@" not in value or value.startswith("@"):
            raise ValueError("Enter a valid email address")
        return value

    @validator("password")
    def validate_password(cls, value):
        if len(value) < 10 or len(value) > 128:
            raise ValueError("Password must contain 10 to 128 characters")
        return value


class UserLogin(BaseModel):
    email: str
    password: str
    role: str = ""

    @validator("email")
    def normalize_login_email(cls, value):
        return value.strip().lower()

    @validator("password")
    def validate_login_password(cls, value):
        if not value or len(value) > 128:
            raise ValueError("Invalid email or password")
        return value

class DeleteConfirmation(BaseModel):
    password: str

    @validator("password")
    def validate_delete_password(cls, value):
        if not value or len(value) > 128:
            raise ValueError("Invalid password")
        return value

class CaseCreate(BaseModel):
    case_number: str
    title: str
    description: str = ""
    status: str = "Active"

    @validator("case_number", "title")
    def required_case_text(cls, value):
        value = value.strip()
        if not value or len(value) > 255:
            raise ValueError("Value is required and is too long")
        return value

    @validator("description")
    def limit_description(cls, value):
        if len(value) > 10000:
            raise ValueError("Description is too long")
        return value.strip()


class AlertUpdate(BaseModel):
    action: str

    @validator("action")
    def validate_action(cls, value):
        value = value.strip().lower()
        if value not in {"review", "dismiss"}:
            raise ValueError("Action must be review or dismiss")
        return value


ALLOWED_UPLOAD_TYPES = {
    ".pdf": {"application/pdf"},
    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/octet-stream",
    },
    ".txt": {"text/plain", "application/octet-stream"},
    ".jpg": {"image/jpeg", "application/octet-stream"},
    ".jpeg": {"image/jpeg", "application/octet-stream"},
    ".png": {"image/png", "application/octet-stream"},
}

# Administrators must be provisioned by the organization, never self-registered.
PUBLIC_REGISTRATION_ROLES = {
    "Police/Investigator",
    "Lawyer/Legal Officer",
    "Court Authority",
}


# =========================================================
# HELPER - AUDIT LOG
# =========================================================

def create_audit_log(
    db: Session,
    user_id: int,
    action: str,
    details: str
):
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details
    )

    db.add(log)
    db.commit()


def create_security_audit(db: Session, user: User | None, action: str, details: str):
    """Record security outcomes without ever storing secrets, OTPs, or tokens."""
    logger.warning("%s: %s", action, details)
    if user:
        create_audit_log(db, user.id, action, details)


def utc_iso(value: datetime | None):
    if not value:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def serialize_alert(alert: SecurityAlert):
    return {
        "id": alert.id,
        "document_id": alert.document_id,
        "case_id": alert.case_id,
        "user_id": alert.user_id,
        "type": alert.alert_type,
        "severity": alert.severity,
        "status": alert.status,
        "details": alert.details,
        "expected_hash": alert.expected_hash,
        "observed_hash": alert.observed_hash,
        "detected_at": utc_iso(alert.detected_at),
        "resolved_at": utc_iso(alert.resolved_at),
    }


def get_throttle(db: Session, email: str) -> AuthenticationThrottle:
    throttle = db.query(AuthenticationThrottle).filter(
        AuthenticationThrottle.email == email
    ).first()
    if not throttle:
        throttle = AuthenticationThrottle(email=email)
        db.add(throttle)
        db.commit()
        db.refresh(throttle)
    return throttle


def check_login_lock(db: Session, email: str, user: User | None):
    throttle = get_throttle(db, email)
    now = datetime.utcnow()
    if throttle.locked_until and throttle.locked_until > now:
        create_security_audit(
            db, user, "LOGIN_BLOCKED",
            "Login blocked because the account is temporarily locked"
        )
        raise HTTPException(
            status_code=429,
            detail="Too many failed login attempts. Try again later."
        )
    if throttle.locked_until and throttle.locked_until <= now:
        throttle.failed_login_count = 0
        throttle.locked_until = None
        throttle.login_window_started_at = now
        db.commit()


def record_failed_login(db: Session, email: str, user: User | None, reason: str):
    throttle = get_throttle(db, email)
    now = datetime.utcnow()
    if now - throttle.login_window_started_at > timedelta(minutes=LOGIN_WINDOW_MINUTES):
        throttle.failed_login_count = 0
        throttle.login_window_started_at = now
    throttle.failed_login_count += 1
    action = "LOGIN_FAILED"
    if throttle.failed_login_count >= LOGIN_MAX_FAILURES:
        throttle.locked_until = now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
        action = "LOGIN_LOCKED"
    db.commit()
    create_security_audit(db, user, action, reason)


def clear_failed_logins(db: Session, email: str):
    throttle = get_throttle(db, email)
    throttle.failed_login_count = 0
    throttle.locked_until = None
    throttle.login_window_started_at = datetime.utcnow()
    db.commit()


def consume_otp_request(db: Session, email: str, user: User | None):
    throttle = get_throttle(db, email)
    now = datetime.utcnow()
    if now - throttle.otp_window_started_at > timedelta(minutes=OTP_REQUEST_WINDOW_MINUTES):
        throttle.otp_request_count = 0
        throttle.otp_window_started_at = now
    if throttle.otp_request_count >= OTP_REQUEST_LIMIT:
        create_security_audit(
            db, user, "OTP_RATE_LIMITED",
            "OTP request blocked by rate limit"
        )
        raise HTTPException(
            status_code=429,
            detail="Too many OTP requests. Try again later."
        )
    throttle.otp_request_count += 1
    db.commit()


def validate_upload(filename: str | None, content_type: str | None, file_data: bytes):
    if not filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    clean_name = os.path.basename(filename)
    if clean_name != filename or clean_name in {"", ".", ".."}:
        raise HTTPException(status_code=400, detail="Invalid filename")
    if any(ord(character) < 32 for character in clean_name) or len(clean_name) > 200:
        raise HTTPException(status_code=400, detail="Invalid filename")

    extension = os.path.splitext(clean_name)[1].lower()
    if extension not in ALLOWED_UPLOAD_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Allowed: PDF, DOCX, TXT, JPG, PNG."
        )
    if content_type and content_type not in ALLOWED_UPLOAD_TYPES[extension]:
        raise HTTPException(status_code=415, detail="File content type does not match its extension")

    valid_content = (
        (extension == ".pdf" and file_data.startswith(b"%PDF-"))
        or (extension in {".jpg", ".jpeg"} and file_data.startswith(b"\xff\xd8\xff"))
        or (extension == ".png" and file_data.startswith(b"\x89PNG\r\n\x1a\n"))
        or (extension == ".txt" and b"\x00" not in file_data[:8192])
        or (extension == ".docx" and zipfile.is_zipfile(BytesIO(file_data))
            and "[Content_Types].xml" in zipfile.ZipFile(BytesIO(file_data)).namelist())
    )
    if not valid_content:
        raise HTTPException(status_code=415, detail="File content does not match the selected type")
    return clean_name


# =========================================================
# HELPER - CURRENT USER
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        if not isinstance(payload.get("user_id"), int) or not payload.get("email"):
            raise JWTError("Required claims are missing")
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials"
        )


# =========================================================
# HELPER - CHECK CASE OWNERSHIP
# =========================================================

def user_owns_case(
    db: Session,
    case_id: int,
    user_id: int
):
    """
    A case belongs to the user who created it.

    We determine ownership from the CASE_CREATED audit record.
    This avoids changing the existing database structure.
    """

    case = db.query(Case).filter(
        Case.id == case_id
    ).first()

    if not case:
        raise HTTPException(
            status_code=404,
            detail="Case not found"
        )

    ownership = db.query(AuditLog).filter(
        AuditLog.user_id == user_id,
        AuditLog.action == "CASE_CREATED",
        AuditLog.details.like(f"%case {case.case_number}%")
    ).first()

    if not ownership:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this case"
        )

    return case

def ensure_case_active(db: Session, case_id: int, user_id: int):
    case = user_owns_case(
        db,
        case_id,
        user_id
    )

    if case.status == "Closed":
        raise HTTPException(
            status_code=403,
            detail="This case is closed. Its documents are locked until the case is reopened."
        )

    return case
# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return {
        "message": "Secure Digital Document Management System backend is running!",
        "status": "online"
    }


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    allowed_roles = [
        "Police/Investigator",
        "Lawyer/Legal Officer",
        "Court Authority",
        "Administrator"
    ]

    if user.role not in allowed_roles:
        raise HTTPException(
            status_code=400,
            detail="Invalid role"
        )

    if user.role not in PUBLIC_REGISTRATION_ROLES:
        raise HTTPException(
            status_code=403,
            detail="Administrator accounts must be created by an existing system administrator"
        )

    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    hashed_password = pwd_context.hash(user.password)

    new_user = User(
        username=user.username,
        email=user.email,
        password_hash=hashed_password,
        role=user.role
    )

    db.add(new_user)

    try:
        db.commit()
        db.refresh(new_user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail="Could not create user"
        )

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "role": new_user.role
    }

# =========================================================
# OTP SECURITY
# =========================================================

def generate_otp():
    """
    Generate a cryptographically secure 6-digit OTP.
    """
    return f"{secrets.randbelow(1000000):06d}"


def hash_otp(otp: str):
    """Hash OTP using SHA-256 before storing it."""
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def send_otp_email(email: str, otp: str):
    """
    Send OTP to the user's registered email address.
    """

    if not SMTP_EMAIL or not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP_EMAIL and SMTP_PASSWORD must be configured"
        )

    message = EmailMessage()

    message["Subject"] = "TRACE Login OTP"
    message["From"] = SMTP_EMAIL
    message["To"] = email

    message.set_content(
        f"""
TRACE Two-Factor Authentication

Your OTP is:

{otp}

This OTP is valid for {OTP_EXPIRE_MINUTES} minutes.

If you did not attempt to log in, please ignore this email.

TRACE Secure Digital Document Management System
"""
    )

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT
    ) as server:

        server.starttls()

        server.login(
            SMTP_EMAIL,
            SMTP_PASSWORD
        )

        server.send_message(message)


# =========================================================
# DOCUMENT INTEGRITY MONITORING
# =========================================================

def get_blob_sha256(blob_path: str) -> str:
    """Download a blob to a temporary file and return its current SHA-256 hash."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
    try:
        command = [
            "cmd", "/c", "az", "storage", "blob", "download",
            "--account-name", AZURE_STORAGE_ACCOUNT,
            "--container-name", AZURE_CONTAINER,
            "--name", blob_path,
            "--file", temp_file_path,
            "--auth-mode", "login",
            "--overwrite",
        ]
        result = subprocess.run(command, capture_output=True, text=True, shell=False)
        if result.returncode != 0:
            raise RuntimeError("Azure Blob could not be retrieved")
        with open(temp_file_path, "rb") as downloaded_file:
            return hashlib.sha256(downloaded_file.read()).hexdigest()
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


def send_security_alert_email(user: User, document: Document, alert: SecurityAlert):
    """Best-effort notification; failure never hides or rolls back an alert."""
    if not INTEGRITY_ALERT_EMAILS_ENABLED:
        return
    message = EmailMessage()
    message["Subject"] = f"TRACE alert: {alert.alert_type}"
    message["From"] = SMTP_EMAIL
    message["To"] = user.email
    message.set_content(
        f"""TRACE detected a document-integrity incident.

Alert: {alert.alert_type}
Document: {document.filename}
Case ID: {document.case_id}
Severity: {alert.severity}
Time (UTC): {utc_iso(alert.detected_at)}

The document has been marked as TAMPERED/UNAVAILABLE. Review the Security Alerts page and preserve the original evidence.
"""
    )
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(message)
    except Exception:
        logger.exception("Security alert email could not be sent")


def raise_integrity_alert(
    db: Session,
    document: Document,
    alert_type: str,
    details: str,
    observed_hash: str | None = None,
):
    """Create or refresh one open incident per document, then notify its owner."""
    owner = db.query(User).filter(User.id == document.uploaded_by).first()
    alert = db.query(SecurityAlert).filter(
        SecurityAlert.document_id == document.id,
        SecurityAlert.status == "OPEN",
    ).first()
    new_or_changed = not alert or alert.observed_hash != observed_hash or alert.alert_type != alert_type
    if not alert:
        alert = SecurityAlert(
            document_id=document.id,
            case_id=document.case_id,
            user_id=document.uploaded_by,
            alert_type=alert_type,
            severity="HIGH",
            status="OPEN",
            details=details,
            expected_hash=document.file_hash,
            observed_hash=observed_hash,
        )
        db.add(alert)
    else:
        alert.alert_type = alert_type
        alert.details = details
        alert.expected_hash = document.file_hash
        alert.observed_hash = observed_hash
        alert.detected_at = datetime.utcnow()

    document.status = "TAMPERED" if alert_type == "DOCUMENT_TAMPERED" else "UNAVAILABLE"
    db.commit()
    db.refresh(alert)

    if new_or_changed:
        create_security_audit(db, owner, alert_type, details)
        if owner:
            send_security_alert_email(owner, document, alert)
    return alert


def scan_document_integrity(db: Session, document: Document):
    """Compare the Azure blob against the immutable upload-time SHA-256 baseline."""
    try:
        current_hash = get_blob_sha256(document.blob_path)
    except RuntimeError:
        alert = raise_integrity_alert(
            db, document, "BLOB_UNAVAILABLE",
            f"Azure blob for document {document.id} could not be retrieved during integrity monitoring.",
        )
        return {"document_id": document.id, "integrity": "UNAVAILABLE", "alert_id": alert.id}

    if not hmac.compare_digest(current_hash, document.file_hash):
        alert = raise_integrity_alert(
            db, document, "DOCUMENT_TAMPERED",
            f"SHA-256 mismatch detected for document {document.id} ({document.filename}).",
            current_hash,
        )
        return {"document_id": document.id, "integrity": "TAMPERED", "alert_id": alert.id}

    document.status = "Verified"
    db.commit()
    return {"document_id": document.id, "integrity": "VALID"}

# =========================================================
# REQUEST OTP
# =========================================================

@app.post("/request-otp")
def request_otp(
    email: str = Query(..., min_length=3, max_length=150),
    db: Session = Depends(get_db)
):

    email = email.strip().lower()

    user = db.query(User).filter(
        User.email == email
    ).first()

    # Do not reveal whether an email exists
    if not user:
        return {
            "message": "If the account exists, an OTP has been sent."
        }

    consume_otp_request(db, email, user)

    # Generate secure OTP
    otp = generate_otp()

    # Hash OTP before storing
    otp_hash = hash_otp(otp)

    # Expiration time
    expires_at = datetime.utcnow() + timedelta(
        minutes=OTP_EXPIRE_MINUTES
    )

    # Invalidate previous OTPs
    db.query(OTPVerification).filter(
        OTPVerification.email == email,
        OTPVerification.used == 0
    ).update(
        {"used": 1}
    )

    otp_record = OTPVerification(
        email=email,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts=0,
        used=0
    )

    db.add(otp_record)
    db.commit()

    try:

        send_otp_email(
            email,
            otp
        )

    except Exception as e:

        otp_record.used = 1
        db.commit()

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP"
        )

    create_security_audit(db, user, "OTP_REQUESTED", "OTP requested through the OTP endpoint")

    return {
        "message": "OTP sent successfully",
        "expires_in_minutes": OTP_EXPIRE_MINUTES
    }
# =========================================================
# VERIFY OTP
# =========================================================

class OTPVerify(BaseModel):
    email: str
    otp: str

    @validator("email")
    def normalize_otp_email(cls, value):
        return value.strip().lower()

    @validator("otp")
    def validate_otp(cls, value):
        if len(value) != 6 or not value.isdigit():
            raise ValueError("OTP must be a 6-digit code")
        return value


@app.post("/verify-otp")
def verify_otp(
    data: OTPVerify,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.email == data.email
    ).first()

    if not user:
        logger.warning("OTP_VERIFICATION_FAILED for an unknown account")
        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )

    otp_record = db.query(
        OTPVerification
    ).filter(
        OTPVerification.email == data.email,
        OTPVerification.used == 0
    ).order_by(
        OTPVerification.created_at.desc()
    ).first()

    if not otp_record:
        create_security_audit(db, user, "OTP_VERIFICATION_FAILED", "Missing, expired, or already used OTP")
        raise HTTPException(
            status_code=401,
            detail="OTP expired or invalid"
        )

    # Maximum 5 attempts
    if otp_record.attempts >= 5:

        otp_record.used = 1
        db.commit()
        create_security_audit(db, user, "OTP_LOCKED", "OTP disabled after too many verification attempts")

        raise HTTPException(
            status_code=401,
            detail="Too many OTP attempts"
        )

    # Check expiration
    if datetime.utcnow() > otp_record.expires_at:

        otp_record.used = 1
        db.commit()
        create_security_audit(db, user, "OTP_EXPIRED", "Expired OTP verification was attempted")

        raise HTTPException(
            status_code=401,
            detail="OTP expired"
        )

    # Count attempt
    otp_record.attempts += 1

    # Verify OTP
    if not hmac.compare_digest(
        hash_otp(data.otp),
        otp_record.otp_hash
    ):

        db.commit()
        create_security_audit(db, user, "OTP_VERIFICATION_FAILED", "Incorrect OTP submitted")

        raise HTTPException(
            status_code=401,
            detail="Invalid OTP"
        )

    # OTP successfully used
    otp_record.used = 1
    db.commit()

    # Generate JWT
    now = datetime.utcnow()
    token = jwt.encode(
        {
            "user_id": user.id,
            "email": user.email,
            "role": user.role,
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        },
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    create_audit_log(
        db,
        user.id,
        "OTP_VERIFIED",
        "Successful two-factor authentication"
    )

    return {
        "message": "Two-factor authentication successful",
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": ACCESS_TOKEN_EXPIRE_MINUTES,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    }
# =========================================================
# LOGIN - PASSWORD FIRST FACTOR
# =========================================================

@app.post("/login")
def login_user(
    user: UserLogin,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    check_login_lock(db, user.email, existing_user)

    if not existing_user:
        record_failed_login(db, user.email, None, "Login failed for an unknown account")
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not pwd_context.verify(
        user.password,
        existing_user.password_hash
    ):

        record_failed_login(db, user.email, existing_user, "Incorrect password")
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if user.role and existing_user.role != user.role:
        record_failed_login(db, user.email, existing_user, "Selected role did not match the account")
        raise HTTPException(
            status_code=403,
            detail="Selected role does not match this account"
        )

    # Password is correct. Do not issue JWT yet; a valid OTP remains required.
    clear_failed_logins(db, user.email)
    consume_otp_request(db, existing_user.email, existing_user)

    otp = generate_otp()

    otp_hash = hash_otp(otp)

    expires_at = datetime.utcnow() + timedelta(
        minutes=OTP_EXPIRE_MINUTES
    )

    # Invalidate old OTPs
    db.query(OTPVerification).filter(
        OTPVerification.email == existing_user.email,
        OTPVerification.used == 0
    ).update(
        {"used": 1}
    )

    otp_record = OTPVerification(
        email=existing_user.email,
        otp_hash=otp_hash,
        expires_at=expires_at,
        attempts=0,
        used=0
    )

    db.add(otp_record)
    db.commit()

    try:

        send_otp_email(
            existing_user.email,
            otp
        )

    except Exception:

        otp_record.used = 1
        db.commit()

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP"
        )

    create_audit_log(
        db,
        existing_user.id,
        "PASSWORD_VERIFIED",
        "Password verified; OTP required"
    )
    create_security_audit(db, existing_user, "OTP_REQUESTED", "OTP requested after password verification")

    return {
        "message": "Password verified. OTP sent.",
        "requires_otp": True,
        "email": existing_user.email,
        "expires_in_minutes": OTP_EXPIRE_MINUTES
    }
# =========================================================
# CURRENT USER
# =========================================================

@app.get("/me")
def get_me(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.id == current_user["user_id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role
    }


# =========================================================
# CREATE CASE
# =========================================================

@app.post("/cases")
def create_case(
    case_data: CaseCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    existing_case = db.query(Case).filter(
        Case.case_number == case_data.case_number
    ).first()

    if existing_case:
        raise HTTPException(
            status_code=400,
            detail="Case number already exists"
        )

    new_case = Case(
        case_number=case_data.case_number,
        title=case_data.title,
        description=case_data.description,
        status=case_data.status
    )

    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # IMPORTANT:
    # Record who created this case.
    create_audit_log(
        db,
        current_user["user_id"],
        "CASE_CREATED",
        f"Created case {new_case.case_number}"
    )

    return new_case


# =========================================================
# LIST ONLY CURRENT USER'S CASES
# =========================================================

@app.get("/cases")
def get_cases(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    if current_user.get("role") == "Administrator":
        return db.query(Case).order_by(
            Case.created_at.desc()
        ).all()

    # Get case creation audit records belonging to this user
    audit_records = db.query(AuditLog).filter(
        AuditLog.user_id == user_id,
        AuditLog.action == "CASE_CREATED"
    ).all()

    case_numbers = []

    for log in audit_records:

        if log.details.startswith("Created case "):

            case_number = log.details.replace(
                "Created case ",
                "",
                1
            )

            case_numbers.append(case_number)

    if not case_numbers:
        return []

    cases = db.query(Case).filter(
        Case.case_number.in_(case_numbers)
    ).order_by(
        Case.created_at.desc()
    ).all()

    return cases


# =========================================================
# ACTIVE CASE USERS - ADMIN ONLY
# =========================================================

@app.get("/admin/active-case-users")
def active_case_users(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.get("role") != "Administrator":
        raise HTTPException(
            status_code=403,
            detail="Administrator access required"
        )

    users = db.query(User).order_by(User.username.asc()).all()
    return [
        {
            "id": item.id,
            "username": item.username,
            "email": item.email,
            "role": item.role,
            "documents": db.query(Document).filter(Document.uploaded_by == item.id).count(),
            "audit_events": db.query(AuditLog).filter(AuditLog.user_id == item.id).count(),
            "open_alerts": db.query(SecurityAlert).filter(
                SecurityAlert.user_id == item.id,
                SecurityAlert.status == "OPEN",
            ).count(),
        }
        for item in users
    ]


# =========================================================
# GET SINGLE CASE - USER ONLY
# =========================================================

@app.get("/cases/{case_id}")
def get_case(
    case_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    case = ensure_case_active(
        db,
        case_id,
        user_id
    )

    if case.status == "Closed":
        raise HTTPException(
            status_code=403,
            detail="This case is closed. Documents cannot be uploaded until the case is reopened."
        )

    documents = db.query(Document).filter(
        Document.case_id == case_id,
        Document.uploaded_by == user_id
    ).all()

    return {
        "case": case,
        "documents": documents
    }

# =========================================================
# CLOSE CASE
# =========================================================

@app.put("/cases/{case_id}/close")
def close_case(
    case_id: int,
    confirmation: DeleteConfirmation,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user["user_id"]

    # Make sure this case belongs to the current user
    case = user_owns_case(
        db,
        case_id,
        user_id
    )

    # Verify user's password
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not pwd_context.verify(
        confirmation.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password. Case was not closed."
        )

    # Check if already closed
    if case.status == "Closed":
        raise HTTPException(
            status_code=400,
            detail="Case is already closed."
        )

    case.status = "Closed"

    create_audit_log(
        db,
        user_id,
        "CASE_CLOSED",
        f"Closed case {case.case_number}"
    )

    db.commit()
    db.refresh(case)

    return {
        "message": "Case closed successfully",
        "case_id": case.id,
        "status": case.status
    }
# =========================================================
# REOPEN CASE - PASSWORD REQUIRED
# =========================================================

@app.put("/cases/{case_id}/reopen")
def reopen_case(
    case_id: int,
    confirmation: DeleteConfirmation,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user["user_id"]

    case = user_owns_case(
        db,
        case_id,
        user_id
    )

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not pwd_context.verify(
        confirmation.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password. Case was not reopened."
        )

    if case.status != "Closed":
        raise HTTPException(
            status_code=400,
            detail="Case is already active."
        )

    case.status = "Active"

    create_audit_log(
        db,
        user_id,
        "CASE_REOPENED",
        f"Reopened case {case.case_number}"
    )

    db.commit()
    db.refresh(case)

    return {
        "message": "Case reopened successfully",
        "case_id": case.id,
        "status": case.status
    }
# =========================================================
# DOCUMENT UPLOAD
# =========================================================

@app.post("/documents/upload")
def upload_document(
    case_id: int = Form(...),
    document_type: str = Form("General"),
    file: UploadFile = File(...),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    # IMPORTANT:
    # Make sure the user owns the case before uploading.
    case = user_owns_case(
        db,
        case_id,
        user_id
    )
    case = ensure_case_active(
        db,
        case_id,
        user_id
    )

    # Read at most one byte beyond the limit, so oversized uploads are rejected
    # before hashing, temporary-file creation, or Azure transfer.
    file_data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if not file_data:
        create_security_audit(db, current_user and db.query(User).get(user_id), "UPLOAD_REJECTED", "Empty upload rejected")
        raise HTTPException(status_code=400, detail="Empty files cannot be uploaded")
    if len(file_data) > MAX_UPLOAD_BYTES:
        create_security_audit(
            db, db.query(User).get(user_id), "UPLOAD_REJECTED",
            f"Upload exceeded the {MAX_UPLOAD_BYTES} byte limit"
        )
        raise HTTPException(
            status_code=413,
            detail=f"File is too large. Maximum size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
        )

    try:
        filename = validate_upload(file.filename, file.content_type, file_data)
    except HTTPException as error:
        create_security_audit(
            db, db.query(User).get(user_id), "UPLOAD_REJECTED",
            f"Upload rejected: {error.detail}"
        )
        raise

    document_type = document_type.strip()
    if not document_type or len(document_type) > 100:
        raise HTTPException(status_code=400, detail="Invalid document type")

    # =====================================================
    # SHA-256 INTEGRITY HASH
    # =====================================================

    file_hash = hashlib.sha256(
        file_data
    ).hexdigest()

    # =====================================================
    # TEMPORARY FILE
    # =====================================================

    with tempfile.NamedTemporaryFile(
        delete=False
    ) as temp_file:

        temp_file.write(file_data)
        temp_file_path = temp_file.name

    blob_path = (
        f"cases/{case.case_number}/{filename}"
    )

    try:

        # =================================================
        # AZURE BLOB UPLOAD
        # =================================================

        command = [
            "cmd",
            "/c",
            "az",
            "storage",
            "blob",
            "upload",
            "--account-name",
            AZURE_STORAGE_ACCOUNT,
            "--container-name",
            AZURE_CONTAINER,
            "--name",
            blob_path,
            "--file",
            temp_file_path,
            "--auth-mode",
            "login",
            "--overwrite"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:

            raise HTTPException(
                status_code=500,
                detail={
                    "message": "Azure Blob upload failed",
                    "error": result.stderr
                }
            )

        # =================================================
        # SAVE DOCUMENT METADATA
        # =================================================

        new_document = Document(
            filename=filename,
            document_type=document_type,
            blob_path=blob_path,
            file_hash=file_hash,
            status="Verified",
            case_id=case_id,
            uploaded_by=user_id
        )

        db.add(new_document)
        db.commit()
        db.refresh(new_document)

        # =================================================
        # BLOCKCHAIN LEDGER
        # =================================================

        ensure_blockchain_initialized(db)
        blockchain_block = append_document_block(db, new_document, user_id)

        # =================================================
        # AUDIT
        # =================================================

        create_audit_log(
            db,
            user_id,
            "DOCUMENT_UPLOADED",
            f"Uploaded {filename} to case {case.case_number}. SHA-256: {file_hash}"
        )

        return {
            "message": "Document uploaded successfully",
            "document_id": new_document.id,
            "filename": filename,
            "case_number": case.case_number,
            "blob_path": blob_path,
            "sha256": file_hash,
            "integrity_status": "VERIFIED",
            "blockchain": {
                "status": "RECORDED",
                "block_index": blockchain_block.block_index,
                "block_hash": blockchain_block.block_hash,
                "previous_hash": blockchain_block.previous_hash
            }
        }

    finally:

        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

# =========================================================
# DELETE DOCUMENT - PASSWORD REQUIRED
# =========================================================

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    confirmation: DeleteConfirmation,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user["user_id"]

    # ---------------------------------------------------------
    # 1. Make sure the document belongs to the logged-in user
    # ---------------------------------------------------------
    document = db.query(Document).filter(
        Document.id == document_id,
        Document.uploaded_by == user_id
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    # ---------------------------------------------------------
    # 2. If the document belongs to a case,
    #    the case MUST be active
    # ---------------------------------------------------------
    if document.case_id:
        ensure_case_active(
            db,
            document.case_id,
            user_id
        )

    # ---------------------------------------------------------
    # 3. Verify the user's password
    # ---------------------------------------------------------
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not pwd_context.verify(
        confirmation.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password. Document was not deleted."
        )

    # Save required information before deleting the DB record
    filename = document.filename
    blob_path = document.blob_path
    case_id = document.case_id

    # ---------------------------------------------------------
    # 4. PERMANENTLY DELETE FILE FROM AZURE BLOB STORAGE
    # ---------------------------------------------------------
    command = [
        "cmd",
        "/c",
        "az",
        "storage",
        "blob",
        "delete",
        "--account-name",
        AZURE_STORAGE_ACCOUNT,
        "--container-name",
        AZURE_CONTAINER,
        "--name",
        blob_path,
        "--auth-mode",
        "login",
        "--delete-snapshots",
        "include"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False
    )

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail="Could not permanently delete document from Azure."
        )

    # ---------------------------------------------------------
    # 5. Keep audit trail
    #    The document itself is deleted, but the audit record
    #    remains for accountability.
    # ---------------------------------------------------------
    create_audit_log(
        db,
        user_id,
        "DOCUMENT_DELETED",
        f"Deleted document {filename} from case {case_id}"
    )

    # ---------------------------------------------------------
    # 6. Remove security alerts associated with this document
    # ---------------------------------------------------------
    db.query(SecurityAlert).filter(
        SecurityAlert.document_id == document_id
    ).delete(
        synchronize_session=False
    )

    # ---------------------------------------------------------
    # 7. Delete document metadata from PostgreSQL
    # ---------------------------------------------------------
    db.delete(document)
    db.commit()

    # ---------------------------------------------------------
    # 8. Return success
    # ---------------------------------------------------------
    return {
        "message": "Document permanently deleted successfully"
    }
# =========================================================
# DELETE CASE - PASSWORD REQUIRED
# =========================================================

@app.delete("/cases/{case_id}")
def delete_case(
    case_id: int,
    confirmation: DeleteConfirmation,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user["user_id"]

    # Make sure this user owns the case
    case = user_owns_case(
        db,
        case_id,
        user_id
    )

    # Verify password
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if not user or not pwd_context.verify(
        confirmation.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password. Case was not deleted."
        )

    # Get documents belonging to this case
    documents = db.query(Document).filter(
        Document.case_id == case_id
    ).all()

    # Delete associated Azure files
    for document in documents:

        command = [
            "cmd",
            "/c",
            "az",
            "storage",
            "blob",
            "delete",
            "--account-name",
            AZURE_STORAGE_ACCOUNT,
            "--container-name",
            AZURE_CONTAINER,
            "--name",
            document.blob_path,
            "--auth-mode",
            "login",
            "--delete-snapshots",
            "include"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail="Could not delete associated document from Azure."
            )

    case_number = case.case_number

    # Audit before deletion
    create_audit_log(
        db,
        user_id,
        "CASE_DELETED",
        f"Deleted case {case_number} and its associated documents"
    )

    # Remove security alerts
    document_ids = [
        document.id for document in documents
    ]

    if document_ids:
        db.query(SecurityAlert).filter(
            SecurityAlert.document_id.in_(document_ids)
        ).delete(
            synchronize_session=False
        )

    # Delete documents from database
    for document in documents:
        db.delete(document)

    # Delete case
    db.delete(case)

    db.commit()

    return {
        "message": "Case deleted successfully"
    }
# =========================================================
# LIST ONLY CURRENT USER'S DOCUMENTS
# =========================================================

@app.get("/documents")
def get_documents(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    documents = db.query(Document).filter(
        Document.uploaded_by == user_id
    ).order_by(
        Document.uploaded_at.desc()
    ).all()

    return documents


# =========================================================
# SMART DOCUMENT SEARCH - USER ONLY
# =========================================================

@app.get("/documents/search")
def search_documents(
    q: str = Query(..., min_length=1),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    search_text = f"%{q.strip()}%"

    results = (
        db.query(Document)
        .join(
            Case,
            Document.case_id == Case.id
        )
        .filter(
            Document.uploaded_by == user_id,
            or_(
                Document.filename.ilike(search_text),
                Document.document_type.ilike(search_text),
                Case.case_number.ilike(search_text),
                Case.title.ilike(search_text),
                Case.description.ilike(search_text)
            )
        )
        .order_by(
            Document.uploaded_at.desc()
        )
        .all()
    )

    create_audit_log(
        db,
        user_id,
        "DOCUMENT_SEARCH",
        f"Searched documents for: {q}"
    )

    return {
        "query": q,
        "count": len(results),
        "results": [
            {
                "id": doc.id,
                "filename": doc.filename,
                "document_type": doc.document_type,
                "case_id": doc.case_id,
                "uploaded_at": doc.uploaded_at,
            }
            for doc in results
        ]
    }

# =========================================================
# VIEW / OPEN DOCUMENT - USER ONLY
# =========================================================

@app.get("/documents/{document_id}/file")
def view_document(
    document_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    # ---------------------------------------------------------
    # SECURITY: document must belong to the logged-in user
    # ---------------------------------------------------------

    document = db.query(Document).filter(
        Document.id == document_id,
        Document.uploaded_by == user_id
    ).first()
    case = ensure_case_active(
        db,
        document.case_id,
        user_id
    )
    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    # ---------------------------------------------------------
    # DOWNLOAD FILE FROM AZURE TO TEMPORARY FILE
    # ---------------------------------------------------------

    with tempfile.NamedTemporaryFile(
        delete=False
    ) as temp_file:
        temp_file_path = temp_file.name

    command = [
        "cmd",
        "/c",
        "az",
        "storage",
        "blob",
        "download",
        "--account-name",
        AZURE_STORAGE_ACCOUNT,
        "--container-name",
        AZURE_CONTAINER,
        "--name",
        document.blob_path,
        "--file",
        temp_file_path,
        "--auth-mode",
        "login",
        "--overwrite"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=False
    )

    if result.returncode != 0:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

        raise HTTPException(
            status_code=500,
            detail="Could not retrieve document from Azure"
        )

    # ---------------------------------------------------------
    # DETERMINE CONTENT TYPE
    # ---------------------------------------------------------

    extension = os.path.splitext(
        document.filename
    )[1].lower()

    content_types = {
        ".pdf": "application/pdf",
        ".txt": "text/plain",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    }

    media_type = content_types.get(
        extension,
        "application/octet-stream"
    )

    # ---------------------------------------------------------
    # AUDIT DOCUMENT VIEW
    # ---------------------------------------------------------

    create_audit_log(
        db,
        user_id,
        "DOCUMENT_VIEWED",
        f"Viewed document: {document.filename}"
    )

    # ---------------------------------------------------------
    # CLEAN UP TEMPORARY FILE AFTER RESPONSE
    # ---------------------------------------------------------

    def cleanup_file():
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass

    # ---------------------------------------------------------
    # STREAM FILE TO FRONTEND
    # ---------------------------------------------------------

    def file_iterator():
        try:
            with open(
                temp_file_path,
                "rb"
            ) as file:
                while True:
                    chunk = file.read(1024 * 1024)

                    if not chunk:
                        break

                    yield chunk

        finally:
            cleanup_file()

    return StreamingResponse(
        file_iterator(),
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f'inline; filename="{document.filename}"'
            )
        },
        background=BackgroundTask(cleanup_file)
    )
# =========================================================
# VERIFY DOCUMENT INTEGRITY - USER ONLY
# =========================================================

@app.get("/documents/{document_id}/verify")
def verify_document(
    document_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]

    # IMPORTANT:
    # Only find documents belonging to this user.
    document = db.query(Document).filter(
        Document.id == document_id,
        Document.uploaded_by == user_id
    ).first()

    if not document:

        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )
    ensure_case_active(
        db,
        document.case_id,
        user_id
    )
    case = db.query(Case).filter(
    Case.id == document.case_id
    ).first()

    if case and case.status == "Closed":
        raise HTTPException(
            status_code=403,
            detail="This case is closed. The document cannot be accessed until the case is reopened."
        )

    # =====================================================
    # RETRIEVE DOCUMENT FROM AZURE
    # =====================================================

    with tempfile.NamedTemporaryFile(
        delete=False
    ) as temp_file:

        temp_file_path = temp_file.name

    try:

        command = [
            "cmd",
            "/c",
            "az",
            "storage",
            "blob",
            "download",
            "--account-name",
            AZURE_STORAGE_ACCOUNT,
            "--container-name",
            AZURE_CONTAINER,
            "--name",
            document.blob_path,
            "--file",
            temp_file_path,
            "--auth-mode",
            "login",
            "--overwrite"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=False
        )

        if result.returncode != 0:

            raise HTTPException(
                status_code=500,
                detail="Could not retrieve document from Azure"
            )

        with open(
            temp_file_path,
            "rb"
        ) as downloaded_file:

            current_hash = hashlib.sha256(
                downloaded_file.read()
            ).hexdigest()

        is_valid = (
            current_hash == document.file_hash
        )

        if not is_valid:
            raise_integrity_alert(
                db,
                document,
                "DOCUMENT_TAMPERED",
                f"Manual verification found a SHA-256 mismatch for document {document.id} ({document.filename}).",
                current_hash,
            )
        elif document.status != "Verified":
            # A valid re-check does not close an alert automatically; it only restores
            # the current document state after a transient retrieval issue.
            document.status = "Verified"
            db.commit()

        blockchain_status = verify_document_block(db, document.id, current_hash)

        create_audit_log(
            db,
            user_id,
            "INTEGRITY_CHECK",
            f"Document {document.filename}: "
            f"{'VALID' if is_valid else 'TAMPERED'}"
        )

        return {
            "document": document.filename,
            "stored_hash": document.file_hash,
            "current_hash": current_hash,
            "integrity": (
                "VALID"
                if is_valid
                else "TAMPERED"
            ),
            "blockchain": blockchain_status
        }

    finally:

        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


# =========================================================
# INTEGRITY ALERTS AND AZURE EVENT GRID WEBHOOK
# =========================================================

@app.get("/security/alerts")
def get_security_alerts(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(SecurityAlert).filter(SecurityAlert.status != "DISMISSED")
    if current_user.get("role") != "Administrator":
        query = query.filter(SecurityAlert.user_id == current_user["user_id"])
    alerts = query.order_by(SecurityAlert.detected_at.desc()).all()
    return [serialize_alert(alert) for alert in alerts]


@app.get("/security/alerts/{alert_id}")
def get_security_alert(
    alert_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if current_user.get("role") != "Administrator" and alert.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="You cannot access this alert")
    return serialize_alert(alert)


@app.patch("/security/alerts/{alert_id}")
def update_security_alert(
    alert_id: int,
    update: AlertUpdate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if current_user.get("role") != "Administrator" and alert.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="You cannot modify this alert")

    actor = db.query(User).filter(User.id == current_user["user_id"]).first()
    now = datetime.utcnow()

    if update.action == "review":
        alert.status = "REVIEWED"
        alert.resolved_at = now
        create_security_audit(db, actor, "ALERT_REVIEWED", f"Reviewed security alert {alert.id}")
    else:
        alert.status = "DISMISSED"
        alert.resolved_at = now
        create_security_audit(db, actor, "ALERT_DISMISSED", f"Dismissed security alert {alert.id}")

    db.commit()
    db.refresh(alert)
    return serialize_alert(alert)


@app.delete("/security/alerts/{alert_id}")
def dismiss_security_alert(
    alert_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if current_user.get("role") != "Administrator" and alert.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="You cannot dismiss this alert")

    actor = db.query(User).filter(User.id == current_user["user_id"]).first()
    alert.status = "DISMISSED"
    alert.resolved_at = datetime.utcnow()
    create_security_audit(db, actor, "ALERT_DISMISSED", f"Dismissed security alert {alert.id}")
    db.commit()
    return {"message": "Alert dismissed", "id": alert_id}


@app.post("/integrity/scan")
def scan_my_documents(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manual fallback scan for demos or scheduled jobs when Event Grid is unavailable."""
    query = db.query(Document)
    if current_user.get("role") != "Administrator":
        query = query.filter(Document.uploaded_by == current_user["user_id"])
    results = [scan_document_integrity(db, document) for document in query.all()]
    return {
        "scanned": len(results),
        "valid": sum(result["integrity"] == "VALID" for result in results),
        "incidents": [result for result in results if result["integrity"] != "VALID"],
    }


@app.post("/integrity/events", include_in_schema=False)
async def azure_blob_event_grid(
    request: Request,
    event_grid_secret: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    """Receive Azure Blob Event Grid events and turn file changes into incidents."""
    if EVENT_GRID_WEBHOOK_SECRET and not hmac.compare_digest(
        event_grid_secret or "", EVENT_GRID_WEBHOOK_SECRET
    ):
        raise HTTPException(status_code=401, detail="Invalid event webhook secret")

    events = await request.json()
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="Expected an Event Grid event array")

    # Azure sends this handshake when an Event Grid subscription is created.
    for event in events:
        if event.get("eventType") == "Microsoft.EventGrid.SubscriptionValidationEvent":
            validation_code = event.get("data", {}).get("validationCode")
            if validation_code:
                return {"validationResponse": validation_code}

    processed = 0
    incidents = 0
    for event in events:
        subject = unquote(event.get("subject", ""))
        marker = "/blobs/"
        if marker not in subject:
            continue
        blob_path = subject.split(marker, 1)[1]
        document = db.query(Document).filter(Document.blob_path == blob_path).first()
        if not document:
            continue

        processed += 1
        if event.get("eventType") == "Microsoft.Storage.BlobDeleted":
            raise_integrity_alert(
                db, document, "BLOB_DELETED",
                f"Azure reported deletion of document {document.id} ({document.filename}).",
            )
            incidents += 1
        elif event.get("eventType") == "Microsoft.Storage.BlobCreated":
            result = scan_document_integrity(db, document)
            if result["integrity"] != "VALID":
                incidents += 1

    return {"processed": processed, "incidents": incidents}


# =========================================================
# BLOCKCHAIN LEDGER (supporting tamper-evident audit history)
# =========================================================

@app.get("/blockchain/status")
def blockchain_status(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ensure_blockchain_initialized(db)
    status = verify_blockchain(db)
    return {
        "technology": "Permissioned tamper-evident hash-chain ledger",
        "valid": status.get("valid", False),
        "blocks": status.get("blocks", 0),
        "latest_hash": status.get("latest_hash"),
        "errors": status.get("errors", [])
    }


@app.get("/blockchain/ledger")
def blockchain_ledger(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Make sure the blockchain has its genesis block
    # and any existing documents are registered.
    ensure_blockchain_initialized(db)

    user_id = current_user["user_id"]
    role = current_user.get("role")

    query = db.query(BlockchainBlock)

    # Administrators can see the complete blockchain.
    if role == "Administrator":
        blocks = query.order_by(
            BlockchainBlock.block_index.asc()
        ).all()

    # Other users can see:
    # 1. The genesis block
    # 2. Blocks belonging to their own documents
    else:
        blocks = query.filter(
            (BlockchainBlock.user_id == user_id) |
            (BlockchainBlock.document_id == 0)
        ).order_by(
            BlockchainBlock.block_index.asc()
        ).all()

    return [
        {
            "block_index": block.block_index,
            "timestamp": block.timestamp,
            "document_id": block.document_id,
            "case_id": block.case_id,
            "file_hash": block.file_hash,
            "action": block.action,
            "user_id": block.user_id,
            "previous_hash": block.previous_hash,
            "block_hash": block.block_hash
        }
        for block in blocks
    ]

@app.get("/blockchain/verify")
def verify_blockchain_endpoint(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ensure_blockchain_initialized(db)
    return verify_blockchain(db)


# =========================================================
# AUDIT TRAIL - USER ONLY
# =========================================================

@app.get("/audit-logs")
def get_audit_logs(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]
    query = db.query(AuditLog)
    if current_user.get("role") != "Administrator":
        query = query.filter(AuditLog.user_id == user_id)

    logs = query.order_by(AuditLog.timestamp.desc()).all()

    return [
        {
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "details": log.details,
            "timestamp": utc_iso(log.timestamp),
        }
        for log in logs
    ]


# =========================================================
# DASHBOARD - USER-SPECIFIC
# =========================================================

@app.get("/dashboard")
def dashboard(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user_id = current_user["user_id"]
    role = current_user.get("role")

    if role == "Administrator":
        total_cases = db.query(Case).count()
        total_documents = db.query(Document).count()
        total_audits = db.query(AuditLog).count()
        total_users = db.query(User).count()
        open_security_alerts = db.query(SecurityAlert).filter(
            SecurityAlert.status == "OPEN"
        ).count()

        return {
            "role": role,
            "users": total_users,
            "cases": total_cases,
            "documents": total_documents,
            "audit_events": total_audits,
            "open_security_alerts": open_security_alerts,
            "actions": ["active_case_users", "cases", "documents", "audit", "security"],
        }

    case_creation_logs = db.query(AuditLog).filter(
        AuditLog.user_id == user_id,
        AuditLog.action == "CASE_CREATED"
    ).all()

    case_numbers = []

    for log in case_creation_logs:

        if log.details.startswith("Created case "):

            case_number = log.details.replace(
                "Created case ",
                "",
                1
            )

            case_numbers.append(case_number)

    total_cases = len(set(case_numbers))
    total_documents = db.query(Document).filter(
        Document.uploaded_by == user_id
    ).count()
    total_audits = db.query(AuditLog).filter(
        AuditLog.user_id == user_id
    ).count()
    open_security_alerts = db.query(SecurityAlert).filter(
        SecurityAlert.status == "OPEN",
        SecurityAlert.user_id == user_id,
    ).count()

    role_actions = {
        "Police/Investigator": ["cases", "documents", "search", "audit", "security"],
        "Lawyer/Legal Officer": ["cases", "documents", "search", "audit", "security"],
        "Court Authority": ["cases", "documents", "search", "audit", "security"],
    }

    return {
        "role": role,
        "users": None,
        "cases": total_cases,
        "documents": total_documents,
        "audit_events": total_audits,
        "open_security_alerts": open_security_alerts,
        "actions": role_actions.get(role, ["cases", "documents", "search", "audit", "security"]),
    }
