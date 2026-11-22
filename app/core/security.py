import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db

ph = PasswordHasher()  # Argon2id بإعدادات OWASP الافتراضية
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def _token(data: dict, ttl: timedelta, kind: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {**data, "iat": now, "exp": now + ttl, "kind": kind}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def create_access_token(user_id: uuid.UUID, role: str) -> str:
    return _token({"sub": str(user_id), "role": role},
                  timedelta(minutes=settings.access_token_minutes), "access")


def create_refresh_token(user_id: uuid.UUID) -> tuple[str, str]:
    """بيرجع (التوكن, الـ SHA-256 hash اللي بيتخزن في user_sessions)."""
    raw = _token({"sub": str(user_id)}, timedelta(days=settings.refresh_token_days), "refresh")
    return raw, hashlib.sha256(raw.encode()).digest().hex()


def decode_token(token: str, kind: str = "access") -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if payload.get("kind") != kind:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
    return payload


def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)):
    from app import models  # import متأخر عشان نتفادى circular

    payload = decode_token(token)
    user = db.get(models.User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_423_LOCKED, "Account temporarily locked")
    return user


def require_analyst(user=Depends(get_current_user)):
    if user.role not in ("analyst", "admin"):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Analyst role required")
    return user


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
