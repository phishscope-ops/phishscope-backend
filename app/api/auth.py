"""Auth + Profile (Person 1: Register/Login/Logout/Profile/Password/Access Control)."""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (create_access_token, create_refresh_token, decode_token,
                               get_current_user, hash_password, verify_password)
from app.models import User, UserSession, audit
from app.schemas import LoginIn, ProfileOut, ProfilePatch, RegisterIn, TokenOut

router = APIRouter(prefix="/api/auth", tags=["auth"])
MAX_FAILED = 5
LOCK_MINUTES = 15


@router.post("/register", response_model=TokenOut, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if db.execute(select(User).where(User.email == email)).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(email=email, password_hash=hash_password(body.password),
                full_name=body.full_name)
    db.add(user)
    db.flush()
    audit(db, "register", user_id=user.id, entity="users", entity_id=str(user.id),
          ip=request.client.host if request.client else None)
    db.commit()
    return _issue_tokens(db, user, request)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.execute(select(User).where(User.email == body.email.strip().lower())).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if user and user.locked_until:
        locked = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked > now:
            raise HTTPException(status.HTTP_423_LOCKED, "Account locked, try again later")
    if not user or not verify_password(body.password, user.password_hash):
        if user:
            user.failed_logins += 1
            if user.failed_logins >= MAX_FAILED:
                user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
                user.failed_logins = 0
                audit(db, "account_locked", user_id=user.id, entity="users", entity_id=str(user.id))
            audit(db, "login_failed", entity="users", entity_id=str(user.id))
            db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    user.failed_logins = 0
    user.last_login_at = now
    audit(db, "login_success", user_id=user.id, entity="users", entity_id=str(user.id),
          ip=request.client.host if request.client else None)
    db.commit()
    return _issue_tokens(db, user, request)


def _issue_tokens(db: Session, user: User, request: Request) -> TokenOut:
    access = create_access_token(user.id, user.role.value)
    refresh, refresh_hash_hex = create_refresh_token(user.id)
    db.add(UserSession(user_id=user.id, token_hash=bytes.fromhex(refresh_hash_hex),
                       user_agent=request.headers.get("user-agent"),
                       ip=request.client.host if request.client else None,
                       expires_at=datetime.now(timezone.utc) + timedelta(days=30)))
    db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, db: Session = Depends(get_db)):
    token = request.headers.get("X-Refresh-Token", "")
    payload = decode_token(token, kind="refresh")
    import hashlib
    digest = hashlib.sha256(token.encode()).digest()
    sess = db.execute(select(UserSession).where(UserSession.token_hash == digest)).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    exp = sess.expires_at if sess and sess.expires_at.tzinfo else (sess.expires_at.replace(tzinfo=timezone.utc) if sess else None)
    if not sess or sess.revoked_at or exp < now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token invalid")
    user = db.get(User, uuid.UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found")
    return _issue_tokens(db, user, request)


@router.post("/logout", status_code=204)
def logout(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    token = request.headers.get("X-Refresh-Token", "")
    if token:
        import hashlib
        digest = hashlib.sha256(token.encode()).digest()
        sess = db.execute(select(UserSession).where(UserSession.token_hash == digest)).scalar_one_or_none()
        if sess:
            sess.revoked_at = datetime.now(timezone.utc)
    audit(db, "logout", user_id=user.id, entity="users", entity_id=str(user.id))
    db.commit()


users_router = APIRouter(prefix="/api/users", tags=["users"])


@users_router.get("/me", response_model=ProfileOut)
def get_me(user: User = Depends(get_current_user)):
    return user


@users_router.patch("/me", response_model=ProfileOut)
def patch_me(body: ProfilePatch, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.password is not None:  # Password Management
        user.password_hash = hash_password(body.password)
        audit(db, "password_change", user_id=user.id, entity="users", entity_id=str(user.id))
    db.commit()
    return user
