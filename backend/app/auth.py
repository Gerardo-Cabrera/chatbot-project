import os
import time
import json
import secrets
from typing import Optional
from fastapi import Header, HTTPException, Cookie, APIRouter, Response
from fastapi.responses import JSONResponse
import jwt
import bcrypt
from .db import get_user_by_email
from pydantic import BaseModel

# Redis client or in-memory fallback
_REDIS_URL = os.environ.get("REDIS_URL")
_redis = None
_refresh_store = {}  # fallback store: {jti: {user_id, exp}}

if _REDIS_URL:
    try:
        import redis
        _redis = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
        _redis.ping()
    except Exception:
        _redis = None

def _store_refresh_jti(jti: str, user_id: int, exp_ts: int):
    payload = json.dumps({"user_id": user_id, "exp": exp_ts})
    if _redis:
        _redis.setex(f"refresh:{jti}", exp_ts - int(time.time()), payload)
    else:
        _refresh_store[jti] = {"user_id": user_id, "exp": exp_ts}

def _get_refresh_jti(jti: str):
    if not jti:
        return None
    if _redis:
        raw = _redis.get(f"refresh:{jti}")
        return json.loads(raw) if raw else None
    else:
        return _refresh_store.get(jti)

def _delete_refresh_jti(jti: str):
    if not jti:
        return
    if _redis:
        _redis.delete(f"refresh:{jti}")
    else:
        _refresh_store.pop(jti, None)

# Configuration
API_KEY = os.environ.get("API_KEY", "demo_super_secret_key_please_change")
JWT_SECRET = os.environ.get("JWT_SECRET", "change_me_secret")
JWT_ALG = os.environ.get("JWT_ALG", "HS256")
ACCESS_TTL = int(os.environ.get("ACCESS_TTL", str(60 * 60)))  # 1 hour
REFRESH_TTL = int(os.environ.get("REFRESH_TTL", str(60 * 60 * 24 * 7)))  # 7 days
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")

# Server start time (kept for compatibility; we will NOT invalidate by iat automatically)
SERVER_START_TIME = int(time.time())

# JWT helpers
def create_access_token(payload: dict) -> str:
    now = int(time.time())
    to_encode = dict(payload)
    to_encode.update({"iat": now, "exp": now + ACCESS_TTL, "typ": "access"})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def create_refresh_token(payload: dict, jti: str) -> str:
    now = int(time.time())
    to_encode = dict(payload)
    to_encode.update({"iat": now, "exp": now + REFRESH_TTL, "typ": "refresh", "jti": jti})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def decode_jwt_no_side_effects(token: str) -> dict:
    try:
        # Algunos tokens antiguos usan 'sub' como entero; PyJWT valida el tipo
        # de 'sub' y puede lanzar InvalidSubjectError. Para compatibilidad con
        # tokens emitidos por este servicio, desactivamos la validación estricta
        # del claim 'sub' aquí usando options={"verify_sub": False}.
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_sub": False})
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# API key verify (compatibility)
def verify_api_key(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header required")
    
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    
    provided = authorization.split(" ", 1)[1].strip()

    if API_KEY.startswith("$2b$"):
        try:
            if bcrypt.checkpw(provided.encode("utf-8"), API_KEY.encode("utf-8")):
                return True
        except Exception:
            pass

    if provided != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True

# Verify access token or cookie 'admin_jwt' (compat)
def verify_jwt(authorization: Optional[str] = Header(None), admin_jwt: Optional[str] = Cookie(None)):
    token = None

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif admin_jwt:
        token = admin_jwt

    if not token:
        raise HTTPException(status_code=401, detail="Authorization required")
    
    payload = decode_jwt_no_side_effects(token)

    if payload.get("typ") != "access":
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload

def verify_admin_auth(authorization: Optional[str] = Header(None), admin_jwt: Optional[str] = Cookie(None)):
    # Try API key first
    if authorization:
        try:
            verify_api_key(authorization)
            return True
        except HTTPException:
            pass
    return verify_jwt(authorization=authorization, admin_jwt=admin_jwt)

# CSRF helper
def make_csrf_token():
    return secrets.token_urlsafe(16)

# Expose jwt_encode for compatibility
def jwt_encode(payload: dict) -> str:
    return create_access_token(payload)

# Export TTL vars for compatibility
JWT_TTL = ACCESS_TTL


router = APIRouter(prefix="/api/v1")

class LoginPayload(BaseModel):
    email: str
    password: str

@router.post("/auth/login")
def auth_login(payload: LoginPayload, response: Response):
    email = payload.email.strip().lower()
    pw = payload.password

    if not email or not pw:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    row = get_user_by_email(email)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    try:
        if not bcrypt.checkpw(pw.encode("utf-8"), row["password_hash"].encode("utf-8")):
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception:
        raise HTTPException(status_code=500, detail="Error verifying password")

    payload_token = {"sub": row["id"], "email": row["email"], "scope": "admin"}
    access = create_access_token(payload_token)

    jti = secrets.token_urlsafe(12)
    now = int(time.time())
    exp_ts = now + REFRESH_TTL
    refresh = create_refresh_token(payload_token, jti)
    _store_refresh_jti(jti, row["id"], exp_ts)

    csrf = make_csrf_token()

    samesite_val = "None" if COOKIE_SECURE else "Lax"
    resp = JSONResponse({"ok": True, "access_token": access})
    # set refresh cookie (HttpOnly)
    resp.set_cookie("refresh_token", refresh, max_age=REFRESH_TTL, httponly=True, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    # set admin_jwt cookie for compatibility (short-lived access token, HttpOnly)
    resp.set_cookie("admin_jwt", access, max_age=ACCESS_TTL, httponly=True, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    # csrf token (readable by JS)
    resp.set_cookie("csrf_token", csrf, max_age=REFRESH_TTL, httponly=False, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    return resp

@router.post("/auth/refresh")
def auth_refresh(refresh_token: Optional[str] = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")
    
    payload = decode_jwt_no_side_effects(refresh_token)

    if payload.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")
    
    jti = payload.get("jti")
    rec = _get_refresh_jti(jti)
    if not rec:
        raise HTTPException(status_code=401, detail="Refresh revoked")

    # rotate
    _delete_refresh_jti(jti)
    user_id = rec["user_id"] if isinstance(rec, dict) else rec.get("user_id")
    new_jti = secrets.token_urlsafe(12)
    now = int(time.time())
    exp_ts = now + REFRESH_TTL
    new_refresh = create_refresh_token({"sub": user_id}, new_jti)
    _store_refresh_jti(new_jti, user_id, exp_ts)

    access = create_access_token({"sub": user_id})
    csrf = make_csrf_token()
    samesite_val = "None" if COOKIE_SECURE else "Lax"
    resp = JSONResponse({"access_token": access})
    resp.set_cookie("refresh_token", new_refresh, max_age=REFRESH_TTL, httponly=True, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    resp.set_cookie("admin_jwt", access, max_age=ACCESS_TTL, httponly=True, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    resp.set_cookie("csrf_token", csrf, max_age=REFRESH_TTL, httponly=False, secure=COOKIE_SECURE, samesite=samesite_val, path="/")
    return resp

@router.post("/auth/logout")
def auth_logout(refresh_token: Optional[str] = Cookie(None)):
    if refresh_token:
        try:
            payload = decode_jwt_no_side_effects(refresh_token)
            if payload.get("typ") == "refresh":
                jti = payload.get("jti")
                _delete_refresh_jti(jti)
        except Exception:
            pass
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("refresh_token", path="/")
    resp.delete_cookie("csrf_token", path="/")
    resp.delete_cookie("admin_jwt", path="/")
    return resp
