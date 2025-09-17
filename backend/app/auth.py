import os, time
from fastapi import Header, HTTPException
from typing import Optional

API_KEY = os.environ.get("API_KEY", "demo_super_secret_key_please_change")
JWT_SECRET = os.environ.get("JWT_SECRET", "change_me_secret")
JWT_ALG = os.environ.get("JWT_ALG", "HS256")
JWT_TTL = int(os.environ.get("JWT_TTL", "3600"))

def verify_api_key(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Authorization header required")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    provided = authorization.split(" ", 1)[1].strip()
    
    # Check if API_KEY is a bcrypt hash (starts with $2b$)
    if API_KEY.startswith("$2b$"):
        try:
            import bcrypt
            if bcrypt.checkpw(provided.encode('utf-8'), API_KEY.encode('utf-8')):
                return True
        except ImportError:
            # If bcrypt not available, fall back to plain text comparison
            pass
    
    # Plain text comparison
    if provided != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")
    return True

def jwt_encode(payload: dict) -> str:
    try:
        import jwt
    except Exception as e:
        raise HTTPException(status_code=500, detail="JWT library not installed")
    to_encode = dict(payload)
    now = int(time.time())
    if 'iat' not in to_encode:
        to_encode['iat'] = now
    if 'exp' not in to_encode:
        to_encode['exp'] = now + JWT_TTL
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def jwt_decode(token: str) -> dict:
    try:
        import jwt
    except Exception as e:
        raise HTTPException(status_code=500, detail="JWT library not installed")
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return data
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def verify_jwt(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth scheme")
    token = authorization.split(" ", 1)[1].strip()
    return jwt_decode(token)

def verify_admin_auth(authorization: Optional[str] = Header(None)):
    """
    Accept either API Key (Bearer) or JWT Bearer token.
    Returns decoded JWT data if JWT, else True for API key.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    # Try API key first
    try:
        verify_api_key(authorization)
        return True
    except HTTPException:
        # Fallback to JWT
        return verify_jwt(authorization)
