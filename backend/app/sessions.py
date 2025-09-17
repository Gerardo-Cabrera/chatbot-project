import os, json, time
from typing import Dict, Any

_immemory_sessions: Dict[str, Dict[str, Any]] = {}

_REDIS_URL = os.environ.get("REDIS_URL")
_SESSION_TTL = int(os.environ.get("SESSION_TTL", "3600"))

_redis_client = None
try:
    if _REDIS_URL:
        import redis
        _redis_client = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
        _redis_client.ping()
except Exception:
    _redis_client = None

def _session_key(session_id: str) -> str:
    return f"chat:s:{session_id}"

async def save_session(session_id: str, session: Dict[str, Any]):
    if _redis_client is not None:
        try:
            _redis_client.setex(_session_key(session_id), _SESSION_TTL, json.dumps(session))
            return
        except Exception:
            pass
    _immemory_sessions[session_id] = session

async def load_session(session_id: str) -> Dict[str, Any]:
    if _redis_client is not None:
        try:
            data = _redis_client.get(_session_key(session_id))
            if data:
                return json.loads(data)
        except Exception:
            pass
    return _immemory_sessions.get(session_id, {"history": [], "last_active": time.time()})
