"""
Módulo de API REST para el sistema de chatbot.

Este módulo define todos los endpoints de la API, incluyendo:
- Endpoints públicos para el chat (sin autenticación)
- Endpoints de administración (con autenticación Bearer Token)
- Rate limiting distribuido con Redis
- Gestión de sesiones de conversación
- Algoritmos de matching de similitud
"""

from fastapi import APIRouter, FastAPI, Request, Depends, HTTPException, Form
from .auth import verify_api_key, verify_admin_auth, jwt_encode
from .db import create_user, get_user_by_email
import bcrypt
from .db import get_conn
from .db import load_samples
import hashlib
from .matching import similarity_score, normalize_text
from .sessions import save_session, load_session
from pydantic import BaseModel
from typing import Optional
import os, time, json

# Router principal con prefijo /api/v1 para todos los endpoints
router = APIRouter(prefix="/api/v1")

# Configuración de rate limiting
_RATE_WINDOW = int(os.environ.get('RATE_WINDOW', '60'))  # Ventana de tiempo en segundos
_RATE_LIMIT = int(os.environ.get('RATE_LIMIT', '120'))   # Máximo requests por ventana
_ip_calls = {}  # Fallback en memoria para rate limiting

# Configuración de Redis para rate limiting distribuido
_REDIS_URL = os.environ.get('REDIS_URL')
_redis_client = None

# Intentar conectar a Redis para rate limiting distribuido
try:
    if _REDIS_URL:
        import redis
        _redis_client = redis.Redis.from_url(_REDIS_URL, decode_responses=True)
        _redis_client.ping()  # Verificar conexión
except Exception:
    _redis_client = None  # Fallback a rate limiting en memoria

def _rate_limit(request: Request):
    """
    Implementa rate limiting por IP para prevenir abuso de la API.
    
    Utiliza Redis para distribución si está disponible, sino fallback a memoria.
    Limita a RATE_LIMIT requests por RATE_WINDOW segundos por IP.
    
    Args:
        request: Request HTTP para obtener la IP del cliente
        
    Raises:
        HTTPException: 429 Too Many Requests si se excede el límite
    """
    ip = request.client.host
    now = time.time()
    
    # Intentar usar Redis para rate limiting distribuido
    if _redis_client is not None:
        try:
            # Crear clave única por IP y ventana de tiempo
            key = f"chat:rate:{ip}:{int(now // _RATE_WINDOW)}"
            current = _redis_client.incr(key)
            
            # Establecer TTL solo en el primer request de la ventana
            if current == 1:
                _redis_client.expire(key, _RATE_WINDOW)
                
            # Verificar si se excedió el límite
            if current > _RATE_LIMIT:
                raise HTTPException(status_code=429, detail="Too many requests")
            return
        except Exception:
            # Si Redis falla, continuar con fallback en memoria
            pass
    
    # Fallback: rate limiting en memoria (para desarrollo o sin Redis)
    calls = _ip_calls.get(ip, [])
    # Filtrar calls dentro de la ventana de tiempo
    calls = [t for t in calls if now - t < _RATE_WINDOW]
    
    if len(calls) >= _RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")
        
    calls.append(now)
    _ip_calls[ip] = calls

class ConversePayload(BaseModel):
    """
    Modelo Pydantic para validar el payload del endpoint /converse.
    
    Attributes:
        message: Mensaje del usuario al chatbot
        session_id: ID de sesión opcional para mantener contexto
    """
    message: str
    session_id: Optional[str] = None

class RegisterPayload(BaseModel):
    email: str
    password: str

class LoginPayload(BaseModel):
    email: str
    password: str

@router.get('/questions')
def get_questions(limit: int = 10, request: Request = None):
    """
    Endpoint público para obtener preguntas sugeridas para el chatbot.
    
    Este endpoint no requiere autenticación y es usado por el frontend
    para mostrar sugerencias al usuario.
    
    Args:
        limit: Número máximo de preguntas a retornar (default: 10)
        request: Request HTTP para rate limiting
        
    Returns:
        dict: Diccionario con lista de preguntas sugeridas
        
    Raises:
        HTTPException: 429 si se excede el rate limit
    """
    _rate_limit(request)
    
    # Obtener preguntas de la base de datos
    conn = get_conn()
    cur = conn.cursor()
    # Filtrar registros con id > 0 (excluir configuraciones internas)
    cur.execute("SELECT id, question FROM qa WHERE id > 0 ORDER BY id LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    
    return {"questions": [{"id": r['id'], "question": r['question']} for r in rows]}

@router.post('/converse')
async def converse(payload: ConversePayload, request: Request = None):
    """
    Endpoint principal del chatbot para procesar mensajes del usuario.
    
    Este endpoint implementa la lógica central del chatbot:
    1. Carga/crea sesión de conversación
    2. Almacena el mensaje del usuario en el historial
    3. Busca la mejor respuesta usando algoritmos de similitud
    4. Aplica contextualización usando mensajes anteriores
    5. Retorna respuesta o sugerencias si no entiende
    
    Args:
        payload: Datos del mensaje y session_id del usuario
        request: Request HTTP para rate limiting
        
    Returns:
        dict: Respuesta del chatbot con metadatos de confianza
        
    Raises:
        HTTPException: 429 si se excede el rate limit
    """
    _rate_limit(request)
    
    # Obtener mensaje y session_id
    message = payload.message
    session_id = payload.session_id or f"ip-{request.client.host}"
    
    # Cargar sesión existente o crear nueva
    s = await load_session(session_id)
    
    # Agregar mensaje del usuario al historial
    s['history'].append({'role':'user','text':message,'time':time.time()})
    
    # Limitar tamaño del historial para evitar memoria excesiva
    max_history = int(os.environ.get('MAX_HISTORY','6'))
    if len(s['history']) > max_history:
        s['history'] = s['history'][-max_history:]
    
    # Guardar sesión actualizada
    await save_session(session_id, s)

    # TEMPORAL: Deshabilitar contexto completamente para debug
    user_msgs = [h['text'] for h in s['history'] if h['role']=='user']
    context_concat = ""
    
    print(f"DEBUG: Mensaje actual: '{message[:30]}...'")
    print(f"DEBUG: Historial de mensajes: {len(user_msgs)} mensajes")
    if len(user_msgs) > 1:
        print(f"DEBUG: Último mensaje: '{user_msgs[-1][:30]}...'")
        similarity = similarity_score(normalize_text(message), normalize_text(user_msgs[-1]))
        print(f"DEBUG: Similitud con último mensaje: {similarity:.3f}")
    
    # NO usar contexto por ahora para debug
    print(f"DEBUG: NO usando contexto - procesando solo mensaje actual")
    
    # Obtener todas las Q&A de la base de datos
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, question, answer FROM qa WHERE id > 0")
    rows = cur.fetchall()
    conn.close()

    # Buscar la mejor coincidencia usando SOLO el mensaje actual (sin contexto)
    best = {'id': None, 'question': None, 'answer': None, 'score': 0.0}
    norm_msg = normalize_text(message)      # Normalizar mensaje actual
    
    print(f"DEBUG: Buscando coincidencia para mensaje: '{message[:30]}...'")
    
    for r in rows:
        q = r['question']
        # Calcular similitud SOLO del mensaje actual
        score = similarity_score(norm_msg, q)
        
        print(f"DEBUG: Pregunta '{q[:20]}...' -> Score: {score:.3f}")
        
        if score > best['score']:
            best.update({'id': r['id'], 'question': q, 'answer': r['answer'], 'score': score})
    
    print(f"DEBUG: Mejor coincidencia: '{best['question'][:20] if best['question'] else 'None'}...' -> Score: {best['score']:.3f}")

    # Aplicar umbral de similitud para determinar si entendió
    THRESH = float(os.environ.get('THRESH', '0.45'))
    if best['score'] >= THRESH:
        # El bot entendió - responder con la mejor coincidencia
        reply = best['answer']
        understood = True
        matched_id = best['id']
    else:
        # El bot no entendió - proporcionar sugerencias
        sorted_rows = sorted(rows, key=lambda r: similarity_score(normalize_text(message), r['question']), reverse=True)
        suggestions = [r['question'] for r in sorted_rows[:5]]
        reply = ("No entendí completamente. ¿Quizá quisiste alguna de estas preguntas?\n\n" + 
                "\n".join([f"- {s}" for s in suggestions]))
        understood = False
        matched_id = None

    # Agregar respuesta del bot al historial
    s['history'].append({'role':'bot','text':reply,'time':time.time()})
    
    # Limitar tamaño del historial nuevamente
    if len(s['history']) > max_history:
        s['history'] = s['history'][-max_history:]
    
    # Actualizar timestamp de última actividad
    s['last_active'] = time.time()
    
    # Guardar sesión final
    await save_session(session_id, s)
    
    return {
        'reply': reply, 
        'matched_question_id': matched_id, 
        'confidence': round(best['score'],3), 
        'understood': understood
    }

@router.post('/auth/register')
def auth_register(payload: RegisterPayload):
    email = payload.email.strip().lower()
    if not email or not payload.password or len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="Invalid email or password too short")
    if get_user_by_email(email):
        raise HTTPException(status_code=409, detail="User already exists")
    pw_hash = bcrypt.hashpw(payload.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    uid = create_user(email, pw_hash)
    return { 'ok': True, 'id': uid }

@router.post('/auth/login')
def auth_login(payload: LoginPayload):
    email = payload.email.strip().lower()
    row = get_user_by_email(email)
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(payload.password.encode('utf-8'), row['password_hash'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt_encode({ 'sub': row['id'], 'email': row['email'], 'scope': 'admin' })
    return { 'ok': True, 'token': token }

@router.get('/admin/qa')
def admin_list(auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, question, answer, tags FROM qa WHERE id > 0 ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return {'qa': [{ 'id': r['id'], 'question': r['question'], 'answer': r['answer'], 'tags': r['tags']} for r in rows]}

@router.post('/admin/qa')
def admin_create(question: str = Form(...), answer: str = Form(...), tags: str = Form(''), auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO qa (question,answer,tags) VALUES (?,?,?)", (question.strip(), answer.strip(), tags))
    conn.commit()
    nid = cur.lastrowid
    conn.close()
    return {'ok': True, 'id': nid}

@router.put('/admin/qa/{qa_id}')
def admin_update(qa_id: int, question: str = Form(...), answer: str = Form(...), tags: str = Form(''), auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE qa SET question=?, answer=?, tags=? WHERE id=?", (question.strip(), answer.strip(), tags, qa_id))
    conn.commit()
    conn.close()
    return {'ok': True}

@router.delete('/admin/qa/{qa_id}')
def admin_delete(qa_id: int, auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM qa WHERE id=?", (qa_id,))
    conn.commit()
    conn.close()
    return {'ok': True}

@router.post('/admin/reseed')
def admin_reseed(auth=Depends(verify_admin_auth)):
    # Danger: clears table and loads samples
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM qa WHERE id > 0")  # Keep config records
    samples = load_samples()
    if samples:
        cur.executemany("INSERT INTO qa (question, answer, tags) VALUES (?, ?, ?)",
                        [(s['question'], s['answer'], s.get('tags','')) for s in samples])
    conn.commit()
    conn.close()
    return { 'ok': True, 'count': len(samples) }

@router.get('/admin/config')
def admin_get_config(auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT answer FROM qa WHERE id = -2 AND question = '__config__'")
    row = cur.fetchone()
    conn.close()
    
    if row:
        import json
        config = json.loads(row['answer'])
        return config
    else:
        return {
            'THRESH': float(os.environ.get('THRESH', '0.45')),
            'MAX_HISTORY': int(os.environ.get('MAX_HISTORY', '6')),
            'RATE_LIMIT': int(os.environ.get('RATE_LIMIT', '120')),
            'RATE_WINDOW': int(os.environ.get('RATE_WINDOW', '60')),
        }

@router.post('/admin/config')
def admin_save_config(thresh: float = Form(...), max_history: int = Form(...), auth=Depends(verify_admin_auth)):
    conn = get_conn()
    cur = conn.cursor()
    config = {
        'THRESH': thresh,
        'MAX_HISTORY': max_history,
        'RATE_LIMIT': int(os.environ.get('RATE_LIMIT', '120')),
        'RATE_WINDOW': int(os.environ.get('RATE_WINDOW', '60')),
    }
    import json
    config_json = json.dumps(config)
    cur.execute("INSERT OR REPLACE INTO qa (id, question, answer, tags) VALUES (-2, '__config__', ?, '')", (config_json,))
    conn.commit()
    conn.close()
    return {'ok': True, 'config': config}

@router.post('/admin/sync-samples')
def admin_sync_samples(auth=Depends(verify_api_key)):
    # Load current samples and compute hash
    samples = load_samples()
    samples_str = str(sorted(samples, key=lambda x: x.get('question','')))
    samples_hash = hashlib.md5(samples_str.encode()).hexdigest()
    # Check if we have a stored hash
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT answer FROM qa WHERE id = -1 AND question = '__samples_hash__'")
    row = cur.fetchone()
    stored_hash = row['answer'] if row else None
    if stored_hash == samples_hash:
        conn.close()
        return { 'ok': True, 'synced': False, 'message': 'No changes detected' }
    # Clear and reseed
    cur.execute("DELETE FROM qa")
    if samples:
        cur.executemany("INSERT INTO qa (question, answer, tags) VALUES (?, ?, ?)",
                        [(s['question'], s['answer'], s.get('tags','')) for s in samples])
    # Store new hash
    cur.execute("INSERT OR REPLACE INTO qa (id, question, answer, tags) VALUES (-1, '__samples_hash__', ?, '')", (samples_hash,))
    conn.commit()
    conn.close()
    return { 'ok': True, 'synced': True, 'count': len(samples) }

def register_routes(app: FastAPI):
    app.include_router(router)
