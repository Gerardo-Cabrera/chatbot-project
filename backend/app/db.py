import os, json
import sqlite3
from pathlib import Path

DB_PATH = os.environ.get("QA_DB_PATH", str(Path(__file__).parent.parent / "data" / "chatbot_data.db"))
SAMPLES_ENV = os.environ.get("SAMPLES_JSON")
SAMPLES_FILE = Path(__file__).parent / "samples_seed.json"


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _create_tables(conn):
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS qa (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT NOT NULL,
        answer TEXT NOT NULL,
        tags TEXT DEFAULT ''
    );""")
    # Users table for authentication (email unique, bcrypt password hash)
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );""")
    conn.commit()


def load_samples():
    if SAMPLES_ENV:
        try:
            obj = json.loads(SAMPLES_ENV)
            if isinstance(obj, list):
                return obj
        except Exception:
            pass
    
    if SAMPLES_FILE.exists():
        try:
            with open(SAMPLES_FILE, 'r', encoding='utf-8') as f:
                obj = json.load(f)
            if isinstance(obj, list):
                return obj
        except Exception:
            pass
    return []


def init_db():
    dbfile = Path(DB_PATH)
    dbfile.parent.mkdir(parents=True, exist_ok=True)
    conn = get_conn()
    _create_tables(conn)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(1) as c FROM qa")
    count = cur.fetchone()["c"]

    if count == 0:
        samples = load_samples()
        if not samples:
            samples = []
            for i in range(1, 11):
                q = f"Ejemplo pregunta {i}"
                a = f"Ejemplo respuesta {i}."
                samples.append({"question": q, "answer": a})
        cur.executemany("INSERT INTO qa (question, answer, tags) VALUES (?, ?, ?)",
                        [(s['question'], s['answer'], s.get('tags', '')) for s in samples])
        conn.commit()
    conn.close()

# Helper functions for users table
def create_user(email: str, password_hash: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email.lower().strip(), password_hash))
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid

def get_user_by_email(email: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password_hash, created_at FROM users WHERE email = ?", (email.lower().strip(),))
    row = cur.fetchone()
    conn.close()
    return row
