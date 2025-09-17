Chatbot project (modular) - v2

Structure:
- backend/ (FastAPI app, modular)
- frontend/ (static, served by nginx container)
- docker-compose.yml orchestrates frontend (nginx), backend (uvicorn), redis

Build & run:
- docker-compose up --build

Frontend accessible at http://localhost:8080
API at http://localhost:8000

Configuration (env):
- API_KEY: Bearer token required by the API (client and admin)
- THRESH: Similarity threshold for matching (default 0.45)
- RATE_LIMIT / RATE_WINDOW: Requests per time window (default 120 / 60s)
- MAX_HISTORY: Max conversation turns kept in session (default 6)
- QA_DB_PATH: SQLite DB path (default /app/data/chatbot_data.db)
- REDIS_URL: Optional. Enables Redis for sessions and rate limiting
- SESSION_TTL: Session expiration in seconds (default 3600)
- CORS_ALLOW_ORIGINS: Comma-separated origins (default *)

Train (manage Q&A):
1) Admin UI
   - Open /admin.html from the frontend container (http://localhost:8080/admin.html)
   - Enter API Key and use the form to create/update/delete Q&A.
2) REST API
   - POST /api/admin/qa (FormData: question, answer, tags?)
   - PUT /api/admin/qa/{id}
   - DELETE /api/admin/qa/{id}
   - All require header: Authorization: Bearer <API_KEY>
3) Seed data
   - Edit backend/app/samples_seed.json or pass SAMPLES_JSON env with an array of {question, answer, tags}
   - On first run (empty table), samples are inserted automatically.

Public UI:
- The chat widget is embedded in frontend/index.html.
- It loads up to 10 suggested questions from GET /api/questions and sends messages to POST /api/converse.
- The widget enforces a 5s timeout client-side. Server should respond under that SLO.

Security:
- API protected by Bearer API Key. Use HTTPS in production (TLS termination in Nginx or upstream).
- CORS and security headers are enabled in backend/app/main.py.
- For production, avoid exposing admin API Key in the browser. Prefer server-side auth or Basic Auth on /admin.html.

Scalability:
- Redis-based sessions and rate limiting allow multiple backend replicas.
- Consider migrating SQLite to PostgreSQL when traffic grows; enable trigram/FTS indices for faster search.

