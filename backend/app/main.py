# backend/app/main.py
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .api0 import register_routes
from .db import init_db
from pathlib import Path

def create_app():
    app = FastAPI(
        title="Chatbot Modular App",
        description="API REST para sistema de chatbot con autenticación y gestión de Q&A",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        path = request.url.path
        if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi"):
            return response
        csp = ("default-src 'self'; "
               "img-src 'self' data:; "
               "style-src 'self' 'unsafe-inline'; "
               "script-src 'self' 'unsafe-inline'; "
               "connect-src 'self'")
        response.headers["Content-Security-Policy"] = csp
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    @app.middleware("http")
    async def clear_cookie_on_401(request: Request, call_next):
        response = await call_next(request)
        # By default we do NOT delete the admin_jwt cookie automatically on 401 responses.
        # Automatic deletion on 401 can create login/logout redirect loops in the frontend
        # when the client is performing auth checks. Provide an opt-in via environment
        # variable CLEAR_COOKIE_ON_401=true if you want the previous behavior.
        try:
            clear_on_401 = os.environ.get("CLEAR_COOKIE_ON_401", "false").lower() in ("1", "true", "yes")
            if clear_on_401 and response.status_code == 401 and 'admin_jwt' in request.cookies:
                response.delete_cookie('admin_jwt', path='/')
        except Exception:
            # swallow any errors to avoid breaking responses
            pass
        return response

    allowed = os.environ.get("CORS_ALLOW_ORIGINS")
    if allowed:
        allow_origins = [o.strip() for o in allowed.split(",") if o.strip()]
    else:
        allow_origins = ["http://localhost:8080"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        allow_credentials=True,
        max_age=3600,
    )

    init_db()

    STATIC_DIR = Path(__file__).parent.parent / "frontend"
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    register_routes(app)

    return app

app = create_app()
