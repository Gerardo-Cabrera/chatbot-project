"""
Módulo principal de la aplicación FastAPI para el chatbot.

Este módulo configura la aplicación FastAPI con middleware de seguridad,
CORS, y montaje de archivos estáticos. Implementa headers de seguridad
para prevenir ataques comunes como XSS, clickjacking, y otros.

Autor: Sistema de Chatbot
Versión: 2.0
Fecha: Diciembre 2024
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from .api import register_routes
from .db import init_db
from pathlib import Path

def create_app():
    """
    Crea y configura la aplicación FastAPI.
    
    Configura:
    - Headers de seguridad (CSP, X-Frame-Options, etc.)
    - CORS para permitir requests desde el frontend
    - Montaje de archivos estáticos
    - Inicialización de la base de datos
    - Registro de rutas API
    
    Returns:
        FastAPI: Aplicación configurada y lista para usar
    """
    app = FastAPI(
        title="Chatbot Modular App",
        description="API REST para sistema de chatbot con autenticación y gestión de Q&A",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # Middleware de headers de seguridad
    @app.middleware("http")
    async def add_security_headers(request, call_next):
        """
        Middleware que agrega headers de seguridad a todas las respuestas.
        
        Implementa medidas de seguridad contra:
        - XSS (Cross-Site Scripting)
        - Clickjacking
        - MIME type sniffing
        - Information disclosure
        
        Args:
            request: Request HTTP entrante
            call_next: Función para continuar con el siguiente middleware
            
        Returns:
            Response: Respuesta HTTP con headers de seguridad
        """
        response = await call_next(request)
        
        # Prevenir MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        # Prevenir clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        
        # Controlar información de referrer
        response.headers["Referrer-Policy"] = "no-referrer"
        
        # Restringir APIs del navegador
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
        
        # Content Security Policy - relajado para docs de Swagger
        path = request.url.path
        if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi"):
            return response
            
        # CSP estricto para el resto de la aplicación
        csp = ("default-src 'self'; "
               "img-src 'self' data:; "
               "style-src 'self' 'unsafe-inline'; "
               "script-src 'self' 'unsafe-inline'; "
               "connect-src 'self'")
        response.headers["Content-Security-Policy"] = csp
        
        # Prevenir cache de respuestas para evitar respuestas obsoletas
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        
        return response

    # Configuración de CORS (Cross-Origin Resource Sharing)
    # Permite requests desde el frontend al backend
    allowed_origins = (os.environ.get("CORS_ALLOW_ORIGINS", "").split(",") 
                      if os.environ.get("CORS_ALLOW_ORIGINS") 
                      else ["*"])
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,  # Dominios permitidos
        allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],  # Métodos HTTP permitidos
        allow_headers=["*"],  # Headers permitidos
        allow_credentials=False,  # No permite cookies en requests cross-origin
        max_age=3600,  # Cache de preflight requests por 1 hora
    )
    
    # Inicializar la base de datos al arrancar la aplicación
    init_db()
    
    # Montar archivos estáticos del frontend (si existen)
    # Esto permite servir el frontend desde el mismo servidor del backend
    STATIC_DIR = Path(__file__).parent.parent / "frontend"
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    
    # Registrar todas las rutas de la API
    register_routes(app)
    
    return app
