"""
FORENSIC-X — Main Application Entry Point
app/main.py

Creates and configures the FastAPI application instance.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app import __version__
from app.config import settings
from app.core.logging import get_logger, setup_logging
from app.core.security_headers import SecurityHeadersMiddleware

# ── Setup logging before anything else ───────────────────────
setup_logging()
logger = get_logger(__name__)


# ── Rate Limiter ──────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_API])


# ── Lifespan (startup / shutdown) ─────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    startup: initialise connections, create storage dirs, etc.
    shutdown: close connections gracefully.
    """
    logger.info(
        "FORENSIC-X starting up",
        version=__version__,
        environment=settings.APP_ENV,
    )

    # Ensure required directories exist
    settings.evidence_upload_path
    settings.reports_path
    settings.logs_path

    logger.info("Storage directories ready")

    # Initialize the database (roles & superuser)
    from app.db.session import AsyncSessionLocal
    from app.db.init_db import init_db
    
    # We do not want to fail startup entirely if the DB is offline (e.g. during tests/build)
    # but we will attempt to initialize it.
    try:
        async with AsyncSessionLocal() as session:
            await init_db(session)
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

    yield  # Application is running

    logger.info("FORENSIC-X shutting down gracefully")


# ── Create FastAPI app ────────────────────────────────────────
def create_app() -> FastAPI:
    """Application factory — returns a configured FastAPI instance."""

    app = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Professional Digital Forensics & Incident Response (DFIR) Platform. "
            "For authorized investigations only."
        ),
        version=__version__,
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url="/api/redoc" if not settings.is_production else None,
        openapi_url="/api/openapi.json" if not settings.is_production else None,
        contact={
            "name": "FORENSIC-X Security Team",
            "email": "security@forensicx.local",
        },
        license_info={
            "name": "MIT License",
            "url": "https://opensource.org/licenses/MIT",
        },
        lifespan=lifespan,
    )

    # ── Middleware (order matters — outermost first) ───────────

    # 1. Trusted hosts (prevent host header injection)
    #    In testing we allow all hosts so httpx ASGITransport works.
    trusted_hosts = (
        ["*"]
        if settings.APP_ENV == "testing"
        else settings.allowed_hosts_list
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=trusted_hosts,
    )

    # 2. Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # 3. CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # 4. Rate limiting
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)

    # ── Static files & templates ──────────────────────────────
    import os
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")

    os.makedirs(static_dir, exist_ok=True)
    os.makedirs(templates_dir, exist_ok=True)

    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # ── API Routers ───────────────────────────────────────────
    from app.api.v1.health import router as health_router
    from app.users.router import router as users_router
    from app.cases.router import router as cases_router
    from app.evidence.router import router as evidence_router
    from app.analysis.router import router as analysis_router
    from app.timeline.router import router as timeline_router
    from app.iocs.router import router as iocs_router
    from app.detection.router import router as detection_router
    from app.incidents.router import router as incidents_router
    from app.reports.router import router as reports_router

    app.include_router(health_router, prefix="/api/v1")
    app.include_router(users_router, prefix="/api/v1", tags=["users"])
    app.include_router(cases_router, prefix="/api/v1")
    app.include_router(evidence_router, prefix="/api/v1")
    app.include_router(analysis_router, prefix="/api/v1")
    app.include_router(timeline_router, prefix="/api/v1")
    app.include_router(iocs_router, prefix="/api/v1")
    app.include_router(detection_router, prefix="/api/v1")
    app.include_router(incidents_router, prefix="/api/v1")
    app.include_router(reports_router, prefix="/api/v1")

    # ── Web Dashboard & Root Endpoint ─────────────────────────
    from fastapi.responses import HTMLResponse

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_view(request: Request):
        html_file = os.path.join(templates_dir, "index.html")
        if os.path.exists(html_file):
            with open(html_file, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
        return JSONResponse(content={"service": settings.APP_NAME, "status": "operational"})

    @app.get("/", include_in_schema=False)
    async def root_endpoint(request: Request):
        accept = request.headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            html_file = os.path.join(templates_dir, "index.html")
            if os.path.exists(html_file):
                with open(html_file, "r", encoding="utf-8") as f:
                    return HTMLResponse(content=f.read())
        return JSONResponse(
            content={
                "service": settings.APP_NAME,
                "version": __version__,
                "status": "operational",
                "docs": "/api/docs",
                "health": "/api/v1/health",
            }
        )

    # ── Global exception handlers ─────────────────────────────
    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return JSONResponse(
            status_code=404,
            content={
                "error": "Not Found",
                "detail": f"The requested resource was not found: {request.url.path}",
            },
        )

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc):
        logger.error("Unhandled internal server error", exc_info=exc)
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred. Please contact the administrator.",
            },
        )

    logger.info("FastAPI application created successfully")
    return app


# ── Application instance ──────────────────────────────────────
app = create_app()
