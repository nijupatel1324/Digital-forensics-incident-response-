"""
FORENSIC-X — Health-Check & System Info Router
app/api/v1/health.py

Provides:
  GET /api/v1/health          — basic liveness
  GET /api/v1/health/detail   — database + redis connectivity
  GET /api/v1/health/version  — version information
"""

import platform
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app import __version__
from app.config import settings
from app.core.logging import get_logger

router = APIRouter(prefix="/health", tags=["Health"])
logger = get_logger(__name__)

# Track application start time
_start_time = time.monotonic()


# ── Response schemas ──────────────────────────────────────────

class HealthBasic(BaseModel):
    status: str
    timestamp: str
    service: str
    version: str


class ComponentStatus(BaseModel):
    status: str
    latency_ms: float | None = None
    error: str | None = None


class HealthDetail(BaseModel):
    status: str
    timestamp: str
    service: str
    version: str
    environment: str
    uptime_seconds: float
    components: dict[str, ComponentStatus]


class VersionInfo(BaseModel):
    service: str
    version: str
    api_version: str
    python_version: str
    platform: str
    environment: str
    build_timestamp: str


# ── Endpoints ─────────────────────────────────────────────────

@router.get(
    "/",
    response_model=HealthBasic,
    summary="Liveness check",
    description="Returns 200 if the application is running.",
)
async def health_liveness() -> HealthBasic:
    """Simple liveness probe — no external dependency checks."""
    return HealthBasic(
        status="healthy",
        timestamp=datetime.now(timezone.utc).isoformat(),
        service=settings.APP_NAME,
        version=__version__,
    )


@router.get(
    "/detail",
    response_model=HealthDetail,
    summary="Detailed health check",
    description="Checks connectivity to database and Redis.",
)
async def health_detail() -> HealthDetail:
    """
    Readiness probe — verifies all infrastructure components.
    Used by Docker / Kubernetes health checks.
    """
    components: dict[str, ComponentStatus] = {}
    overall = "healthy"

    # ── Database check ────────────────────────────────────────
    try:
        t0 = time.monotonic()
        # Import here to avoid circular imports at module load time
        from app.db.session import engine
        from sqlalchemy import text

        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (time.monotonic() - t0) * 1000
        components["database"] = ComponentStatus(
            status="healthy", latency_ms=round(latency, 2)
        )
    except Exception as exc:
        logger.warning("Database health check failed", error=str(exc))
        components["database"] = ComponentStatus(
            status="unhealthy", error=str(exc)
        )
        overall = "degraded"

    # ── Redis check ───────────────────────────────────────────
    try:
        t0 = time.monotonic()
        import redis.asyncio as aioredis  # type: ignore

        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await r.ping()
        await r.aclose()
        latency = (time.monotonic() - t0) * 1000
        components["redis"] = ComponentStatus(
            status="healthy", latency_ms=round(latency, 2)
        )
    except Exception as exc:
        logger.warning("Redis health check failed", error=str(exc))
        components["redis"] = ComponentStatus(
            status="unavailable", error=str(exc)
        )
        # Redis is optional in dev; don't mark as fully unhealthy
        if overall == "healthy":
            overall = "degraded"

    return HealthDetail(
        status=overall,
        timestamp=datetime.now(timezone.utc).isoformat(),
        service=settings.APP_NAME,
        version=__version__,
        environment=settings.APP_ENV,
        uptime_seconds=round(time.monotonic() - _start_time, 2),
        components=components,
    )


@router.get(
    "/version",
    response_model=VersionInfo,
    summary="Version information",
    description="Returns build and runtime version details.",
)
async def health_version() -> VersionInfo:
    """Return version and runtime information."""
    return VersionInfo(
        service=settings.APP_NAME,
        version=__version__,
        api_version="v1",
        python_version=platform.python_version(),
        platform=platform.system(),
        environment=settings.APP_ENV,
        build_timestamp=datetime.now(timezone.utc).isoformat(),
    )
