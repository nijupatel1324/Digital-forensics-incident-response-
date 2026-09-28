"""
FORENSIC-X — Phase 1 Tests
tests/test_phase1_health.py

Verifies:
- Application starts correctly
- Health endpoint returns 200
- Version endpoint returns correct version
- Root endpoint responds
- Security headers are present
"""

import pytest
from httpx import AsyncClient

from app.main import app
from app import __version__


# ── Liveness ──────────────────────────────────────────────────

@pytest.mark.anyio
async def test_health_liveness_returns_200(client: AsyncClient):
    """Basic liveness probe must return HTTP 200."""
    response = await client.get("/api/v1/health/")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_health_liveness_payload(client: AsyncClient):
    """Liveness payload must contain expected fields."""
    response = await client.get("/api/v1/health/")
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == __version__
    assert "timestamp" in data
    assert "service" in data


# ── Version ───────────────────────────────────────────────────

@pytest.mark.anyio
async def test_health_version_returns_200(client: AsyncClient):
    """Version endpoint must return HTTP 200."""
    response = await client.get("/api/v1/health/version")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_health_version_payload(client: AsyncClient):
    """Version payload must include version and platform info."""
    response = await client.get("/api/v1/health/version")
    data = response.json()
    assert data["version"] == __version__
    assert data["api_version"] == "v1"
    assert "python_version" in data
    assert "platform" in data


# ── Root endpoint ─────────────────────────────────────────────

@pytest.mark.anyio
async def test_root_endpoint(client: AsyncClient):
    """Root / must return 200 with service info."""
    response = await client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "service" in data
    assert data["status"] == "operational"


# ── Security headers ──────────────────────────────────────────

@pytest.mark.anyio
async def test_security_headers_present(client: AsyncClient):
    """OWASP security headers must be present on all responses."""
    response = await client.get("/api/v1/health/")
    headers = response.headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in headers
    assert "referrer-policy" in headers


# ── 404 handler ───────────────────────────────────────────────

@pytest.mark.anyio
async def test_404_returns_json(client: AsyncClient):
    """Unknown routes must return structured JSON 404."""
    response = await client.get("/api/v1/nonexistent-endpoint")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data


# ── Config ───────────────────────────────────────────────────

def test_settings_loaded():
    """Settings must load without error."""
    from app.config import settings
    assert settings.APP_NAME == "FORENSIC-X"
    assert settings.APP_VERSION == "1.0.0"
    assert len(settings.allowed_extensions_set) > 0


def test_version_string():
    """__version__ must be defined."""
    assert __version__ is not None
    assert isinstance(__version__, str)
    # Basic semver check
    parts = __version__.split(".")
    assert len(parts) == 3
