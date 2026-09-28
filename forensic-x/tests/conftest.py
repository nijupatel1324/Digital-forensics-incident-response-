"""
FORENSIC-X — pytest conftest.py
tests/conftest.py

Shared fixtures and test configuration.
"""

import os
import pytest
from httpx import AsyncClient, ASGITransport

# Set test environment variables BEFORE any app imports
# This must be at module level, before any app code is imported.
os.environ["APP_ENV"] = "testing"
os.environ["ALLOWED_HOSTS"] = "localhost,127.0.0.1,testserver,0.0.0.0,*"
os.environ["CORS_ORIGINS"] = "http://localhost,http://testserver"
os.environ["SECRET_KEY"] = "test_secret_key_32_chars_minimum_here"
os.environ["JWT_SECRET"] = "test_jwt_secret_32_chars_minimum_ok"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "TestPassword123!"
os.environ["DATABASE_URL"] = (
    "postgresql+asyncpg://forensicx:test@localhost:5432/forensicx_test"
)
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["LOG_FORMAT"] = "console"
os.environ["LOG_LEVEL"] = "WARNING"


# Import app *after* environment variables are set
from app.main import app

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.fixture
async def client():
    """Async HTTP client bound to the FastAPI app (no network needed)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
