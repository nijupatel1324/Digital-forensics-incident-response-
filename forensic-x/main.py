"""
FORENSIC-X — WSGI/ASGI entry point
main.py  (project root — used by uvicorn and Docker)
"""

import uvicorn

from app.config import settings
from app.main import app  # noqa: F401  (import for uvicorn string reference)

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=settings.APP_DEBUG,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        workers=1,  # Use 1 worker in dev; scale in production
    )
