# ============================================================
# FORENSIC-X — Dockerfile
# Multi-stage build: development → production
# ============================================================

# ── Stage 1: Base ────────────────────────────────────────────
FROM python:3.12-slim AS base

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Non-root user for security
RUN groupadd -r forensicx && useradd -r -g forensicx forensicx

# ── Stage 2: Dependencies ─────────────────────────────────────
FROM base AS dependencies

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 3: Development ─────────────────────────────────────
FROM dependencies AS development

ENV APP_ENV=development
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY . .

RUN chown -R forensicx:forensicx /app

USER forensicx

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# ── Stage 4: Production ───────────────────────────────────────
FROM dependencies AS production

ENV APP_ENV=production
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy application code
COPY --chown=forensicx:forensicx . .

# Create storage directories
RUN mkdir -p /app/evidence_store /app/reports_store /app/logs && \
    chown -R forensicx:forensicx /app/evidence_store /app/reports_store /app/logs

USER forensicx

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/ || exit 1

CMD ["python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--log-level", "info", \
     "--no-access-log"]
