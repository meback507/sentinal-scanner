# Sentinel AppSec - Cloud-Ready Production Dockerfile
# Optimized for AWS ECS/EKS, GCP Cloud Run/GKE, Azure Container Apps, DigitalOcean, and standalone VPS

FROM python:3.12-slim

# Set environment variables for unbuffered logging, bytecode prevention, and default cloud port
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    SENTINEL_DB_PATH=/app/data/sentinel.db \
    APP_ENV=production

# Install system dependencies:
# - git: for repository cloning, git blame, commit-level vulnerability attribution & age tracking
# - curl: for health check probes and remote downloading
# - ca-certificates: for secure outbound TLS connections to Git providers & Jira/Zammad integrations
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Security Hardening (CIS Docker 4.1):
# Create an unprivileged system user/group to avoid running container processes as root
RUN groupadd -g 10001 sentinel && \
    useradd -u 10001 -g sentinel -s /bin/bash -m sentinel

WORKDIR /app

# Install Python dependencies first to leverage Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and assets
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY .sentinel/ ./.sentinel/
COPY ide-extension/ ./ide-extension/
COPY scripts/ ./scripts/

# Create persistent storage directories for SQLite DB, reports, and temp workspaces
RUN mkdir -p /app/data /app/reports /app/workspaces && \
    chown -R sentinel:sentinel /app

# Switch to unprivileged runtime user
USER sentinel

# Expose default HTTP port (overridable via $PORT in cloud environments)
EXPOSE 8000

# Cloud-native healthcheck probe (works with dynamic $PORT on Cloud Run, ECS, or Kubernetes)
HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT:-8000}/api/health || exit 1

# Launch uvicorn dynamically bound to $PORT with multi-worker concurrency
CMD ["sh", "-c", "exec uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers ${WORKERS:-2}"]
