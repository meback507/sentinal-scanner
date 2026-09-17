# AegisSec - Enterprise SAST & SCA Security Platform Dockerfile
FROM python:3.12-slim

# Install system dependencies: git for repository scanning, curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Create persistent storage directory
RUN mkdir -p /app/data

# Environment configuration
ENV PYTHONUNBUFFERED=1
ENV PORT=8000
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/auth/me || exit 1

# Launch AegisSec platform
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
