# ==============================================================================
# Honeypot-System v2.0 - Production Multi-Stage Dockerfile
# ==============================================================================

# Stage 1: Build Dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Minimal Runtime
FROM python:3.11-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install minimal runtime utility for Docker health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python dependencies from builder
COPY --from=builder /install /usr/local

# Copy application source code
COPY core/ /app/core/
COPY services/ /app/services/
COPY api/ /app/api/
COPY main.py /app/main.py

# Create persistent storage directories
RUN mkdir -p /app/data /app/recordings

# Expose Decoy Service Ports and Telemetry API
EXPOSE 2222 8080 2121 2323 9090

# Ensure graceful SIGTERM propagation
STOPSIGNAL SIGTERM

# Container health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:9090/api/v1/health || exit 1

ENTRYPOINT ["python", "main.py"]
