# ============================================================
#  HoneypotNet — Base Dockerfile (shared by all services)
# ============================================================
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (needed for paramiko's cryptography wheel)
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project source
COPY . .

# Create unprivileged runtime user and data directories for defense-in-depth
RUN groupadd -g 10001 honeypot && \
    useradd -u 10001 -g honeypot -s /sbin/nologin -M honeypot && \
    mkdir -p /app/data /app/logs && \
    chown -R honeypot:honeypot /app

USER honeypot:honeypot

# Default command runs the monolith launcher
CMD ["python", "main.py"]
