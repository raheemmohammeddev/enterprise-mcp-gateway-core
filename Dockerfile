# Enterprise MCP Gateway - Production Dockerfile
# Multi-stage build for minimal image size.

FROM python:3.12-slim AS base

LABEL maintainer="Raheem Mohammed"
LABEL description="Enterprise MCP Gateway with RBAC, Multi-Backend, and Audit"

WORKDIR /app

# Install system dependencies (ODBC driver for SQL Server connectivity)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg2 && \
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list && \
    apt-get update && \
    ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 && \
    apt-get purge -y curl gnupg2 && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ src/
COPY scripts/ scripts/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health')" || exit 1

EXPOSE 8100

# Run as non-root user
RUN useradd -m -r gateway && chown -R gateway:gateway /app
USER gateway

CMD ["python", "src/gateway/app.py", "--transport=streamable-http", "--port=8100"]
