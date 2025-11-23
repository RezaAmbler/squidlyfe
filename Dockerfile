# Squid Whitelist Proxy - Docker Image
# Single container running Squid proxy + Flask web UI for whitelist management

FROM debian:bookworm-slim

LABEL maintainer="IT Security Team"
LABEL description="Squid HTTP proxy with web-based whitelist management for layer-7 egress control"
LABEL version="1.0"

# ==============================================================================
# Install system packages
# ==============================================================================

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        squid \
        python3 \
        python3-pip \
        python3-yaml \
        ca-certificates \
        procps \
        curl \
        gosu && \
    rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Create application directory and copy files
# ==============================================================================

WORKDIR /app

# Copy Python dependencies first (for better layer caching)
COPY requirements.txt /app/

# Install Python packages
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application files
COPY app/ /app/

# Copy Squid configuration template
COPY squid/squid.conf.template /etc/squid/squid.conf.template

# Make entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# ==============================================================================
# Create necessary directories and set permissions
# ==============================================================================

RUN mkdir -p /var/log/squid && \
    mkdir -p /var/spool/squid && \
    mkdir -p /var/run && \
    chmod 755 /var/log/squid && \
    chmod 755 /var/spool/squid

# ==============================================================================
# Create non-root user for Flask application
# ==============================================================================

# Create appuser with UID 1000 (common for first user on most systems)
# This user will run the Flask web application via gunicorn
# Squid will continue to run as the 'proxy' user (created by squid package)
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser

# Set ownership of application files to appuser
RUN chown -R appuser:appuser /app

# Ensure appuser can write to necessary directories
# Note: /data volume permissions will be handled at runtime in entrypoint.sh
RUN mkdir -p /data && \
    chown -R appuser:appuser /data

# ==============================================================================
# Expose ports
# ==============================================================================

# 3128: Squid HTTP proxy
# 8080: Flask web UI
EXPOSE 3128 8080

# ==============================================================================
# Volume for persistent data
# ==============================================================================

# Mount this volume to persist whitelist and configuration
# Example: -v ./data:/data
VOLUME ["/data"]

# ==============================================================================
# Environment variables (defaults)
# ==============================================================================

# Admin credentials for web UI
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=changeme

# Paths
ENV DATA_DIR=/data
ENV WHITELIST_PATH=/etc/squid/whitelist.txt
ENV CONFIG_PATH=/data/config.yaml

# ==============================================================================
# Health check
# ==============================================================================

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# ==============================================================================
# Entrypoint
# ==============================================================================

ENTRYPOINT ["/app/entrypoint.sh"]
