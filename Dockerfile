# Squid Whitelist Proxy - Docker Image
# Single container running Squid proxy + Flask web UI for whitelist management

FROM debian:trixie-slim

LABEL org.opencontainers.image.title="squidlyfe"
LABEL org.opencontainers.image.description="Squid HTTP proxy with web-based allow-list management for layer-7 egress control"
LABEL org.opencontainers.image.source="https://github.com/RezaAmbler/squidlyfe"
LABEL org.opencontainers.image.version="2.0.0"

# ==============================================================================
# Install system packages
# ==============================================================================

# Debian trixie ships Squid 6.13 and Python 3.13.
# python3-venv replaces python3-pip / python3-yaml: all Python dependencies
# live in the /opt/venv virtualenv created below, so nothing is installed into
# the externally-managed system interpreter.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        squid \
        python3 \
        python3-venv \
        ca-certificates \
        procps \
        curl \
        gosu \
        sudo && \
    rm -rf /var/lib/apt/lists/*

# ==============================================================================
# Environment variables (defaults)
# ==============================================================================

# Declared before the build-time config validation below, which imports
# squid_control and therefore reads WHITELIST_PATH from the environment.

# Admin credentials for web UI
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD=changeme

# Paths
ENV DATA_DIR=/data
ENV WHITELIST_PATH=/etc/squid/whitelist.txt
ENV CONFIG_PATH=/data/config.yaml

# ==============================================================================
# Create application directory and copy files
# ==============================================================================

WORKDIR /app

# Copy Python dependencies first (for better layer caching)
COPY requirements.txt /app/

# Install Python packages into a dedicated virtualenv.
# PATH must put /opt/venv/bin first: entrypoint.sh renders squid.conf by
# importing squid_control (needs PyYAML) through `python3`, and there is no
# system PyYAML any more.
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

# Copy application files
COPY app/ /app/

# Copy Squid configuration template
COPY squid/squid.conf.template /etc/squid/squid.conf.template

# Make entrypoint script executable
RUN chmod +x /app/entrypoint.sh

# Ensure appuser can read Squid configuration template
RUN chmod 644 /etc/squid/squid.conf.template

# ==============================================================================
# Build-time Squid configuration validation
# ==============================================================================

# Render the template with the real renderer and parse it with the Squid
# binary that will run in this image, so a directive this Squid version
# rejects fails `docker build` instead of surfacing at container start.
# Both generated files are removed again: entrypoint.sh STEP 2 would otherwise
# back up the stray regular whitelist file instead of symlinking /data.
RUN touch "$WHITELIST_PATH" && \
    python3 -c "import sys; sys.path.insert(0, '/app'); import squid_control as s; ok, msg = s.regenerate_squid_config(s.get_default_logging_config()); print(msg); sys.exit(0 if ok else 1)" && \
    squid -k parse -f /etc/squid/squid.conf && \
    rm -f "$WHITELIST_PATH" /etc/squid/squid.conf

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
# The home directory is required: gunicorn 26 opens its control socket at
# $HOME/.gunicorn/gunicorn.ctl and refuses to start without a writable HOME.
RUN groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -s /bin/bash -m appuser && \
    usermod -aG proxy appuser

# Set ownership of application files to appuser
RUN chown -R appuser:appuser /app

# Ensure appuser can write to necessary directories
# Note: /data volume permissions will be handled at runtime in entrypoint.sh
RUN mkdir -p /data && \
    chown -R appuser:appuser /data

# Configure sudo to allow appuser to control Squid without password
# This is required because appuser needs to send signals to Squid (running as proxy user)
# Limited to specific squid control commands for security
RUN echo "appuser ALL=(ALL) NOPASSWD: /usr/sbin/squid -k reconfigure" >> /etc/sudoers.d/appuser-squid && \
    echo "appuser ALL=(ALL) NOPASSWD: /usr/sbin/squid -k parse" >> /etc/sudoers.d/appuser-squid && \
    chmod 0440 /etc/sudoers.d/appuser-squid

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
# Health check
# ==============================================================================

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# ==============================================================================
# Entrypoint
# ==============================================================================

ENTRYPOINT ["/app/entrypoint.sh"]
