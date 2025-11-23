#!/bin/bash
# Note: We don't use 'set -e' here because we need to handle Squid warnings
# vs errors explicitly. Squid warnings (like empty ACL) are not fatal.

echo "============================================"
echo "Squid Whitelist Proxy - Starting Container"
echo "============================================"

# Configuration paths
DATA_DIR=${DATA_DIR:-/data}
WHITELIST_PATH=${WHITELIST_PATH:-/etc/squid/whitelist.txt}
CONFIG_PATH=${CONFIG_PATH:-/data/config.yaml}
SQUID_CONFIG_PATH=/etc/squid/squid.conf
SQUID_CONFIG_TEMPLATE=/etc/squid/squid.conf.template

# ==============================================================================
# STEP 1: Initialize data directory and ensure it's writable
# ==============================================================================

echo "[1/6] Checking data directory..."

if [ ! -d "$DATA_DIR" ]; then
    echo "ERROR: Data directory $DATA_DIR does not exist!"
    echo "Please mount a volume at $DATA_DIR"
    exit 1
fi

if [ ! -w "$DATA_DIR" ]; then
    echo "ERROR: Data directory $DATA_DIR is not writable!"
    echo "Please check volume permissions"
    exit 1
fi

echo "  ✓ Data directory: $DATA_DIR"

# ==============================================================================
# STEP 2: Initialize whitelist file if it doesn't exist
# ==============================================================================

echo "[2/6] Initializing whitelist..."

if [ ! -f "$DATA_DIR/whitelist.txt" ]; then
    echo "  → Creating initial whitelist file"
    cat > "$DATA_DIR/whitelist.txt" <<EOF
# Squid Whitelist - Allowed Domains/URLs
# This file is managed by the Squid Proxy Web UI
# Each line should contain one domain or URL pattern
#
# Examples:
#   example.com           - Exact domain
#   .example.com          - Domain and all subdomains
#   subdomain.example.com - Specific subdomain only
#
# Add your allowed domains below:

EOF
    chmod 644 "$DATA_DIR/whitelist.txt"
    echo "  ✓ Created empty whitelist at $DATA_DIR/whitelist.txt"
else
    echo "  ✓ Existing whitelist found"
fi

# Check if whitelist is empty (only comments/whitespace)
WHITELIST_ENTRIES=$(grep -v "^#" "$DATA_DIR/whitelist.txt" | grep -v "^[[:space:]]*$" | wc -l)
if [ "$WHITELIST_ENTRIES" -eq 0 ]; then
    echo "  ⚠️  Whitelist is currently empty - Squid will start in 'deny all' mode"
    echo "  → Add domains via the Web UI (port 8080) to allow traffic"
fi

# Create symlink from Squid config location to data directory
# This allows Squid to read the whitelist from /etc/squid/ while data persists in /data
if [ -L "$WHITELIST_PATH" ]; then
    rm -f "$WHITELIST_PATH"
fi

if [ -f "$WHITELIST_PATH" ] && [ ! -L "$WHITELIST_PATH" ]; then
    echo "  → Backing up existing whitelist"
    mv "$WHITELIST_PATH" "$WHITELIST_PATH.bak"
fi

ln -sf "$DATA_DIR/whitelist.txt" "$WHITELIST_PATH"
echo "  ✓ Symlinked $WHITELIST_PATH -> $DATA_DIR/whitelist.txt"

# ==============================================================================
# STEP 3: Initialize config file if it doesn't exist
# ==============================================================================

echo "[3/6] Initializing configuration..."

if [ ! -f "$CONFIG_PATH" ]; then
    echo "  → Creating default configuration"
    cat > "$CONFIG_PATH" <<EOF
# Squid Proxy Manager Configuration
# This file is managed by the web UI

logging:
  mode: local_file
  syslog_host: ''
  syslog_port: '514'
  syslog_protocol: udp
EOF
    chmod 644 "$CONFIG_PATH"
    echo "  ✓ Created default config at $CONFIG_PATH"
else
    echo "  ✓ Existing configuration found"
fi

# ==============================================================================
# STEP 4: Generate Squid configuration from template
# ==============================================================================

echo "[4/6] Generating Squid configuration..."

if [ ! -f "$SQUID_CONFIG_TEMPLATE" ]; then
    echo "ERROR: Squid config template not found at $SQUID_CONFIG_TEMPLATE"
    exit 1
fi

# Read logging config from YAML (simple parsing - defaults to local_file)
LOGGING_MODE=$(grep -A 1 "^logging:" "$CONFIG_PATH" | grep "mode:" | awk '{print $2}' || echo "local_file")

echo "  → Logging mode: $LOGGING_MODE"

# Generate logging configuration based on mode
if [ "$LOGGING_MODE" = "stdout" ]; then
    LOGGING_CONFIG="access_log stdio:/dev/stdout squid"
elif [ "$LOGGING_MODE" = "remote_syslog" ]; then
    SYSLOG_HOST=$(grep "syslog_host:" "$CONFIG_PATH" | awk '{print $2}' | tr -d "'\"" || echo "")
    SYSLOG_PORT=$(grep "syslog_port:" "$CONFIG_PATH" | awk '{print $2}' | tr -d "'\"" || echo "514")
    SYSLOG_PROTO=$(grep "syslog_protocol:" "$CONFIG_PATH" | awk '{print $2}' | tr -d "'\"" || echo "udp")
    LOGGING_CONFIG="# Remote syslog mode: logs to stdout (use external log shipper to forward)
# Target: ${SYSLOG_PROTO}://${SYSLOG_HOST}:${SYSLOG_PORT}
access_log stdio:/dev/stdout squid"
else
    # Default: local_file
    LOGGING_CONFIG="access_log /var/log/squid/access.log squid"
fi

# Generate squid.conf from template
sed -e "s|{{LOGGING_CONFIG}}|$LOGGING_CONFIG|g" \
    -e "s|{{WHITELIST_PATH}}|$WHITELIST_PATH|g" \
    "$SQUID_CONFIG_TEMPLATE" > "$SQUID_CONFIG_PATH"

chmod 644 "$SQUID_CONFIG_PATH"
echo "  ✓ Generated Squid config at $SQUID_CONFIG_PATH"

# ==============================================================================
# STEP 5: Initialize Squid cache directories and validate config
# ==============================================================================

echo "[5/6] Initializing Squid..."

# Create log directory
mkdir -p /var/log/squid
chmod 755 /var/log/squid

# Initialize Squid cache directory with proper ownership and structure
# This function handles both fresh setup and recovery from incomplete states
initialize_squid_cache() {
    local cache_dir="/var/spool/squid"

    echo "  → Checking Squid cache directory: $cache_dir"

    # Ensure the cache directory exists
    if [ ! -d "$cache_dir" ]; then
        echo "  → Creating cache directory"
        mkdir -p "$cache_dir"
    fi

    # Ensure /var/run is writable for PID file
    mkdir -p /var/run
    chmod 755 /var/run

    # Set ownership to proxy user (Squid runs as 'proxy' user in Debian)
    # This is critical for bind-mounted volumes which may have wrong ownership
    chown -R proxy:proxy "$cache_dir" 2>/dev/null || true
    chmod 750 "$cache_dir"

    # Check if cache structure exists (00-0F subdirectories)
    if [ ! -d "$cache_dir/00" ]; then
        echo "  → Cache structure not found, initializing..."

        # Remove stale PID file if it exists (prevents "already running" errors)
        # PID file is now in cache directory: /var/spool/squid/squid.pid
        if [ -f /var/spool/squid/squid.pid ]; then
            echo "  → Removing stale PID file"
            rm -f /var/spool/squid/squid.pid
        fi

        # Initialize cache structure as root
        # -z: create swap directories
        # -f: specify config file
        # Note: We run as root here because squid -z needs to write to /var/run/squid.pid
        # and may have permission issues when run as proxy user
        echo "  → Running: squid -z to create cache structure"

        # Capture output and check for actual errors (not warnings)
        SQUID_Z_OUTPUT=$(squid -z -f "$SQUID_CONFIG_PATH" 2>&1) || SQUID_Z_EXIT=$?

        # Check if it failed
        if echo "$SQUID_Z_OUTPUT" | grep -q "FATAL.*failed to open"; then
            echo "ERROR: squid -z failed with FATAL error"
            echo "$SQUID_Z_OUTPUT"
            return 1
        elif [ "${SQUID_Z_EXIT:-0}" -ne 0 ]; then
            echo "ERROR: squid -z exited with code $SQUID_Z_EXIT"
            echo "$SQUID_Z_OUTPUT"
            return 1
        else
            echo "  ✓ Cache initialization completed"
        fi

        # Fix ownership after root creation
        chown -R proxy:proxy "$cache_dir" 2>/dev/null || true

        # Verify cache directories were created
        # squid -z creates 00/ through 0F/ (16 directories)
        if [ -d "$cache_dir/00" ] && [ -d "$cache_dir/0F" ]; then
            echo "  ✓ Cache directories verified (00-0F present)"
        else
            echo "ERROR: Cache directories not created properly"
            echo "Expected directories 00-0F in $cache_dir"
            ls -la "$cache_dir" || true
            return 1
        fi
    else
        echo "  ✓ Cache structure already exists"

        # Ensure ownership is correct even for existing cache
        chown -R proxy:proxy "$cache_dir" 2>/dev/null || true
    fi

    return 0
}

# Run cache initialization
if ! initialize_squid_cache; then
    echo "ERROR: Squid cache initialization failed"
    exit 1
fi

# Validate Squid configuration
# Note: We only care about the exit code, not warnings like "empty ACL"
echo "  → Validating Squid configuration"
PARSE_OUTPUT=$(squid -k parse 2>&1)
PARSE_EXIT_CODE=$?

if [ $PARSE_EXIT_CODE -eq 0 ]; then
    echo "  ✓ Squid configuration is valid"
    # Check for empty ACL warning (informational only)
    if echo "$PARSE_OUTPUT" | grep -q "Warning: empty ACL"; then
        echo "  ℹ️  Note: Empty whitelist detected (this is OK - deny all mode)"
    fi
else
    echo "ERROR: Squid configuration is invalid!"
    echo "Exit code: $PARSE_EXIT_CODE"
    echo "Output:"
    echo "$PARSE_OUTPUT"
    echo "Check the configuration at $SQUID_CONFIG_PATH"
    exit 1
fi

# ==============================================================================
# STEP 6: Start Squid and Flask application
# ==============================================================================

echo "[6/6] Starting services..."

# Start Squid in background (daemon mode)
echo "  → Starting Squid proxy on port 3128"

# Clean up any stale PID file before starting Squid
# This prevents "Squid is already running" errors after container restarts
# PID file is now in cache directory: /var/spool/squid/squid.pid
PID_FILE="/var/spool/squid/squid.pid"
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE" 2>/dev/null || echo "")
    if [ -n "$PID" ]; then
        # Check if process is actually running
        if ! kill -0 "$PID" 2>/dev/null; then
            echo "  → Removing stale PID file (process $PID not running)"
            rm -f "$PID_FILE"
        fi
    else
        rm -f "$PID_FILE"
    fi
fi

# Start Squid without the -s flag (which prints to stderr and can confuse error detection)
# Squid will daemonize itself and logs will go to the configured log files
squid

# Give Squid a moment to initialize
sleep 2

# Check if Squid is running
# Use a retry loop since Squid may take a moment to fully start
RETRY_COUNT=0
MAX_RETRIES=10
SQUID_RUNNING=false

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    # Check if squid process is running
    if pgrep -x squid > /dev/null 2>&1; then
        SQUID_RUNNING=true
        echo "  ✓ Squid proxy started successfully"
        break
    fi

    # Check if there are errors in cache.log that would indicate a fatal problem
    if [ -f /var/log/squid/cache.log ]; then
        if grep -q "FATAL" /var/log/squid/cache.log 2>/dev/null; then
            echo "ERROR: Squid encountered a fatal error during startup"
            echo "Recent cache log entries:"
            tail -n 20 /var/log/squid/cache.log
            exit 1
        fi
    fi

    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
        echo "  → Waiting for Squid to start (attempt $RETRY_COUNT/$MAX_RETRIES)..."
        sleep 1
    fi
done

if [ "$SQUID_RUNNING" = "false" ]; then
    echo "ERROR: Squid process not detected after startup"
    echo "This may indicate a configuration problem or permission issue"

    if [ -f /var/log/squid/cache.log ]; then
        echo ""
        echo "Recent cache log entries:"
        tail -n 30 /var/log/squid/cache.log
    fi

    # List any squid processes that might exist
    echo ""
    echo "Process check:"
    ps aux | grep squid || echo "No squid processes found"

    exit 1
fi

# Display admin credentials warning
echo ""
echo "============================================"
echo "Services Started Successfully!"
echo "============================================"
echo "Squid Proxy:  port 3128"
echo "Web UI:       port 8080"
echo ""
echo "Admin Username: ${ADMIN_USERNAME:-admin}"
if [ "${ADMIN_PASSWORD:-changeme}" = "changeme" ]; then
    echo "Admin Password: changeme (DEFAULT - CHANGE THIS!)"
    echo ""
    echo "⚠️  WARNING: Using default password 'changeme'!"
    echo "⚠️  Set ADMIN_PASSWORD environment variable to secure the UI"
else
    echo "Admin Password: <set via environment>"
fi
echo ""
echo "Whitelist: $DATA_DIR/whitelist.txt"
echo "Config:    $DATA_DIR/config.yaml"
echo "============================================"
echo ""

# Start Flask application using gunicorn
# This runs in the foreground and keeps the container alive
echo "Starting web UI..."
cd /app

exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 2 \
    --threads 4 \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    app:app
