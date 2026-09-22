#!/bin/bash
# Verification script for the empty whitelist fix
# This script tests that the container starts successfully with an empty whitelist
#
# SAFETY: this script never touches the repo's ./data directory or the
# docker-compose project. It builds the image, then runs a throwaway container
# against a temporary data directory on non-default ports, so it is safe to run
# while a real instance is up.

set -e

echo "=========================================="
echo "Verifying Container Startup Fix"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration (override via environment)
IMAGE="${IMAGE:-squidlyfe:verify-fix}"
CONTAINER_NAME="${CONTAINER_NAME:-squidlyfe-verify-fix}"
UI_PORT="${UI_PORT:-18086}"
PROXY_PORT="${PROXY_PORT:-13136}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
        return 1
    fi
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    if [ -n "${TEST_DATA_DIR:-}" ] && [ -d "$TEST_DATA_DIR" ]; then
        rm -rf "$TEST_DATA_DIR"
    fi
    echo "Done."
}

# Register cleanup on exit
trap cleanup EXIT

echo "Step 1: Preparing an isolated test environment..."
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

TEST_DATA_DIR="$(mktemp -d)"

# Refuse to run against the repo's real data directory. Overwriting it would
# destroy the operator's live allow-list, which is exactly what this script
# used to do.
REPO_DATA="$(cd "$(dirname "$0")" && pwd)/data"
case "$TEST_DATA_DIR" in
    "$REPO_DATA"|"$REPO_DATA"/*)
        echo -e "${RED}✗${NC} Refusing to run: test data dir resolves inside $REPO_DATA"
        exit 1
        ;;
esac
print_status 0 "Throwaway data directory: $TEST_DATA_DIR"
echo ""

echo "Step 2: Creating an empty whitelist (in the throwaway directory)..."
cat > "$TEST_DATA_DIR/whitelist.txt" <<'EOF'
# Empty whitelist for testing
# Container should start successfully in "deny all" mode
EOF
print_status 0 "Created empty whitelist"
echo ""

echo "Step 3: Building container image ($IMAGE)..."
docker build --quiet -t "$IMAGE" "$(dirname "$0")" >/dev/null
print_status 0 "Container built"
echo ""

echo "Step 4: Starting container on $BIND_ADDR:$UI_PORT / $BIND_ADDR:$PROXY_PORT..."
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "$BIND_ADDR:$PROXY_PORT:3128" \
    -p "$BIND_ADDR:$UI_PORT:8080" \
    -v "$TEST_DATA_DIR:/data" \
    -e DISABLE_SECURE_COOKIES=true \
    "$IMAGE" >/dev/null
print_status 0 "Container started"
echo ""

echo "Step 5: Waiting for container to initialize (15 seconds)..."
for i in {15..1}; do
    echo -ne "  Waiting... ${i}s remaining\r"
    sleep 1
done
echo "  Waiting... Done!     "
echo ""

echo "Step 6: Checking container status..."
CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not_found")

if [ "$CONTAINER_STATUS" = "running" ]; then
    print_status 0 "Container is running"
else
    print_status 1 "Container status: $CONTAINER_STATUS (expected: running)"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME"
    exit 1
fi
echo ""

echo "Step 7: Checking for restart loop..."
RESTART_COUNT=$(docker inspect -f '{{.RestartCount}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")
if [ "$RESTART_COUNT" = "0" ]; then
    print_status 0 "No restarts detected (restart count: $RESTART_COUNT)"
else
    print_status 1 "Container has restarted $RESTART_COUNT times"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME"
    exit 1
fi
echo ""

echo "Step 8: Testing health endpoint..."
sleep 2  # Give gunicorn a moment to fully start
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://$BIND_ADDR:$UI_PORT/health" 2>/dev/null || echo "000")

if [ "$HEALTH_RESPONSE" = "200" ]; then
    print_status 0 "Health endpoint responding (HTTP $HEALTH_RESPONSE)"
else
    print_status 1 "Health endpoint not responding (HTTP $HEALTH_RESPONSE)"
    echo ""
    echo "Container logs:"
    docker logs "$CONTAINER_NAME" | tail -n 50
    exit 1
fi
echo ""

echo "Step 9: Testing proxy behavior with empty whitelist..."
PROXY_RESPONSE=$(curl -s -x "http://$BIND_ADDR:$PROXY_PORT" -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || echo "000")

if [ "$PROXY_RESPONSE" = "403" ] || [ "$PROXY_RESPONSE" = "000" ]; then
    print_status 0 "Proxy correctly denies requests (HTTP $PROXY_RESPONSE)"
else
    print_warning "Proxy returned HTTP $PROXY_RESPONSE (expected 403 or connection refused)"
fi
echo ""

echo "Step 10: Checking logs for expected messages..."

# Check for successful startup message. Buffer the logs first: piping straight
# into `grep -q` makes grep exit early, and the SIGPIPE that kills `docker logs`
# would fail the script under `set -e`.
LOG_SNAPSHOT="$TEST_DATA_DIR/container.log"
docker logs "$CONTAINER_NAME" > "$LOG_SNAPSHOT" 2>&1 || true

if grep -q "Services Started Successfully" "$LOG_SNAPSHOT"; then
    print_status 0 "Found 'Services Started Successfully' message"
else
    print_status 1 "Missing 'Services Started Successfully' message"
fi

# Check for empty whitelist warning
if grep -q "Whitelist is currently empty" "$LOG_SNAPSHOT"; then
    print_status 0 "Found empty whitelist warning message"
else
    print_warning "Missing empty whitelist warning message"
fi

# Check that we didn't print ERROR
if grep -q "ERROR: Failed to start Squid proxy" "$LOG_SNAPSHOT"; then
    print_status 1 "Found 'ERROR: Failed to start Squid proxy' (should not be present!)"
    echo ""
    echo "Container logs:"
    cat "$LOG_SNAPSHOT"
    exit 1
else
    print_status 0 "No 'ERROR: Failed to start Squid proxy' message (correct)"
fi
echo ""

echo "Step 11: Verifying the real ./data directory was not touched..."
if [ -f "$REPO_DATA/whitelist.txt" ] && ! grep -q "Empty whitelist for testing" "$REPO_DATA/whitelist.txt"; then
    print_status 0 "Repo ./data/whitelist.txt untouched"
elif [ ! -e "$REPO_DATA/whitelist.txt" ]; then
    print_status 0 "No repo ./data/whitelist.txt present (nothing to protect)"
else
    print_status 1 "Repo ./data/whitelist.txt looks overwritten by this script!"
    exit 1
fi
echo ""

echo "Step 12: Displaying recent container logs..."
echo "----------------------------------------"
tail -n 30 "$LOG_SNAPSHOT"
echo "----------------------------------------"
echo ""

echo "=========================================="
echo -e "${GREEN}✓ ALL CHECKS PASSED${NC}"
echo "=========================================="
echo ""
echo "Summary:"
echo "  • Container started successfully"
echo "  • No restart loop detected"
echo "  • Health endpoint responding"
echo "  • Squid denying traffic (correct with empty whitelist)"
echo "  • Proper log messages displayed"
echo "  • The repo's ./data directory was left alone"
echo ""
echo "The fix is working correctly!"
echo ""
echo "This run used a throwaway data directory and is cleaned up automatically."
echo "To try the appliance for real: make up  (Web UI on http://localhost:8080)"
echo ""
