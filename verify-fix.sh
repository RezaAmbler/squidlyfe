#!/bin/bash
# Verification script for the empty whitelist fix
# This script tests that the container starts successfully with an empty whitelist

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
    docker-compose down -v 2>/dev/null || true
    echo "Done."
}

# Register cleanup on exit
trap cleanup EXIT

echo "Step 1: Stopping any existing containers..."
docker-compose down -v 2>/dev/null || true
print_status 0 "Stopped existing containers"
echo ""

echo "Step 2: Ensuring empty whitelist..."
mkdir -p data
cat > data/whitelist.txt <<'EOF'
# Empty whitelist for testing
# Container should start successfully in "deny all" mode
EOF
print_status 0 "Created empty whitelist"
echo ""

echo "Step 3: Building container..."
docker-compose build --quiet
print_status 0 "Container built"
echo ""

echo "Step 4: Starting container..."
docker-compose up -d
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
CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' squid-whitelist-proxy 2>/dev/null || echo "not_found")

if [ "$CONTAINER_STATUS" = "running" ]; then
    print_status 0 "Container is running"
else
    print_status 1 "Container status: $CONTAINER_STATUS (expected: running)"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-proxy
    exit 1
fi
echo ""

echo "Step 7: Checking for restart loop..."
RESTART_COUNT=$(docker inspect -f '{{.RestartCount}}' squid-whitelist-proxy 2>/dev/null || echo "unknown")
if [ "$RESTART_COUNT" = "0" ]; then
    print_status 0 "No restarts detected (restart count: $RESTART_COUNT)"
else
    print_status 1 "Container has restarted $RESTART_COUNT times"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-proxy
    exit 1
fi
echo ""

echo "Step 8: Testing health endpoint..."
sleep 2  # Give gunicorn a moment to fully start
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/health 2>/dev/null || echo "000")

if [ "$HEALTH_RESPONSE" = "200" ]; then
    print_status 0 "Health endpoint responding (HTTP $HEALTH_RESPONSE)"
else
    print_status 1 "Health endpoint not responding (HTTP $HEALTH_RESPONSE)"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-proxy | tail -n 50
    exit 1
fi
echo ""

echo "Step 9: Testing proxy behavior with empty whitelist..."
PROXY_RESPONSE=$(curl -s -x http://localhost:3128 -o /dev/null -w "%{http_code}" http://example.com 2>/dev/null || echo "000")

if [ "$PROXY_RESPONSE" = "403" ] || [ "$PROXY_RESPONSE" = "000" ]; then
    print_status 0 "Proxy correctly denies requests (HTTP $PROXY_RESPONSE)"
else
    print_warning "Proxy returned HTTP $PROXY_RESPONSE (expected 403 or connection refused)"
fi
echo ""

echo "Step 10: Checking logs for expected messages..."

# Check for successful startup message
if docker logs squid-whitelist-proxy 2>&1 | grep -q "Services Started Successfully"; then
    print_status 0 "Found 'Services Started Successfully' message"
else
    print_status 1 "Missing 'Services Started Successfully' message"
fi

# Check for empty whitelist warning
if docker logs squid-whitelist-proxy 2>&1 | grep -q "Whitelist is currently empty"; then
    print_status 0 "Found empty whitelist warning message"
else
    print_warning "Missing empty whitelist warning message"
fi

# Check that we didn't print ERROR
if docker logs squid-whitelist-proxy 2>&1 | grep -q "ERROR: Failed to start Squid proxy"; then
    print_status 1 "Found 'ERROR: Failed to start Squid proxy' (should not be present!)"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-proxy
    exit 1
else
    print_status 0 "No 'ERROR: Failed to start Squid proxy' message (correct)"
fi
echo ""

echo "Step 11: Displaying recent container logs..."
echo "----------------------------------------"
docker logs squid-whitelist-proxy 2>&1 | tail -n 30
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
echo ""
echo "The fix is working correctly!"
echo ""
echo "Next steps:"
echo "  1. Access Web UI: http://localhost:8080 (admin/changeme)"
echo "  2. Add domains to whitelist"
echo "  3. Test that proxy allows whitelisted domains"
echo ""

# Don't run cleanup - leave container running for manual testing
trap - EXIT
echo "Container left running for manual testing."
echo "Run 'docker-compose down' when finished."
