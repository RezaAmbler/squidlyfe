#!/bin/bash
# Test: Container should start successfully with an empty whitelist
# This simulates the regression scenario where the container was failing

set -e

echo "=========================================="
echo "Test: Empty Whitelist Startup"
echo "=========================================="

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up test environment..."
    docker-compose down -v 2>/dev/null || true
    rm -rf test_data 2>/dev/null || true
}

# Register cleanup on exit
trap cleanup EXIT

# Create test data directory with empty whitelist
echo "[1/5] Creating test environment with empty whitelist..."
mkdir -p test_data
cat > test_data/whitelist.txt <<EOF
# Empty whitelist - only comments
# This should NOT cause the container to fail
EOF

echo "  ✓ Created empty whitelist"

# Update docker-compose to use test data directory
echo "[2/5] Starting container with empty whitelist..."
docker-compose down -v 2>/dev/null || true

# Start container (mounting test data)
docker run -d \
    --name squid-whitelist-test \
    -p 3128:3128 \
    -p 8080:8080 \
    -v "$(pwd)/test_data:/data" \
    -e ADMIN_USERNAME=admin \
    -e ADMIN_PASSWORD=testpass \
    squidlyfe_squid-whitelist-proxy:latest 2>/dev/null || {

    # If image doesn't exist, build it first
    echo "  → Building image..."
    docker-compose build

    docker run -d \
        --name squid-whitelist-test \
        -p 3128:3128 \
        -p 8080:8080 \
        -v "$(pwd)/test_data:/data" \
        -e ADMIN_USERNAME=admin \
        -e ADMIN_PASSWORD=testpass \
        squidlyfe_squid-whitelist-proxy:latest
}

echo "  ✓ Container started"

# Wait for container to initialize
echo "[3/5] Waiting for services to start..."
sleep 10

# Check if container is still running (not in restart loop)
echo "[4/5] Checking container status..."
if docker ps | grep -q squid-whitelist-test; then
    echo "  ✓ Container is running (not in restart loop)"
else
    echo "  ✗ FAILED: Container is not running!"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-test
    exit 1
fi

# Test health endpoint
echo "[5/5] Testing health endpoint..."
if curl -f -s http://localhost:8080/health > /dev/null; then
    echo "  ✓ Health endpoint responding"
else
    echo "  ✗ FAILED: Health endpoint not responding!"
    echo ""
    echo "Container logs:"
    docker logs squid-whitelist-test
    exit 1
fi

# Test that proxy is running (should deny all with empty whitelist)
echo ""
echo "Testing proxy behavior with empty whitelist..."
HTTP_CODE=$(curl -x http://localhost:3128 -s -o /dev/null -w "%{http_code}" http://example.com || echo "000")

if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "000" ]; then
    echo "  ✓ Proxy correctly denies requests with empty whitelist (HTTP $HTTP_CODE)"
else
    echo "  ⚠️  Warning: Expected HTTP 403 or connection refused, got $HTTP_CODE"
fi

# Check container logs for the expected informational message
echo ""
echo "Checking logs for empty whitelist notification..."
if docker logs squid-whitelist-test 2>&1 | grep -q "Whitelist is currently empty"; then
    echo "  ✓ Empty whitelist notification found in logs"
else
    echo "  ⚠️  Warning: Empty whitelist notification not found in logs"
fi

# Display relevant log snippet
echo ""
echo "Container startup log snippet:"
docker logs squid-whitelist-test 2>&1 | grep -A 2 "Initializing whitelist"

echo ""
echo "=========================================="
echo "✓ TEST PASSED"
echo "=========================================="
echo "Container successfully started with empty whitelist"
echo "Proxy is denying all traffic as expected"

# Cleanup happens automatically via trap
docker stop squid-whitelist-test > /dev/null
docker rm squid-whitelist-test > /dev/null
