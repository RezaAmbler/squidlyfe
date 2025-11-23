#!/usr/bin/env bash
# Dev Reset and Test Script
# Performs a clean restart of the Squid proxy container and validates functionality
#
# Usage: ./scripts/dev_reset_and_test.sh
#
# This script:
# 1. Stops the container
# 2. Removes the cache directory
# 3. Rebuilds and starts the container
# 4. Waits for healthy status
# 5. Tests web UI and proxy functionality

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONTAINER_NAME="squid-whitelist-proxy"
CACHE_DIR="data/squid-cache"
MAX_HEALTH_WAIT=120  # seconds
HEALTH_CHECK_INTERVAL=2  # seconds

# Functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_step() {
    echo -e "${BLUE}[$(date +%H:%M:%S)]${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC}  $1"
}

# Main script
print_header "Squid Proxy - Dev Reset & Test"
echo ""

# Step 1: Stop container
print_step "Step 1: Stopping existing container..."
if docker-compose down 2>&1 | grep -q "Container"; then
    print_success "Container stopped"
else
    print_warning "No running container found"
fi
echo ""

# Step 2: Clean cache directory
print_step "Step 2: Cleaning cache directory..."
if [ -d "$CACHE_DIR" ]; then
    print_step "Removing $CACHE_DIR"
    rm -rf "$CACHE_DIR"
    print_success "Cache directory removed"
else
    print_warning "Cache directory doesn't exist"
fi

print_step "Creating fresh cache directory"
mkdir -p "$CACHE_DIR"
chmod 777 "$CACHE_DIR"  # Permissive so container can fix ownership
print_success "Cache directory created with permissions 777"
echo ""

# Step 3: Build and start container
print_step "Step 3: Building and starting container..."
if docker-compose up -d --build; then
    print_success "Container started"
else
    print_error "Failed to start container"
    exit 1
fi
echo ""

# Step 4: Wait for healthy status
print_step "Step 4: Waiting for container to become healthy..."
SECONDS_WAITED=0
HEALTH_STATUS="starting"

while [ "$HEALTH_STATUS" != "healthy" ] && [ $SECONDS_WAITED -lt $MAX_HEALTH_WAIT ]; do
    # Get health status
    HEALTH_STATUS=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "unknown")

    # Show progress
    echo -ne "  Status: $HEALTH_STATUS (waited ${SECONDS_WAITED}s / ${MAX_HEALTH_WAIT}s)\r"

    # Check if container exited
    CONTAINER_STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null || echo "not_found")
    if [ "$CONTAINER_STATUS" = "exited" ] || [ "$CONTAINER_STATUS" = "not_found" ]; then
        echo ""  # New line after progress
        print_error "Container exited unexpectedly!"
        echo ""
        print_step "Recent container logs:"
        docker logs --tail 50 "$CONTAINER_NAME"
        exit 1
    fi

    # Break if healthy
    if [ "$HEALTH_STATUS" = "healthy" ]; then
        break
    fi

    # Wait before next check
    sleep $HEALTH_CHECK_INTERVAL
    SECONDS_WAITED=$((SECONDS_WAITED + HEALTH_CHECK_INTERVAL))
done

echo ""  # New line after progress

if [ "$HEALTH_STATUS" = "healthy" ]; then
    print_success "Container is healthy (took ${SECONDS_WAITED}s)"
else
    print_error "Container did not become healthy within ${MAX_HEALTH_WAIT}s"
    echo ""
    print_step "Container logs:"
    docker logs --tail 100 "$CONTAINER_NAME"
    exit 1
fi
echo ""

# Step 5: Test web UI health endpoint
print_step "Step 5: Testing web UI health endpoint..."
if curl -f -s http://localhost:8080/health > /dev/null; then
    HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
    print_success "Health endpoint responded: $HEALTH_RESPONSE"
else
    print_error "Health endpoint failed"
    echo ""
    print_step "Container logs:"
    docker logs --tail 50 "$CONTAINER_NAME"
    exit 1
fi
echo ""

# Step 6: Test proxy functionality
print_step "Step 6: Testing proxy functionality..."

# Test 1: Proxy should be listening
print_step "  → Testing proxy connection..."
if curl -f -s -x http://localhost:3128 --connect-timeout 5 https://example.com -I > /dev/null 2>&1; then
    # Proxy connected - check if it allowed or denied
    HTTP_CODE=$(curl -s -x http://localhost:3128 -o /dev/null -w "%{http_code}" https://example.com 2>/dev/null || echo "000")

    if [ "$HTTP_CODE" = "403" ]; then
        print_success "Proxy is working (denied as expected with empty whitelist: HTTP $HTTP_CODE)"
    elif [ "$HTTP_CODE" = "200" ]; then
        print_warning "Proxy allowed request (HTTP $HTTP_CODE) - whitelist may not be empty"
    else
        print_warning "Proxy responded with HTTP $HTTP_CODE"
    fi
else
    print_error "Proxy is not accessible on port 3128"
    exit 1
fi
echo ""

# Step 7: Display container info
print_step "Step 7: Container information..."
echo ""
docker ps | grep "$CONTAINER_NAME" || true
echo ""

# Final summary
print_header "SUCCESS - All Tests Passed!"
echo ""
echo "Summary:"
echo "  • Container: $CONTAINER_NAME"
echo "  • Status: $(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME")"
echo "  • Health: $(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER_NAME")"
echo "  • Uptime: $(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER_NAME" | cut -d'T' -f2 | cut -d'.' -f1)"
echo ""
echo "Services:"
echo "  • Web UI:  http://localhost:8080 (admin/changeme)"
echo "  • Proxy:   http://localhost:3128"
echo ""
echo "Next steps:"
echo "  1. Access the Web UI and add domains to the whitelist"
echo "  2. Test proxy with whitelisted domain"
echo "  3. View logs: docker logs -f $CONTAINER_NAME"
echo ""
print_success "Development environment is ready!"
echo ""
