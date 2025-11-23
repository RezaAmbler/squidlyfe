# Squid Whitelist Proxy - Makefile
# Common operations for managing the appliance

.PHONY: help build up down restart logs shell squid-logs squid-reload validate clean backup

# Default target
help:
	@echo "Squid Whitelist Proxy - Available Commands"
	@echo ""
	@echo "  make build         - Build Docker image"
	@echo "  make up            - Start container"
	@echo "  make down          - Stop container"
	@echo "  make restart       - Restart container"
	@echo "  make logs          - View container logs"
	@echo "  make shell         - Open shell in container"
	@echo "  make squid-logs    - View Squid access logs"
	@echo "  make squid-reload  - Reload Squid configuration"
	@echo "  make validate      - Validate Squid configuration"
	@echo "  make clean         - Remove containers and images"
	@echo "  make backup        - Backup whitelist and config"
	@echo "  make health        - Check container health"
	@echo "  make test          - Test proxy functionality"
	@echo ""

# Build the Docker image
build:
	@echo "Building Docker image..."
	docker-compose build

# Start the container
up:
	@echo "Starting container..."
	mkdir -p data
	docker-compose up -d
	@echo ""
	@echo "Services started!"
	@echo "Web UI: http://localhost:8080"
	@echo "Proxy:  http://localhost:3128"

# Stop the container
down:
	@echo "Stopping container..."
	docker-compose down

# Restart the container
restart:
	@echo "Restarting container..."
	docker-compose restart

# View container logs
logs:
	docker-compose logs -f

# Open shell in container
shell:
	docker exec -it squid-whitelist-proxy /bin/bash

# View Squid access logs
squid-logs:
	docker exec -it squid-whitelist-proxy tail -f /var/log/squid/access.log

# Reload Squid configuration
squid-reload:
	@echo "Reloading Squid configuration..."
	docker exec squid-whitelist-proxy squid -k reconfigure
	@echo "Squid reloaded successfully"

# Validate Squid configuration
validate:
	@echo "Validating Squid configuration..."
	docker exec squid-whitelist-proxy squid -k parse

# Clean up containers and images
clean:
	@echo "Removing containers and images..."
	docker-compose down -v
	docker rmi squidlyfe_squid-whitelist-proxy 2>/dev/null || true
	@echo "Cleanup complete"

# Backup whitelist and config
backup:
	@echo "Backing up configuration..."
	@mkdir -p backups
	@cp data/whitelist.txt backups/whitelist-$$(date +%Y%m%d-%H%M%S).txt 2>/dev/null || echo "No whitelist to backup"
	@cp data/config.yaml backups/config-$$(date +%Y%m%d-%H%M%S).yaml 2>/dev/null || echo "No config to backup"
	@echo "Backup complete (see backups/ directory)"

# Check container health
health:
	@echo "Checking container health..."
	@docker inspect squid-whitelist-proxy --format='{{.State.Health.Status}}' 2>/dev/null || echo "Container not running"
	@curl -s http://localhost:8080/health || echo "Health check failed"

# Test proxy functionality
test:
	@echo "Testing proxy functionality..."
	@echo ""
	@echo "Testing allowed site (example.com):"
	@curl -s -x http://localhost:3128 -o /dev/null -w "HTTP Status: %{http_code}\n" http://example.com
	@echo ""
	@echo "Note: Add example.com to whitelist via Web UI first"
	@echo "Web UI: http://localhost:8080"

# View current whitelist
show-whitelist:
	@echo "Current whitelist:"
	@cat data/whitelist.txt 2>/dev/null || echo "Whitelist file not found"

# Add domain to whitelist (usage: make add-domain DOMAIN=example.com)
add-domain:
	@if [ -z "$(DOMAIN)" ]; then \
		echo "Usage: make add-domain DOMAIN=example.com"; \
		exit 1; \
	fi
	@echo "$(DOMAIN)" >> data/whitelist.txt
	@echo "Added $(DOMAIN) to whitelist"
	@make squid-reload
