# Squid Whitelist Proxy - Makefile
# Common operations for managing the appliance

.PHONY: help build up down restart logs shell squid-logs squid-reload validate clean backup password-hash test-unit test-e2e

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
	@echo "  make test-unit     - Run Python unit tests (each file as its own process)"
	@echo "  make test-e2e      - Build the image and run the end-to-end smoke test"
	@echo "  make password-hash - Generate an ADMIN_PASSWORD_HASH value"
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
# Run all Python unit tests. Each file runs as its own process on purpose:
# they mutate os.environ and importlib.reload(app), so sharing one interpreter
# makes that state collide.
# PY can override the interpreter, e.g. `make test-unit PY=.venv/bin/python`.
PY ?= python3

test-unit:
	@echo "Running unit tests with $(PY)..."
	@for f in tests/test_*.py; do \
		echo "== $$f"; \
		$(PY) "$$f" || exit 1; \
	done
	@echo "All unit tests passed"

# Build the image and run the end-to-end smoke test against it
test-e2e:
	docker build -t squidlyfe:ci .
	IMAGE=squidlyfe:ci ./tests/test_e2e_smoke.sh

test:
	@echo "Testing proxy functionality..."
	@echo ""
	@echo "Testing allowed site (example.com):"
	@curl -s -x http://localhost:3128 -o /dev/null -w "HTTP Status: %{http_code}\n" http://example.com
	@echo ""
	@echo "Note: Add example.com to whitelist via Web UI first"
	@echo "Web UI: http://localhost:8080"

# Generate a password hash for ADMIN_PASSWORD_HASH (no local Python needed).
# Remember: when pasting the result into docker-compose.yml, every '$' must be
# doubled to '$$' or Compose will mangle the hash via variable interpolation.
password-hash:
	@docker-compose run --rm --no-deps --entrypoint python3 squid-whitelist-proxy \
		-c "from werkzeug.security import generate_password_hash; import getpass; print(generate_password_hash(getpass.getpass('Password: ')))"

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
