# Contributing to Squid Whitelist Proxy Manager

Thank you for your interest in contributing! This document provides guidelines for developers working on this project.

## Project Structure

- **`app/`** - Flask UI and control logic
  - `app.py` - Flask routes, authentication, whitelist/logging management
  - `squid_control.py` - Squid control functions (read/write whitelist, reload, config)
  - `config.py` - Configuration loader
  - `templates/` - Jinja2 HTML templates
  - `static/` - CSS and JavaScript assets
- **`squid/`** - Squid configuration
  - `squid.conf.template` - Squid config template with variable substitution
- **`data/`** - Persistent storage (excluded from git via .gitignore)
  - `whitelist.txt` - Domain whitelist (auto-managed by web UI)
  - `config.yaml` - Application configuration
  - `.secret_key` - Flask session secret
- **`tests/`** - Unit and integration tests
  - `test_whitelist_validation.py` - Whitelist normalization and conflict filtering
  - `test_flask_ui.py` - Flask UI and session handling
  - `test_log_viewer.py` - Log viewer functionality
  - `test_empty_whitelist.sh` - Integration test for empty whitelist handling
- **`scripts/`** and **`Makefile`** - Helper commands for development and operations

## Build, Run, and Test

### Local Development

```bash
# Build Docker image
make build

# Start container
make up

# View logs
make logs

# Open shell in container
make shell

# Stop container
make down

# Restart container
make restart
```

### Testing

Run all unit tests:

```bash
# Whitelist validation tests (32 tests)
python -m unittest tests/test_whitelist_validation.py

# Flask UI tests (session handling, removal)
python -m unittest tests/test_flask_ui.py

# Log viewer tests
python -m unittest tests/test_log_viewer.py

# Run all Python tests
python -m unittest tests/test_whitelist_validation.py tests/test_flask_ui.py tests/test_log_viewer.py
```

Integration tests:

```bash
# Empty whitelist handling (requires Docker)
./tests/test_empty_whitelist.sh
```

### Squid Operations

```bash
# View Squid access logs
make squid-logs

# Reload Squid config (zero-downtime)
make squid-reload

# Validate Squid config syntax
make validate
```

### Manual Proxy Testing

```bash
# Test proxy functionality (requires whitelist entry for target domain)
make test

# Or manually:
curl -x http://localhost:3128 -o /dev/null -w "%{http_code}\n" http://example.com
```

## Coding Style

### Python

- Python 3.11+
- Follow PEP 8 conventions with 4-space indents
- Use `snake_case` for functions and variables
- Use `CAPS` for constants
- Keep functions small and explicit
- Add docstrings for all public functions

Example:

```python
def normalize_whitelist_entries(raw_entries: List[str]) -> Tuple[List[str], List[str]]:
    """
    Normalize whitelist entries into exact and wildcard lists.

    Args:
        raw_entries: Raw list of domain/URL strings

    Returns:
        Tuple of (exact_entries, wildcard_entries)
    """
    # Implementation...
```

### Flask Routes

- All Flask routes go in `app/app.py`
- Shared helper functions go in `app/squid_control.py`
- Use `@login_required` decorator for protected routes
- Return proper HTTP status codes

### Frontend

- Keep JavaScript modular (e.g., `app/static/logs.js`)
- Minimize inline scripts in templates
- Use semantic HTML and accessible markup
- Follow existing CSS patterns

### File Headers and Comments

- Keep generated file headers intact (e.g., whitelist.txt header)
- Add comments for non-obvious logic
- Document the "why" not just the "what"

## Testing Guidelines

### Unit Tests

- Use Python's `unittest` framework
- Add new tests to existing test files or create new ones in `tests/`
- Use descriptive class and method names
- Test edge cases:
  - Exact vs wildcard entries
  - Empty whitelist handling
  - Log rotation and missing files
  - Auth-protected endpoints

### When to Run Tests

- **Changing whitelist logic**: Run `tests/test_whitelist_validation.py`
- **Changing Flask UI**: Run `tests/test_flask_ui.py`
- **Changing log viewer**: Run `tests/test_log_viewer.py`
- **Before committing**: Run all tests

### Test Coverage

Current coverage includes:
- ✅ Exact vs wildcard normalization
- ✅ Duplicate detection
- ✅ Conflict filtering (Bug A fix)
- ✅ Session persistence (Bug B fix)
- ✅ Empty whitelist handling
- ✅ Log viewer cursor logic
- ✅ Authentication and authorization

## Commit Guidelines

### Commit Messages

- Use concise, imperative subjects (50 chars or less)
- Start with a verb: "Add", "Fix", "Update", "Remove", "Refactor"
- Provide context in the body if needed

Good examples:
```
Handle wildcard overlap in whitelist writer
Fix session invalidation across Gunicorn workers
Add Live Log Viewer with cursor-based polling
```

Bad examples:
```
Fixed bug
Updated stuff
Changes
```

### Pull Requests

When submitting a PR, include:

1. **Summary**: Brief description of what changed and why
2. **Changes**: List of modified files and key changes
3. **Testing**: Commands to test the changes
4. **Regressions**: Any potential issues or breaking changes
5. **Screenshots**: For UI changes (if applicable)

Example PR description:

```markdown
## Summary
Add support for filtering exact entries covered by wildcards to prevent Squid ACL errors.

## Changes
- Modified `filter_conflicts()` in `squid_control.py`
- Updated `write_whitelist()` to call conflict filter
- Added 8 new tests in `test_whitelist_validation.py`

## Testing
```bash
python -m unittest tests/test_whitelist_validation.py
./tests/test_empty_whitelist.sh
```

## Regressions Considered
- Existing whitelists with conflicts will auto-fix on next write
- No breaking changes to API
```

## Security & Configuration

### Security Best Practices

1. **Change default credentials**:
   ```yaml
   environment:
     - ADMIN_PASSWORD=YourSecurePassword123
     - SECRET_KEY=your-random-secret-key
   ```

2. **File permissions**: Whitelist file must be readable by Squid (644):
   ```bash
   chmod 644 /data/whitelist.txt
   ```

3. **Input validation**: Always validate user input in Flask routes
4. **No arbitrary file access**: Whitelist file paths in API endpoints
5. **Use atomic writes**: Prevent corruption during concurrent access

### Configuration Files

- **Whitelist**: `/data/whitelist.txt` (symlinked to `/etc/squid/whitelist.txt`)
- **App config**: `/data/config.yaml`
- **Secret key**: `/data/.secret_key` (auto-generated if missing)

### Validation

Before deploying changes:

```bash
# Validate Squid configuration
make validate

# Or manually:
docker exec squid-whitelist-proxy squid -k parse
```

## Architecture Reference

For detailed architectural information, see [ARCHITECTURE.md](ARCHITECTURE.md).

Key architectural concepts:
- **Exact vs Wildcard entries** - Different semantics, not duplicates
- **Conflict filtering** - Prevents Squid ACL errors
- **Atomic file writes** - Prevents corruption
- **Zero-downtime reloads** - Use `squid -k reconfigure`, never restart
- **Session stability** - Persisted secret key for multi-worker environments

## Development Tips

### Debugging

```bash
# Check Squid config
docker exec squid-whitelist-proxy cat /etc/squid/squid.conf

# View Squid cache log (errors)
docker exec squid-whitelist-proxy cat /var/log/squid/cache.log

# View Squid access log
docker exec squid-whitelist-proxy tail -f /var/log/squid/access.log

# Check Flask logs
docker compose logs | grep ERROR
```

### Testing Whitelist Logic

Test normalization and filtering in Python shell:

```python
from app.squid_control import normalize_whitelist_entries, entry_coverage, filter_conflicts

# Test normalization
exact, wild = normalize_whitelist_entries(['example.com', '*.github.com'])
# exact = ['example.com'], wild = ['.github.com']

# Test coverage detection
coverage = entry_coverage('api.github.com', exact, wild)
# {'type': 'exact', 'value': 'api.github.com', 'covered_by_wildcard': True}

# Test conflict filtering
filtered_exact, wild = filter_conflicts(['github.com', 'example.com'], ['.github.com'])
# filtered_exact = ['example.com'], wild = ['.github.com']
```

## Getting Help

- Review [README.md](README.md) for user documentation
- Check [QUICKSTART.md](QUICKSTART.md) for setup instructions
- See [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
- Open an issue for bugs or feature requests

## License

This project is provided as-is for IT infrastructure use. Modify and distribute freely.
