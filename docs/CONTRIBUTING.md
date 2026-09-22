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
  - `whitelist.txt` - Domain whitelist (auto-managed by web UI; `/etc/squid/whitelist.txt` is a symlink to it)
  - `config.yaml` - Logging and DNS configuration
  - `.secret_key` - Flask session secret
  - `.login_attempts.json` - Shared login rate-limit state
- **`tests/`** - Unit, integration and end-to-end tests. See
  [tests/README.md](../tests/README.md) for the full breakdown.
  - `test_whitelist_validation.py` - Whitelist normalization, conflict filtering, symlinked-whitelist persistence (36 tests)
  - `test_security.py` - CSRF, login rate limiting, security headers, credentials (41 tests)
  - `test_log_viewer.py` - Log viewer functionality (20 tests)
  - `test_squid_config_render.py` - `squid.conf` rendering and placeholder substitution (11 tests)
  - `test_flask_ui.py` - Flask UI and session handling (4 tests)
  - `test_e2e_smoke.sh` - End-to-end smoke test against a built image (34 checks)
  - `test_empty_whitelist.sh` - Integration test for empty whitelist handling
- **`.github/workflows/ci.yml`** - CI: unit tests, `pip-audit`, Docker end-to-end
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

The unit suite is **112 tests across 5 files**. Run it with:

```bash
make test-unit

# Point at a virtualenv holding the pinned dependencies
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
make test-unit PY=.venv/bin/python
```

Every file must run as **its own process**. They mutate `os.environ`,
monkeypatch module-level paths such as `squid_control.WHITELIST_PATH`, and call
`importlib.reload(app)`; collecting them into a single `pytest` (or
`python -m unittest a.py b.py`) invocation makes that state collide and
produces both false passes and false failures. Run individual files directly:

```bash
python3 tests/test_whitelist_validation.py
python3 tests/test_security.py
```

`test_whitelist_validation.py` and `test_squid_config_render.py` need only the
standard library and PyYAML; the rest need Flask.

End-to-end and integration tests (require Docker):

```bash
# Build the image and run the 34-check smoke test against it
make test-e2e

# Empty whitelist handling
./tests/test_empty_whitelist.sh
```

The smoke test never touches the repository's `./data` directory — it mounts a
throwaway `mktemp -d` and publishes on ports 18080/13128, so a running
`make up` is left alone.

### Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

| Job | What it does |
|---|---|
| `unit` | Python 3.11 and 3.13; byte-compiles `app/*.py`, `bash -n`s every shell script, runs each `tests/test_*.py` as its own process |
| `audit` | `pipx run pip-audit --strict -r requirements.txt` — **blocking**, so a new advisory against a pinned dependency fails the build |
| `docker` | Builds the image and runs `tests/test_e2e_smoke.sh` |

A new `tests/test_*.py` or `tests/*.sh` is picked up automatically; no workflow
edit is needed.

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

- Python 3.11+ (the image ships 3.13; CI runs both 3.11 and 3.13, so do not use
  syntax or stdlib APIs newer than 3.11)
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

- **Changing whitelist logic**: `python3 tests/test_whitelist_validation.py`
- **Changing auth, CSRF or rate limiting**: `python3 tests/test_security.py`
- **Changing Flask UI**: `python3 tests/test_flask_ui.py`
- **Changing log viewer**: `python3 tests/test_log_viewer.py`
- **Changing `squid.conf.template`, the renderer or `entrypoint.sh`**:
  `python3 tests/test_squid_config_render.py`, then `make test-e2e`
- **Changing the Dockerfile or anything about boot**: `make test-e2e`
- **Before committing**: `make test-unit`

### Test Coverage

Current coverage includes:
- ✅ Exact vs wildcard normalization
- ✅ Duplicate detection
- ✅ Conflict filtering (Bug A fix)
- ✅ Session persistence (Bug B fix)
- ✅ Empty whitelist handling
- ✅ Whitelist writes follow the `/data` symlink instead of replacing it
- ✅ Log viewer cursor logic
- ✅ Authentication and authorization, CSRF, security headers, login rate limit
- ✅ `squid.conf` rendering leaves no `{{...}}` placeholder in any logging mode

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
make test-unit
make test-e2e
```

## Regressions Considered
- Existing whitelists with conflicts will auto-fix on next write
- No breaking changes to API
```

## Security & Configuration

### Security Best Practices

1. **Change default credentials**. Prefer a hash over a plaintext password:
   ```bash
   make password-hash   # prints e.g. scrypt:32768:8:1$Kb1p...$9f2c...

   # Scriptable: stdout carries only the hash.
   HASH=$(printf '%s' 'your-password' | make password-hash)
   ```
   ```yaml
   environment:
     # Compose interpolates '$': every one MUST be doubled to '$$' here, or the
     # container receives a truncated hash and every login silently fails.
     - ADMIN_PASSWORD_HASH=scrypt:32768:8:1$$Kb1p...$$9f2c...
     - SECRET_KEY=your-random-secret-key
     - SESSION_LIFETIME_MINUTES=480
   ```
   `ADMIN_PASSWORD_HASH` takes precedence over `ADMIN_PASSWORD` and suppresses
   the default-password banner.

2. **File permissions**: Whitelist file must be readable by Squid (644):
   ```bash
   chmod 644 /data/whitelist.txt
   ```

3. **Input validation**: Always validate user input in Flask routes
4. **No arbitrary file access**: Whitelist file paths in API endpoints
5. **Use atomic writes**: Prevent corruption during concurrent access
6. **CSRF**: every state-changing POST must carry and validate a `csrf_token`.
   If you add a route or a test login helper, send the token — a helper that
   forgets it makes the whole file fail in ways that are easy to miss.
7. **Keep dependencies clean**: CI runs `pip-audit --strict` as a blocking job.
   Bump the pin in `requirements.txt` rather than ignoring an advisory.

### Configuration Files

- **Whitelist**: `/data/whitelist.txt` (symlinked to `/etc/squid/whitelist.txt`)
- **App config**: `/data/config.yaml` (logging + DNS)
- **Secret key**: `/data/.secret_key` (auto-generated if missing)
- **Login attempts**: `/data/.login_attempts.json` (auto-managed, mode 0600)

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
- **Write the whitelist through the symlink** - `write_whitelist()` resolves
  `/etc/squid/whitelist.txt` with `os.path.realpath()` and uses `os.replace()`.
  Using `shutil.move()` replaces the symlink with a regular file, so entries
  never reach `/data` and the whole allow-list reverts on the next restart
- **One `squid.conf` renderer** - `regenerate_squid_config()` is used by the
  web UI, by `entrypoint.sh` at boot, and by the Dockerfile's build-time
  `squid -k parse` check. Never add a second (e.g. `sed`) substitution path;
  Squid accepts an unsubstituted `{{...}}` placeholder without complaining, so
  boot also greps for `{{` and hard-fails
- **Zero-downtime reloads** - Use `squid -k reconfigure`, never restart.
  Exception: Squid's *negative DNS cache* survives a reconfigure, so a DNS
  resolver fix needs a container restart to take full effect
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
# Run from the repo root with app/ on sys.path, e.g.
#   PYTHONPATH=app python3
from squid_control import normalize_whitelist_entries, entry_coverage, filter_conflicts

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

- Review [README.md](../README.md) for user documentation
- Check [QUICKSTART.md](../QUICKSTART.md) for setup instructions
- See [ARCHITECTURE.md](ARCHITECTURE.md) for technical details
- See [tests/README.md](../tests/README.md) for the test suite
- Open an issue for bugs or feature requests

## License

This project is provided as-is for IT infrastructure use. Modify and distribute freely.
