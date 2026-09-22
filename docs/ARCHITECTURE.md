# Architecture

> This document provides technical architecture documentation derived from codebase analysis.

## Project Overview

Squid Whitelist Proxy Appliance - A single Docker container combining Squid HTTP proxy with a Flask web UI for strict allow-list egress control. The proxy operates in deny-by-default mode, only permitting access to explicitly whitelisted domains.

## High-Level Architecture

### Single-Container Design

Both Squid (port 3128) and Flask web UI (port 8080) run in one container, managed by `app/entrypoint.sh`. The entrypoint initializes the environment, renders `squid.conf` from the template by calling `regenerate_squid_config()` (the same Python renderer the web UI uses), starts Squid as a background daemon, then starts Gunicorn as the main process.

The image is built `FROM debian:trixie-slim` (Squid 6.13, Python 3.13). Python
dependencies live in an in-image virtualenv at `/opt/venv`, which is first on
`PATH`; nothing is installed into Debian's externally-managed system
interpreter. A build-time `RUN` renders the template and runs `squid -k parse`,
so a directive this Squid rejects fails `docker build` rather than the
container.

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Container                         │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Squid HTTP Proxy (Port 3128)                      │    │
│  │  • Whitelist-based ACL                             │    │
│  │  • Deny-by-default security                        │    │
│  │  • Layer-7 domain filtering                        │    │
│  │  • Configurable logging                            │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↕                                 │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Flask Web UI (Port 8080) + Gunicorn               │    │
│  │  • Login/authentication                            │    │
│  │  • Whitelist management (add/remove)               │    │
│  │  • Logging configuration                           │    │
│  │  • Auto-reload Squid on changes                    │    │
│  └────────────────────────────────────────────────────┘    │
│                           ↕                                 │
│  ┌────────────────────────────────────────────────────┐    │
│  │  Persistent Storage (/data volume)                 │    │
│  │  • whitelist.txt (allowed domains)                 │    │
│  │  • config.yaml (logging + DNS configuration)       │    │
│  │  • .secret_key (Flask session secret)              │    │
│  │  • .login_attempts.json (shared login rate limit)  │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### app/squid_control.py

Core domain logic for whitelist and Squid management:

- `read_whitelist()` / `write_whitelist()` - Atomic file operations with normalization
- `normalize_whitelist_entries()` - Separates entries into exact vs wildcard lists
- `entry_coverage()` - Checks if new entry is duplicate or covered by existing wildcard
- `filter_conflicts()` - Removes exact entries covered by wildcards (prevents Squid ACL errors)
- `reload_squid()` - Triggers `squid -k reconfigure` without container restart
- `tail_log()` - Cursor-based log reading with rotation detection
- `regenerate_squid_config()` - **The only** `squid.conf` renderer. Substitutes
  `{{LOGGING_CONFIG}}`, `{{WHITELIST_PATH}}` and `{{DNS_NAMESERVERS}}`. Used by
  the web UI, by `entrypoint.sh` at boot, and by the build-time validation in
  the Dockerfile

### app/app.py

Flask routes and UI logic:

- Session-based authentication with `@login_required` decorator
- `/whitelist` - Add/remove domains with duplicate detection and coverage warnings
- `/logging` - Configure logging mode (local_file, stdout, remote_syslog) and
  Squid's upstream DNS nameservers (up to four; default `1.1.1.1 8.8.8.8`)
- `/api/logs` - Real-time log viewer API with cursor-based polling
- Secret key management: persisted to `/data/.secret_key` for multi-worker stability
- `verify_credentials()` - Constant-time comparison of **both** username and
  password; `ADMIN_PASSWORD_HASH` (werkzeug `check_password_hash`) takes
  precedence over plaintext `ADMIN_PASSWORD`
- CSRF token per session, validated with `hmac.compare_digest` on every POST;
  hardening headers applied in an `after_request` hook

## Critical Domain Logic: Exact vs Wildcard Entries

**This is the most important architectural concept** requiring multiple files to understand:

### Squid ACL Behavior (squid/squid.conf.template)

- `example.com` (exact) - Matches ONLY example.com, NOT subdomains
- `.example.com` (wildcard) - Matches BOTH example.com AND *.example.com
- Exact and wildcard are NOT duplicates - they have different semantics
- **Squid 5.7+ REJECTS configs with both exact and wildcard for same domain** (Bug A)
  - Verified identical on Squid 5.7 (bookworm) and Squid 6.13 (trixie): `squid -k parse`
    exits 1 with `ERROR: '.example.com' is a subdomain of 'example.com'` followed by
    `FATAL: Bungled ...`. `filter_conflicts()` remains load-bearing.

### Normalization Pipeline (app/squid_control.py)

1. User enters: `example.com`, `*.github.com`, `https://npmjs.org/path`
2. `normalize_whitelist_entries()` strips schemes/paths, normalizes `*.` to `.` prefix
3. Separates into two lists: `exact = ['example.com', 'npmjs.org']`, `wildcard = ['.github.com']`
4. `filter_conflicts()` removes exact entries covered by wildcards
5. `write_whitelist()` writes both lists to file (exact first, then wildcards)

### UI Feedback (app/app.py)

- Adding exact when wildcard exists: "Entry is already covered by wildcard, not added"
- Adding wildcard when exact exists: "Removed N conflicting exact entries to prevent Squid errors"
- Duplicate detection within same type (exact vs wildcard are different types)

## Session Handling (Bug B Fix)

### Problem

Multi-worker Gunicorn with random `app.secret_key = os.urandom()` caused session invalidation across workers, redirecting authenticated users to login after POST requests.

### Solution (app/app.py)

- `get_or_create_secret_key()` persists secret to `/data/.secret_key`
- Priority: 1) SECRET_KEY env var, 2) persisted file, 3) generate and save new key
- All workers read same secret, sessions remain valid across workers

## Authentication Hardening

- **Credentials**: `ADMIN_PASSWORD_HASH` (a werkzeug hash, e.g. from
  `make password-hash`) takes precedence over `ADMIN_PASSWORD`. A malformed
  hash denies every login rather than raising a 500.
- **Constant time**: username and password are both compared with
  `hmac.compare_digest` and the results combined only at the end, so a failure
  leaks nothing about which half was wrong.
- **Session fixation**: `session.clear()` runs on successful login, so a
  session id planted before authentication cannot be reused.
- **Session lifetime**: `SESSION_LIFETIME_MINUTES` (default 480 = 8h) drives
  `PERMANENT_SESSION_LIFETIME`; sessions are marked permanent at login, so it
  is a sliding window.
- **Rate limiting**: 5 failed attempts per IP per 5 minutes → HTTP 429. State
  lives in `$DATA_DIR/.login_attempts.json` (mode `0600`) under an advisory
  `flock`, not in a per-process dict, so the limit holds across **both**
  gunicorn workers and across container restarts. If the file cannot be used
  the code falls back to the in-process dict and logs a warning.

## Live Log Viewer

### Backend (app/squid_control.py, app/app.py)

- `tail_log()` uses cursor-based incremental reads (byte offset tracking)
- Handles log rotation: if cursor > file_size, resets to tail
- `/api/logs` endpoint validates file parameter against whitelist ('access' or 'cache')
- Only available when logging_mode is 'local_file'

### Frontend (app/templates/logging.html, app/static/logs.js)

- `LogViewer` class polls `/api/logs` every 2 seconds
- Maintains cursor state for incremental fetches
- Client-side filtering, auto-scroll, start/stop controls
- Conditionally rendered only when mode is 'local_file'

## Important Patterns

### Atomic File Writes

All config file writes go through a temp file in the same directory and are
then moved into place, so a reader never sees a half-written file:

```python
temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(target))
with os.fdopen(temp_fd, 'w') as f:
    f.write(content)
shutil.move(temp_path, target)  # config.yaml and squid.conf: plain files
```

The whitelist is the exception — see the next section. It resolves the symlink
and uses `os.replace()`, never `shutil.move()`.

### Write the Whitelist THROUGH the Symlink

`/etc/squid/whitelist.txt` is a symlink to `/data/whitelist.txt`, created by
`entrypoint.sh`. `write_whitelist()` must resolve it first:

```python
target_path = os.path.realpath(WHITELIST_PATH)   # -> /data/whitelist.txt
...
os.replace(temp_path, target_path)
```

`shutil.move()` here is a **data-loss bug**: it replaces the symlink with a
regular file, so entries never reach the `/data` volume. On the next boot
`entrypoint.sh` moves that stray regular file aside to `.bak` and re-links to
the stale `/data` copy — silently reverting the entire allow-list on every
container restart. `TestSymlinkedWhitelistPersistence` in
`tests/test_whitelist_validation.py` guards this.

### One Renderer for squid.conf

`regenerate_squid_config()` is the single place a `squid.conf` is produced.
`entrypoint.sh` calls it at boot instead of doing its own `sed` substitution;
the Dockerfile calls it at build time for `squid -k parse` validation. Boot
additionally greps the rendered file for a surviving `{{` and hard-fails,
because Squid silently *accepts* an unsubstituted placeholder — the earlier
`sed` path never substituted `{{DNS_NAMESERVERS}}`, so Squid booted with zero
nameservers and every lookup failed.

### Squid Reload Pattern

Never restart Squid container - use `squid -k reconfigure` for zero-downtime config updates:

```python
subprocess.run(['squid', '-k', 'reconfigure'], check=True, timeout=10)
```

### Empty Whitelist Handling

Container must start successfully with empty whitelist (deny-all mode). Squid config uses conditional ACL:

```squid
acl allowed_sites dstdomain "{{WHITELIST_PATH}}"
...
http_access allow allowed_sites
# Works even if the file is empty - nothing matches, so everything is denied
http_access deny all
```

## Configuration Files

### Persistent Storage (/data volume)

- `whitelist.txt` - Domain whitelist (auto-managed by web UI); symlinked from
  `/etc/squid/whitelist.txt`
- `config.yaml` - Logging **and** DNS configuration
- `.secret_key` - Flask session secret (auto-generated if missing, mode 0600)
- `.login_attempts.json` - Shared login rate-limit state (mode 0600, `flock`-guarded)

### Templates

- `squid/squid.conf.template` - Placeholders: `{{LOGGING_CONFIG}}`,
  `{{WHITELIST_PATH}}`, `{{DNS_NAMESERVERS}}`
- Rendered by `regenerate_squid_config()` at container boot, at image build
  time, and whenever logging or DNS settings change in the UI
- `localhost` is a Squid built-in ACL (127.0.0.1/32 + ::1) and is deliberately
  **not** redefined in the template; redefining it makes Squid 5 and 6 warn on
  every parse. The template parses with zero warnings.

### Environment Variables

- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Web UI credentials (default: admin/changeme)
- `ADMIN_PASSWORD_HASH` - Werkzeug password hash; takes precedence over
  `ADMIN_PASSWORD` when set (generate with `make password-hash`; double every
  `$` to `$$` in `docker-compose.yml`)
- `SESSION_LIFETIME_MINUTES` - Session expiry, sliding (default: 480 = 8 hours)
- `SECRET_KEY` - Flask session secret (optional, auto-generated if not set)
- `DISABLE_SECURE_COOKIES` - `true` allows session cookies over plain HTTP
  (development only)
- `DATA_DIR` - Persistent data directory (default: /data)
- `WHITELIST_PATH` - Whitelist path (default: /etc/squid/whitelist.txt)
- `CONFIG_PATH` - Config path (default: /data/config.yaml)

## Testing Strategy

### Unit Tests (tests/) — 112 tests across 5 files

| File | Tests | Covers |
|---|---:|---|
| `test_whitelist_validation.py` | 36 | Normalization, coverage detection, conflict filtering, symlinked-whitelist persistence |
| `test_security.py` | 41 | CSRF, login rate limiting, security headers, credential handling |
| `test_log_viewer.py` | 20 | `tail_log()` cursor logic and the `/api/logs` endpoint |
| `test_squid_config_render.py` | 11 | `regenerate_squid_config()` substitutes every placeholder, emits `dns_nameservers`, honours each logging mode |
| `test_flask_ui.py` | 4 | Session handling, removal operations, secret key stability |

Each file must run as **its own process** (`make test-unit`): they mutate
`os.environ`, monkeypatch module-level paths and call `importlib.reload(app)`,
so one shared interpreter makes that state collide.

### End-to-End (tests/test_e2e_smoke.sh)

34 checks driven against a real container and the real proxy: boot, deny by
default, login with CSRF, whitelist add/remove and persistence to `/data`,
exact-vs-wildcard conflict handling, DNS settings round-tripping into
`squid.conf`, `/api/logs` authorization and path-traversal rejection, and the
login rate limit returning 429 by the 6th attempt (later than that means the
limiter went back to being per-worker). Run with `make test-e2e`.

### CI (.github/workflows/ci.yml)

- **`unit`** — Python 3.11 + 3.13 matrix; byte-compiles `app/*.py`, `bash -n`s
  every shell script, runs each test file as its own process
- **`audit`** — `pipx run pip-audit --strict -r requirements.txt`, blocking
- **`docker`** — builds the image and runs the end-to-end smoke test

### Test Coverage

- ✅ Exact vs wildcard semantics (normalization, deduplication)
- ✅ Conflict filtering (prevents Bug A: microsoft.com + .microsoft.com)
- ✅ Empty whitelist handling (container starts, denies all)
- ✅ Session persistence (Bug B: no login redirect after POST)
- ✅ Log viewer cursor logic (initial tail, incremental reads, rotation)
- ✅ Whitelist writes follow the `/data` symlink instead of replacing it
- ✅ `squid.conf` render leaves no `{{...}}` placeholder, in any logging mode
- ✅ CSRF enforcement, security headers, shared cross-worker login rate limit

## Common Pitfalls

1. **Don't auto-broaden domains**: `example.com` is exact only - never silently add `.example.com`
2. **Always filter conflicts before writing**: Use `filter_conflicts()` to remove exact entries covered by wildcards
3. **Never restart Squid**: Use `squid -k reconfigure` instead
4. **Handle empty whitelist gracefully**: Empty whitelist is valid (deny-all mode), not an error
5. **Validate file parameter in log viewer**: Only allow 'access' or 'cache' to prevent arbitrary file reads
6. **Preserve cursor across log rotations**: Check if cursor > file_size, reset to tail if true
7. **Write the whitelist through the symlink**: resolve with `os.path.realpath()`
   and use `os.replace()`. `shutil.move()` clobbers the symlink and silently
   loses every entry on the next container restart
8. **One renderer only**: never re-implement template substitution (a `sed`
   pipeline, a second Python helper). Call `regenerate_squid_config()`, and
   fail loudly if a `{{` survives — Squid accepts unsubstituted placeholders
   without complaint
9. **Don't redefine `localhost` in the template**: it is a Squid built-in;
   redefining it produces a warning on every parse
10. **Escape `$` as `$$`** in `docker-compose.yml` when pasting an
   `ADMIN_PASSWORD_HASH`, or Compose hands the container a truncated hash
