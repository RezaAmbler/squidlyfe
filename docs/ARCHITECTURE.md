# Architecture

> This document provides technical architecture documentation derived from codebase analysis.

## Project Overview

Squid Whitelist Proxy Appliance - A single Docker container combining Squid HTTP proxy with a Flask web UI for strict allow-list egress control. The proxy operates in deny-by-default mode, only permitting access to explicitly whitelisted domains.

## High-Level Architecture

### Single-Container Design

Both Squid (port 3128) and Flask web UI (port 8080) run in one container, managed by `app/entrypoint.sh`. The entrypoint initializes the environment, generates Squid config from template, starts Squid as background daemon, then starts Gunicorn as the main process.

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
│  │  • config.yaml (app configuration)                 │    │
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

### app/app.py

Flask routes and UI logic:

- Session-based authentication with `@login_required` decorator
- `/whitelist` - Add/remove domains with duplicate detection and coverage warnings
- `/logging` - Configure logging mode (local_file, stdout, remote_syslog)
- `/api/logs` - Real-time log viewer API with cursor-based polling
- Secret key management: persisted to `/data/.secret_key` for multi-worker stability

## Critical Domain Logic: Exact vs Wildcard Entries

**This is the most important architectural concept** requiring multiple files to understand:

### Squid ACL Behavior (squid/squid.conf.template)

- `example.com` (exact) - Matches ONLY example.com, NOT subdomains
- `.example.com` (wildcard) - Matches BOTH example.com AND *.example.com
- Exact and wildcard are NOT duplicates - they have different semantics
- **Squid 5.7+ REJECTS configs with both exact and wildcard for same domain** (Bug A)

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

All config file writes use temporary files + atomic move to prevent corruption:

```python
temp_fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(target))
with os.fdopen(temp_fd, 'w') as f:
    f.write(content)
shutil.move(temp_path, target)  # Atomic on same filesystem
```

### Squid Reload Pattern

Never restart Squid container - use `squid -k reconfigure` for zero-downtime config updates:

```python
subprocess.run(['squid', '-k', 'reconfigure'], check=True, timeout=10)
```

### Empty Whitelist Handling

Container must start successfully with empty whitelist (deny-all mode). Squid config uses conditional ACL:

```squid
acl whitelist dstdomain "/etc/squid/whitelist.txt"
# Works even if file is empty - denies all requests
http_access deny !whitelist
```

## Configuration Files

### Persistent Storage (/data volume)

- `whitelist.txt` - Domain whitelist (auto-managed by web UI)
- `config.yaml` - Logging configuration
- `.secret_key` - Flask session secret (auto-generated if missing)

### Templates

- `squid/squid.conf.template` - Variables: `{{WHITELIST_PATH}}`, `{{LOGGING_MODE}}`, `{{SYSLOG_*}}`
- Regenerated by `regenerate_squid_config()` when logging settings change

### Environment Variables

- `ADMIN_USERNAME` / `ADMIN_PASSWORD` - Web UI credentials (default: admin/changeme)
- `SECRET_KEY` - Flask session secret (optional, auto-generated if not set)
- `DATA_DIR` - Persistent data directory (default: /data)

## Testing Strategy

### Unit Tests (tests/)

- `test_whitelist_validation.py` - Normalization, coverage detection, conflict filtering (32 tests)
- `test_flask_ui.py` - Session handling, removal operations, secret key stability
- `test_log_viewer.py` - tail_log() helper and /api/logs endpoint

### Test Coverage

- ✅ Exact vs wildcard semantics (normalization, deduplication)
- ✅ Conflict filtering (prevents Bug A: microsoft.com + .microsoft.com)
- ✅ Empty whitelist handling (container starts, denies all)
- ✅ Session persistence (Bug B: no login redirect after POST)
- ✅ Log viewer cursor logic (initial tail, incremental reads, rotation)

## Common Pitfalls

1. **Don't auto-broaden domains**: `example.com` is exact only - never silently add `.example.com`
2. **Always filter conflicts before writing**: Use `filter_conflicts()` to remove exact entries covered by wildcards
3. **Never restart Squid**: Use `squid -k reconfigure` instead
4. **Handle empty whitelist gracefully**: Empty whitelist is valid (deny-all mode), not an error
5. **Validate file parameter in log viewer**: Only allow 'access' or 'cache' to prevent arbitrary file reads
6. **Preserve cursor across log rotations**: Check if cursor > file_size, reset to tail if true
