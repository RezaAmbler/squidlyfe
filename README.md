# Squid Whitelist Proxy Manager

A **single-container Docker appliance** that combines Squid HTTP proxy with a Flask web UI for strict allow-list egress control in IT networks.

## Overview

Squid Whitelist Proxy Manager provides deny-by-default HTTP proxy control with:

- **Squid HTTP Proxy** (port 3128) - Layer-7 domain filtering, deny-by-default security
- **Web Management UI** (port 8080) - Whitelist management, logging configuration, live log viewer
- **Exact vs Wildcard entries** - Precise control with conflict filtering to prevent Squid ACL errors
- **Zero-downtime reloads** - Squid auto-reloads on configuration changes without restart
- **Live Log Viewer** - Real-time log tailing with cursor-based polling (local_file mode)
- **Flexible logging** - Local file, stdout, or remote syslog modes
- **Configurable DNS resolvers** - Set Squid's upstream nameservers from the web UI
- **Persistent configuration** - Whitelist and config stored in mounted volume

Perfect for IT networks requiring strict outbound web access control, development environments needing package repository filtering, or secure server environments with limited external connectivity.

---

## Getting Started

For detailed setup instructions, see **[QUICKSTART.md](QUICKSTART.md)** - a 15-minute operator guide.

### Quick Start

#### 1. Clone and Build

```bash
git clone <repository-url>
cd squidlyfe

# Create data directory for persistent storage
mkdir -p data

# Build and start the container
docker-compose up -d
```

### 2. Access the Web UI

Open your browser and navigate to:

```
http://localhost:8080
```

**Default credentials:**
- Username: `admin`
- Password: `changeme`

⚠️ **IMPORTANT:** Change the default password immediately by setting the `ADMIN_PASSWORD` environment variable — or, better, `ADMIN_PASSWORD_HASH` (see [Storing the Password as a Hash](#storing-the-password-as-a-hash-recommended)).

### 3. Configure Your Whitelist

1. Log in to the web UI
2. Navigate to **Whitelist** tab
3. Add allowed domains (e.g., `example.com`, `.github.com`)
4. Changes take effect immediately - Squid is reloaded automatically

### 4. Configure Client Systems

Point your servers/clients to use the proxy:

**Linux/macOS:**
```bash
export http_proxy=http://<proxy-ip>:3128
export https_proxy=http://<proxy-ip>:3128
```

**Windows (PowerShell):**
```powershell
$env:http_proxy="http://<proxy-ip>:3128"
$env:https_proxy="http://<proxy-ip>:3128"
```

**System-wide proxy settings:** Configure in your OS network settings or firewall rules to force traffic through the proxy.

---

## Architecture

For complete architectural documentation, see **[ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

### Single Container Design

Both Squid proxy (port 3128) and Flask web UI (port 8080) run in one container:

1. **Squid Proxy** - Layer-7 domain filtering with whitelist-based ACL, deny-by-default security
2. **Flask Web UI** - Whitelist management, logging configuration, live log viewer, authentication
3. **Persistent Storage** - `/data` volume holds whitelist.txt, config.yaml, the session secret and login rate-limit state

### Runtime Stack

| Component | Version |
|-----------|---------|
| Base image | `debian:trixie-slim` |
| Squid | 6.13 (Debian package) |
| Python | 3.13, in an in-image virtualenv at `/opt/venv` |
| Flask / Werkzeug | 3.1.3 / 3.1.8 |
| Gunicorn | 26.2.0 |
| PyYAML | 6.0.3 |

Python dependencies are installed into `/opt/venv` (first on `PATH`) rather than
into Debian's externally-managed system interpreter. `docker build` renders the
Squid template and runs `squid -k parse` as a build step, so a directive this
Squid version rejects fails the build instead of the container.

### Key Features

- **Exact vs Wildcard entries** - `example.com` (exact) matches ONLY the domain; `.example.com` (wildcard) matches apex AND subdomains
- **Conflict filtering** - Automatically removes exact entries covered by wildcards to prevent Squid ACL errors
- **Zero-downtime reloads** - `squid -k reconfigure` updates ACL without restart
- **Session stability** - Persisted secret key prevents multi-worker session invalidation
- **Empty whitelist handling** - Container starts in deny-all mode when whitelist is empty

---

## Basic Commands

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f

# Stop container
docker compose down

# Restart
docker compose restart

# Run the unit suite (112 tests over 5 files, each file as its own process)
make test-unit

# Build the image and run the end-to-end smoke test (34 checks)
make test-e2e

# Squid operations
docker exec squid-whitelist-proxy squid -k reconfigure  # Reload config
docker exec squid-whitelist-proxy squid -k parse         # Validate config
docker exec squid-whitelist-proxy tail -f /var/log/squid/access.log  # View logs
```

See the [Makefile](Makefile) for additional helper commands.

---

## Configuration

### Environment Variables

Configure the container via environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_USERNAME` | `admin` | Web UI admin username |
| `ADMIN_PASSWORD` | `changeme` | Web UI admin password, plaintext (⚠️ **CHANGE THIS!**) |
| `ADMIN_PASSWORD_HASH` | (unset) | **Preferred.** Werkzeug password hash. Takes precedence over `ADMIN_PASSWORD` when set |
| `SESSION_LIFETIME_MINUTES` | `480` | Session expiry in minutes (8 hours, sliding window) |
| `SECRET_KEY` | (auto-generated) | Flask session secret key (persisted to `/data/.secret_key` if unset) |
| `DISABLE_SECURE_COOKIES` | (unset) | Set to `true` to allow session cookies over plain HTTP (development only) |
| `DATA_DIR` | `/data` | Persistent data directory |
| `WHITELIST_PATH` | `/etc/squid/whitelist.txt` | Whitelist file path |
| `CONFIG_PATH` | `/data/config.yaml` | Config file path |

### Example: Secure Configuration

Edit `docker-compose.yml`:

```yaml
environment:
  - ADMIN_USERNAME=securityadmin
  - ADMIN_PASSWORD=YourStrongPasswordHere123!
  - SECRET_KEY=your-random-secret-key-here
  - SESSION_LIFETIME_MINUTES=480
```

Then restart:

```bash
docker-compose down
docker-compose up -d
```

### Storing the Password as a Hash (recommended)

Instead of putting the plaintext password in `docker-compose.yml`, store a
Werkzeug hash. When `ADMIN_PASSWORD_HASH` is set it **takes precedence** over
`ADMIN_PASSWORD`, and the "default password" warning banner is suppressed.

Generate one:

```bash
make password-hash
# Password: (typed invisibly)
# scrypt:32768:8:1$Kb1p...$9f2c...
```

⚠️ **Escaping:** Werkzeug hashes contain `$` characters, and Docker Compose
performs variable interpolation on its YAML. **Every `$` must be doubled to
`$$`** in `docker-compose.yml`. Otherwise Compose treats the salt as a variable
name, substitutes a blank string (`warning: The "Kb1p..." variable is not set`
at startup — easy to miss) and hands the container a truncated hash, after
which every login simply fails with "Invalid username or password":

```yaml
environment:
  # Note the doubled $$ — this is a Compose escaping rule, not part of the hash
  - ADMIN_PASSWORD_HASH=scrypt:32768:8:1$$Kb1p...$$9f2c...
```

With `docker run` there is no interpolation, so pass the hash verbatim inside
**single** quotes so the shell does not expand it:

```bash
docker run -e 'ADMIN_PASSWORD_HASH=scrypt:32768:8:1$Kb1p...$9f2c...' ...
```

A malformed or mis-escaped hash is treated as "deny everything" — the app logs
`ADMIN_PASSWORD_HASH is malformed; rejecting login` rather than crashing.

---

## Whitelist Management

### Entry Types: Exact vs Wildcard

The proxy supports two types of whitelist entries with **NO auto-broadening**:

#### **Exact Entries** (e.g., `example.com`)
- Matches **ONLY** the specified domain
- Does **NOT** match subdomains
- Use when you need precise control

#### **Wildcard Entries** (e.g., `*.example.com` or `.example.com`)
- Matches **BOTH** the apex domain AND all subdomains
- `*.example.com` and `.example.com` are equivalent (normalized to `.example.com`)
- Use for broad domain coverage

### Entry Normalization

The system normalizes entries while **preserving your intent**:

| You Enter | Entry Type | System Normalizes To | What Gets Allowed |
|-----------|-----------|---------------------|-------------------|
| `example.com` | Exact | `example.com` | **ONLY** `example.com` (not subdomains) |
| `*.example.com` | Wildcard | `.example.com` | Both `example.com` AND `*.example.com` |
| `.example.com` | Wildcard | `.example.com` | Both `example.com` AND `*.example.com` |
| `https://example.com/path` | Exact | `example.com` | **ONLY** `example.com` (strips scheme/path) |
| `http://*.github.com` | Wildcard | `.github.com` | Both `github.com` AND `*.github.com` |

**Normalization features:**
- Strips `http://`, `https://`, and paths
- Preserves entry type (exact vs wildcard)
- Converts wildcard inputs (`*.` or `.`) to canonical dotted format (`.example.com`)
- Prevents duplicates **within same type** (exact and wildcard are different entries)
- Warns when exact entry is already covered by wildcard
- Warns when wildcard covers existing exact entries

### Via Web UI

1. Navigate to **Whitelist** tab
2. Enter domain in the input field:
   - `example.com` → exact match only
   - `*.example.com` → wildcard (apex + subdomains)
3. Click **Add to Whitelist**
4. System checks for duplicates and coverage:
   - **Exact duplicate**: Entry already exists
   - **Covered by wildcard**: Not added (already covered)
   - **Wildcard covers exact**: Warning shown, entry added
5. Squid automatically reloads with new configuration

### Via File (Manual)

When editing `./data/whitelist.txt` directly:

```bash
# Exact entry - matches ONLY github.com
echo "github.com" >> ./data/whitelist.txt

# Wildcard entry - matches npmjs.org AND *.npmjs.org
echo ".npmjs.org" >> ./data/whitelist.txt

# Reload Squid
docker exec squid-whitelist-proxy squid -k reconfigure
```

**Note:** Manual edits bypass duplicate checking and coverage warnings. In
particular, listing both `github.com` and `.github.com` by hand makes Squid
refuse the config outright (`FATAL: Bungled ... '.github.com' is a subdomain of
'github.com'`) and the reload will fail. The Web UI removes that conflict for
you — prefer it.

### Example Whitelist

```
# Exact entries - match ONLY these specific domains
example.com
api.internal.company.com

# Wildcard entries - match apex AND all subdomains
.google.com          # Covers google.com and *.google.com
.googleapis.com      # Covers googleapis.com and *.googleapis.com

# Package repositories (wildcard for full coverage)
.debian.org
.ubuntu.com

# GitHub (wildcard)
.github.com
.githubusercontent.com

# NPM/Python packages
.npmjs.org           # Wildcard: registry.npmjs.org, www.npmjs.org, etc.
.pypi.org            # Wildcard: files.pypi.org, pypi.org, etc.
```

### Coverage Scenarios

**Adding exact when wildcard exists:**
```
Existing: .example.com (wildcard)
Add: example.com (exact) → Skipped (already covered by wildcard)
Add: api.example.com (exact) → Skipped (already covered by wildcard)
```

**Adding wildcard when exact exists:**
```
Existing: example.com, api.example.com (exact)
Add: .example.com (wildcard) → Added; the 2 covered exact entries are removed
Result: .example.com only — "Removed 2 conflicting exact entry/entries to prevent Squid errors"
```

The removal is not cosmetic: Squid refuses to start or reconfigure when an
exact entry and a wildcard for the same domain are both present, so
`filter_conflicts()` drops the now-redundant exact entries before the file is
written.

---

## Logging Configuration

### Logging Modes

Configure via the **Logging** tab in the web UI:

1. **Local File** (default)
   - Logs to `/var/log/squid/access.log` inside container
   - Mount volume to access: `-v ./logs:/var/log/squid`

2. **Standard Output**
   - Logs to container stdout
   - Collect via Docker logging driver
   - Example: `docker logs squid-whitelist-proxy`

3. **Remote Syslog**
   - Logs to stdout with syslog target metadata
   - Configure external log shipper (rsyslog, Fluent Bit, etc.) to forward

### DNS Resolvers

Squid does its own DNS resolution and ignores the container's `/etc/resolv.conf`.
The upstream nameservers are set on the **Logging** tab (up to four, space- or
comma-separated) and default to `1.1.1.1 8.8.8.8`. They are stored in
`/data/config.yaml` under `dns.nameservers` and rendered into `squid.conf` as
`dns_nameservers`.

Note that Squid caches negative DNS answers. If a domain was looked up while
the resolvers were wrong, `squid -k reconfigure` will **not** clear that cached
failure — restart the container to flush it.

### Example: External Log Collection

**docker-compose.yml:**
```yaml
volumes:
  - ./logs:/var/log/squid

logging:
  driver: "syslog"
  options:
    syslog-address: "udp://syslog.example.com:514"
    tag: "squid-proxy"
```

---

## Advanced Usage

### Network-Level Enforcement

Force all traffic through the proxy using firewall rules:

**iptables (Linux):**
```bash
# Allow only proxy to connect outbound on ports 80/443
iptables -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner proxy -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j REJECT
iptables -A OUTPUT -p tcp --dport 443 -j REJECT
```

### Health Monitoring

The container includes a health check endpoint:

```bash
# Check health
curl http://localhost:8080/health

# Docker health status
docker inspect --format='{{.State.Health.Status}}' squid-whitelist-proxy
```

### Squid Configuration Customization

Advanced users can modify the Squid config template:

1. Edit `squid/squid.conf.template`
2. Rebuild container: `docker-compose up -d --build`

### Resource Limits

Add resource limits in `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

---

## Project Layout

```
squidlyfe/
├── app/                       # Flask application
│   ├── app.py                 # Routes, authentication, whitelist/logging management
│   ├── squid_control.py       # Squid control functions (read/write, reload, tail_log)
│   ├── config.py              # Configuration loader
│   ├── entrypoint.sh          # Container startup script
│   ├── templates/             # Jinja2 HTML templates
│   └── static/                # CSS and JavaScript
├── squid/                     # Squid configuration
│   └── squid.conf.template    # Config template with variable substitution
├── data/                      # Runtime persistent storage (excluded from git)
│   ├── whitelist.txt          # Domain whitelist (auto-managed by UI)
│   ├── config.yaml            # Application configuration
│   ├── .secret_key            # Flask session secret (auto-generated)
│   └── .login_attempts.json   # Login rate-limit state (auto-managed, 0600)
├── tests/                     # Unit, integration and end-to-end tests
│   ├── README.md              # What each test covers and how to run it
│   ├── test_whitelist_validation.py   # 36 tests
│   ├── test_log_viewer.py             # 20 tests
│   ├── test_security.py               # 41 tests
│   ├── test_squid_config_render.py    # 11 tests
│   ├── test_flask_ui.py               #  4 tests
│   ├── test_e2e_smoke.sh      # End-to-end smoke test (34 checks, needs Docker)
│   └── test_empty_whitelist.sh
├── docs/                      # Documentation
│   ├── ARCHITECTURE.md        # Technical architecture documentation
│   ├── CONTRIBUTING.md        # Developer guide
│   ├── IMPLEMENTATION_SUMMARY.md
│   └── PROJECT_OVERVIEW.md
├── .github/workflows/ci.yml   # CI: unit tests, pip-audit, Docker end-to-end
├── scripts/                   # Helper scripts
├── Makefile                   # Common operations
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md                  # This file
└── QUICKSTART.md              # 15-minute setup guide
```

---

## Troubleshooting

### Container won't start

Check logs:
```bash
docker logs squid-whitelist-proxy
```

Verify data directory permissions:
```bash
ls -la ./data
chmod -R 755 ./data
```

**Note:** The container is designed to start successfully even with an empty whitelist. If you see "Warning: empty ACL" in the logs, this is informational only and not an error. The container will operate in "deny all" mode until domains are added via the Web UI.

### Proxy not blocking sites

1. Verify whitelist is populated: `cat ./data/whitelist.txt`
2. Check Squid config: `docker exec squid-whitelist-proxy cat /etc/squid/squid.conf`
3. Test Squid ACL: `docker exec squid-whitelist-proxy squid -k parse`
4. View Squid logs: `docker exec squid-whitelist-proxy tail -f /var/log/squid/access.log`

### Can't access whitelisted domain

1. Check exact domain format (use `.example.com` for subdomains)
2. Test DNS resolution: `docker exec squid-whitelist-proxy nslookup example.com`
3. Check Squid logs for denied requests
4. Verify Squid reloaded: Look for "Reconfiguring" in logs
5. Check the rendered resolvers: `docker exec squid-whitelist-proxy grep dns_nameservers /etc/squid/squid.conf`.
   Squid caches negative DNS answers and `squid -k reconfigure` does not flush
   them, so after fixing the resolvers you may need `docker compose restart`.

### Web UI shows errors

1. Check Python logs: `docker logs squid-whitelist-proxy | grep ERROR`
2. Verify `/data` volume is writable
3. Restart container: `docker-compose restart`

### Squid reload fails

1. Validate config syntax:
   ```bash
   docker exec squid-whitelist-proxy squid -k parse
   ```
2. Check for permission issues on whitelist file
3. Review Squid cache log:
   ```bash
   docker exec squid-whitelist-proxy cat /var/log/squid/cache.log
   ```

---

## Security Considerations

### Authentication

- ⚠️ **Change default password immediately**
- Use strong, unique passwords for production
- **Prefer `ADMIN_PASSWORD_HASH` over `ADMIN_PASSWORD`** so no plaintext
  password sits in `docker-compose.yml` or the container's environment.
  Generate one with `make password-hash` and remember to escape `$` as `$$`
  in Compose (see [Storing the Password as a Hash](#storing-the-password-as-a-hash-recommended))
- Credentials are compared in constant time (`hmac.compare_digest`), so a
  failed login reveals nothing about how much of it was correct
- **Sessions expire after 8 hours** by default (`SESSION_LIFETIME_MINUTES`).
  The window slides on each request; the session is cleared and re-established
  at login, so a session ID planted before authentication cannot be reused
- **Login lockout: 5 failed attempts per IP within 5 minutes → HTTP 429.**
  Attempts are recorded in `$DATA_DIR/.login_attempts.json` (mode `0600`,
  guarded by an advisory `flock`), so the limit is shared by **all gunicorn
  workers** and **survives a container restart** rather than resetting
- All state-changing POST routes require a CSRF token, validated with
  `hmac.compare_digest`; every response carries hardening headers
  (`X-Frame-Options`, `X-Content-Type-Options`, CSP, `Referrer-Policy`)
- Session cookies are `HttpOnly`, `SameSite=Lax` and `Secure` unless
  `DISABLE_SECURE_COOKIES=true` is set (development only — the shipped
  `docker-compose.yml` sets it so the UI works over plain HTTP)
- Consider adding HTTPS/TLS termination via reverse proxy

### Network Isolation

- Run container in isolated Docker network
- Use firewall rules to restrict access to proxy
- Only expose ports 3128 and 8080 to trusted networks

### Logging

- Enable access logging for audit trails
- Ship logs to centralized SIEM
- Monitor for unusual access patterns

### Updates

Keep the container updated:

```bash
docker-compose pull
docker-compose up -d --build
```

---

## Development & Contributing

For development guidelines, testing instructions, and contribution workflow, see **[CONTRIBUTING.md](docs/CONTRIBUTING.md)**.

### Quick Development Setup

```bash
# Build and run locally
docker compose up -d

# View logs
docker compose logs -f

# Run the unit suite (112 tests; use PY= to point at a virtualenv)
make test-unit
make test-unit PY=.venv/bin/python

# Build the image and run the end-to-end smoke test
make test-e2e

# Open shell in container
docker exec -it squid-whitelist-proxy /bin/bash

# Validate Squid config
docker exec squid-whitelist-proxy squid -k parse
```

See [Makefile](Makefile) for additional commands, [tests/README.md](tests/README.md)
for the test suite, and [CONTRIBUTING.md](docs/CONTRIBUTING.md) for detailed
development instructions.

### Continuous Integration

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

- **`unit`** — Python 3.11 and 3.13, byte-compiles `app/*.py`, `bash -n`s every
  shell script, then runs each `tests/test_*.py` as its own process
- **`audit`** — `pipx run pip-audit --strict -r requirements.txt`, blocking, so
  a new advisory against a pinned dependency fails the build
- **`docker`** — builds the image and runs `tests/test_e2e_smoke.sh` against it

---

## License

This project is provided as-is for IT infrastructure use. Modify and distribute freely.

---

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review container logs: `docker logs squid-whitelist-proxy`
3. Inspect Squid config: `docker exec squid-whitelist-proxy cat /etc/squid/squid.conf`

---

## Roadmap

Future enhancements under consideration:

- [ ] HTTPS/SSL interception with certificate management
- [ ] URL pattern matching (regex support)
- [ ] Import/export whitelist as CSV
- [ ] Multi-user support with different permission levels
- [ ] API for programmatic whitelist management
- [ ] Integration with Active Directory/LDAP
- [ ] Traffic statistics and reporting dashboard

---

**Built with ❤️ for secure IT infrastructure**
