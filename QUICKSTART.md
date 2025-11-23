# Quick Start Guide

Get the Squid Whitelist Proxy Manager running in 15 minutes.

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+

## 1. Clone Repository

```bash
git clone <repository-url>
cd squidlyfe
```

## 2. Start the Container

```bash
docker compose up -d
```

The container will:
- Build the image if needed
- Create the `/data` volume for persistent storage
- Start Squid proxy on port 3128
- Start web UI on port 8080
- **Start in deny-all mode** (blocks all traffic until you add domains)

## 3. Access Web UI

Open your browser and navigate to:

```
http://localhost:8080
```

**Default credentials** (set via environment variables):
- Username: `admin` (from `ADMIN_USERNAME` env var)
- Password: `changeme` (from `ADMIN_PASSWORD` env var)

⚠️ **Change the default password!** Edit `docker-compose.yml`:

```yaml
environment:
  - ADMIN_USERNAME=admin
  - ADMIN_PASSWORD=YourSecurePassword123
```

Then restart: `docker compose down && docker compose up -d`

## 4. Add Whitelist Entry

The proxy starts in **deny-all mode** - no traffic is allowed until you explicitly whitelist domains.

1. Log in to the web UI
2. Navigate to **Whitelist** tab
3. Add a domain:
   - Enter `example.com` for exact match (domain only, no subdomains)
   - Or enter `.github.com` for wildcard (apex + all subdomains)
4. Click **Add to Whitelist**
5. Domain is active immediately (Squid auto-reloads)

### Entry Types

- **Exact** (`example.com`) - Matches ONLY example.com, not subdomains
- **Wildcard** (`.github.com` or `*.github.com`) - Matches BOTH github.com AND *.github.com

## 5. Verify Proxy Access

After adding `example.com` to the whitelist:

```bash
# Should return 200 (allowed)
curl -x http://localhost:3128 -o /dev/null -w "%{http_code}\n" http://example.com

# Should return 403 (denied - not in whitelist)
curl -x http://localhost:3128 -o /dev/null -w "%{http_code}\n" http://blocked-site.com
```

## 6. Configure Clients

Point your systems to use the proxy:

**Linux/macOS:**
```bash
export http_proxy=http://localhost:3128
export https_proxy=http://localhost:3128
curl http://example.com
```

**Docker containers:**
```bash
docker run --rm \
  -e http_proxy=http://host.docker.internal:3128 \
  -e https_proxy=http://host.docker.internal:3128 \
  curlimages/curl curl http://example.com
```

**System-wide:** Configure in OS network settings or use iptables/firewall rules.

## 7. Live Logs (Optional)

The web UI includes a **Live Log Viewer** (only available when logging mode is `local_file`):

1. Navigate to **Logging** tab
2. Scroll to **Live Log Viewer** section
3. Select log file (Access or Cache)
4. Click **Start**
5. See real-time log tail with filtering and auto-scroll

Alternatively, view logs via CLI:

```bash
# Container logs (Flask + Squid startup)
docker compose logs -f

# Squid access logs
docker exec squid-whitelist-proxy tail -f /var/log/squid/access.log
```

## 8. Stop the Container

```bash
docker compose down
```

Data persists in the `/data` volume - whitelist and config are preserved.

## Common Operations

```bash
# View current whitelist
cat data/whitelist.txt

# Restart container
docker compose restart

# Rebuild after code changes
docker compose up -d --build

# Check container health
docker ps
curl http://localhost:8080/health

# Validate Squid config
docker exec squid-whitelist-proxy squid -k parse

# Reload Squid (zero-downtime)
docker exec squid-whitelist-proxy squid -k reconfigure
```

## Example Whitelists

### Development Environment

```
# Package managers
.npmjs.org
.pypi.org
.debian.org
.ubuntu.com

# GitHub
.github.com
.githubusercontent.com

# Google services
.google.com
.googleapis.com
```

### Corporate Network

```
# Approved SaaS
.salesforce.com
.office365.com
.slack.com

# Internal domains
internal.company.com
api.company.com
```

## Troubleshooting

### All requests are denied (403)

**This is normal if whitelist is empty!** Check:

```bash
cat data/whitelist.txt
```

If empty, add domains via web UI.

### Container won't start

Check logs for errors:

```bash
docker compose logs
```

**Note:** "Warning: empty ACL" in logs is **informational** (deny-all mode), not an error.

### Can't access web UI

1. Verify container is running:
   ```bash
   docker ps  # Should show "Up", not "Restarting"
   ```

2. Check port 8080 is available:
   ```bash
   lsof -i :8080
   ```

3. Review logs:
   ```bash
   docker compose logs | grep ERROR
   ```

### Whitelist changes not taking effect

1. Check file permissions:
   ```bash
   ls -la data/
   ```

2. Manually reload Squid:
   ```bash
   docker exec squid-whitelist-proxy squid -k reconfigure
   ```

3. Check for Squid errors:
   ```bash
   docker exec squid-whitelist-proxy cat /var/log/squid/cache.log
   ```

## Next Steps

- **Full documentation:** See [README.md](README.md)
- **Architecture details:** See [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Development guide:** See [CONTRIBUTING.md](docs/CONTRIBUTING.md)
- **Testing:** Run tests with `python -m unittest tests/test_whitelist_validation.py tests/test_log_viewer.py`
