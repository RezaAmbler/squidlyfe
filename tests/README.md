# Tests

Tests for the Squid Whitelist Proxy appliance.

Everything here runs in CI on every push to `main` and on every pull request
(`.github/workflows/ci.yml`).

## Layout

| File | Kind | Tests | Needs |
|---|---|---:|---|
| `test_whitelist_validation.py` | unit | 36 | nothing (stdlib only) |
| `test_squid_config_render.py` | unit | 11 | PyYAML |
| `test_flask_ui.py` | unit | 4 | Flask |
| `test_log_viewer.py` | unit | 20 | Flask |
| `test_security.py` | unit | 41 | Flask |
| `test_e2e_smoke.sh` | end-to-end | 34 checks | Docker, a built image |
| `test_empty_whitelist.sh` | integration | — | Docker |

**112 unit tests in total**, all passing.

## Unit tests

Each Python test file must be run **as its own process**:

```bash
python3 tests/test_whitelist_validation.py
python3 tests/test_flask_ui.py
python3 tests/test_log_viewer.py
python3 tests/test_security.py
python3 tests/test_squid_config_render.py
```

Or all of them:

```bash
make test-unit
# equivalently:
for f in tests/test_*.py; do echo "== $f"; python3 "$f" || break; done
```

Do **not** collect them into a single `pytest` invocation. They mutate
`os.environ`, monkeypatch module-level paths such as
`squid_control.WHITELIST_PATH`, and call `importlib.reload(app)`. Sharing one
interpreter makes that state collide and produces false passes and failures.

The Flask-dependent files need the pinned dependencies:

```bash
uv venv .venv && uv pip install --python .venv/bin/python -r requirements.txt
make test-unit PY=.venv/bin/python
```

### What they cover

- **`test_whitelist_validation.py`** — normalization (`example.com` vs
  `*.example.com` vs `.example.com`), exact/wildcard separation, coverage
  detection, `filter_conflicts()`, empty-whitelist handling, and
  `TestSymlinkedWhitelistPersistence`: `write_whitelist()` must follow the
  `/etc/squid/whitelist.txt → /data/whitelist.txt` symlink instead of
  replacing it with a regular file.
- **`test_squid_config_render.py`** — `regenerate_squid_config()` substitutes
  every `{{...}}` placeholder, emits `dns_nameservers` and the
  `acl allowed_sites dstdomain` line, and honours each logging mode.
- **`test_flask_ui.py`** — session handling, whitelist add/remove routes,
  secret-key stability across workers.
- **`test_log_viewer.py`** — `tail_log()` cursor logic (initial tail,
  incremental reads, rotation) and the `/api/logs` endpoint.
- **`test_security.py`** — CSRF, login rate limiting, security headers,
  credential handling.

## `test_e2e_smoke.sh` — end-to-end smoke test

The reusable core of the release checklist. It starts a container from an
already-built image, drives the real web UI and the real proxy, prints one
`PASS` / `FAIL` / `SKIP` line per check, and exits non-zero if anything failed.

```bash
make test-e2e
# equivalently:
docker build -t squidlyfe:ci .
IMAGE=squidlyfe:ci ./tests/test_e2e_smoke.sh
```

### What it checks

1. `/health` comes up (01)
2. `squid -k parse` is clean (02) and `squid.conf` has no unresolved `{{...}}`
   placeholders from the boot render (03)
3. deny-by-default through the proxy (04)
4. login: CSRF extraction from the rendered form, cookie jar, redirect (05-08)
5. whitelist add (exact), persistence to `/data`, duplicate suppression,
   proxy ALLOW over plain HTTP (09-13)
6. exact + wildcard conflict: the covered exact entry is dropped so Squid does
   not FATAL, `squid -k parse` still clean, no `FATAL` in `cache.log`, proxy
   ALLOW for a subdomain and for CONNECT (14-20)
7. whitelist remove, and deny-by-default again afterwards (21-23)
8. DNS settings saved from the UI reach both `squid.conf` and
   `/data/config.yaml`, and the re-render leaves no placeholders (24-27)
9. `/api/logs`: happy path, path-traversal and absolute-path rejection,
   authentication required (28-31)
10. login rate limiting returns `429`, by the 6th failed attempt — later than
    that means the limiter is per-worker rather than shared (32)
11. the container is still running and the boot banner is present (33-34)

It finishes by printing the Squid, Python and dependency versions from inside
the image.

### Configuration

Everything is an environment variable; nothing is hardcoded.

| Variable | Default | Purpose |
|---|---|---|
| `IMAGE` | `squidlyfe:ci` | image tag to test |
| `NAME` | `squidlyfe-e2e` | container name |
| `UI_PORT` / `PROXY_PORT` | `18080` / `13128` | host ports (non-default so a running `make up` is never disturbed) |
| `BIND_ADDR` | `127.0.0.1` | address the ports are published on |
| `ADMIN_USER` / `ADMIN_PASS` | `admin` / `e2epass` | web UI credentials |
| `ALLOW_DOMAIN` | `example.com` | domain used for the ALLOW checks |
| `DNS_TEST_SERVERS` | `9.9.9.9 1.1.1.1` | nameservers saved through the UI |
| `E2E_DATA_DIR` | `mktemp -d` | throwaway `/data` directory |
| `CURL_TIMEOUT` / `BOOT_TIMEOUT` | `20` / `90` | seconds |
| `RATE_LIMIT_EXPECT_BY` | `6` | attempt by which a `429` must appear |
| `E2E_SKIP_NETWORK=1` | off | skip checks that need real outbound internet |
| `E2E_REQUIRE_NETWORK=1` | off | turn those skips into failures |
| `E2E_FAIL_FAST=1` | off | stop at the first failure |
| `KEEP_CONTAINER=1` | off | leave the container up for debugging |

### Safety and portability

- It **never** mounts the repository's `./data` directory — that holds real
  whitelist, config and secret-key state. A `mktemp -d` directory is used and
  removed on exit, and the script refuses outright to use a path ending in
  `squidlyfe/data`.
- Cleanup (`docker rm -f`, temp dirs) runs from a `trap`, including on Ctrl-C.
- No `timeout(1)` dependency: macOS does not ship one. `curl --max-time` bounds
  every HTTP call, and `timeout`/`gtimeout` is used for `docker exec` only when
  present.
- bash 3.2 compatible (macOS `/bin/bash`), no GNU-only `sed`/`date` flags.
- Checks that need real outbound internet degrade to `SKIP` when the host
  cannot reach `ALLOW_DOMAIN`.

## `test_empty_whitelist.sh`

Integration test for the empty-whitelist regression: the container must start
and stay up with no whitelist entries, serve `/health`, and deny all proxied
traffic with `403`.

```bash
./tests/test_empty_whitelist.sh
```

## CI

`.github/workflows/ci.yml` runs three jobs:

- **`unit`** — Python 3.11 and 3.13 (3.13 is the image interpreter on Debian
  trixie; 3.11 is kept as the lower bound the code still supports).
  Byte-compiles `app/*.py`, `bash -n`s every shell script, then runs each
  `tests/test_*.py` as its own process.
- **`audit`** — `pipx run pip-audit --strict -r requirements.txt`. Blocking, on
  purpose: a new advisory against a pinned dependency should fail the build.
- **`docker`** — builds the image and runs `tests/test_e2e_smoke.sh` against it.

## Adding tests

- Python: a new `tests/test_*.py` is picked up by the loop and by CI
  automatically. Follow the existing style — plain `unittest`, a `run_tests()`
  helper and an `if __name__ == '__main__':` block that exits non-zero on
  failure.
- Shell: a new `tests/*.sh` is syntax-checked by CI automatically. Add
  end-to-end assertions to `test_e2e_smoke.sh` rather than creating another
  container-starting script.
