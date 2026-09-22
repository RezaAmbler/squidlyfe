#!/usr/bin/env bash
#
# tests/test_e2e_smoke.sh — end-to-end smoke test for the squidlyfe appliance.
#
# Builds nothing: it runs an already-built image, exercises the whole product
# surface (boot, Squid config, proxy deny/allow, web UI auth, whitelist CRUD,
# DNS config, log viewer API) and prints one PASS/FAIL/SKIP line per check.
#
# Usage:
#   docker build -t squidlyfe:ci .
#   IMAGE=squidlyfe:ci ./tests/test_e2e_smoke.sh
#
# Configuration (all optional, all via environment):
#   IMAGE                 image tag to test              (default squidlyfe:ci)
#   NAME                  container name                 (default squidlyfe-e2e)
#   UI_PORT               host port -> container 8080    (default 18080)
#   PROXY_PORT            host port -> container 3128    (default 13128)
#   BIND_ADDR             host address to publish on     (default 127.0.0.1)
#   ADMIN_USER            web UI username                (default admin)
#   ADMIN_PASS            web UI password                (default e2epass)
#   ALLOW_DOMAIN          domain used for proxy ALLOW    (default example.com)
#   E2E_DATA_DIR          throwaway /data dir            (default: mktemp -d)
#   CURL_TIMEOUT          per-request timeout, seconds   (default 20)
#   BOOT_TIMEOUT          seconds to wait for /health    (default 90)
#   RATE_LIMIT_EXPECT_BY  attempt number by which a 429 must appear (default 6)
#   RATE_LIMIT_MAX_PROBE  how many bad logins to try at most      (default 14)
#   WHITELIST_PATH        in-container ACL file (default /etc/squid/whitelist.txt)
#   DATA_WHITELIST        in-container persistent copy (default /data/whitelist.txt)
#   DNS_TEST_SERVERS      nameservers saved via the UI  (default "9.9.9.9 1.1.1.1")
#   E2E_SKIP_NETWORK=1    skip every check needing real outbound internet
#   E2E_REQUIRE_NETWORK=1 turn "network unavailable" skips into failures
#   E2E_FAIL_FAST=1       stop at the first FAIL instead of running everything
#   KEEP_CONTAINER=1      leave the container running for debugging
#
# Safety: NEVER mounts the repository's ./data directory. A throwaway
# directory is created with mktemp -d and removed on exit.
#
# Portability: no `timeout(1)` dependency (macOS has none), no GNU-only
# sed/date flags, bash 3.2 compatible (macOS /bin/bash).
#
# Exit status: 0 only when every executed check passed.

set -uo pipefail
# NOTE: deliberately no `set -e`. Checks must all run and report; failures are
# collected and turned into a non-zero exit status at the very end.

# ------------------------------------------------------------------ config ---
IMAGE="${IMAGE:-squidlyfe:ci}"
NAME="${NAME:-squidlyfe-e2e}"
UI_PORT="${UI_PORT:-18080}"
PROXY_PORT="${PROXY_PORT:-13128}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-e2epass}"
ALLOW_DOMAIN="${ALLOW_DOMAIN:-example.com}"
CURL_TIMEOUT="${CURL_TIMEOUT:-20}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"
RATE_LIMIT_EXPECT_BY="${RATE_LIMIT_EXPECT_BY:-6}"
RATE_LIMIT_MAX_PROBE="${RATE_LIMIT_MAX_PROBE:-14}"
# Nameservers saved through the UI. Override on hosts whose container network
# cannot reach public resolvers directly (e.g. Docker Desktop's internal DNS).
DNS_TEST_SERVERS="${DNS_TEST_SERVERS:-9.9.9.9 1.1.1.1}"
DNS_TEST_FIRST="${DNS_TEST_SERVERS%% *}"
# File Squid's allowed_sites ACL reads, and the persistent copy behind it.
WHITELIST_PATH="${WHITELIST_PATH:-/etc/squid/whitelist.txt}"
DATA_WHITELIST="${DATA_WHITELIST:-/data/whitelist.txt}"
E2E_SKIP_NETWORK="${E2E_SKIP_NETWORK:-0}"
E2E_REQUIRE_NETWORK="${E2E_REQUIRE_NETWORK:-0}"
E2E_FAIL_FAST="${E2E_FAIL_FAST:-0}"
KEEP_CONTAINER="${KEEP_CONTAINER:-0}"

BASE="http://${BIND_ADDR}:${UI_PORT}"
PROXY="http://${BIND_ADDR}:${PROXY_PORT}"

# --------------------------------------------------------------- scaffolding ---
CHECKS_TOTAL=0
CHECKS_FAILED=0
CHECKS_SKIPPED=0
FAILED_NAMES=""
OWN_DATA_DIR=0

WORKDIR="$(mktemp -d 2>/dev/null)" || { echo "ERROR: mktemp -d failed" >&2; exit 2; }
if [ -n "${E2E_DATA_DIR:-}" ]; then
    DATA_DIR_HOST="$E2E_DATA_DIR"
    mkdir -p "$DATA_DIR_HOST"
else
    DATA_DIR_HOST="$(mktemp -d 2>/dev/null)" || { echo "ERROR: mktemp -d failed" >&2; exit 2; }
    OWN_DATA_DIR=1
fi

# Hard guard: refuse to run against the repository's real state directory.
case "$DATA_DIR_HOST" in
    */squidlyfe/data|*/squidlyfe/data/) echo "ERROR: refusing to use the repo data dir" >&2; exit 2 ;;
esac

JAR="$WORKDIR/cookies-main.txt"
JAR_BAD="$WORKDIR/cookies-lockout.txt"

cleanup() {
    local rc=$?
    if [ "$KEEP_CONTAINER" = "1" ]; then
        echo ""
        echo "KEEP_CONTAINER=1: leaving container '$NAME' and data dir $DATA_DIR_HOST in place."
    else
        docker rm -f "$NAME" >/dev/null 2>&1 || true
        [ "$OWN_DATA_DIR" = "1" ] && rm -rf "$DATA_DIR_HOST"
    fi
    rm -rf "$WORKDIR"
    exit $rc
}
trap cleanup EXIT INT TERM

hr()   { printf '%s\n' "------------------------------------------------------------------------"; }
info() { printf '      %s\n' "$*"; }

pass() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    printf 'PASS  %-52s %s\n' "$1" "${2:-}"
}

fail() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    FAILED_NAMES="${FAILED_NAMES}
  - $1 ${2:-}"
    printf 'FAIL  %-52s %s\n' "$1" "${2:-}"
    if [ "$E2E_FAIL_FAST" = "1" ]; then
        echo ""
        echo "E2E_FAIL_FAST=1 — aborting at first failure."
        dump_diagnostics
        exit 1
    fi
}

skip() {
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    CHECKS_SKIPPED=$((CHECKS_SKIPPED + 1))
    printf 'SKIP  %-52s %s\n' "$1" "${2:-}"
}

# expect NAME EXPECTED ACTUAL
expect() {
    if [ "$2" = "$3" ]; then
        pass "$1" "($3)"
    else
        fail "$1" "expected '$2', got '$3'"
    fi
}

# net_check NAME EXPECTED ACTUAL  — a check that needs real outbound internet
net_expect() {
    if [ "$NET_OK" != "1" ]; then
        if [ "$E2E_REQUIRE_NETWORK" = "1" ]; then
            fail "$1" "outbound network unavailable and E2E_REQUIRE_NETWORK=1"
        else
            skip "$1" "(no outbound internet)"
        fi
        return
    fi
    expect "$1" "$2" "$3"
}

dump_diagnostics() {
    hr
    echo "DIAGNOSTICS"
    hr
    echo "--- docker logs $NAME (last 120 lines) ---"
    docker logs --tail 120 "$NAME" 2>&1 || true
    echo "--- /etc/squid/squid.conf (grep-able excerpt) ---"
    dexec sh -c "grep -nE '^(acl allowed_sites|dns_nameservers|access_log|http_access)' /etc/squid/squid.conf" 2>&1 || true
    echo "--- whitelist ($WHITELIST_PATH, then $DATA_WHITELIST) ---"
    dexec sh -c "ls -l '$WHITELIST_PATH' '$DATA_WHITELIST'" 2>&1 || true
    entries_in "$WHITELIST_PATH" 2>&1 || true
    echo "  ---"
    entries_in "$DATA_WHITELIST" 2>&1 || true
    echo "--- squid cache.log (last 40 lines) ---"
    dexec sh -c "tail -n 40 /var/log/squid/cache.log" 2>&1 || true
    hr
}

# --------------------------------------------------------------- primitives ---

# dexec <cmd...> — docker exec wrapper. Uses timeout(1)/gtimeout(1) when the
# platform has one (Linux/CI), plain exec otherwise (macOS).
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
fi

dexec() {
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" 30 docker exec "$NAME" "$@"
    else
        docker exec "$NAME" "$@"
    fi
}

# HTTP status of a plain GET (no cookie jar)
code_get() {
    curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_TIMEOUT" "$@" 2>/dev/null
}

# HTTP status of a GET through the Squid proxy
proxy_code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time "$CURL_TIMEOUT" \
        --proxy "$PROXY" "$1" 2>/dev/null
}

# csrf_from <jar> <path> — pull the csrf_token value out of a rendered form
csrf_from() {
    curl -s --max-time "$CURL_TIMEOUT" -b "$1" -c "$1" "${BASE}$2" 2>/dev/null \
        | sed -n 's/.*name="csrf_token"[^>]*value="\([^"]*\)".*/\1/p' \
        | head -1
}

# form_post <jar> <path> <field=value>... — prints the HTTP status code.
# Response headers land in $WORKDIR/hdr.out, body in $WORKDIR/body.out.
form_post() {
    local jar="$1" path="$2"
    shift 2
    local curl_args
    curl_args=()
    while [ $# -gt 0 ]; do
        curl_args[${#curl_args[@]}]="--data-urlencode"
        curl_args[${#curl_args[@]}]="$1"
        shift
    done
    curl -s --max-time "$CURL_TIMEOUT" -b "$jar" -c "$jar" \
        -o "$WORKDIR/body.out" -D "$WORKDIR/hdr.out" -w '%{http_code}' \
        "${curl_args[@]}" "${BASE}${path}" 2>/dev/null
}

# location_header — the Location: value from the last form_post
location_header() {
    sed -n 's/^[Ll]ocation:[[:space:]]*\(.*\)$/\1/p' "$WORKDIR/hdr.out" | tr -d '\r' | head -1
}

# entries_in <path> — active (non-comment, non-blank) lines of a whitelist file
entries_in() {
    dexec sh -c "grep -v '^#' '$1' 2>/dev/null | grep -v '^[[:space:]]*\$'" 2>/dev/null
}

# whitelist_entries — the file Squid's allowed_sites ACL actually reads
whitelist_entries() { entries_in "$WHITELIST_PATH"; }

# count_line <exact-line> — how many times an exact entry appears in the ACL file
count_line() {
    whitelist_entries | grep -c -x -- "$1" 2>/dev/null | tr -d '[:space:]'
}

# count_line_data <exact-line> — same, but in the persistent /data copy
count_line_data() {
    entries_in "$DATA_WHITELIST" | grep -c -x -- "$1" 2>/dev/null | tr -d '[:space:]'
}

# ============================================================================
hr
echo "squidlyfe end-to-end smoke test"
hr
info "image        : $IMAGE"
info "container    : $NAME"
info "web UI       : $BASE"
info "proxy        : $PROXY"
info "data dir     : $DATA_DIR_HOST (throwaway)"
info "timeout(1)   : ${TIMEOUT_BIN:-<absent, using curl --max-time only>}"
hr

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found in PATH" >&2; exit 2; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo "ERROR: image '$IMAGE' not found. Build it first: docker build -t $IMAGE ." >&2
    exit 2
}

# Outbound-internet probe (host side). Container-side DNS is a product concern
# and is NOT probed here: if the container cannot resolve, the ALLOW checks are
# supposed to fail loudly.
NET_OK=0
if [ "$E2E_SKIP_NETWORK" = "1" ]; then
    info "network      : skipped by E2E_SKIP_NETWORK=1"
elif curl -s -o /dev/null --max-time 10 "http://${ALLOW_DOMAIN}" 2>/dev/null; then
    NET_OK=1
    info "network      : outbound internet reachable (${ALLOW_DOMAIN})"
else
    info "network      : outbound internet NOT reachable - ALLOW checks will be skipped"
fi
hr

# --------------------------------------------------------- 0. start container ---
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "Starting container..."
if ! docker run -d --name "$NAME" \
        -p "${BIND_ADDR}:${UI_PORT}:8080" \
        -p "${BIND_ADDR}:${PROXY_PORT}:3128" \
        -v "${DATA_DIR_HOST}:/data" \
        -e "ADMIN_USERNAME=${ADMIN_USER}" \
        -e "ADMIN_PASSWORD=${ADMIN_PASS}" \
        -e DISABLE_SECURE_COOKIES=true \
        "$IMAGE" >/dev/null; then
    echo "ERROR: docker run failed" >&2
    exit 2
fi
hr

# ------------------------------------------------------------- 1. boot/health ---
waited=0
health_code=""
while [ "$waited" -lt "$BOOT_TIMEOUT" ]; do
    health_code="$(code_get "${BASE}/health")"
    [ "$health_code" = "200" ] && break
    # NOTE: no `| grep -q` here — with `set -o pipefail` a short-circuiting
    # grep -q makes the producer die of SIGPIPE and the pipeline report failure.
    if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
        echo "Container exited during boot."
        break
    fi
    sleep 2
    waited=$((waited + 2))
done

if [ "$health_code" = "200" ]; then
    pass "01 health endpoint returns 200" "(after ${waited}s)"
else
    fail "01 health endpoint returns 200" "got '${health_code}' after ${waited}s"
    dump_diagnostics
    echo ""
    echo "Container never became healthy; remaining checks would be meaningless."
    exit 1
fi

# ------------------------------------------------------- 2. squid config sane ---
if dexec squid -k parse >"$WORKDIR/parse.out" 2>&1; then
    pass "02 squid -k parse exits 0"
else
    fail "02 squid -k parse exits 0" "exit $? (see below)"
    sed 's/^/      /' "$WORKDIR/parse.out"
fi

# Step 1b regression: the boot-time renderer must substitute every placeholder.
# This must run BEFORE any /logging POST, because saving settings re-renders
# squid.conf through the Python renderer and would mask a broken boot render.
placeholders="$(dexec sh -c "grep -c '{{' /etc/squid/squid.conf || true" 2>/dev/null | tr -d '[:space:]')"
expect "03 no unresolved {{ }} placeholders in squid.conf" "0" "${placeholders:-?}"
if [ "${placeholders:-0}" != "0" ]; then
    info "offending lines:"
    dexec sh -c "grep -n '{{' /etc/squid/squid.conf" 2>/dev/null | sed 's/^/      /'
fi

# ----------------------------------------------------- 3. deny by default ------
expect "04 proxy denies un-whitelisted domain (403)" "403" "$(proxy_code "http://${ALLOW_DOMAIN}/")"

# --------------------------------------------------------------- 4. login ------
login_page_code="$(code_get -c "$JAR" "${BASE}/login")"
expect "05 GET /login returns 200" "200" "$login_page_code"

token="$(csrf_from "$JAR" /login)"
if [ -n "$token" ]; then
    pass "06 CSRF token extracted from login form" "(${#token} chars)"
else
    fail "06 CSRF token extracted from login form" "empty"
fi

code="$(form_post "$JAR" /login \
    "username=${ADMIN_USER}" "password=${ADMIN_PASS}" "csrf_token=${token}")"
loc="$(location_header)"
case "$code:$loc" in
    302:*/whitelist*) pass "07 POST /login redirects to /whitelist" "(302 -> $loc)" ;;
    *)               fail "07 POST /login redirects to /whitelist" "got $code, Location='$loc'" ;;
esac

expect "08 authenticated GET /whitelist returns 200" "200" \
    "$(code_get -b "$JAR" -c "$JAR" "${BASE}/whitelist")"

# ------------------------------------------------ 5. whitelist add (exact) -----
token="$(csrf_from "$JAR" /whitelist)"
code="$(form_post "$JAR" /whitelist \
    "csrf_token=${token}" "action=add" "new_entry=${ALLOW_DOMAIN}")"
expect "09 POST add exact '${ALLOW_DOMAIN}' returns 302" "302" "$code"
expect "10 ACL file lists exact '${ALLOW_DOMAIN}'" "1" "$(count_line "${ALLOW_DOMAIN}")"

# The allow-list must survive a container restart, i.e. it must land in the
# /data volume, not only in the container-local file Squid reads.
expect "11 ${DATA_WHITELIST} persisted exact '${ALLOW_DOMAIN}'" "1" \
    "$(count_line_data "${ALLOW_DOMAIN}")"
if [ "$(count_line_data "${ALLOW_DOMAIN}")" != "1" ]; then
    info "note: $WHITELIST_PATH should be a symlink into /data; it is now:"
    dexec sh -c "ls -l '$WHITELIST_PATH'" 2>/dev/null | sed 's/^/      /'
fi

# duplicate add must not create a second line
token="$(csrf_from "$JAR" /whitelist)"
form_post "$JAR" /whitelist \
    "csrf_token=${token}" "action=add" "new_entry=${ALLOW_DOMAIN}" >/dev/null
expect "12 duplicate add does not duplicate the entry" "1" "$(count_line "${ALLOW_DOMAIN}")"

sleep 2
# If check 03 failed (boot render left {{DNS_NAMESERVERS}} in squid.conf) this
# check fails with curl code 000: Squid starts with zero nameservers, and the
# resulting negative ipcache entry survives `squid -k reconfigure` and does not
# expire, so the domain stays unresolvable for the life of the process even
# after DNS is fixed through the UI. Verified against Squid 5.7.
net_expect "13 proxy ALLOWs whitelisted http://${ALLOW_DOMAIN}" "200" \
    "$(proxy_code "http://${ALLOW_DOMAIN}/")"

# ------------------------------------- 6. exact + wildcard conflict handling ---
# Squid FATALs if the dstdomain ACL file holds both `example.com` and
# `.example.com`, so adding the wildcard must drop the covered exact entry.
token="$(csrf_from "$JAR" /whitelist)"
code="$(form_post "$JAR" /whitelist \
    "csrf_token=${token}" "action=add" "new_entry=*.${ALLOW_DOMAIN}")"
expect "14 POST add wildcard '*.${ALLOW_DOMAIN}' returns 302" "302" "$code"
expect "15 ACL file lists wildcard '.${ALLOW_DOMAIN}'" "1" "$(count_line ".${ALLOW_DOMAIN}")"
expect "16 conflicting exact entry was filtered out" "0" "$(count_line "${ALLOW_DOMAIN}")"

if dexec squid -k parse >"$WORKDIR/parse2.out" 2>&1; then
    pass "17 squid -k parse still valid after wildcard add"
else
    fail "17 squid -k parse still valid after wildcard add" "non-zero exit"
    sed 's/^/      /' "$WORKDIR/parse2.out"
fi

fatals="$(dexec sh -c "grep -ci 'FATAL' /var/log/squid/cache.log || true" 2>/dev/null | tr -d '[:space:]')"
expect "18 no FATAL lines in squid cache.log" "0" "${fatals:-?}"

sleep 2
net_expect "19 proxy ALLOWs subdomain http://www.${ALLOW_DOMAIN}" "200" \
    "$(proxy_code "http://www.${ALLOW_DOMAIN}/")"
net_expect "20 proxy ALLOWs CONNECT https://www.${ALLOW_DOMAIN}" "200" \
    "$(proxy_code "https://www.${ALLOW_DOMAIN}/")"

# --------------------------------------------------------- 7. whitelist remove ---
token="$(csrf_from "$JAR" /whitelist)"
code="$(form_post "$JAR" /whitelist \
    "csrf_token=${token}" "action=remove" "remove_entries=.${ALLOW_DOMAIN}")"
expect "21 POST remove '.${ALLOW_DOMAIN}' returns 302" "302" "$code"

remaining="$(whitelist_entries | grep -c -- "${ALLOW_DOMAIN}" 2>/dev/null | tr -d '[:space:]')"
expect "22 ACL file no longer lists ${ALLOW_DOMAIN}" "0" "${remaining:-?}"

sleep 2
expect "23 proxy denies ${ALLOW_DOMAIN} again after removal (403)" "403" \
    "$(proxy_code "http://${ALLOW_DOMAIN}/")"

# ---------------------------------------------------------- 8. DNS config save ---
# NOTE: saving here re-renders squid.conf through the Python renderer, which
# always substitutes every placeholder. Check 03 above is the boot-render
# regression guard and must stay ahead of this POST.
token="$(csrf_from "$JAR" /logging)"
code="$(form_post "$JAR" /logging \
    "csrf_token=${token}" "logging_mode=local_file" "syslog_host=" \
    "syslog_port=514" "syslog_protocol=udp" "dns_nameservers=${DNS_TEST_SERVERS}")"
expect "24 POST /logging (DNS ${DNS_TEST_SERVERS}) returns 302" "302" "$code"

if dexec sh -c "grep -qx 'dns_nameservers ${DNS_TEST_SERVERS}' /etc/squid/squid.conf" 2>/dev/null; then
    pass "25 squid.conf has the saved dns_nameservers line"
else
    fail "25 squid.conf has the saved dns_nameservers line" \
        "actual: $(dexec sh -c "grep '^dns_nameservers' /etc/squid/squid.conf || echo '<none>'" 2>/dev/null)"
fi

if dexec sh -c "grep -q '${DNS_TEST_FIRST}' /data/config.yaml" 2>/dev/null; then
    pass "26 /data/config.yaml persisted the nameservers"
else
    fail "26 /data/config.yaml persisted the nameservers" "${DNS_TEST_FIRST} not found"
fi

placeholders="$(dexec sh -c "grep -c '{{' /etc/squid/squid.conf || true" 2>/dev/null | tr -d '[:space:]')"
expect "27 no {{ }} placeholders after UI-driven re-render" "0" "${placeholders:-?}"

# ------------------------------------------------------------ 9. log viewer API ---
body_code="$(curl -s --max-time "$CURL_TIMEOUT" -b "$JAR" -c "$JAR" \
    -o "$WORKDIR/logs.json" -w '%{http_code}' \
    "${BASE}/api/logs?file=access&lines=20" 2>/dev/null)"
if [ "$body_code" = "200" ] \
   && grep -q '"lines"' "$WORKDIR/logs.json" \
   && grep -q '"cursor"' "$WORKDIR/logs.json"; then
    pass "28 GET /api/logs?file=access returns lines+cursor" "(200)"
else
    fail "28 GET /api/logs?file=access returns lines+cursor" \
        "code=$body_code body=$(head -c 200 "$WORKDIR/logs.json" 2>/dev/null)"
fi

expect "29 /api/logs rejects path traversal file param (400)" "400" \
    "$(code_get -b "$JAR" -c "$JAR" -G --data-urlencode 'file=../../etc/passwd' "${BASE}/api/logs")"

expect "30 /api/logs rejects absolute path file param (400)" "400" \
    "$(code_get -b "$JAR" -c "$JAR" -G --data-urlencode 'file=/etc/passwd' "${BASE}/api/logs")"

expect "31 /api/logs requires authentication (302)" "302" \
    "$(code_get "${BASE}/api/logs?file=access")"

# --------------------------------------------------------- 10. rate-limit lockout ---
# Separate cookie jar so the authenticated session above is untouched. Runs late
# on purpose: a successful lockout blocks further logins from this IP for five
# minutes, which would break every check that needs to log in.
#
# MAX_LOGIN_ATTEMPTS is 5 and the limit is checked BEFORE the attempt is
# recorded, so with a store shared by all gunicorn workers the 6th POST is the
# first 429. A per-process store pushes the first 429 out to ~11 with 2 workers,
# which is exactly what this check is meant to catch.
rm -f "$JAR_BAD"
bad_token="$(csrf_from "$JAR_BAD" /login)"
first_429=0
attempt=1
while [ "$attempt" -le "$RATE_LIMIT_MAX_PROBE" ]; do
    c="$(form_post "$JAR_BAD" /login \
        "username=${ADMIN_USER}" "password=definitely-wrong-${attempt}" \
        "csrf_token=${bad_token}")"
    if [ "$c" = "429" ]; then
        first_429=$attempt
        break
    fi
    if [ "$c" = "403" ]; then
        # CSRF token rotated under us; refresh and keep going.
        bad_token="$(csrf_from "$JAR_BAD" /login)"
    fi
    attempt=$((attempt + 1))
done

if [ "$first_429" -eq 0 ]; then
    fail "32 login lockout returns 429" \
        "no 429 within $RATE_LIMIT_MAX_PROBE failed attempts"
elif [ "$first_429" -le "$RATE_LIMIT_EXPECT_BY" ]; then
    pass "32 login lockout returns 429" "(first 429 at attempt $first_429)"
else
    fail "32 login lockout returns 429" \
        "first 429 at attempt $first_429, expected <= $RATE_LIMIT_EXPECT_BY (rate-limit store not shared across gunicorn workers?)"
fi

# --------------------------------------------------------------- 11. liveness ---
running="$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)"
expect "33 container still running at end of run" "true" "$running"

# NOTE: no `docker logs ... | grep -q` — with `set -o pipefail` the short-
# circuiting grep kills the producer with SIGPIPE and the pipeline reports
# failure even on a match. Buffer to a file, then grep the file.
docker logs "$NAME" >"$WORKDIR/container.log" 2>&1 || true
if grep -q 'Services Started Successfully' "$WORKDIR/container.log"; then
    pass "34 boot log contains 'Services Started Successfully'"
else
    fail "34 boot log contains 'Services Started Successfully'" "marker missing"
fi

# ------------------------------------------------------------ 12. version record ---
hr
echo "VERSIONS (informational, not a check)"
hr
info "squid   : $(dexec squid -v 2>/dev/null | head -1)"
info "python  : $(dexec python3 -c 'import sys; print(sys.executable, sys.version.split()[0])' 2>/dev/null)"
info "packages: $(dexec python3 -c 'import flask, werkzeug, gunicorn, yaml; print("flask", flask.__version__, "werkzeug", werkzeug.__version__, "gunicorn", gunicorn.__version__, "pyyaml", yaml.__version__)' 2>/dev/null)"
info "image   : $(docker image inspect -f '{{.Size}}' "$IMAGE" 2>/dev/null) bytes"

# ------------------------------------------------------------------ summary ---
hr
printf 'Checks: %d total, %d failed, %d skipped\n' \
    "$CHECKS_TOTAL" "$CHECKS_FAILED" "$CHECKS_SKIPPED"
hr

if [ "$CHECKS_FAILED" -ne 0 ]; then
    echo "FAILED CHECKS:${FAILED_NAMES}"
    dump_diagnostics
    exit 1
fi

echo "All executed checks passed."
exit 0
