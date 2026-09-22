"""
Squid Whitelist Proxy - Web UI Application
Provides a web interface for managing Squid proxy whitelist and logging configuration.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import check_password_hash
from contextlib import contextmanager
from datetime import timedelta
from functools import wraps
import os
import logging
import secrets
import hmac
import hashlib
import re
import json
import fcntl
import tempfile
from collections import defaultdict
import time

from config import load_config
from squid_control import (
    read_whitelist,
    write_whitelist,
    reload_squid,
    read_logging_config,
    write_logging_config,
    regenerate_squid_config,
    normalize_whitelist_entries,
    entry_coverage,
    filter_conflicts,
    tail_log
)

app = Flask(__name__)

# Rate limiting for login attempts.
#
# The authoritative store is a small JSON file under DATA_DIR, guarded by an
# advisory flock, so the limit is shared by every gunicorn worker and survives
# a container restart. `login_attempts` below is only a per-process fallback
# used when that file cannot be read or written (read-only volume, etc.).
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes
LOGIN_ATTEMPTS_FILENAME = '.login_attempts.json'

# Set once when we first fall back to the in-memory store, so the warning is
# logged a single time per worker instead of on every login attempt.
_rate_limit_fallback_warned = False


def get_or_create_secret_key() -> bytes:
    """
    Get or create a stable secret key for Flask sessions.

    With multiple gunicorn workers, using os.urandom() directly creates different
    keys per worker, invalidating sessions across workers. This function ensures
    a single stable key across all workers and restarts.

    Priority:
    1. Use SECRET_KEY environment variable if set
    2. Load from persisted file /data/.secret_key
    3. If file doesn't exist, generate and save new key

    Returns:
        Stable secret key bytes (32 bytes)
    """
    # Check environment first
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        print("INFO: Using SECRET_KEY from environment", flush=True)
        return env_key.encode('utf-8')

    # Use persisted file in data directory
    data_dir = os.environ.get('DATA_DIR', '/data')
    secret_file = os.path.join(data_dir, '.secret_key')

    try:
        # Try to load existing secret
        if os.path.exists(secret_file):
            with open(secret_file, 'rb') as f:
                key = f.read()
                if len(key) >= 24:
                    print(f"INFO: Loaded secret key from {secret_file}", flush=True)
                    return key
                else:
                    print(f"WARNING: Secret key file {secret_file} too short, regenerating", flush=True)

        # Generate new secret key
        print(f"INFO: Generating new secret key and saving to {secret_file}", flush=True)
        os.makedirs(data_dir, exist_ok=True)
        new_key = os.urandom(32)

        # Write with restrictive permissions
        with open(secret_file, 'wb') as f:
            f.write(new_key)
        os.chmod(secret_file, 0o600)

        return new_key

    except Exception as e:
        print(f"ERROR: Error loading/creating secret key: {e}. Using ephemeral key.", flush=True)
        return os.urandom(24)


# Load secret key (stable across workers and restarts)
app.secret_key = get_or_create_secret_key()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security: Configure secure session cookies
# SESSION_COOKIE_SECURE requires HTTPS; set to False if TLS termination is external
# Override with DISABLE_SECURE_COOKIES env var for development only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('DISABLE_SECURE_COOKIES', '').lower() != 'true'

if not app.config['SESSION_COOKIE_SECURE']:
    logger.warning("SESSION_COOKIE_SECURE is disabled. Enable HTTPS/TLS termination for production.")


# Security: Bound session lifetime. Flask's default is 31 days, which is far
# too long for an admin console. Sessions are marked permanent at login, so
# this is a sliding window (SESSION_REFRESH_EACH_REQUEST defaults to True).
def _session_lifetime_minutes() -> int:
    """Read SESSION_LIFETIME_MINUTES, falling back to 480 (8h) if unusable."""
    raw = os.environ.get('SESSION_LIFETIME_MINUTES', '480')
    try:
        minutes = int(str(raw).strip())
    except (TypeError, ValueError):
        logger.warning(f"Invalid SESSION_LIFETIME_MINUTES={raw!r}; using 480")
        return 480
    if minutes <= 0:
        logger.warning(f"SESSION_LIFETIME_MINUTES={minutes} must be positive; using 480")
        return 480
    return minutes


app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=_session_lifetime_minutes())


# CSRF Protection
def generate_csrf_token():
    """Generate a CSRF token and store it in the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token(token):
    """Validate CSRF token using constant-time comparison"""
    if 'csrf_token' not in session:
        return False
    return hmac.compare_digest(session['csrf_token'], token)


# Make csrf_token available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)


# Security: Input validation for whitelist entries
def validate_domain_input(entry: str) -> bool:
    """
    Validate that a whitelist entry looks like a valid domain.

    Accepts:
    - Bare domains: example.com, api.github.com
    - Wildcard domains: .example.com, *.example.com

    Rejects:
    - Special characters except . - *
    - Strings with spaces or control characters
    - Strings that don't look like domains

    Args:
        entry: User input string

    Returns:
        True if valid, False otherwise
    """
    if not entry or len(entry) > 255:
        return False

    # Strip http://, https://, paths (normalization will handle this too)
    cleaned = entry.strip()
    for prefix in ['https://', 'http://']:
        if cleaned.lower().startswith(prefix):
            cleaned = cleaned[len(prefix):]

    if '/' in cleaned:
        cleaned = cleaned.split('/')[0]

    # Check for wildcard prefix
    if cleaned.startswith('*.'):
        cleaned = cleaned[2:]
    elif cleaned.startswith('.'):
        cleaned = cleaned[1:]

    # Validate domain pattern: alphanumeric, hyphens, dots
    # Must not be empty, no spaces, no special chars except hyphen and dot
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')

    if not domain_pattern.match(cleaned):
        return False

    # Additional checks
    if '..' in cleaned or cleaned.startswith('.') or cleaned.endswith('.'):
        return False

    # Reject if contains invalid characters
    if any(char in cleaned for char in ['#', '$', '@', '!', '%', '^', '&', '*', '(', ')', '=', '+', '[', ']', '{', '}', '|', '\\', ';', ':', '"', "'", '<', '>', '?', ',', ' ']):
        return False

    return True


# Security: Credential verification
def verify_credentials(username: str, password: str) -> bool:
    """
    Verify admin credentials in constant time.

    ADMIN_PASSWORD_HASH (a werkzeug scrypt/pbkdf2 hash, e.g. from
    `make password-hash`) takes precedence over the plaintext ADMIN_PASSWORD.
    Both the username and the password are always compared, and the results
    are only combined at the end, so the answer does not leak which half was
    wrong through timing or short-circuiting.

    Args:
        username: Username supplied by the client
        password: Password supplied by the client

    Returns:
        True only if both username and password match.
    """
    admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
    password_hash = os.environ.get('ADMIN_PASSWORD_HASH', '').strip()

    user_ok = hmac.compare_digest(
        (username or '').encode('utf-8'),
        admin_username.encode('utf-8')
    )

    if password_hash:
        try:
            pass_ok = check_password_hash(password_hash, password or '')
        except Exception:
            # A malformed/unsupported hash must deny access, never 500.
            logger.error("ADMIN_PASSWORD_HASH is malformed; rejecting login")
            pass_ok = False
    else:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
        pass_ok = hmac.compare_digest(
            (password or '').encode('utf-8'),
            admin_password.encode('utf-8')
        )

    return user_ok and pass_ok


# Security: Check if default password is in use
def is_using_default_password():
    """Check if the admin password is still set to the default 'changeme'"""
    if os.environ.get('ADMIN_PASSWORD_HASH', '').strip():
        # A configured hash always overrides ADMIN_PASSWORD, so the default
        # plaintext value is irrelevant.
        return False
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    return hmac.compare_digest(admin_password.encode('utf-8'), b'changeme')


# Security: Rate limiting for login attempts, shared across workers/restarts
def _login_attempts_path() -> str:
    """
    Absolute path of the shared login-attempt store.

    Computed per call rather than at import time because DATA_DIR is set per
    test and could in principle change between reloads.
    """
    return os.path.join(os.environ.get('DATA_DIR', '/data'), LOGIN_ATTEMPTS_FILENAME)


def _prune_attempts(attempts: dict, now: float) -> dict:
    """Drop attempts older than RATE_LIMIT_WINDOW and IPs left with none."""
    pruned = {}
    for ip, timestamps in (attempts or {}).items():
        if not isinstance(timestamps, list):
            continue
        kept = [
            float(t) for t in timestamps
            if isinstance(t, (int, float)) and now - float(t) < RATE_LIMIT_WINDOW
        ]
        if kept:
            pruned[ip] = kept
    return pruned


def _read_attempts_file(path: str) -> dict:
    """Read the attempt store; a missing or corrupt file means 'no attempts'."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}
    except (ValueError, UnicodeDecodeError):
        logger.warning(f"Login attempt store {path} is corrupt; resetting it")
        return {}
    return data if isinstance(data, dict) else {}


def _write_attempts_file(path: str, attempts: dict):
    """Atomically replace the attempt store with 0600 permissions."""
    directory = os.path.dirname(path) or '.'
    temp_fd, temp_path = tempfile.mkstemp(dir=directory, prefix='.login_attempts.')
    try:
        with os.fdopen(temp_fd, 'w') as f:
            json.dump(attempts, f)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


@contextmanager
def _locked_attempts():
    """
    Yield the shared attempt store under an exclusive flock.

    Yields a mutable dict-holding state object; set state['dirty'] = True to
    have the (pruned) contents written back atomically before the lock drops.
    Raises OSError if the store is unusable, so callers can fall back.
    """
    path = _login_attempts_path()
    lock_path = path + '.lock'
    directory = os.path.dirname(path) or '.'
    os.makedirs(directory, exist_ok=True)

    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state = {'attempts': _read_attempts_file(path), 'dirty': False}
        yield state
        if state['dirty']:
            _write_attempts_file(path, state['attempts'])
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _warn_rate_limit_fallback(error: Exception):
    """Log the degraded-mode warning once per process."""
    global _rate_limit_fallback_warned
    if not _rate_limit_fallback_warned:
        _rate_limit_fallback_warned = True
        logger.warning(
            f"Shared login-attempt store unavailable ({error}); falling back to "
            "per-process rate limiting. The 5-attempt limit is then enforced "
            "per gunicorn worker instead of globally."
        )


def check_rate_limit(ip_address: str) -> bool:
    """
    Check if IP address has exceeded the login attempt rate limit.

    Reads the shared, file-backed store so the limit holds across gunicorn
    workers and container restarts.

    Args:
        ip_address: Client IP address

    Returns:
        True if under limit, False if rate limited
    """
    now = time.time()

    try:
        with _locked_attempts() as state:
            pruned = _prune_attempts(state['attempts'], now)
            if pruned != state['attempts']:
                state['attempts'] = pruned
                state['dirty'] = True
            return len(pruned.get(ip_address, [])) < MAX_LOGIN_ATTEMPTS
    except Exception as e:
        _warn_rate_limit_fallback(e)

    # In-memory fallback (per process)
    login_attempts[ip_address] = [
        attempt_time for attempt_time in login_attempts[ip_address]
        if now - attempt_time < RATE_LIMIT_WINDOW
    ]
    return len(login_attempts[ip_address]) < MAX_LOGIN_ATTEMPTS


def record_login_attempt(ip_address: str):
    """Record a failed login attempt in the shared store."""
    now = time.time()

    try:
        with _locked_attempts() as state:
            attempts = _prune_attempts(state['attempts'], now)
            attempts.setdefault(ip_address, []).append(now)
            state['attempts'] = attempts
            state['dirty'] = True
            return
    except Exception as e:
        _warn_rate_limit_fallback(e)

    # In-memory fallback (per process)
    login_attempts[ip_address].append(now)


def clear_login_attempts():
    """
    Forget every recorded login attempt.

    Removes the shared store (and its lock file) and clears the in-memory
    fallback. Intended for tests and for administrative unlocking.
    """
    path = _login_attempts_path()
    for candidate in (path, path + '.lock'):
        try:
            os.unlink(candidate)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.warning(f"Could not remove {candidate}: {e}")
    login_attempts.clear()


# Security: Add security headers to all responses
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


# Authentication decorator
def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    """Redirect to whitelist page if logged in, otherwise to login"""
    if session.get('logged_in'):
        return redirect(url_for('whitelist'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler"""
    # Security: Warn if using default password
    if is_using_default_password():
        flash('Security Warning: Default password "changeme" is in use. Set ADMIN_PASSWORD environment variable to a secure password for production.', 'warning')
        logger.warning("Default password 'changeme' is still in use")

    if request.method == 'POST':
        # Security: Validate CSRF token
        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            flash('Security Error: Invalid CSRF token. Please try again.', 'danger')
            logger.warning("Login attempt with invalid CSRF token")
            abort(403)

        # Security: Rate limiting
        client_ip = request.remote_addr or 'unknown'
        if not check_rate_limit(client_ip):
            flash('Too many failed login attempts. Please try again in 5 minutes.', 'danger')
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return render_template('login.html'), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Constant-time check against ADMIN_PASSWORD_HASH or ADMIN_PASSWORD
        if verify_credentials(username, password):
            # Drop every value carried by the pre-authentication session
            # (including the CSRF token) so a session fixed by an attacker
            # cannot be promoted to an authenticated one. A fresh CSRF token
            # is generated on the next render.
            session.clear()
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            flash('Successfully logged in!', 'success')
            logger.info(f"User '{username}' logged in successfully from IP {client_ip}")
            return redirect(url_for('whitelist'))
        else:
            # Security: Record failed attempt
            record_login_attempt(client_ip)
            flash('Invalid username or password.', 'danger')
            logger.warning(f"Failed login attempt for username '{username}' from IP {client_ip}")

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout handler"""
    username = session.get('username', 'unknown')
    session.clear()
    flash('You have been logged out.', 'info')
    logger.info(f"User '{username}' logged out")
    return redirect(url_for('login'))


@app.route('/whitelist', methods=['GET', 'POST'])
@login_required
def whitelist():
    """Whitelist management page"""
    if request.method == 'POST':
        # Security: Validate CSRF token
        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            flash('Security Error: Invalid CSRF token. Please try again.', 'danger')
            logger.warning(f"Whitelist operation with invalid CSRF token from user '{session.get('username')}'")
            abort(403)

        action = request.form.get('action')

        if action == 'add':
            # Add new domain/URL to whitelist
            new_entry = request.form.get('new_entry', '').strip()

            if not new_entry:
                flash('Please enter a domain or URL.', 'warning')
            elif '\n' in new_entry or '\r' in new_entry:
                flash('Only one domain per entry allowed.', 'danger')
            # Security: Validate domain input format
            elif not validate_domain_input(new_entry):
                flash('Invalid domain format. Please enter a valid domain (e.g., example.com or .example.com for wildcards).', 'danger')
                logger.warning(f"User '{session['username']}' attempted to add invalid domain format: '{new_entry}'")
            else:
                try:
                    # Read current whitelist
                    current_list = read_whitelist()

                    # Normalize current entries to separate exact and wildcard
                    current_exact, current_wildcard = normalize_whitelist_entries(current_list)

                    # Check coverage and duplication status
                    coverage_info = entry_coverage(new_entry, current_exact, current_wildcard)

                    if coverage_info['type'] == 'invalid':
                        flash('Invalid entry. Please enter a valid domain or URL.', 'danger')
                        logger.warning(f"User '{session['username']}' attempted to add invalid entry '{new_entry}'")

                    elif coverage_info['type'] == 'exact':
                        # Adding exact entry
                        exact_value = coverage_info['value']

                        # Check for exact duplicate
                        if exact_value in current_exact:
                            flash(f'Exact entry "{exact_value}" already exists in whitelist.', 'warning')
                            logger.info(f"User '{session['username']}' attempted to add duplicate exact entry '{new_entry}'")
                        # Check if covered by existing wildcard
                        elif coverage_info['covered_by_wildcard']:
                            flash(f'Entry "{exact_value}" is already covered by an existing wildcard entry. Not added.', 'info')
                            logger.info(f"User '{session['username']}' attempted to add exact entry '{new_entry}' covered by wildcard")
                        else:
                            # Add exact entry
                            current_list.append(new_entry)
                            write_whitelist(current_list)

                            # Reload Squid configuration
                            success, message = reload_squid()
                            if success:
                                flash(f'Added exact entry "{exact_value}" to whitelist (matches ONLY this domain, not subdomains). Squid reloaded.', 'success')
                                logger.info(f"User '{session['username']}' added exact entry '{new_entry}' to whitelist")
                            else:
                                flash(f'Added "{exact_value}" but Squid reload failed: {message}', 'warning')
                                logger.error(f"Squid reload failed: {message}")

                    elif coverage_info['type'] == 'wildcard':
                        # Adding wildcard entry
                        wildcard_value = coverage_info['value']

                        # Check for wildcard duplicate
                        if coverage_info['duplicate']:
                            flash(f'Wildcard entry "{wildcard_value}" already exists in whitelist.', 'warning')
                            logger.info(f"User '{session['username']}' attempted to add duplicate wildcard entry '{new_entry}'")
                        else:
                            # Check which exact entries will be removed due to conflict
                            # (write_whitelist will filter them, but we want to inform the user)
                            temp_exact, temp_wild = normalize_whitelist_entries(current_list + [new_entry])
                            filtered_exact, _ = filter_conflicts(temp_exact, temp_wild)
                            removed_count = len(temp_exact) - len(filtered_exact)

                            # Add wildcard entry
                            current_list.append(new_entry)
                            write_whitelist(current_list)

                            # Reload Squid configuration
                            success, message = reload_squid()

                            # Build success message with coverage/removal info
                            if removed_count > 0:
                                success_msg = f'Added wildcard "{wildcard_value}" (matches apex AND subdomains). Removed {removed_count} conflicting exact entry/entries to prevent Squid errors.'
                            else:
                                success_msg = f'Added wildcard entry "{wildcard_value}" to whitelist (matches apex AND all subdomains). Squid reloaded.'

                            if success:
                                flash(success_msg, 'success')
                                logger.info(f"User '{session['username']}' added wildcard entry '{new_entry}' to whitelist (removed {removed_count} conflicting exacts)")
                            else:
                                flash(f'Added "{wildcard_value}" but Squid reload failed: {message}', 'warning')
                                logger.error(f"Squid reload failed: {message}")

                except Exception as e:
                    flash(f'Error adding entry: {str(e)}', 'danger')
                    logger.error(f"Error adding whitelist entry: {str(e)}", exc_info=True)

        elif action == 'remove':
            # Remove selected entries from whitelist
            entries_to_remove = request.form.getlist('remove_entries')

            if not entries_to_remove:
                flash('No entries selected for removal.', 'warning')
            else:
                try:
                    # Read current whitelist
                    current_list = read_whitelist()

                    # Remove selected entries
                    updated_list = [entry for entry in current_list if entry not in entries_to_remove]

                    # Write updated list
                    write_whitelist(updated_list)

                    # Reload Squid configuration
                    success, message = reload_squid()
                    if success:
                        flash(f'Removed {len(entries_to_remove)} entry/entries and reloaded Squid.', 'success')
                        logger.info(f"User '{session['username']}' removed {len(entries_to_remove)} entries from whitelist")
                    else:
                        flash(f'Removed entries but Squid reload failed: {message}', 'warning')
                        logger.error(f"Squid reload failed: {message}")

                except Exception as e:
                    flash(f'Error removing entries: {str(e)}', 'danger')
                    logger.error(f"Error removing whitelist entries: {str(e)}", exc_info=True)

        return redirect(url_for('whitelist'))

    # GET request - display current whitelist
    try:
        whitelist_entries = read_whitelist()
    except Exception as e:
        flash(f'Error reading whitelist: {str(e)}', 'danger')
        whitelist_entries = []
        logger.error(f"Error reading whitelist: {str(e)}", exc_info=True)

    return render_template('whitelist.html', entries=whitelist_entries)


@app.route('/logging', methods=['GET', 'POST'])
@login_required
def logging_config():
    """Logging configuration page"""
    if request.method == 'POST':
        # Security: Validate CSRF token
        csrf_token = request.form.get('csrf_token', '')
        if not validate_csrf_token(csrf_token):
            flash('Security Error: Invalid CSRF token. Please try again.', 'danger')
            logger.warning(f"Logging config change with invalid CSRF token from user '{session.get('username')}'")
            abort(403)

        try:
            # Get form data
            logging_mode = request.form.get('logging_mode', 'local_file')
            syslog_host = request.form.get('syslog_host', '').strip()
            syslog_port = request.form.get('syslog_port', '514').strip()
            syslog_protocol = request.form.get('syslog_protocol', 'udp')
            dns_nameservers_input = request.form.get('dns_nameservers', '').strip()

            # Validate syslog settings if mode is remote_syslog
            if logging_mode == 'remote_syslog':
                if not syslog_host:
                    flash('Syslog host is required for remote syslog mode.', 'danger')
                    return redirect(url_for('logging_config'))

                try:
                    port_int = int(syslog_port)
                    if port_int < 1 or port_int > 65535:
                        raise ValueError("Port out of range")
                except ValueError:
                    flash('Syslog port must be a valid number between 1 and 65535.', 'danger')
                    return redirect(url_for('logging_config'))

            # Parse and validate DNS nameservers
            dns_nameservers = []
            if dns_nameservers_input:
                # Split on spaces or commas
                raw_nameservers = re.split(r'[,\s]+', dns_nameservers_input)
                # Filter and validate
                import ipaddress
                for ns in raw_nameservers:
                    ns = ns.strip()
                    if not ns:
                        continue
                    try:
                        # Validate IPv4 or IPv6 address
                        ipaddress.ip_address(ns)
                        dns_nameservers.append(ns)
                        if len(dns_nameservers) >= 4:
                            break  # Limit to 4 nameservers
                    except ValueError:
                        logger.warning(f"Invalid DNS nameserver '{ns}' ignored")

            # Use defaults if no valid nameservers provided
            if not dns_nameservers:
                dns_nameservers = ['1.1.1.1', '8.8.8.8']
                logger.info("No valid DNS nameservers provided, using defaults")

            # Build config dictionary
            config = {
                'logging': {
                    'mode': logging_mode,
                    'syslog_host': syslog_host,
                    'syslog_port': syslog_port,
                    'syslog_protocol': syslog_protocol
                },
                'dns': {
                    'nameservers': dns_nameservers
                }
            }

            # Write configuration
            write_logging_config(config)

            # Regenerate Squid configuration with new logging settings
            success, message = regenerate_squid_config(config)
            if not success:
                flash(f'Configuration saved but Squid config regeneration failed: {message}', 'warning')
                logger.error(f"Squid config regeneration failed: {message}")
                return redirect(url_for('logging_config'))

            # Reload Squid
            success, message = reload_squid()
            if success:
                flash('Logging configuration updated and Squid reloaded successfully.', 'success')
                logger.info(f"User '{session['username']}' updated logging configuration to mode '{logging_mode}'")
            else:
                flash(f'Configuration updated but Squid reload failed: {message}', 'warning')
                logger.error(f"Squid reload failed: {message}")

        except Exception as e:
            flash(f'Error updating logging configuration: {str(e)}', 'danger')
            logger.error(f"Error updating logging config: {str(e)}", exc_info=True)

        return redirect(url_for('logging_config'))

    # GET request - display current configuration
    try:
        config = read_logging_config()
    except Exception as e:
        flash(f'Error reading logging configuration: {str(e)}', 'danger')
        logger.error(f"Error reading logging config: {str(e)}", exc_info=True)
        config = {
            'logging': {
                'mode': 'local_file',
                'syslog_host': '',
                'syslog_port': '514',
                'syslog_protocol': 'udp'
            },
            'dns': {
                'nameservers': ['1.1.1.1', '8.8.8.8']
            }
        }

    return render_template('logging.html', config=config)


@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    return {'status': 'ok'}, 200


@app.route('/api/logs')
@login_required
def api_logs():
    """
    API endpoint for retrieving log file contents with cursor support.

    Query Parameters:
        file: 'access' or 'cache' - which log file to read
        lines: optional int (default 100, max 500) - number of lines to return
        cursor: optional int - byte offset for incremental reads

    Returns:
        JSON response with:
        - lines: List of log lines
        - cursor: Current byte offset for next request
        - file: Which log file was read
        - error: Error message if applicable
    """
    try:
        # Parse query parameters
        file_param = request.args.get('file', 'access').strip().lower()
        lines_param = request.args.get('lines', '100')
        cursor_param = request.args.get('cursor', None)

        # Validate file parameter (whitelist only 'access' or 'cache')
        if file_param not in ['access', 'cache']:
            return {
                'error': 'Invalid file parameter. Must be "access" or "cache".',
                'lines': [],
                'cursor': 0,
                'file': file_param
            }, 400

        # Parse and validate lines parameter
        try:
            lines = int(lines_param)
            lines = min(max(1, lines), 500)  # Clamp between 1 and 500
        except ValueError:
            return {
                'error': 'Invalid lines parameter. Must be an integer.',
                'lines': [],
                'cursor': 0,
                'file': file_param
            }, 400

        # Parse cursor parameter
        cursor = None
        if cursor_param is not None:
            try:
                cursor = int(cursor_param)
            except ValueError:
                return {
                    'error': 'Invalid cursor parameter. Must be an integer.',
                    'lines': [],
                    'cursor': 0,
                    'file': file_param
                }, 400

        # Read logging configuration
        config = read_logging_config()
        logging_mode = config.get('logging', {}).get('mode', 'local_file')

        # Check if logging mode is local_file
        if logging_mode != 'local_file':
            return {
                'error': 'Log viewer is only available when logging mode is "local_file".',
                'lines': [],
                'cursor': 0,
                'file': file_param
            }, 400

        # Map file parameter to actual log path from config
        if file_param == 'access':
            log_path = config.get('logging', {}).get('access_log_path', '/var/log/squid/access.log')
        else:  # cache
            log_path = config.get('logging', {}).get('cache_log_path', '/var/log/squid/cache.log')

        # Call tail_log helper
        result = tail_log(log_path, max_lines=lines, cursor=cursor)

        # Add file parameter to response
        result['file'] = file_param

        # Return successful response
        if 'error' in result:
            return result, 500
        else:
            return result, 200

    except Exception as e:
        logger.error(f"Error in /api/logs endpoint: {str(e)}", exc_info=True)
        return {
            'error': f'Internal server error: {str(e)}',
            'lines': [],
            'cursor': 0,
            'file': file_param if 'file_param' in locals() else 'unknown'
        }, 500


if __name__ == '__main__':
    # Development server (use gunicorn in production)
    app.run(host='0.0.0.0', port=8080, debug=False)
