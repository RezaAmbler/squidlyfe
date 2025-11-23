"""
Squid Whitelist Proxy - Web UI Application
Provides a web interface for managing Squid proxy whitelist and logging configuration.
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from functools import wraps
import os
import logging
import secrets
import hmac
import hashlib
import re
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

# Simple rate limiting for login attempts (in-memory)
login_attempts = defaultdict(list)
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300  # 5 minutes


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

# Security: Configure secure session cookies
# SESSION_COOKIE_SECURE requires HTTPS; set to False if TLS termination is external
# Override with DISABLE_SECURE_COOKIES env var for development only
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('DISABLE_SECURE_COOKIES', '').lower() != 'true'

if not app.config['SESSION_COOKIE_SECURE']:
    logger.warning("SESSION_COOKIE_SECURE is disabled. Enable HTTPS/TLS termination for production.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


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


# Security: Check if default password is in use
def is_using_default_password():
    """Check if the admin password is still set to the default 'changeme'"""
    admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')
    return admin_password == 'changeme'


# Security: Rate limiting for login attempts
def check_rate_limit(ip_address: str) -> bool:
    """
    Check if IP address has exceeded login attempt rate limit.

    Args:
        ip_address: Client IP address

    Returns:
        True if under limit, False if rate limited
    """
    now = time.time()

    # Clean old attempts
    login_attempts[ip_address] = [
        attempt_time for attempt_time in login_attempts[ip_address]
        if now - attempt_time < RATE_LIMIT_WINDOW
    ]

    # Check if limit exceeded
    if len(login_attempts[ip_address]) >= MAX_LOGIN_ATTEMPTS:
        return False

    return True


def record_login_attempt(ip_address: str):
    """Record a failed login attempt"""
    login_attempts[ip_address].append(time.time())


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

        # Get credentials from environment variables
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'changeme')

        if username == admin_username and password == admin_password:
            session['logged_in'] = True
            session['username'] = username
            # Regenerate session ID to prevent session fixation
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

            # Build config dictionary
            config = {
                'logging': {
                    'mode': logging_mode,
                    'syslog_host': syslog_host,
                    'syslog_port': syslog_port,
                    'syslog_protocol': syslog_protocol
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
