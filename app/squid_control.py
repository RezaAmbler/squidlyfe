"""
Squid Control Module
Handles reading/writing whitelist, reloading Squid, and managing configuration.
"""

import os
import subprocess
import tempfile
import shutil
import logging
from typing import List, Tuple, Dict, Any

logger = logging.getLogger(__name__)

# File paths
WHITELIST_PATH = os.environ.get('WHITELIST_PATH', '/etc/squid/whitelist.txt')
CONFIG_PATH = os.environ.get('CONFIG_PATH', '/data/config.yaml')
SQUID_CONFIG_PATH = '/etc/squid/squid.conf'
SQUID_CONFIG_TEMPLATE = '/etc/squid/squid.conf.template'


def read_whitelist() -> List[str]:
    """
    Read the whitelist file and return list of domains/URLs.

    Returns:
        List of whitelist entries (non-empty, stripped lines)
    """
    try:
        if not os.path.exists(WHITELIST_PATH):
            logger.warning(f"Whitelist file not found at {WHITELIST_PATH}, returning empty list")
            return []

        with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # Filter out empty lines and comments, strip whitespace
        entries = []
        for line in lines:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                entries.append(line)

        logger.debug(f"Read {len(entries)} entries from whitelist")
        return entries

    except Exception as e:
        logger.error(f"Error reading whitelist: {str(e)}", exc_info=True)
        raise


def normalize_whitelist_entries(raw_entries: List[str]) -> Tuple[List[str], List[str]]:
    """
    Normalize whitelist entries into exact and wildcard lists.

    Exact entries (e.g., 'example.com') match ONLY that specific domain.
    Wildcard entries (e.g., '*.example.com' or '.example.com') match both
    the apex domain AND all subdomains.

    This function preserves user intent: bare domains stay exact, wildcard
    prefixes create wildcard entries. NO auto-broadening.

    Args:
        raw_entries: Raw list of domain/URL strings

    Returns:
        Tuple of (exact_entries, wildcard_entries) where wildcard entries
        are in canonical dotted format (.example.com)

    Examples:
        >>> normalize_whitelist_entries(['example.com'])
        (['example.com'], [])

        >>> normalize_whitelist_entries(['*.example.com'])
        ([], ['.example.com'])

        >>> normalize_whitelist_entries(['.example.com'])
        ([], ['.example.com'])

        >>> normalize_whitelist_entries(['example.com', '*.github.com'])
        (['example.com'], ['.github.com'])

    Note:
        In Squid's dstdomain ACL:
        - 'example.com' matches ONLY 'example.com' (exact)
        - '.example.com' matches both 'example.com' AND '*.example.com' (wildcard)
        Exact and wildcard entries are NOT duplicates of each other.
    """
    exact = []
    wildcard = []
    exact_set = set()
    wildcard_set = set()

    for raw in raw_entries:
        if not raw:
            continue

        entry = raw.strip()

        # Skip empty lines and comments
        if not entry or entry.startswith('#'):
            continue

        # Strip scheme prefixes (http://, https://)
        for prefix in ['https://', 'http://']:
            if entry.lower().startswith(prefix):
                entry = entry.split('://', 1)[1]
                break

        # Strip paths (but preserve domain)
        if '/' in entry:
            entry = entry.split('/', 1)[0]

        # Skip if we ended up with an empty entry
        if not entry:
            continue

        # Determine if wildcard or exact
        is_wildcard = entry.startswith('*.') or entry.startswith('.')

        if is_wildcard:
            # Wildcard entry: normalize to canonical dotted format
            base = entry.lstrip('*.')
            if not base:
                continue
            canonical = f'.{base}'

            if canonical not in wildcard_set:
                wildcard_set.add(canonical)
                wildcard.append(canonical)
        else:
            # Exact entry: keep as-is (no auto-broadening)
            if entry not in exact_set:
                exact_set.add(entry)
                exact.append(entry)

    return exact, wildcard


def entry_coverage(new_entry: str, existing_exact: List[str], existing_wildcard: List[str]) -> Dict[str, Any]:
    """
    Check coverage and duplication status of a new whitelist entry.

    Args:
        new_entry: The new entry to check
        existing_exact: List of existing exact entries
        existing_wildcard: List of existing wildcard entries (dotted format)

    Returns:
        Dictionary with keys:
        - 'type': 'exact', 'wildcard', or 'invalid'
        - 'value': The normalized value
        - 'covered_by_wildcard': (exact only) True if covered by existing wildcard
        - 'duplicate': (wildcard only) True if wildcard already exists
        - 'covers_exacts': (wildcard only) List of existing exact entries that would be covered

    Examples:
        >>> entry_coverage('example.com', [], ['.example.com'])
        {'type': 'exact', 'value': 'example.com', 'covered_by_wildcard': True}

        >>> entry_coverage('*.github.com', ['api.github.com'], [])
        {'type': 'wildcard', 'value': '.github.com', 'duplicate': False, 'covers_exacts': ['api.github.com']}
    """
    exact, wildcard = normalize_whitelist_entries([new_entry])

    if exact:
        host = exact[0]
        # Check if this exact entry is covered by any existing wildcard
        # A wildcard .example.com covers both example.com and *.example.com
        covered = False
        for wild in existing_wildcard:
            wild_domain = wild.lstrip('.')
            # Check if host matches the wildcard domain or is a subdomain of it
            if host == wild_domain or host.endswith(f'.{wild_domain}'):
                covered = True
                break

        return {
            'type': 'exact',
            'value': host,
            'covered_by_wildcard': covered
        }

    elif wildcard:
        canon = wildcard[0]
        wild_domain = canon.lstrip('.')

        # Check for duplicate wildcard
        duplicate = canon in existing_wildcard

        # Find existing exact entries that this wildcard would cover
        covered_exacts = []
        for exact_entry in existing_exact:
            # Wildcard .example.com covers example.com and *.example.com
            if exact_entry == wild_domain or exact_entry.endswith(f'.{wild_domain}'):
                covered_exacts.append(exact_entry)

        return {
            'type': 'wildcard',
            'value': canon,
            'duplicate': duplicate,
            'covers_exacts': covered_exacts
        }

    return {'type': 'invalid'}


def filter_conflicts(exact_entries: List[str], wildcard_entries: List[str]) -> Tuple[List[str], List[str]]:
    """
    Remove exact entries that are covered by wildcard entries to avoid Squid conflicts.

    Squid 5.7+ rejects dstdomain ACLs where both an exact domain and a wildcard
    covering it exist (e.g., 'example.com' and '.example.com'). Wildcards supersede
    exact entries.

    Args:
        exact_entries: List of exact domain entries
        wildcard_entries: List of wildcard entries in dotted format (e.g., '.example.com')

    Returns:
        Tuple of (filtered_exact_entries, wildcard_entries) where exact entries
        covered by any wildcard are removed

    Examples:
        >>> filter_conflicts(['microsoft.com'], ['.microsoft.com'])
        ([], ['.microsoft.com'])

        >>> filter_conflicts(['api.github.com', 'example.com'], ['.github.com'])
        (['example.com'], ['.github.com'])
    """
    if not wildcard_entries:
        # No wildcards, no conflicts
        return exact_entries, wildcard_entries

    filtered_exact = []
    removed_exacts = []

    for exact_entry in exact_entries:
        covered = False
        for wildcard in wildcard_entries:
            wild_domain = wildcard.lstrip('.')
            # Check if exact matches apex or is subdomain of wildcard
            if exact_entry == wild_domain or exact_entry.endswith(f'.{wild_domain}'):
                covered = True
                removed_exacts.append(exact_entry)
                break

        if not covered:
            filtered_exact.append(exact_entry)

    if removed_exacts:
        logger.info(f"Removed {len(removed_exacts)} exact entries covered by wildcards: {removed_exacts}")

    return filtered_exact, wildcard_entries


def write_whitelist(entries: List[str]) -> None:
    """
    Write whitelist entries to file safely (atomic write with temp file).

    Preserves user intent: exact entries stay exact, wildcard entries are
    normalized to canonical dotted format. NO auto-broadening.

    Automatically removes exact entries covered by wildcards to prevent Squid
    ACL conflicts (e.g., 'example.com' + '.example.com' causes parse errors).

    Args:
        entries: List of domain/URL strings to write
    """
    try:
        # Normalize entries into exact and wildcard lists
        exact_entries, wildcard_entries = normalize_whitelist_entries(entries)

        # Filter out exact entries covered by wildcards to avoid Squid conflicts
        exact_entries, wildcard_entries = filter_conflicts(exact_entries, wildcard_entries)

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)

        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(WHITELIST_PATH),
            prefix='.whitelist_tmp_',
            text=True
        )

        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                # Write header comment
                f.write("# Squid Whitelist - Allowed Domains/URLs\n")
                f.write("# This file is managed by the Squid Proxy Web UI\n")
                f.write("#\n")
                f.write("# Entry Types:\n")
                f.write("#   example.com     - EXACT: Matches ONLY example.com (not subdomains)\n")
                f.write("#   .example.com    - WILDCARD: Matches BOTH example.com AND *.example.com\n")
                f.write("#   *.example.com   - WILDCARD: Normalized to .example.com\n")
                f.write("#\n")
                f.write("# Notes:\n")
                f.write("#   - Exact and wildcard are distinct entry types (not duplicates)\n")
                f.write("#   - Normalization strips: http://, https://, paths\n")
                f.write("#   - NO auto-broadening: bare domains stay exact unless you add wildcard\n")
                f.write("#   - Duplicates within same type are automatically removed\n\n")

                # Write exact entries first
                for entry in exact_entries:
                    f.write(f"{entry}\n")

                # Write wildcard entries (canonical dotted format)
                for entry in wildcard_entries:
                    f.write(f"{entry}\n")

            # Atomic move (replaces old file)
            shutil.move(temp_path, WHITELIST_PATH)

            # Set appropriate permissions (readable by squid)
            os.chmod(WHITELIST_PATH, 0o644)

            total_entries = len(exact_entries) + len(wildcard_entries)
            logger.info(f"Successfully wrote {total_entries} entries to whitelist ({len(exact_entries)} exact, {len(wildcard_entries)} wildcard)")

        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    except Exception as e:
        logger.error(f"Error writing whitelist: {str(e)}", exc_info=True)
        raise


def reload_squid() -> Tuple[bool, str]:
    """
    Reload Squid configuration without restarting the process.

    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        # Use 'squid -k reconfigure' to reload config
        result = subprocess.run(
            ['squid', '-k', 'reconfigure'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            logger.info("Squid reloaded successfully")
            return True, "Squid configuration reloaded successfully"
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            logger.error(f"Squid reload failed with return code {result.returncode}: {error_msg}")
            return False, f"Reload failed: {error_msg}"

    except subprocess.TimeoutExpired:
        logger.error("Squid reload timed out after 10 seconds")
        return False, "Reload command timed out"

    except FileNotFoundError:
        logger.error("Squid executable not found")
        return False, "Squid executable not found on system"

    except Exception as e:
        logger.error(f"Error reloading Squid: {str(e)}", exc_info=True)
        return False, f"Error: {str(e)}"


def read_logging_config() -> Dict[str, Any]:
    """
    Read logging configuration from YAML config file.

    Returns:
        Configuration dictionary with logging settings
    """
    try:
        import yaml

        if not os.path.exists(CONFIG_PATH):
            logger.warning(f"Config file not found at {CONFIG_PATH}, using defaults")
            return get_default_logging_config()

        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        # Ensure logging section exists
        if not config or 'logging' not in config:
            logger.warning("No logging section in config, using defaults")
            return get_default_logging_config()

        # Merge with defaults to ensure all keys exist
        default = get_default_logging_config()
        for key, value in default['logging'].items():
            if key not in config['logging']:
                config['logging'][key] = value

        logger.debug("Successfully read logging configuration")
        return config

    except Exception as e:
        logger.error(f"Error reading logging config: {str(e)}", exc_info=True)
        return get_default_logging_config()


def write_logging_config(config: Dict[str, Any]) -> None:
    """
    Write logging configuration to YAML config file.

    Args:
        config: Configuration dictionary with logging settings
    """
    try:
        import yaml

        # Ensure parent directory exists
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(CONFIG_PATH),
            prefix='.config_tmp_',
            suffix='.yaml',
            text=True
        )

        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

            # Atomic move
            shutil.move(temp_path, CONFIG_PATH)

            # Set appropriate permissions
            os.chmod(CONFIG_PATH, 0o644)

            logger.info("Successfully wrote logging configuration")

        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    except Exception as e:
        logger.error(f"Error writing logging config: {str(e)}", exc_info=True)
        raise


def get_default_logging_config() -> Dict[str, Any]:
    """
    Get default logging configuration.

    Returns:
        Default configuration dictionary
    """
    return {
        'logging': {
            'mode': 'local_file',
            'syslog_host': '',
            'syslog_port': '514',
            'syslog_protocol': 'udp',
            'access_log_path': '/var/log/squid/access.log',
            'cache_log_path': '/var/log/squid/cache.log'
        }
    }


def regenerate_squid_config(config: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Regenerate Squid configuration from template with current settings.

    Args:
        config: Configuration dictionary with logging settings

    Returns:
        Tuple of (success: bool, message: str)
    """
    try:
        if not os.path.exists(SQUID_CONFIG_TEMPLATE):
            logger.error(f"Squid config template not found at {SQUID_CONFIG_TEMPLATE}")
            return False, "Squid config template not found"

        # Read template
        with open(SQUID_CONFIG_TEMPLATE, 'r', encoding='utf-8') as f:
            template = f.read()

        # Get logging settings
        logging_config = config.get('logging', {})
        mode = logging_config.get('mode', 'local_file')
        syslog_host = logging_config.get('syslog_host', '')
        syslog_port = logging_config.get('syslog_port', '514')
        syslog_protocol = logging_config.get('syslog_protocol', 'udp')

        # Build logging configuration based on mode
        if mode == 'stdout':
            log_config = "access_log stdio:/dev/stdout squid"
        elif mode == 'remote_syslog':
            # Note: Squid doesn't natively support syslog, so we log to stdout
            # and document that an external log shipper should forward to syslog
            log_config = f"""# Remote syslog mode: logs to stdout (use external log shipper to forward)
# Target: {syslog_protocol}://{syslog_host}:{syslog_port}
access_log stdio:/dev/stdout squid"""
        else:  # local_file
            log_config = "access_log /var/log/squid/access.log squid"

        # Substitute template variables
        squid_config = template.replace('{{LOGGING_CONFIG}}', log_config)
        squid_config = squid_config.replace('{{WHITELIST_PATH}}', WHITELIST_PATH)

        # Write to temporary file first
        temp_fd, temp_path = tempfile.mkstemp(
            dir=os.path.dirname(SQUID_CONFIG_PATH),
            prefix='.squid_conf_tmp_',
            text=True
        )

        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                f.write(squid_config)

            # Atomic move
            shutil.move(temp_path, SQUID_CONFIG_PATH)

            # Set appropriate permissions
            os.chmod(SQUID_CONFIG_PATH, 0o644)

            logger.info(f"Successfully regenerated Squid config with logging mode: {mode}")
            return True, "Squid configuration regenerated successfully"

        except Exception as e:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

    except Exception as e:
        logger.error(f"Error regenerating Squid config: {str(e)}", exc_info=True)
        return False, f"Error: {str(e)}"


def verify_squid_config() -> Tuple[bool, str]:
    """
    Verify Squid configuration syntax.

    Returns:
        Tuple of (valid: bool, message: str)
    """
    try:
        result = subprocess.run(
            ['squid', '-k', 'parse'],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            logger.info("Squid configuration is valid")
            return True, "Configuration is valid"
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            logger.error(f"Squid config validation failed: {error_msg}")
            return False, f"Invalid configuration: {error_msg}"

    except subprocess.TimeoutExpired:
        logger.error("Squid config validation timed out")
        return False, "Validation timed out"

    except Exception as e:
        logger.error(f"Error verifying Squid config: {str(e)}", exc_info=True)
        return False, f"Error: {str(e)}"


def tail_log(log_path: str, max_lines: int = 100, cursor: int = None) -> Dict[str, Any]:
    """
    Read the tail of a log file with cursor support for incremental fetching.

    Args:
        log_path: Path to the log file
        max_lines: Maximum number of lines to return (clamped to 500)
        cursor: Optional byte offset for incremental reads (None = read from tail)

    Returns:
        Dictionary with:
        - 'lines': List of log lines
        - 'cursor': New cursor position (byte offset)
        - 'error': Error message if file cannot be read

    Examples:
        >>> tail_log('/var/log/squid/access.log', max_lines=50)
        {'lines': [...], 'cursor': 12345}

        >>> tail_log('/var/log/squid/access.log', cursor=12345)
        {'lines': [...], 'cursor': 12400}
    """
    # Clamp max_lines
    max_lines = min(max(1, max_lines), 500)

    try:
        # Check if file exists
        if not os.path.exists(log_path):
            logger.warning(f"Log file not found: {log_path}")
            return {'lines': [], 'cursor': 0, 'error': f'Log file not found: {log_path}'}

        # Get file size
        file_size = os.path.getsize(log_path)

        # If file is empty
        if file_size == 0:
            return {'lines': [], 'cursor': 0}

        with open(log_path, 'rb') as f:
            if cursor is None:
                # Initial read: get last N lines
                # Read from tail
                lines = []
                chunk_size = 8192
                f.seek(0, 2)  # Seek to end
                remaining_bytes = f.tell()

                while remaining_bytes > 0 and len(lines) < max_lines:
                    # Read chunk from current position backwards
                    chunk_size = min(chunk_size, remaining_bytes)
                    f.seek(remaining_bytes - chunk_size)
                    chunk = f.read(chunk_size)
                    remaining_bytes -= chunk_size

                    # Decode and split into lines
                    try:
                        text = chunk.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        text = chunk.decode('latin-1', errors='replace')

                    chunk_lines = text.split('\n')
                    lines = chunk_lines + lines

                    # If we have enough lines, stop
                    if len(lines) >= max_lines + 1:  # +1 because first might be partial
                        break

                # Clean up: remove empty lines, take last N
                lines = [line for line in lines if line.strip()]
                lines = lines[-max_lines:]

                # Set cursor to end of file
                new_cursor = file_size

            else:
                # Incremental read: read from cursor position
                # Handle log rotation: if cursor > file_size, reset to tail
                if cursor > file_size:
                    logger.info(f"Log rotation detected for {log_path}: cursor {cursor} > size {file_size}, resetting to tail")
                    # Start from beginning or tail, depending on file size
                    if file_size < 100000:  # Small file, read from beginning
                        f.seek(0)
                    else:
                        # Large file, read last max_lines
                        return tail_log(log_path, max_lines=max_lines, cursor=None)
                else:
                    f.seek(cursor)

                # Read new content
                new_content = f.read()

                # Decode
                try:
                    text = new_content.decode('utf-8', errors='replace')
                except UnicodeDecodeError:
                    text = new_content.decode('latin-1', errors='replace')

                # Split into lines
                lines = text.split('\n')

                # Remove last empty line if present (incomplete line)
                if lines and not lines[-1].strip():
                    lines = lines[:-1]

                # Limit to max_lines
                lines = lines[-max_lines:]

                # Set new cursor
                new_cursor = f.tell()

        logger.debug(f"Tailed {len(lines)} lines from {log_path}, cursor: {new_cursor}")
        return {'lines': lines, 'cursor': new_cursor}

    except PermissionError:
        logger.error(f"Permission denied reading log file: {log_path}")
        return {'lines': [], 'cursor': 0, 'error': f'Permission denied: {log_path}'}

    except Exception as e:
        logger.error(f"Error reading log file {log_path}: {str(e)}", exc_info=True)
        return {'lines': [], 'cursor': 0, 'error': f'Error reading log: {str(e)}'}
