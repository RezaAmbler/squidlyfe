"""
Configuration Loader
Loads configuration from environment variables and config files.
"""

import os
import logging

logger = logging.getLogger(__name__)


def load_config():
    """
    Load application configuration from environment variables.

    Returns:
        Dictionary with configuration values
    """
    config = {
        'admin_username': os.environ.get('ADMIN_USERNAME', 'admin'),
        'admin_password': os.environ.get('ADMIN_PASSWORD', 'changeme'),
        'secret_key': os.environ.get('SECRET_KEY', os.urandom(24)),
        'whitelist_path': os.environ.get('WHITELIST_PATH', '/etc/squid/whitelist.txt'),
        'config_path': os.environ.get('CONFIG_PATH', '/data/config.yaml'),
        'data_dir': os.environ.get('DATA_DIR', '/data'),
    }

    # Warn if using default password
    if config['admin_password'] == 'changeme':
        logger.warning("="*60)
        logger.warning("WARNING: Using default admin password 'changeme'!")
        logger.warning("Please set ADMIN_PASSWORD environment variable to a secure password!")
        logger.warning("="*60)

    return config


def get_admin_credentials():
    """
    Get admin username and password from environment.

    Returns:
        Tuple of (username, password)
    """
    username = os.environ.get('ADMIN_USERNAME', 'admin')
    password = os.environ.get('ADMIN_PASSWORD', 'changeme')

    return username, password
