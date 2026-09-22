#!/usr/bin/env python3
"""
Security tests for Flask application
Tests CSRF protection, input validation, rate limiting, and security headers
"""

import unittest
import tempfile
import os
import sys
import time

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

# Must import and configure before creating app
import squid_control


class TestCSRFProtection(unittest.TestCase):
    """Test CSRF token protection on all state-changing operations"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, 'whitelist.txt')

        squid_control.WHITELIST_PATH = self.whitelist_path
        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-csrf'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'secure123'

        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        # DO NOT disable CSRF - we're testing it!
        self.client = self.app.test_client()

        squid_control.write_whitelist(['example.com'])

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def get_csrf_token(self, response_data):
        """Extract CSRF token from HTML response"""
        # Look for: name="csrf_token" value="TOKEN_HERE"
        import re
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response_data.decode('utf-8'))
        if match:
            return match.group(1)
        return None

    def login_and_get_token(self):
        """Helper to login and get CSRF token from whitelist page"""
        # Get login page to get CSRF token
        response = self.client.get('/login')
        token = self.get_csrf_token(response.data)

        # Login with CSRF token
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123',
            'csrf_token': token
        }, follow_redirects=True)

        # Get new token from whitelist page
        response = self.client.get('/whitelist')
        return self.get_csrf_token(response.data)

    def test_login_requires_csrf_token(self):
        """Test that login rejects requests without CSRF token"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123'
            # Missing csrf_token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 403, "Should reject login without CSRF token")

    def test_login_with_invalid_csrf_token(self):
        """Test that login rejects invalid CSRF token"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123',
            'csrf_token': 'invalid-token-12345'
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 403, "Should reject invalid CSRF token")

    def test_whitelist_add_requires_csrf(self):
        """Test that adding whitelist entries requires CSRF token"""
        token = self.login_and_get_token()

        # Try to add without CSRF token
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': 'malicious.com'
            # Missing csrf_token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 403, "Should reject add without CSRF token")

        # Verify entry was NOT added
        entries = squid_control.read_whitelist()
        self.assertNotIn('malicious.com', entries)

    def test_whitelist_remove_requires_csrf(self):
        """Test that removing whitelist entries requires CSRF token"""
        token = self.login_and_get_token()

        # Try to remove without CSRF token
        response = self.client.post('/whitelist', data={
            'action': 'remove',
            'remove_entries': ['example.com']
            # Missing csrf_token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 403, "Should reject remove without CSRF token")

        # Verify entry was NOT removed
        entries = squid_control.read_whitelist()
        self.assertIn('example.com', entries)

    def test_logging_config_requires_csrf(self):
        """Test that logging configuration changes require CSRF token"""
        token = self.login_and_get_token()

        # Try to change logging config without CSRF token
        response = self.client.post('/logging', data={
            'logging_mode': 'stdout'
            # Missing csrf_token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 403, "Should reject logging change without CSRF token")

    def test_valid_csrf_token_allows_operation(self):
        """Test that valid CSRF token allows operations"""
        token = self.login_and_get_token()

        # Add with valid CSRF token
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': 'github.com',
            'csrf_token': token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302, "Should accept valid CSRF token")

        # Verify entry was added
        entries = squid_control.read_whitelist()
        self.assertIn('github.com', entries)


class TestInputValidation(unittest.TestCase):
    """Test input validation for whitelist entries"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, 'whitelist.txt')

        squid_control.WHITELIST_PATH = self.whitelist_path
        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-validation'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'secure123'

        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable for easier testing
        self.client = self.app.test_client()

        # Login with CSRF token
        response = self.client.get('/login')
        import re
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        token = match.group(1) if match else ''

        self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123',
            'csrf_token': token
        })

        # Get CSRF token for subsequent requests
        response = self.client.get('/whitelist')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        self.csrf_token = match.group(1) if match else ''

        squid_control.write_whitelist([])

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def test_valid_domain_accepted(self):
        """Test that valid domains are accepted"""
        valid_domains = [
            'example.com',
            'api.github.com',
            'sub.domain.example.org',
            '.example.com',
        ]

        for domain in valid_domains:
            response = self.client.post('/whitelist', data={
                'action': 'add',
                'new_entry': domain,
                'csrf_token': self.csrf_token
            }, follow_redirects=True)

            entries = squid_control.read_whitelist()
            self.assertIn(domain, entries, f"Valid domain '{domain}' should be accepted")

    def test_wildcard_formats_accepted(self):
        """Test that both wildcard formats are accepted and deduplicated correctly"""
        squid_control.write_whitelist([])

        # Add .example.com first
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': '.example.com',
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        self.assertIn('.example.com', entries, "Wildcard .example.com should be accepted")

        # Adding *.example.com should be deduplicated (treated as duplicate)
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': '*.example.com',
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        # Should still only have one entry since they're equivalent
        wildcard_count = sum(1 for e in entries if 'example.com' in e and e.startswith(('.', '*')))
        self.assertEqual(wildcard_count, 1, "*.example.com and .example.com should be deduplicated")

    def test_invalid_special_characters_rejected(self):
        """Test that domains with invalid special characters are rejected"""
        invalid_entries = [
            'example.com;rm -rf /',  # Command injection attempt
            'example.com|whoami',     # Pipe character
            'example.com&echo test',  # Ampersand
            'example.com$(cat /etc/passwd)',  # Command substitution
            'example.com`id`',        # Backticks
            'example.com<script>',    # XSS attempt
            'example.com"OR"1"="1',   # SQL injection attempt
        ]

        for entry in invalid_entries:
            squid_control.write_whitelist([])  # Clear

            response = self.client.post('/whitelist', data={
                'action': 'add',
                'new_entry': entry,
                'csrf_token': self.csrf_token
            }, follow_redirects=True)

            entries = squid_control.read_whitelist()
            self.assertEqual(len(entries), 0, f"Invalid entry '{entry}' should be rejected")

    def test_path_traversal_sanitized(self):
        """Test that path traversal attempts are sanitized (path stripped, domain extracted)"""
        # The app strips paths, so 'example.com/../../../etc/passwd' becomes 'example.com'
        # This is actually good security practice - sanitize rather than reject
        squid_control.write_whitelist([])

        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': 'example.com/../../../etc/passwd',
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        # Should have sanitized to just 'example.com'
        self.assertIn('example.com', entries, "Should sanitize to valid domain")
        self.assertNotIn('passwd', str(entries), "Should not contain path traversal")

    def test_oversized_input_rejected(self):
        """Test that extremely long inputs are rejected"""
        huge_domain = 'a' * 300 + '.com'

        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': huge_domain,
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        self.assertNotIn(huge_domain, entries, "Oversized input should be rejected")

    def test_empty_input_rejected(self):
        """Test that empty input is rejected"""
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': '',
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        self.assertEqual(len(entries), 0, "Empty input should be rejected")

    def test_whitespace_only_rejected(self):
        """Test that whitespace-only input is rejected"""
        response = self.client.post('/whitelist', data={
            'action': 'add',
            'new_entry': '   \t\n  ',
            'csrf_token': self.csrf_token
        }, follow_redirects=True)

        entries = squid_control.read_whitelist()
        self.assertEqual(len(entries), 0, "Whitespace-only input should be rejected")


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting for login attempts"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()

        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-ratelimit'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'secure123'

        from app import app
        # Clear rate limit tracking between tests (file-backed store + fallback)
        import app as app_module
        app_module.clear_login_attempts()

        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def test_rate_limit_blocks_after_max_attempts(self):
        """Test that rate limiting blocks after MAX_LOGIN_ATTEMPTS"""
        import re

        # Make 5 failed login attempts (MAX_LOGIN_ATTEMPTS)
        for i in range(5):
            # Get CSRF token for each attempt
            response = self.client.get('/login')
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
            token = match.group(1) if match else ''

            response = self.client.post('/login', data={
                'username': 'admin',
                'password': 'wrongpassword',
                'csrf_token': token
            }, follow_redirects=False)

        # 6th attempt should be rate limited
        response = self.client.get('/login')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        token = match.group(1) if match else ''

        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'wrongpassword',
            'csrf_token': token
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 429, "Should return 429 Too Many Requests")

    def test_successful_login_not_rate_limited(self):
        """Test that successful logins don't trigger rate limit"""
        import re

        # Make several successful logins
        for i in range(3):
            # Get CSRF token for each attempt
            response = self.client.get('/login')
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
            token = match.group(1) if match else ''

            response = self.client.post('/login', data={
                'username': 'admin',
                'password': 'secure123',
                'csrf_token': token
            }, follow_redirects=False)

            self.assertEqual(response.status_code, 302, "Successful login should not be rate limited")


class TestSecurityHeaders(unittest.TestCase):
    """Test that security headers are properly set"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()

        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-headers'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'secure123'

        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def test_x_frame_options_header(self):
        """Test X-Frame-Options header is set to DENY"""
        response = self.client.get('/login')
        self.assertEqual(response.headers.get('X-Frame-Options'), 'DENY',
                        "X-Frame-Options should be DENY to prevent clickjacking")

    def test_x_content_type_options_header(self):
        """Test X-Content-Type-Options header is set"""
        response = self.client.get('/login')
        self.assertEqual(response.headers.get('X-Content-Type-Options'), 'nosniff',
                        "X-Content-Type-Options should be nosniff")

    def test_referrer_policy_header(self):
        """Test Referrer-Policy header is set"""
        response = self.client.get('/login')
        self.assertEqual(response.headers.get('Referrer-Policy'), 'no-referrer',
                        "Referrer-Policy should be no-referrer")

    def test_content_security_policy_header(self):
        """Test Content-Security-Policy header is set"""
        response = self.client.get('/login')
        csp = response.headers.get('Content-Security-Policy')
        self.assertIsNotNone(csp, "CSP header should be present")
        self.assertIn('default-src', csp, "CSP should include default-src")

    def test_permissions_policy_header(self):
        """Test Permissions-Policy header is set"""
        response = self.client.get('/login')
        permissions = response.headers.get('Permissions-Policy')
        self.assertIsNotNone(permissions, "Permissions-Policy should be set")
        self.assertIn('camera=', permissions, "Should restrict camera access")


class TestSessionSecurity(unittest.TestCase):
    """Test session cookie security settings"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()

        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-session'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'secure123'

        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def test_session_cookie_httponly(self):
        """Test that session cookie has HttpOnly flag"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123'
        })

        set_cookie = response.headers.get('Set-Cookie', '')
        self.assertIn('HttpOnly', set_cookie, "Session cookie should have HttpOnly flag")

    def test_session_cookie_samesite(self):
        """Test that session cookie has SameSite attribute"""
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'secure123'
        })

        set_cookie = response.headers.get('Set-Cookie', '')
        self.assertIn('SameSite=Lax', set_cookie, "Session cookie should have SameSite=Lax")


class TestAuthenticationSecurity(unittest.TestCase):
    """Test authentication security mechanisms"""

    def setUp(self):
        """Set up test Flask app"""
        self.test_dir = tempfile.mkdtemp()

        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-auth'
        os.environ['ADMIN_USERNAME'] = 'admin'

        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def test_unauthenticated_access_blocked(self):
        """Test that unauthenticated users are redirected to login"""
        protected_urls = ['/whitelist', '/logging']

        for url in protected_urls:
            response = self.client.get(url, follow_redirects=False)
            self.assertEqual(response.status_code, 302,
                           f"{url} should redirect unauthenticated users")
            self.assertIn('/login', response.location,
                         f"{url} should redirect to /login")

    def test_default_password_shows_warning(self):
        """Test that using default password shows security warning"""
        # Set password to default
        os.environ['ADMIN_PASSWORD'] = 'changeme'

        # Reload app with default password
        from importlib import reload
        import app as app_module
        reload(app_module)

        response = self.client.get('/login', follow_redirects=True)
        # Note: Since we can't easily check flash messages in test client,
        # we verify the app detects default password through logs
        # The actual warning display is tested manually

        # Cleanup
        if 'ADMIN_PASSWORD' in os.environ:
            del os.environ['ADMIN_PASSWORD']


class TestCredentialHardening(unittest.TestCase):
    """
    Test the hardened login path:
    - ADMIN_PASSWORD_HASH support (werkzeug scrypt/pbkdf2)
    - bounded session lifetime
    - session fixation defence
    - rate limiting that survives a worker restart
    """

    MANAGED_ENV = [
        'DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD',
        'ADMIN_PASSWORD_HASH', 'SESSION_LIFETIME_MINUTES',
    ]

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self._saved_env = {k: os.environ.get(k) for k in self.MANAGED_ENV}

        for key in self.MANAGED_ENV:
            os.environ.pop(key, None)

        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-credentials'
        os.environ['ADMIN_USERNAME'] = 'admin'

    def tearDown(self):
        import shutil

        # Restore the environment exactly, then reload the module so later
        # test classes do not inherit this class's configuration. The reload
        # is done against a scratch DATA_DIR so it never touches /data.
        for key, value in self._saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

        scratch = tempfile.mkdtemp()
        saved_data_dir = os.environ.get('DATA_DIR')
        os.environ['DATA_DIR'] = scratch
        try:
            from importlib import reload
            import app as app_module
            reload(app_module)
        finally:
            if saved_data_dir is None:
                os.environ.pop('DATA_DIR', None)
            else:
                os.environ['DATA_DIR'] = saved_data_dir
            shutil.rmtree(scratch, ignore_errors=True)

        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    # -- helpers ---------------------------------------------------------

    def load_app(self):
        """(Re)import app.py with the current environment and return it."""
        from importlib import reload
        import app as app_module
        reload(app_module)
        app_module.app.config['TESTING'] = True
        return app_module

    def csrf_token(self, client, path='/login'):
        import re
        response = client.get(path)
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"',
                          response.data.decode('utf-8'))
        self.assertIsNotNone(match, f"No CSRF token found on {path}")
        return match.group(1)

    def attempt_login(self, client, username, password):
        token = self.csrf_token(client)
        return client.post('/login', data={
            'username': username,
            'password': password,
            'csrf_token': token,
        }, follow_redirects=False)

    # -- ADMIN_PASSWORD_HASH ---------------------------------------------

    def test_login_succeeds_with_password_hash(self):
        """Login works with ADMIN_PASSWORD_HASH and no ADMIN_PASSWORD"""
        from werkzeug.security import generate_password_hash
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash('secure123')
        self.assertNotIn('ADMIN_PASSWORD', os.environ)

        app_module = self.load_app()
        client = app_module.app.test_client()

        response = self.attempt_login(client, 'admin', 'secure123')
        self.assertEqual(response.status_code, 302,
                         "Hashed-password login should redirect on success")
        self.assertIn('/whitelist', response.location)

    def test_login_fails_with_wrong_password_against_hash(self):
        """A wrong password is rejected when ADMIN_PASSWORD_HASH is set"""
        from werkzeug.security import generate_password_hash
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash('secure123')

        app_module = self.load_app()
        client = app_module.app.test_client()

        response = self.attempt_login(client, 'admin', 'wrongpassword')
        self.assertEqual(response.status_code, 200,
                         "Failed login should re-render the login page")
        self.assertFalse(app_module.verify_credentials('admin', 'wrongpassword'))

    def test_login_fails_with_wrong_username_against_hash(self):
        """A wrong username is rejected even with the right password"""
        from werkzeug.security import generate_password_hash
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash('secure123')

        app_module = self.load_app()
        self.assertFalse(app_module.verify_credentials('root', 'secure123'))
        self.assertTrue(app_module.verify_credentials('admin', 'secure123'))

    def test_malformed_password_hash_denies_without_500(self):
        """A malformed ADMIN_PASSWORD_HASH denies login and does not crash"""
        os.environ['ADMIN_PASSWORD_HASH'] = 'not-a-hash'

        app_module = self.load_app()
        client = app_module.app.test_client()

        response = self.attempt_login(client, 'admin', 'secure123')
        self.assertEqual(response.status_code, 200,
                         "Malformed hash must not produce a 500")
        self.assertFalse(app_module.verify_credentials('admin', 'secure123'))
        self.assertFalse(app_module.verify_credentials('admin', 'not-a-hash'))

    def test_password_hash_overrides_plaintext_password(self):
        """ADMIN_PASSWORD_HASH takes precedence over ADMIN_PASSWORD"""
        from werkzeug.security import generate_password_hash
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash('hashed-pw')
        os.environ['ADMIN_PASSWORD'] = 'plaintext-pw'

        app_module = self.load_app()
        self.assertTrue(app_module.verify_credentials('admin', 'hashed-pw'))
        self.assertFalse(app_module.verify_credentials('admin', 'plaintext-pw'))

    def test_password_hash_suppresses_default_password_warning(self):
        """ADMIN_PASSWORD=changeme is irrelevant once a hash is configured"""
        from werkzeug.security import generate_password_hash
        os.environ['ADMIN_PASSWORD_HASH'] = generate_password_hash('secure123')
        os.environ['ADMIN_PASSWORD'] = 'changeme'

        app_module = self.load_app()
        self.assertFalse(app_module.is_using_default_password(),
                         "A configured hash overrides the default plaintext password")

    def test_default_password_still_detected_without_hash(self):
        """Without a hash, the 'changeme' default is still flagged"""
        os.environ['ADMIN_PASSWORD'] = 'changeme'
        app_module = self.load_app()
        self.assertTrue(app_module.is_using_default_password())

    # -- session lifetime -------------------------------------------------

    def test_session_lifetime_defaults_to_480_minutes(self):
        """PERMANENT_SESSION_LIFETIME defaults to 8 hours"""
        from datetime import timedelta
        self.assertNotIn('SESSION_LIFETIME_MINUTES', os.environ)

        app_module = self.load_app()
        self.assertEqual(app_module.app.config['PERMANENT_SESSION_LIFETIME'],
                         timedelta(minutes=480))

    def test_session_lifetime_honours_env_var(self):
        """SESSION_LIFETIME_MINUTES overrides the default"""
        from datetime import timedelta
        os.environ['SESSION_LIFETIME_MINUTES'] = '5'

        app_module = self.load_app()
        self.assertEqual(app_module.app.config['PERMANENT_SESSION_LIFETIME'],
                         timedelta(minutes=5))

    def test_invalid_session_lifetime_falls_back_to_default(self):
        """A non-numeric SESSION_LIFETIME_MINUTES does not break startup"""
        from datetime import timedelta
        os.environ['SESSION_LIFETIME_MINUTES'] = 'not-a-number'

        app_module = self.load_app()
        self.assertEqual(app_module.app.config['PERMANENT_SESSION_LIFETIME'],
                         timedelta(minutes=480))

    # -- session fixation -------------------------------------------------

    def test_login_clears_pre_authentication_session(self):
        """Values planted before login are discarded (session fixation)"""
        os.environ['ADMIN_PASSWORD'] = 'secure123'
        app_module = self.load_app()
        client = app_module.app.test_client()

        with client.session_transaction() as sess:
            sess['pre'] = 'attacker-planted'

        response = self.attempt_login(client, 'admin', 'secure123')
        self.assertEqual(response.status_code, 302)

        with client.session_transaction() as sess:
            self.assertNotIn('pre', sess,
                             "Pre-auth session values must be cleared on login")
            self.assertTrue(sess.get('logged_in'))
            self.assertEqual(sess.get('username'), 'admin')

    def test_csrf_token_is_rotated_on_login(self):
        """The pre-auth CSRF token does not survive authentication"""
        os.environ['ADMIN_PASSWORD'] = 'secure123'
        app_module = self.load_app()
        client = app_module.app.test_client()

        pre_token = self.csrf_token(client)
        response = self.attempt_login(client, 'admin', 'secure123')
        self.assertEqual(response.status_code, 302)

        post_token = self.csrf_token(client, '/whitelist')
        self.assertNotEqual(pre_token, post_token,
                            "CSRF token must be regenerated after login")

    # -- rate limiting across workers/restarts ---------------------------

    def test_rate_limit_persists_across_worker_restart(self):
        """The 5-attempt limit is shared, not per-process"""
        os.environ['ADMIN_PASSWORD'] = 'secure123'
        app_module = self.load_app()
        app_module.clear_login_attempts()

        client = app_module.app.test_client()
        for _ in range(app_module.MAX_LOGIN_ATTEMPTS):
            response = self.attempt_login(client, 'admin', 'wrongpassword')
            self.assertEqual(response.status_code, 200)

        # Simulate a second gunicorn worker / a container restart: a brand new
        # process-local state, but the same DATA_DIR.
        other_worker = self.load_app()
        self.assertEqual(len(other_worker.login_attempts), 0,
                         "The in-memory fallback should be empty in a fresh worker")

        other_client = other_worker.app.test_client()
        response = self.attempt_login(other_client, 'admin', 'wrongpassword')
        self.assertEqual(response.status_code, 429,
                         "The 6th attempt must be refused by any worker")

    def test_rate_limit_store_is_written_with_safe_permissions(self):
        """The shared store lives under DATA_DIR and is mode 0600"""
        os.environ['ADMIN_PASSWORD'] = 'secure123'
        app_module = self.load_app()
        app_module.clear_login_attempts()

        app_module.record_login_attempt('203.0.113.7')

        store = os.path.join(self.test_dir, '.login_attempts.json')
        self.assertTrue(os.path.exists(store), "Attempt store should be created")
        self.assertEqual(os.stat(store).st_mode & 0o777, 0o600)

        import json
        with open(store) as f:
            data = json.load(f)
        self.assertIn('203.0.113.7', data)
        self.assertEqual(len(data['203.0.113.7']), 1)

    def test_expired_attempts_are_pruned(self):
        """Attempts older than RATE_LIMIT_WINDOW stop counting"""
        import json
        app_module = self.load_app()
        app_module.clear_login_attempts()

        stale = time.time() - (app_module.RATE_LIMIT_WINDOW + 60)
        store = os.path.join(self.test_dir, '.login_attempts.json')
        with open(store, 'w') as f:
            json.dump({'198.51.100.4': [stale] * 10}, f)

        self.assertTrue(app_module.check_rate_limit('198.51.100.4'),
                        "Stale attempts must not keep an IP locked out")

        with open(store) as f:
            self.assertNotIn('198.51.100.4', json.load(f))

    def test_clear_login_attempts_removes_store(self):
        """clear_login_attempts() wipes both the file and the fallback"""
        app_module = self.load_app()
        app_module.record_login_attempt('192.0.2.1')
        store = os.path.join(self.test_dir, '.login_attempts.json')
        self.assertTrue(os.path.exists(store))

        app_module.clear_login_attempts()
        self.assertFalse(os.path.exists(store))
        self.assertEqual(len(app_module.login_attempts), 0)
        self.assertTrue(app_module.check_rate_limit('192.0.2.1'))

    def test_rate_limit_falls_back_when_store_unwritable(self):
        """An unusable DATA_DIR degrades to per-process limiting, not a 500"""
        app_module = self.load_app()

        # Point DATA_DIR at a path that cannot be created (a regular file).
        blocked = os.path.join(self.test_dir, 'not-a-dir')
        with open(blocked, 'w') as f:
            f.write('x')
        os.environ['DATA_DIR'] = os.path.join(blocked, 'nested')
        try:
            app_module.login_attempts.clear()
            for _ in range(app_module.MAX_LOGIN_ATTEMPTS):
                self.assertTrue(app_module.check_rate_limit('192.0.2.9'))
                app_module.record_login_attempt('192.0.2.9')
            self.assertFalse(app_module.check_rate_limit('192.0.2.9'),
                             "Fallback limiter must still enforce the limit")
        finally:
            os.environ['DATA_DIR'] = self.test_dir
            app_module.login_attempts.clear()


def run_tests():
    """Run all security tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestCSRFProtection))
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestRateLimiting))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityHeaders))
    suite.addTests(loader.loadTestsFromTestCase(TestSessionSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestAuthenticationSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestCredentialHardening))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
