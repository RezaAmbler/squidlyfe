#!/usr/bin/env python3
"""
Unit tests for Flask UI operations (Bug B - removal/session handling)
Tests that whitelist removal works without redirecting to login
"""

import unittest
import tempfile
import os
import sys

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

# Must import and configure before creating app
import squid_control


class TestFlaskUIRemoval(unittest.TestCase):
    """Test Flask UI whitelist removal (Bug B)"""

    def setUp(self):
        """Set up test Flask app and temp whitelist"""
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, 'whitelist.txt')
        self.secret_key_path = os.path.join(self.test_dir, '.secret_key')

        # Override paths before importing app
        squid_control.WHITELIST_PATH = self.whitelist_path
        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key-for-testing-only'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'test123'

        # Now import app (will use test paths and secret key)
        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.client = self.app.test_client()

        # Seed initial whitelist
        squid_control.write_whitelist(['example.com', 'microsoft.com', '.github.com'])

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        # Clean up env vars
        if 'DATA_DIR' in os.environ:
            del os.environ['DATA_DIR']
        if 'SECRET_KEY' in os.environ:
            del os.environ['SECRET_KEY']
        if 'ADMIN_USERNAME' in os.environ:
            del os.environ['ADMIN_USERNAME']
        if 'ADMIN_PASSWORD' in os.environ:
            del os.environ['ADMIN_PASSWORD']

    def test_removal_with_valid_session_no_redirect_to_login(self):
        """Test that removing entries while logged in does NOT redirect to login"""
        import re

        # Get CSRF token from login page
        response = self.client.get('/login')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        csrf_token = match.group(1) if match else ''

        # Log in first with CSRF token
        response = self.client.post('/login', data={
            'username': 'admin',
            'password': 'test123',
            'csrf_token': csrf_token
        }, follow_redirects=False)

        # Should redirect to whitelist page after login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/whitelist', response.location)

        # Get CSRF token from whitelist page
        response = self.client.get('/whitelist')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        csrf_token = match.group(1) if match else ''

        # Read initial whitelist
        initial_entries = squid_control.read_whitelist()
        self.assertEqual(len(initial_entries), 3, "Should start with 3 entries")
        self.assertIn('example.com', initial_entries)
        self.assertIn('microsoft.com', initial_entries)

        # Perform removal with CSRF token
        response = self.client.post('/whitelist', data={
            'action': 'remove',
            'remove_entries': ['example.com', 'microsoft.com'],
            'csrf_token': csrf_token
        }, follow_redirects=False)

        # CRITICAL: Should redirect to /whitelist, NOT /login
        self.assertEqual(response.status_code, 302, "Should be a redirect")
        self.assertIn('/whitelist', response.location, "Should redirect to whitelist, NOT login")
        self.assertNotIn('/login', response.location, "Should NOT redirect to login")

        # Verify entries were actually removed
        remaining_entries = squid_control.read_whitelist()
        self.assertEqual(len(remaining_entries), 1, "Should have 1 entry remaining")
        self.assertNotIn('example.com', remaining_entries, "example.com should be removed")
        self.assertNotIn('microsoft.com', remaining_entries, "microsoft.com should be removed")
        self.assertIn('.github.com', remaining_entries, ".github.com should remain")

    def test_removal_persists_across_requests(self):
        """Test that removal persists and is visible in subsequent requests"""
        import re

        # Get CSRF token and log in
        response = self.client.get('/login')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        csrf_token = match.group(1) if match else ''

        self.client.post('/login', data={
            'username': 'admin',
            'password': 'test123',
            'csrf_token': csrf_token
        })

        # Get CSRF token for whitelist operation
        response = self.client.get('/whitelist')
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.data.decode('utf-8'))
        csrf_token = match.group(1) if match else ''

        # Remove entries with CSRF token
        self.client.post('/whitelist', data={
            'action': 'remove',
            'remove_entries': ['microsoft.com'],
            'csrf_token': csrf_token
        })

        # Make a new GET request to whitelist page
        response = self.client.get('/whitelist', follow_redirects=True)

        self.assertEqual(response.status_code, 200, "Should successfully load whitelist page")

        # Verify removal persisted
        entries = squid_control.read_whitelist()
        self.assertNotIn('microsoft.com', entries, "Removal should persist")
        self.assertEqual(len(entries), 2, "Should have 2 remaining entries")

    def test_removal_without_login_redirects_to_login(self):
        """Test that removal without login properly redirects to login (expected behavior)"""
        # Try to remove without logging in
        response = self.client.post('/whitelist', data={
            'action': 'remove',
            'remove_entries': ['example.com']
        }, follow_redirects=False)

        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)

        # Entries should NOT be removed
        entries = squid_control.read_whitelist()
        self.assertIn('example.com', entries, "Entries should not be removed without auth")

    def test_stable_secret_key_across_app_instances(self):
        """Test that secret key is stable (helps with multi-worker sessions)"""
        # Import app module
        import app as app_module

        # Get secret key from first app instance
        key1 = self.app.secret_key

        # Simulate another worker creating the app
        from importlib import reload
        reload(app_module)
        app2 = app_module.app

        key2 = app2.secret_key

        # Keys should be identical (both read from same source)
        self.assertEqual(key1, key2, "Secret keys should be stable across app instances")


def run_tests():
    """Run all Flask UI tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestFlaskUIRemoval)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
