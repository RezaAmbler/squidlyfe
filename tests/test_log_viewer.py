#!/usr/bin/env python3
"""
Unit tests for Live Log Viewer functionality
Tests the tail_log helper and /api/logs endpoint
"""

import unittest
import tempfile
import os
import sys

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import squid_control


class TestTailLogHelper(unittest.TestCase):
    """Test the tail_log helper function"""

    def setUp(self):
        """Set up test log file"""
        self.test_dir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.test_dir, 'test.log')

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_tail_missing_file(self):
        """Test tailing a file that doesn't exist"""
        result = squid_control.tail_log('/nonexistent/file.log', max_lines=10)

        self.assertIn('error', result)
        self.assertEqual(result['lines'], [])
        self.assertEqual(result['cursor'], 0)
        self.assertIn('not found', result['error'].lower())

    def test_tail_empty_file(self):
        """Test tailing an empty file"""
        # Create empty file
        open(self.log_path, 'w').close()

        result = squid_control.tail_log(self.log_path, max_lines=10)

        self.assertNotIn('error', result)
        self.assertEqual(result['lines'], [])
        self.assertEqual(result['cursor'], 0)

    def test_tail_initial_read_small_file(self):
        """Test initial tail read (cursor=None) on a small file"""
        # Write 5 lines
        with open(self.log_path, 'w') as f:
            for i in range(1, 6):
                f.write(f'Line {i}\n')

        result = squid_control.tail_log(self.log_path, max_lines=10)

        self.assertNotIn('error', result)
        self.assertEqual(len(result['lines']), 5)
        self.assertEqual(result['lines'][0], 'Line 1')
        self.assertEqual(result['lines'][-1], 'Line 5')
        self.assertGreater(result['cursor'], 0)

    def test_tail_initial_read_limits_lines(self):
        """Test that initial read respects max_lines"""
        # Write 100 lines
        with open(self.log_path, 'w') as f:
            for i in range(1, 101):
                f.write(f'Line {i}\n')

        result = squid_control.tail_log(self.log_path, max_lines=10)

        self.assertNotIn('error', result)
        self.assertEqual(len(result['lines']), 10)
        # Should get last 10 lines
        self.assertEqual(result['lines'][0], 'Line 91')
        self.assertEqual(result['lines'][-1], 'Line 100')

    def test_tail_clamps_max_lines_to_500(self):
        """Test that max_lines is clamped to 500"""
        # Write 1000 lines
        with open(self.log_path, 'w') as f:
            for i in range(1, 1001):
                f.write(f'Line {i}\n')

        result = squid_control.tail_log(self.log_path, max_lines=1000)

        self.assertNotIn('error', result)
        # Should be clamped to 500
        self.assertEqual(len(result['lines']), 500)
        self.assertEqual(result['lines'][0], 'Line 501')
        self.assertEqual(result['lines'][-1], 'Line 1000')

    def test_tail_incremental_read_with_cursor(self):
        """Test incremental read with cursor"""
        # Write initial content
        with open(self.log_path, 'w') as f:
            for i in range(1, 6):
                f.write(f'Line {i}\n')

        # Initial read
        result1 = squid_control.tail_log(self.log_path, max_lines=10)
        cursor1 = result1['cursor']

        # Append more lines
        with open(self.log_path, 'a') as f:
            for i in range(6, 11):
                f.write(f'Line {i}\n')

        # Incremental read
        result2 = squid_control.tail_log(self.log_path, max_lines=10, cursor=cursor1)

        self.assertNotIn('error', result2)
        self.assertEqual(len(result2['lines']), 5)
        self.assertEqual(result2['lines'][0], 'Line 6')
        self.assertEqual(result2['lines'][-1], 'Line 10')
        self.assertGreater(result2['cursor'], cursor1)

    def test_tail_incremental_read_no_new_content(self):
        """Test incremental read when no new content has been added"""
        # Write initial content
        with open(self.log_path, 'w') as f:
            f.write('Line 1\n')

        # Initial read
        result1 = squid_control.tail_log(self.log_path, max_lines=10)
        cursor1 = result1['cursor']

        # Incremental read without adding content
        result2 = squid_control.tail_log(self.log_path, max_lines=10, cursor=cursor1)

        self.assertNotIn('error', result2)
        self.assertEqual(result2['lines'], [])
        self.assertEqual(result2['cursor'], cursor1)

    def test_tail_log_rotation_detection(self):
        """Test that log rotation is detected and handled"""
        # Write initial content
        with open(self.log_path, 'w') as f:
            for i in range(1, 101):
                f.write(f'Old Line {i}\n')

        # Initial read
        result1 = squid_control.tail_log(self.log_path, max_lines=10)
        cursor1 = result1['cursor']

        # Simulate log rotation - replace file with smaller content
        with open(self.log_path, 'w') as f:
            for i in range(1, 6):
                f.write(f'New Line {i}\n')

        # Incremental read - should detect rotation
        result2 = squid_control.tail_log(self.log_path, max_lines=10, cursor=cursor1)

        self.assertNotIn('error', result2)
        # Should return content from rotated file
        self.assertGreater(len(result2['lines']), 0)
        self.assertTrue(any('New Line' in line for line in result2['lines']))

    def test_tail_permission_denied(self):
        """Test handling of permission denied errors"""
        # Create file and remove read permissions
        with open(self.log_path, 'w') as f:
            f.write('Line 1\n')

        os.chmod(self.log_path, 0o000)

        try:
            result = squid_control.tail_log(self.log_path, max_lines=10)

            self.assertIn('error', result)
            self.assertEqual(result['lines'], [])
            self.assertIn('permission', result['error'].lower())
        finally:
            # Restore permissions for cleanup
            os.chmod(self.log_path, 0o644)


class TestAPILogsEndpoint(unittest.TestCase):
    """Test the /api/logs endpoint"""

    def setUp(self):
        """Set up test Flask app and temp files"""
        self.test_dir = tempfile.mkdtemp()
        self.access_log_path = os.path.join(self.test_dir, 'access.log')
        self.cache_log_path = os.path.join(self.test_dir, 'cache.log')
        self.config_path = os.path.join(self.test_dir, 'config.yaml')

        # Override paths
        os.environ['DATA_DIR'] = self.test_dir
        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['ADMIN_USERNAME'] = 'admin'
        os.environ['ADMIN_PASSWORD'] = 'test123'
        squid_control.CONFIG_PATH = self.config_path

        # Create test log files
        with open(self.access_log_path, 'w') as f:
            for i in range(1, 11):
                f.write(f'Access log line {i}\n')

        with open(self.cache_log_path, 'w') as f:
            for i in range(1, 11):
                f.write(f'Cache log line {i}\n')

        # Write config
        squid_control.write_logging_config({
            'logging': {
                'mode': 'local_file',
                'access_log_path': self.access_log_path,
                'cache_log_path': self.cache_log_path
            }
        })

        # Import app after setting up paths
        from app import app
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

        # Clean up env vars
        for key in ['DATA_DIR', 'SECRET_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']:
            if key in os.environ:
                del os.environ[key]

    def login(self):
        """Helper to log in"""
        self.client.post('/login', data={
            'username': 'admin',
            'password': 'test123'
        })

    def test_api_logs_requires_authentication(self):
        """Test that /api/logs requires login"""
        response = self.client.get('/api/logs')

        # Should redirect to login
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.location)

    def test_api_logs_access_log_default(self):
        """Test fetching access log (default)"""
        self.login()

        response = self.client.get('/api/logs')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertIn('lines', data)
        self.assertIn('cursor', data)
        self.assertIn('file', data)
        self.assertEqual(data['file'], 'access')
        self.assertEqual(len(data['lines']), 10)
        self.assertTrue(any('Access log' in line for line in data['lines']))

    def test_api_logs_cache_log(self):
        """Test fetching cache log"""
        self.login()

        response = self.client.get('/api/logs?file=cache')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertEqual(data['file'], 'cache')
        self.assertTrue(any('Cache log' in line for line in data['lines']))

    def test_api_logs_invalid_file_parameter(self):
        """Test that invalid file parameter is rejected"""
        self.login()

        response = self.client.get('/api/logs?file=../../etc/passwd')

        self.assertEqual(response.status_code, 400)
        data = response.get_json()

        self.assertIn('error', data)
        self.assertIn('Invalid file parameter', data['error'])

    def test_api_logs_lines_parameter(self):
        """Test lines parameter"""
        self.login()

        response = self.client.get('/api/logs?file=access&lines=5')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        self.assertEqual(len(data['lines']), 5)

    def test_api_logs_lines_parameter_clamped(self):
        """Test that lines parameter is clamped to max 500"""
        self.login()

        response = self.client.get('/api/logs?file=access&lines=1000')

        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        # Should be clamped to available lines (10 in this case)
        self.assertLessEqual(len(data['lines']), 500)

    def test_api_logs_invalid_lines_parameter(self):
        """Test that invalid lines parameter returns error"""
        self.login()

        response = self.client.get('/api/logs?file=access&lines=invalid')

        self.assertEqual(response.status_code, 400)
        data = response.get_json()

        self.assertIn('error', data)
        self.assertIn('Invalid lines parameter', data['error'])

    def test_api_logs_cursor_parameter(self):
        """Test cursor parameter for incremental reads"""
        self.login()

        # Initial read
        response1 = self.client.get('/api/logs?file=access')
        data1 = response1.get_json()
        cursor1 = data1['cursor']

        # Append to log
        with open(self.access_log_path, 'a') as f:
            f.write('New access log line\n')

        # Incremental read
        response2 = self.client.get(f'/api/logs?file=access&cursor={cursor1}')
        data2 = response2.get_json()

        self.assertEqual(response2.status_code, 200)
        self.assertEqual(len(data2['lines']), 1)
        self.assertEqual(data2['lines'][0], 'New access log line')

    def test_api_logs_invalid_cursor_parameter(self):
        """Test that invalid cursor parameter returns error"""
        self.login()

        response = self.client.get('/api/logs?file=access&cursor=invalid')

        self.assertEqual(response.status_code, 400)
        data = response.get_json()

        self.assertIn('error', data)
        self.assertIn('Invalid cursor parameter', data['error'])

    def test_api_logs_only_available_in_local_file_mode(self):
        """Test that log viewer is only available in local_file mode"""
        self.login()

        # Change to stdout mode
        squid_control.write_logging_config({
            'logging': {
                'mode': 'stdout'
            }
        })

        response = self.client.get('/api/logs?file=access')

        self.assertEqual(response.status_code, 400)
        data = response.get_json()

        self.assertIn('error', data)
        self.assertIn('only available when logging mode is "local_file"', data['error'])

    def test_api_logs_handles_missing_log_file(self):
        """Test that missing log file is handled gracefully"""
        self.login()

        # Remove access log
        os.remove(self.access_log_path)

        response = self.client.get('/api/logs?file=access')

        self.assertEqual(response.status_code, 500)
        data = response.get_json()

        self.assertIn('error', data)


def run_tests():
    """Run all log viewer tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestTailLogHelper))
    suite.addTests(loader.loadTestsFromTestCase(TestAPILogsEndpoint))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
