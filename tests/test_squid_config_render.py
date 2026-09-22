#!/usr/bin/env python3
"""
Unit tests for Squid configuration rendering.

These guard the boot-time render path: app/entrypoint.sh renders
/etc/squid/squid.conf by calling squid_control.regenerate_squid_config(),
so every placeholder in squid/squid.conf.template must be substituted.
An unsubstituted placeholder is NOT rejected by `squid -k parse` - it is
silently accepted - so the only reliable guard is asserting on the
rendered text.

Requires PyYAML only (no Flask).
"""

import os
import shutil
import sys
import tempfile
import unittest

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

import squid_control
from squid_control import get_default_logging_config, regenerate_squid_config

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPO_TEMPLATE = os.path.join(REPO_ROOT, 'squid', 'squid.conf.template')


class TestSquidConfigRender(unittest.TestCase):
    """Render the real repo template and inspect the output"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.test_dir, 'squid.conf')
        self.whitelist_path = os.path.join(self.test_dir, 'whitelist.txt')

        self._old_template = squid_control.SQUID_CONFIG_TEMPLATE
        self._old_output = squid_control.SQUID_CONFIG_PATH
        self._old_whitelist = squid_control.WHITELIST_PATH

        squid_control.SQUID_CONFIG_TEMPLATE = REPO_TEMPLATE
        squid_control.SQUID_CONFIG_PATH = self.output_path
        squid_control.WHITELIST_PATH = self.whitelist_path

    def tearDown(self):
        squid_control.SQUID_CONFIG_TEMPLATE = self._old_template
        squid_control.SQUID_CONFIG_PATH = self._old_output
        squid_control.WHITELIST_PATH = self._old_whitelist
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def render(self, config):
        """Render config and return (success, message, rendered text)"""
        success, message = regenerate_squid_config(config)
        text = ''
        if os.path.exists(self.output_path):
            with open(self.output_path, 'r', encoding='utf-8') as f:
                text = f.read()
        return success, message, text

    def test_template_exists(self):
        """The repo template the container ships must exist"""
        self.assertTrue(os.path.exists(REPO_TEMPLATE),
                        "squid/squid.conf.template missing from repo")

    def test_render_succeeds_with_defaults(self):
        """Rendering the default config succeeds"""
        success, message, _ = self.render(get_default_logging_config())
        self.assertTrue(success, "Render failed: {}".format(message))

    def test_no_placeholders_remain(self):
        """No {{...}} placeholder may survive the render (boot-bug regression)"""
        _, _, text = self.render(get_default_logging_config())
        leftovers = [line for line in text.splitlines() if '{{' in line]
        self.assertEqual(leftovers, [],
                         "Unsubstituted placeholders remain: {}".format(leftovers))

    def test_default_dns_nameservers_rendered(self):
        """{{DNS_NAMESERVERS}} becomes the default resolver list"""
        _, _, text = self.render(get_default_logging_config())
        self.assertIn('dns_nameservers 1.1.1.1 8.8.8.8', text.splitlines())

    def test_custom_dns_nameservers_rendered(self):
        """Custom nameservers from config reach the rendered file"""
        config = get_default_logging_config()
        config['dns']['nameservers'] = ['9.9.9.9', '1.1.1.1']
        _, _, text = self.render(config)
        self.assertIn('dns_nameservers 9.9.9.9 1.1.1.1', text.splitlines())
        self.assertNotIn('{{DNS_NAMESERVERS}}', text)

    def test_whitelist_path_rendered(self):
        """The allowed_sites ACL points at the configured whitelist path"""
        _, _, text = self.render(get_default_logging_config())
        expected = 'acl allowed_sites dstdomain "{}"'.format(self.whitelist_path)
        self.assertIn(expected, text.splitlines())

    def test_local_file_logging_rendered(self):
        """local_file mode logs to the on-disk access log"""
        _, _, text = self.render(get_default_logging_config())
        self.assertIn('access_log /var/log/squid/access.log squid', text.splitlines())

    def test_stdout_logging_rendered(self):
        """stdout mode logs to stdout"""
        config = get_default_logging_config()
        config['logging']['mode'] = 'stdout'
        _, _, text = self.render(config)
        self.assertIn('access_log stdio:/dev/stdout squid', text.splitlines())

    def test_remote_syslog_logging_rendered(self):
        """remote_syslog mode logs to stdout and records the target"""
        config = get_default_logging_config()
        config['logging']['mode'] = 'remote_syslog'
        config['logging']['syslog_host'] = 'logs.example.com'
        config['logging']['syslog_port'] = '5514'
        config['logging']['syslog_protocol'] = 'tcp'
        _, _, text = self.render(config)
        self.assertIn('access_log stdio:/dev/stdout squid', text.splitlines())
        self.assertIn('tcp://logs.example.com:5514', text)
        self.assertNotIn('{{', text)

    def test_missing_template_fails_cleanly(self):
        """A missing template returns failure instead of raising"""
        squid_control.SQUID_CONFIG_TEMPLATE = os.path.join(self.test_dir, 'nope.template')
        success, message = regenerate_squid_config(get_default_logging_config())
        self.assertFalse(success)
        self.assertIn('template', message.lower())

    def test_invalid_dns_falls_back_to_defaults(self):
        """Garbage nameserver config still renders a usable resolver line"""
        config = get_default_logging_config()
        config['dns']['nameservers'] = []
        _, _, text = self.render(config)
        self.assertIn('dns_nameservers 1.1.1.1 8.8.8.8', text.splitlines())


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestSquidConfigRender))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
