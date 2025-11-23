#!/usr/bin/env python3
"""
Unit tests for whitelist validation logic
Tests exact vs wildcard entry handling
"""

import unittest
import tempfile
import os
import sys

# Add parent directory to path to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))

from squid_control import (
    read_whitelist,
    write_whitelist,
    normalize_whitelist_entries,
    entry_coverage,
    filter_conflicts
)


class TestEmptyWhitelistHandling(unittest.TestCase):
    """Test that empty whitelists are handled gracefully"""

    def setUp(self):
        """Create a temporary directory for test files"""
        self.test_dir = tempfile.mkdtemp()
        self.whitelist_path = os.path.join(self.test_dir, 'whitelist.txt')

    def tearDown(self):
        """Clean up temporary directory"""
        import shutil
        shutil.rmtree(self.test_dir)

    def test_read_empty_whitelist(self):
        """Test reading an empty whitelist file"""
        # Create empty file
        with open(self.whitelist_path, 'w') as f:
            f.write("")

        # Temporarily override the whitelist path
        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = self.whitelist_path

        try:
            entries = read_whitelist()
            self.assertEqual(entries, [], "Empty whitelist should return empty list")
        finally:
            squid_control.WHITELIST_PATH = old_path

    def test_read_whitelist_only_comments(self):
        """Test reading a whitelist with only comments"""
        # Create file with only comments
        with open(self.whitelist_path, 'w') as f:
            f.write("# Comment 1\n")
            f.write("# Comment 2\n")
            f.write("\n")
            f.write("   # Indented comment\n")

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = self.whitelist_path

        try:
            entries = read_whitelist()
            self.assertEqual(entries, [], "Whitelist with only comments should return empty list")
        finally:
            squid_control.WHITELIST_PATH = old_path

    def test_read_whitelist_mixed_content(self):
        """Test reading a whitelist with comments and entries"""
        with open(self.whitelist_path, 'w') as f:
            f.write("# Comment\n")
            f.write("example.com\n")
            f.write("\n")
            f.write(".github.com\n")
            f.write("# Another comment\n")

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = self.whitelist_path

        try:
            entries = read_whitelist()
            self.assertEqual(len(entries), 2, "Should have 2 entries")
            self.assertIn("example.com", entries)
            self.assertIn(".github.com", entries)
        finally:
            squid_control.WHITELIST_PATH = old_path

    def test_write_empty_whitelist(self):
        """Test writing an empty whitelist"""
        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = self.whitelist_path

        try:
            # Write empty list
            write_whitelist([])

            # File should exist and have header comments
            self.assertTrue(os.path.exists(self.whitelist_path))

            with open(self.whitelist_path, 'r') as f:
                content = f.read()

            # Should have header comments
            self.assertIn("# Squid Whitelist", content)

            # Reading it back should return empty list
            entries = read_whitelist()
            self.assertEqual(entries, [], "Empty whitelist should read back as empty")
        finally:
            squid_control.WHITELIST_PATH = old_path

    def test_write_then_read_whitelist(self):
        """Test write-then-read round trip with exact and wildcard entries"""
        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = self.whitelist_path

        try:
            # Mix of exact and wildcard entries
            test_entries = ["example.com", ".github.com", "registry.npmjs.org"]

            # Write entries
            write_whitelist(test_entries)

            # Read back
            entries = read_whitelist()

            # Should have 2 exact entries and 1 wildcard
            # example.com -> exact
            # .github.com -> wildcard
            # registry.npmjs.org -> exact
            self.assertEqual(len(entries), 3, "Should have 3 entries")

            # Verify entries are present
            self.assertIn('example.com', entries, "Should have exact entry")
            self.assertIn('.github.com', entries, "Should have wildcard entry")
            self.assertIn('registry.npmjs.org', entries, "Should have exact entry")
        finally:
            squid_control.WHITELIST_PATH = old_path


class TestWhitelistValidation(unittest.TestCase):
    """Test whitelist entry validation"""

    def test_empty_entries_filtered(self):
        """Test that empty entries are filtered out"""
        test_dir = tempfile.mkdtemp()
        whitelist_path = os.path.join(test_dir, 'whitelist.txt')

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = whitelist_path

        try:
            # Write list with empty strings
            entries_with_empty = ["example.com", "", "  ", ".github.com", None]
            # Filter out None first (as write_whitelist might not handle None)
            entries_to_write = [e for e in entries_with_empty if e is not None]

            write_whitelist(entries_to_write)

            # Read back
            entries = read_whitelist()

            # Should have 1 exact (example.com) and 1 wildcard (.github.com)
            # Empty entries are filtered out
            self.assertEqual(len(entries), 2, "Should have 2 entries")
            self.assertIn("example.com", entries, "Should have exact entry")
            self.assertIn(".github.com", entries, "Should have wildcard entry")
        finally:
            squid_control.WHITELIST_PATH = old_path
            import shutil
            shutil.rmtree(test_dir)


class TestExactVsWildcardSemantics(unittest.TestCase):
    """Test exact vs wildcard entry handling"""

    def test_exact_not_broadened(self):
        """Test that bare domain stays exact (no auto-broadening)"""
        exact, wildcard = normalize_whitelist_entries(['example.com'])
        self.assertEqual(exact, ['example.com'], "Bare domain should stay exact")
        self.assertEqual(wildcard, [], "No wildcard should be created")

    def test_wildcard_canonical_asterisk(self):
        """Test that *.example.com is normalized to .example.com"""
        exact, wildcard = normalize_whitelist_entries(['*.example.com'])
        self.assertEqual(exact, [], "No exact entry should be created")
        self.assertEqual(wildcard, ['.example.com'], "Should normalize to dotted format")

    def test_wildcard_canonical_dotted(self):
        """Test that .example.com stays in dotted format"""
        exact, wildcard = normalize_whitelist_entries(['.example.com'])
        self.assertEqual(exact, [], "No exact entry should be created")
        self.assertEqual(wildcard, ['.example.com'], "Should keep dotted format")

    def test_exact_and_wildcard_not_duplicates(self):
        """Test that exact and wildcard entries are distinct"""
        exact, wildcard = normalize_whitelist_entries(['example.com', '.example.com'])
        self.assertIn('example.com', exact, "Exact entry should be present")
        self.assertIn('.example.com', wildcard, "Wildcard entry should be present")
        self.assertEqual(len(exact), 1, "Should have 1 exact entry")
        self.assertEqual(len(wildcard), 1, "Should have 1 wildcard entry")

    def test_wildcard_dedup(self):
        """Test that duplicate wildcard entries are removed"""
        exact, wildcard = normalize_whitelist_entries(['.example.com', '*.example.com'])
        self.assertEqual(exact, [], "No exact entries")
        self.assertEqual(wildcard, ['.example.com'], "Should deduplicate to single wildcard")

    def test_exact_dedup(self):
        """Test that duplicate exact entries are removed"""
        exact, wildcard = normalize_whitelist_entries(['example.com', 'example.com'])
        self.assertEqual(exact, ['example.com'], "Should deduplicate to single exact")
        self.assertEqual(wildcard, [], "No wildcard entries")

    def test_scheme_stripping_exact(self):
        """Test that schemes are stripped for exact entries"""
        exact, wildcard = normalize_whitelist_entries(['http://example.com', 'https://github.com'])
        self.assertIn('example.com', exact, "Should strip http://")
        self.assertIn('github.com', exact, "Should strip https://")
        self.assertEqual(len(exact), 2, "Should have 2 exact entries")
        self.assertEqual(wildcard, [], "No wildcard entries")

    def test_scheme_stripping_wildcard(self):
        """Test that schemes are stripped for wildcard entries"""
        exact, wildcard = normalize_whitelist_entries(['http://*.example.com', 'https://.github.com'])
        self.assertEqual(exact, [], "No exact entries")
        self.assertIn('.example.com', wildcard, "Should strip http:// from wildcard")
        self.assertIn('.github.com', wildcard, "Should strip https:// from wildcard")
        self.assertEqual(len(wildcard), 2, "Should have 2 wildcard entries")

    def test_path_stripping(self):
        """Test that paths are stripped"""
        exact, wildcard = normalize_whitelist_entries(['example.com/path', '*.github.com/api/v1'])
        self.assertIn('example.com', exact, "Should strip path from exact")
        self.assertIn('.github.com', wildcard, "Should strip path from wildcard")

    def test_mixed_entries(self):
        """Test normalization with mixed exact and wildcard entries"""
        entries = ['example.com', '*.github.com', 'google.com', '.npmjs.org']
        exact, wildcard = normalize_whitelist_entries(entries)

        self.assertEqual(len(exact), 2, "Should have 2 exact entries")
        self.assertIn('example.com', exact)
        self.assertIn('google.com', exact)

        self.assertEqual(len(wildcard), 2, "Should have 2 wildcard entries")
        self.assertIn('.github.com', wildcard)
        self.assertIn('.npmjs.org', wildcard)

    def test_write_whitelist_preserves_types(self):
        """Test that write_whitelist correctly writes exact and wildcard entries"""
        test_dir = tempfile.mkdtemp()
        whitelist_path = os.path.join(test_dir, 'whitelist.txt')

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = whitelist_path

        try:
            # Write mixed entries
            write_whitelist(['example.com', '*.github.com'])

            # Read back
            entries = read_whitelist()

            # Should have exact and wildcard
            self.assertIn('example.com', entries, "Should have exact entry")
            self.assertIn('.github.com', entries, "Should have wildcard entry")
            self.assertEqual(len(entries), 2, "Should have 2 entries total")

        finally:
            squid_control.WHITELIST_PATH = old_path
            import shutil
            shutil.rmtree(test_dir)


class TestEntryCoverage(unittest.TestCase):
    """Test coverage checking helper function"""

    def test_exact_covered_by_wildcard(self):
        """Test that exact entry covered by wildcard is detected"""
        coverage = entry_coverage('example.com', [], ['.example.com'])
        self.assertEqual(coverage['type'], 'exact')
        self.assertEqual(coverage['value'], 'example.com')
        self.assertTrue(coverage['covered_by_wildcard'], "Should be covered by .example.com")

    def test_exact_not_covered(self):
        """Test that exact entry not covered is detected"""
        coverage = entry_coverage('example.com', [], ['.github.com'])
        self.assertEqual(coverage['type'], 'exact')
        self.assertEqual(coverage['value'], 'example.com')
        self.assertFalse(coverage['covered_by_wildcard'], "Should not be covered")

    def test_subdomain_covered_by_wildcard(self):
        """Test that subdomain exact entry is covered by parent wildcard"""
        coverage = entry_coverage('api.example.com', [], ['.example.com'])
        self.assertEqual(coverage['type'], 'exact')
        self.assertEqual(coverage['value'], 'api.example.com')
        self.assertTrue(coverage['covered_by_wildcard'], "Should be covered by .example.com")

    def test_wildcard_duplicate_detected(self):
        """Test that duplicate wildcard is detected"""
        coverage = entry_coverage('*.example.com', [], ['.example.com'])
        self.assertEqual(coverage['type'], 'wildcard')
        self.assertEqual(coverage['value'], '.example.com')
        self.assertTrue(coverage['duplicate'], "Should be detected as duplicate")

    def test_wildcard_not_duplicate(self):
        """Test that new wildcard is not marked as duplicate"""
        coverage = entry_coverage('*.example.com', [], ['.github.com'])
        self.assertEqual(coverage['type'], 'wildcard')
        self.assertEqual(coverage['value'], '.example.com')
        self.assertFalse(coverage['duplicate'], "Should not be duplicate")

    def test_wildcard_covers_exact_apex(self):
        """Test that wildcard covers exact apex domain"""
        coverage = entry_coverage('*.example.com', ['example.com', 'github.com'], [])
        self.assertEqual(coverage['type'], 'wildcard')
        self.assertEqual(coverage['value'], '.example.com')
        self.assertIn('example.com', coverage['covers_exacts'], "Should cover apex domain")
        self.assertNotIn('github.com', coverage['covers_exacts'], "Should not cover unrelated domain")

    def test_wildcard_covers_exact_subdomain(self):
        """Test that wildcard covers exact subdomain entries"""
        coverage = entry_coverage('*.example.com', ['api.example.com', 'www.example.com'], [])
        self.assertEqual(coverage['type'], 'wildcard')
        self.assertIn('api.example.com', coverage['covers_exacts'], "Should cover subdomain")
        self.assertIn('www.example.com', coverage['covers_exacts'], "Should cover subdomain")

    def test_exact_duplicate_detection(self):
        """Test that duplicate exact entry is detected via coverage"""
        coverage = entry_coverage('example.com', ['example.com'], [])
        self.assertEqual(coverage['type'], 'exact')
        self.assertEqual(coverage['value'], 'example.com')
        # Duplicate detection for exact is done by caller checking value in existing_exact


class TestConflictFiltering(unittest.TestCase):
    """Test conflict filtering to prevent Squid ACL errors (Bug A)"""

    def test_filter_microsoft_exact_and_wildcard(self):
        """Test that microsoft.com + .microsoft.com only keeps wildcard"""
        exact, wildcard = filter_conflicts(['microsoft.com'], ['.microsoft.com'])
        self.assertEqual(exact, [], "Exact should be removed when covered by wildcard")
        self.assertEqual(wildcard, ['.microsoft.com'], "Wildcard should remain")

    def test_filter_subdomain_covered_by_wildcard(self):
        """Test that api.github.com is removed when .github.com exists"""
        exact, wildcard = filter_conflicts(['api.github.com', 'example.com'], ['.github.com'])
        self.assertEqual(len(exact), 1, "Only uncovered exact should remain")
        self.assertIn('example.com', exact, "Uncovered exact should remain")
        self.assertNotIn('api.github.com', exact, "Subdomain exact should be removed")
        self.assertEqual(wildcard, ['.github.com'], "Wildcard should remain")

    def test_filter_multiple_exacts_covered(self):
        """Test that multiple exact entries covered by same wildcard are all removed"""
        exact_entries = ['github.com', 'api.github.com', 'www.github.com', 'example.com']
        wildcard_entries = ['.github.com']
        exact, wildcard = filter_conflicts(exact_entries, wildcard_entries)

        self.assertEqual(len(exact), 1, "Only uncovered exact should remain")
        self.assertIn('example.com', exact, "Uncovered exact should remain")
        self.assertNotIn('github.com', exact, "Apex covered by wildcard should be removed")
        self.assertNotIn('api.github.com', exact, "Subdomain covered by wildcard should be removed")
        self.assertNotIn('www.github.com', exact, "Subdomain covered by wildcard should be removed")

    def test_filter_no_wildcards_no_changes(self):
        """Test that with no wildcards, all exact entries remain"""
        exact_entries = ['example.com', 'github.com', 'google.com']
        exact, wildcard = filter_conflicts(exact_entries, [])
        self.assertEqual(exact, exact_entries, "All exact entries should remain when no wildcards")
        self.assertEqual(wildcard, [], "No wildcards")

    def test_filter_no_conflicts(self):
        """Test that non-overlapping exact and wildcard entries both remain"""
        exact_entries = ['example.com', 'google.com']
        wildcard_entries = ['.github.com', '.npmjs.org']
        exact, wildcard = filter_conflicts(exact_entries, wildcard_entries)
        self.assertEqual(len(exact), 2, "Both exact entries should remain")
        self.assertEqual(len(wildcard), 2, "Both wildcard entries should remain")

    def test_write_whitelist_filters_conflicts(self):
        """Test that write_whitelist automatically filters conflicts (microsoft.com + .microsoft.com)"""
        test_dir = tempfile.mkdtemp()
        whitelist_path = os.path.join(test_dir, 'whitelist.txt')

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = whitelist_path

        try:
            # Write both exact and wildcard for same base domain
            write_whitelist(['microsoft.com', '.microsoft.com'])

            # Read back
            entries = read_whitelist()

            # Should only have wildcard, exact should be filtered out
            self.assertEqual(len(entries), 1, "Should have only 1 entry (conflict filtered)")
            self.assertIn('.microsoft.com', entries, "Wildcard should be present")
            self.assertNotIn('microsoft.com', entries, "Exact should be removed to prevent Squid error")

        finally:
            squid_control.WHITELIST_PATH = old_path
            import shutil
            shutil.rmtree(test_dir)

    def test_write_whitelist_filters_subdomain_conflicts(self):
        """Test that write_whitelist filters subdomain conflicts (api.github.com + .github.com)"""
        test_dir = tempfile.mkdtemp()
        whitelist_path = os.path.join(test_dir, 'whitelist.txt')

        import squid_control
        old_path = squid_control.WHITELIST_PATH
        squid_control.WHITELIST_PATH = whitelist_path

        try:
            # Write exact subdomain and wildcard
            write_whitelist(['api.github.com', 'www.github.com', '.github.com', 'example.com'])

            # Read back
            entries = read_whitelist()

            # Should have wildcard and uncovered exact, but not covered exact subdomains
            self.assertEqual(len(entries), 2, "Should have 2 entries (wildcards filter covered exacts)")
            self.assertIn('.github.com', entries, "Wildcard should be present")
            self.assertIn('example.com', entries, "Uncovered exact should be present")
            self.assertNotIn('api.github.com', entries, "Covered subdomain should be removed")
            self.assertNotIn('www.github.com', entries, "Covered subdomain should be removed")

        finally:
            squid_control.WHITELIST_PATH = old_path
            import shutil
            shutil.rmtree(test_dir)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestEmptyWhitelistHandling))
    suite.addTests(loader.loadTestsFromTestCase(TestWhitelistValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestExactVsWildcardSemantics))
    suite.addTests(loader.loadTestsFromTestCase(TestEntryCoverage))
    suite.addTests(loader.loadTestsFromTestCase(TestConflictFiltering))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
