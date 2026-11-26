"""Composer release identity in the two offline OSV consumers."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import known_vulns, security_osv_snapshot  # noqa: E402


class PackagistVersionTests(unittest.TestCase):
    def test_numeric_release_tags_and_prereleases(self):
        for scanner in (known_vulns, security_osv_snapshot):
            for installed, listed, expected in (
                ('v5.9.0', '5.9.0.0', True), ('11.5.58', '11.5.50', False),
                ('v1.2.0-beta.2', '1.2.0.0-b2', True), ('1.2-RC1', '1.2.0', False),
                ('1.2.3.4', 'v1.2.3', False), ('1.0-p1', '1.0.0.0-pl1', True),
            ):
                with self.subTest(scanner=scanner.__name__, installed=installed, listed=listed):
                    self.assertEqual(scanner._in_ranges(installed, {'versions': [listed]}, ecosystem='Packagist'), expected)

    def test_ecosystem_range_and_enumeration_are_both_checked(self):
        # The 11.x range is published in GHSA-vvj3-c3rp-c85p for phpunit/phpunit.
        affected = {'versions': ['11.0.0'], 'ranges': [{'type': 'ECOSYSTEM', 'events': [
            {'introduced': '11.0.0'}, {'fixed': '11.5.50'}]}]}
        for scanner in (known_vulns, security_osv_snapshot):
            for version, expected in [('11.5.50-RC1', True), ('v11.5.50.0', False), ('11.5.58', False)]:
                with self.subTest(scanner=scanner.__name__, version=version):
                    self.assertEqual(scanner._in_ranges(version, affected, ecosystem='Packagist'), expected)
            for bad in ({'versions': ['11.0.0', 'dev-feature']},
                        {'versions': ['11.0.0'], 'ranges': [{'type': 'GIT', 'events': [{'introduced': '0'}]}]}):
                with self.subTest(scanner=scanner.__name__, bad=bad), self.assertRaises(scanner.VulnerabilityError):
                    scanner._in_ranges('11.0.0', bad, ecosystem='Packagist')
