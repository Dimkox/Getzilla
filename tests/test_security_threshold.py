"""Owner decision #456 applies to vulnerability findings after complete coverage."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import security_image_authority as authority
from getzilla import security_threshold as policy
from getzilla import security_osv_snapshot as osv


class AdmissionTests(unittest.TestCase):
    def test_published_fix_changes_the_next_decision(self):
        f = dict(id='CVE-2026-12345', package='lib', version='1', severity='HIGH', fixed='')
        self.assertFalse(policy.blocks_vulnerability(f))
        self.assertTrue(policy.blocks_vulnerability(dict(f, fixed='2')))
        self.assertFalse(policy.blocks_vulnerability(dict(f, fixed=['2'], severity='MODERATE')))
        self.assertTrue(policy.blocks_vulnerability(dict(f, fixed=None)))

    def test_base_file_requires_every_other_image_and_every_use(self):
        inv = dict(complete=True, builds=[dict(dockerfile='Dockerfile')],
                   images=[dict(reference='base', manifest='Dockerfile'), dict(reference='app', manifest='compose.yaml')])
        guard = object()
        app = ({}, set(), set())
        live = dict(native_guard=guard, declared_inventory=inv, builds={'recipe': 'app'},
                    threshold_filesystems={'base': ({'bin/a': 'hash'}, {'hash'}, set()), 'app': app})
        row = dict(image='base', target='bin/a')
        with mock.patch.object(authority, '_LIVE', live), mock.patch.object(authority, '_GUARD', guard):
            self.assertTrue(policy.removed_from_finals(row, inv))
            app[1].add('hash')
            self.assertFalse(policy.removed_from_finals(row, inv))
            app[1].clear()
            app[0]['bin/a'] = 'different'
            self.assertFalse(policy.removed_from_finals(row, inv))
            app[0].clear()
            inv['images'].append(dict(reference='base', manifest='compose.yaml'))
            self.assertFalse(policy.removed_from_finals(row, inv))

    def test_osv_packagist_release_tags_and_ecosystem_ranges(self):
        entry = dict(package=dict(ecosystem='Packagist', name='phpunit/phpunit'),
                     versions=['13.4.0','13.4.1','13.4.2','13.4.3'],
                     ranges=[dict(type='ECOSYSTEM', events=[dict(introduced='13.4.0'),dict(fixed='13.4.4')])])
        self.assertTrue(osv._in_ranges('v13.4.3.0', entry))
        self.assertTrue(osv._in_ranges('13.4.4-RC1', entry))
        self.assertFalse(osv._in_ranges('13.4.4', entry))
        with self.assertRaises(osv.VulnerabilityError):
            osv._in_ranges('dev-main', entry)
