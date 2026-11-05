"""Local disclosure depends on real OS ownership and private descriptors."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

try:
    from getzilla import observation_privacy
except ImportError:
    observation_privacy = None


class PrivacyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'.getzilla/runtime').mkdir(parents=True, mode=0o700)
        (self.root/'.getzilla').chmod(0o755)
        self.path = self.root/'.getzilla/runtime/metrics.jsonl'
        self.path.write_text(json.dumps({'event': 'route', 'route_id': 'private-sentinel'})+'\n')
        self.path.chmod(0o600)

    def load(self):
        self.assertIsNotNone(observation_privacy, 'native privacy reader is missing')
        return observation_privacy.load_local(self.root)

    def test_private_local_owner_can_read_bounded_rows(self):
        result = self.load()
        self.assertEqual(result['access'], 'local_owner')
        self.assertEqual(result['events'][0]['event'], 'route')
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_public_parent_or_journal_returns_metadata_only_without_ids(self):
        for path in (self.path, self.path.parent):
            original = path.stat().st_mode & 0o777
            path.chmod(0o644 if path == self.path else 0o755)
            result = self.load()
            self.assertEqual(result['access'], 'metadata_only')
            self.assertNotIn('private-sentinel', json.dumps(result))
            path.chmod(original)

    def test_symlink_and_hardlink_are_refused(self):
        self.path.unlink()
        target = self.root/'outside'
        target.write_text('private-sentinel')
        self.path.symlink_to(target)
        self.assertEqual(self.load()['access'], 'metadata_only')
        self.path.unlink()
        os.link(target, self.path)
        self.assertEqual(self.load()['access'], 'metadata_only')

    def test_owner_initialization_is_private_without_upgrading_legacy_authenticity(self):
        self.assertIsNotNone(observation_privacy)
        self.path.parent.chmod(0o755)
        observation_privacy.initialize_private(self.root)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        result = self.load()
        self.assertNotEqual(result['events'][0].get('schema_version'), 3)
        self.assertNotIn('private-sentinel', json.dumps(result))

    def test_foreign_project_payload_cannot_claim_local_disclosure_permission(self):
        from tests.test_trace_contracts import observation
        self.path.write_text(json.dumps(observation())+'\n')
        result = self.load()
        self.assertEqual(result['events'], [])
        self.assertIn('project_binding_mismatch', result['gaps'])


if __name__ == '__main__':
    unittest.main()
