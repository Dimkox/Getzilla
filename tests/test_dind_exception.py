import copy
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_dind_exception as policy


class DindExceptionTests(unittest.TestCase):
    def test_exact_finding_only_during_the_approved_window(self):
        now = datetime(2026, 11, 25, tzinfo=timezone.utc)
        finding = {'id': policy.CVE, 'image': policy.REFERENCE, 'target': 'usr/local/bin/dockerd',
                   'package': 'github.com/docker/distribution', 'version': 'v2.8.3+incompatible'}
        self.assertTrue(policy.matches(finding, policy.MANIFEST, now))
        for key, other in [('id', 'CVE-2026-41567'), ('target', 'usr/local/bin/docker'),
                           ('image', 'other@' + policy.MANIFEST)]:
            self.assertFalse(policy.matches({**finding, key: other}, policy.MANIFEST, now))
        self.assertFalse(policy.matches(finding, 'sha256:' + 'a' * 64, now))
        self.assertFalse(policy.matches(finding, policy.MANIFEST, datetime(2026, 12, 25, tzinfo=timezone.utc)))

    def test_closed_config(self):
        import json
        configured = json.loads((ROOT / policy.FILE).read_bytes())
        policy.validate(configured)
        for change in ({'expires': '2026-12-26'}, {'extra': True}, {'cve': 'CVE-2026-41567'},
                       {'manifest': 'sha256:' + '0' * 64}):
            invalid = copy.deepcopy(configured)
            invalid['exceptions'][0].update(change)
            with self.assertRaises(ValueError):
                policy.validate(invalid)

    def test_upstream_change_or_wrong_catalog_disables_acceptance(self):
        self.assertFalse(policy.same_upstream(b'bad catalog', {}))

    def test_current_producer_and_complete_same_run_inventory_required(self):
        inventory = {'digest': 'a' * 64, 'images': []}
        guard = object()
        live = dict(native_guard=guard, declared_inventory=inventory, dind_exception=True,
                    run={'repository': 'Dimkox/Getzilla'})
        with patch.object(policy.authority, '_GUARD', guard), patch.object(policy.authority, '_LIVE', live):
            self.assertTrue(policy.authorized(inventory))
            self.assertFalse(policy.authorized({**inventory, 'images': ['other']}))
            live['dind_exception'] = False
            self.assertFalse(policy.authorized(inventory))
        self.assertFalse(policy.authorized(inventory))

    def test_catalog_and_registry_platform_digest_must_both_remain_current(self):
        import hashlib
        raw = b'reviewed fixture'
        index = {'schemaVersion': 2, 'manifests': [
            {'platform': {'os': 'linux', 'architecture': 'amd64'}, 'digest': policy.MANIFEST}]}
        with patch.object(policy, 'CATALOG_SHA', hashlib.sha256(raw).hexdigest()):
            self.assertTrue(policy.same_upstream(raw, index))
            self.assertFalse(policy.same_upstream(raw + b'changed', index))
            index['manifests'][0]['digest'] = 'sha256:' + '0' * 64
            self.assertFalse(policy.same_upstream(raw, index))

    def test_only_the_daemon_finding_is_accepted(self):
        from types import SimpleNamespace
        now = datetime(2026, 11, 25, tzinfo=timezone.utc)
        finding = {'id': policy.CVE, 'target': 'usr/local/bin/dockerd', 'image': policy.REFERENCE,
                   'package': 'github.com/docker/distribution', 'version': 'v2.8.3+incompatible'}
        others = [{**finding, 'target': 'usr/local/bin/docker'}, {**finding, 'id': 'GO-2026-5932'}]
        image = SimpleNamespace(platform='linux/amd64', manifest_digest=policy.MANIFEST)
        with patch.object(policy, 'authorized', return_value=True):
            self.assertEqual(policy.partition([finding, *others], image, {}, now), (others, [finding]))
            self.assertEqual(policy.partition([finding], None, {}, now), ([finding], []))
            image.manifest_digest = 'sha256:' + '0' * 64
            self.assertEqual(policy.partition([finding], image, {}, now), ([finding], []))
