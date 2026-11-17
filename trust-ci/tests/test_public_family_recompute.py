"""NEW owned data controls; accepted-checker execution is an explicit mocked seam."""
from datetime import datetime, timezone
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from adaptive_trust_ci import public_admission as admission
from adaptive_trust_ci import public_producer as producer
from adaptive_trust_ci import security_bundle as bundle
ACTIVE = False


def guard(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('os.', 'socket.', 'subprocess.', 'ctypes.', 'shutil.'))):
        raise AssertionError('new fixture denies Root/native/network/outside I/O')


sys.addaudithook(guard)
NAMES = ('security-inventory', 'known-vulnerabilities', 'security-kev', 'security-epss',
         'security-malicious-packages', 'security-licenses', 'security-container-images',
         'opengrep', 'secret-scan', 'bandit', 'trivy-config')


class FullFamilyRecomputation(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.calls = []
        self.inventory = {'digest': 'a' * 64, 'images': []}
        self.report = {'schema_version': 1, 'kind': 'security-expanded', 'status': 'pass',
            'qualification_gaps': [], 'inventory_sha256': 'a' * 64, 'policy_sha256': 'b' * 64,
            'checks': [{'name': name, 'status': 'pass', 'details': [{'kind': 'owned-new-data'}]} for name in NAMES]}
        def execute(*args, **kwargs):
            self.calls.append((args, kwargs))
            return self.report
        self.core = SimpleNamespace(report=SimpleNamespace(evaluate=execute, REQUIRED_CHECKS=NAMES),
            inventory=SimpleNamespace(collect_inventory=lambda root: self.inventory),
            security=SimpleNamespace(_policy_digest=lambda root: 'b' * 64), policy_root=Path('/UNREAD-checker'))
    def guarded(self, callback):
        global ACTIVE
        ACTIVE = True
        try:
            return callback()
        finally:
            ACTIVE = False
    def run_fixture(self):
        return admission.recompute_family_checks(self.core, Path('/UNREAD-source'), Path('/UNREAD-snapshots'),
                                                 self.inventory, now=self.now)
    def test_every_family_is_recomputed_from_explicit_snapshots(self):
        value = self.guarded(self.run_fixture)
        self.assertEqual(set(value), set(NAMES))
        self.assertEqual(len(self.calls), 1)
        args, kwargs = self.calls[0]
        self.assertEqual(args[1:], tuple(Path('/UNREAD-snapshots') / name for name in ('database', 'artifacts', 'tools')))
        self.assertEqual(kwargs, {'refresh': False, 'provision': False, 'now': self.now})
    def test_missing_family_cannot_be_replaced_by_supplied_claim(self):
        self.report['checks'].pop()
        with self.assertRaises(bundle.BundleError):
            self.guarded(self.run_fixture)
    def test_failed_actual_evaluation_remains_refused(self):
        self.report['status'] = 'fail'
        with self.assertRaises(bundle.BundleError):
            self.guarded(self.run_fixture)
    def test_image_family_refuses_missing_accepted_contract_before_legacy_daemon(self):
        self.inventory['images'] = [{'owned': 'explicit-image'}]
        with self.assertRaisesRegex(bundle.BundleError, '^accepted-independent-image-evaluator-unavailable$'):
            self.guarded(self.run_fixture)
        self.assertEqual(self.calls, [])
    def test_offline_checker_never_forges_candidate_as_actual_runner_head(self):
        self.guarded(lambda: producer.run_checker(self.core, object(), object(), Path('/UNREAD-source'),
            Path('/UNREAD-snapshots'), image_artifacts=None, now=self.now))
        self.assertNotIn('run', self.calls[0][1])
        self.assertNotIn('profile', self.calls[0][1])
    def test_positive_compliance_records_are_preserved_and_not_vulnerability_counts(self):
        marker = {'outcome': 'pass', 'findings': [{'owned': 'positive-record'}]}
        for name in ('security-licenses', 'security-epss'):
            self.assertEqual(self.guarded(lambda: bundle.result_finding_count(name, marker)), 0)
        self.assertEqual(self.guarded(lambda: bundle.result_finding_count('known-vulnerabilities', marker)), 1)
        self.assertEqual(marker['findings'], [{'owned': 'positive-record'}])


if __name__ == '__main__':
    unittest.main()
