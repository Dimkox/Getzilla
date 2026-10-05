from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from _support import policy_data
from adaptive_trust_ci.holdout import bundle_digest
from adaptive_trust_ci.onboarding import main, plan_catalog
from adaptive_trust_ci.policy import Policy, PolicyCatalog

ROOT = Path(__file__).resolve().parents[2]
GETZILLA_BUNDLE = ROOT / 'trust-ci/holdout.example'
OWNER_BUNDLE = ROOT / 'trust-ci/holdout.consumer.example'
HOLDOUT_ROOT = Path('/etc/adaptive-trust-ci/holdout')


def legacy_policy() -> dict:
    data = policy_data(holdout_path=str(HOLDOUT_ROOT), holdout_digest='a' * 64)
    data['allowed_repositories'] = ['Dimkox/adaptive-grok-build-pro']  # predecessor-record
    return data


class OnboardingPlanTests(unittest.TestCase):
    def _plan(self, deployed: dict) -> dict:
        return plan_catalog(
            deployed,
            owner='Dimkox',
            holdout_root=HOLDOUT_ROOT,
            holdout_host_root=HOLDOUT_ROOT,
            getzilla_bundle=GETZILLA_BUNDLE,
            owner_bundle=OWNER_BUNDLE,
        )

    def test_legacy_policy_becomes_a_catalog_with_unchanged_commands_and_holdout_digest(self) -> None:
        deployed = legacy_policy()
        planned = self._plan(deployed)
        catalog = PolicyCatalog.from_dict(planned)
        legacy = Policy.from_dict(deployed)
        kept = catalog.resolve_repository('Dimkox/adaptive-grok-build-pro')  # predecessor-record
        self.assertEqual([item.to_dict() for item in kept.commands], [item.to_dict() for item in legacy.commands])
        self.assertEqual(kept.holdout.digest, legacy.holdout.digest)
        self.assertEqual(kept.holdout.path, HOLDOUT_ROOT / 'adaptive-grok-build-pro')  # predecessor-record
        getzilla = catalog.resolve_repository('Dimkox/Getzilla')
        self.assertEqual(getzilla.holdout.digest, bundle_digest(GETZILLA_BUNDLE))
        self.assertEqual(getzilla.commands[-1].argv[1], 'scripts/getzilla_verify.py')
        anyone = catalog.resolve_repository('Dimkox/brand-new-repository')
        self.assertEqual(anyone.owner_scope, 'Dimkox')
        self.assertEqual(anyone.holdout.digest, bundle_digest(OWNER_BUNDLE))
        with self.assertRaises(Exception):
            catalog.resolve_repository('stranger/project')

    def test_existing_catalog_profiles_keep_their_epochs(self) -> None:
        first = self._plan(legacy_policy())
        before = PolicyCatalog.from_dict(first).resolve_repository('Dimkox/adaptive-grok-build-pro').check_name  # predecessor-record
        second = self._plan(first)
        after = PolicyCatalog.from_dict(second)
        self.assertEqual(after.resolve_repository('Dimkox/adaptive-grok-build-pro').check_name, before)  # predecessor-record
        self.assertEqual(len(second['owner_profiles']), 1)
        self.assertEqual([item['repository'] for item in second['repository_profiles']].count('Dimkox/Getzilla'), 1)

    def test_cli_writes_a_new_file_and_reports_epochs_without_touching_the_deployed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deployed = Path(tmp) / 'policy.json'
            deployed.write_text(json.dumps(legacy_policy()), encoding='utf-8')
            original = deployed.read_bytes()
            out = Path(tmp) / 'policy.catalog.json'
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(['--policy', str(deployed), '--out', str(out),
                      '--holdout-root', str(HOLDOUT_ROOT), '--holdout-host-root', str(HOLDOUT_ROOT),
                      '--getzilla-bundle', str(GETZILLA_BUNDLE), '--owner-bundle', str(OWNER_BUNDLE),
                      '--repository', 'Dimkox/brand-new-repository'])
            self.assertEqual(deployed.read_bytes(), original)
            report = json.loads(buffer.getvalue())
            epochs = {item['repository']: item for item in report['epochs']}
            self.assertTrue(epochs['Dimkox/adaptive-grok-build-pro']['rerun_branch_protect'])  # predecessor-record
            self.assertIsNone(epochs['Dimkox/Getzilla']['check_before'])
            self.assertIsNone(epochs['Dimkox/brand-new-repository']['check_before'])
            self.assertEqual(len(report['holdout_bundles']), 3)
            PolicyCatalog.load(out)
            with self.assertRaises(SystemExit):
                with redirect_stdout(io.StringIO()):
                    main(['--policy', str(deployed), '--out', str(out),
                          '--holdout-root', str(HOLDOUT_ROOT), '--holdout-host-root', str(HOLDOUT_ROOT),
                          '--getzilla-bundle', str(GETZILLA_BUNDLE), '--owner-bundle', str(OWNER_BUNDLE)])


if __name__ == '__main__':
    unittest.main()
