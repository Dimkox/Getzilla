from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from _support import policy_data
from adaptive_trust_ci.customers import add_customer, list_customers, main, remove_customer
from adaptive_trust_ci.holdout import bundle_digest
from adaptive_trust_ci.onboarding import plan_catalog
from adaptive_trust_ci.policy import PolicyCatalog, PolicyError

ROOT = Path(__file__).resolve().parents[2]
GETZILLA_BUNDLE = ROOT / 'trust-ci/holdout.example'
CONSUMER_BUNDLE = ROOT / 'trust-ci/holdout.consumer.example'
HOLDOUT_ROOT = Path('/etc/adaptive-trust-ci/holdout')


def deployed_catalog() -> dict:
    legacy = policy_data(holdout_path=str(HOLDOUT_ROOT), holdout_digest='a' * 64)
    legacy['allowed_repositories'] = ['Dimkox/adaptive-grok-build-pro']  # predecessor-record
    return plan_catalog(legacy, owner='Dimkox', holdout_root=HOLDOUT_ROOT, holdout_host_root=HOLDOUT_ROOT,
                        getzilla_bundle=GETZILLA_BUNDLE, owner_bundle=CONSUMER_BUNDLE)


def add(policy: dict, owner: str) -> dict:
    return add_customer(policy, owner, holdout_root=HOLDOUT_ROOT, holdout_host_root=HOLDOUT_ROOT,
                        bundle=CONSUMER_BUNDLE)


class CustomerPlanTests(unittest.TestCase):
    def test_paying_account_gets_every_repository_with_the_consumer_holdout(self) -> None:
        before = deployed_catalog()
        with self.assertRaisesRegex(PolicyError, 'not configured'):
            PolicyCatalog.from_dict(before).resolve_repository('acme-corp/private-app')
        after = add(before, 'acme-corp')
        catalog = PolicyCatalog.from_dict(after)
        profile = catalog.resolve_repository('acme-corp/private-app')
        self.assertEqual(profile.owner_scope, 'acme-corp')
        self.assertEqual(profile.holdout.digest, bundle_digest(CONSUMER_BUNDLE))
        self.assertEqual(profile.holdout.host_path, HOLDOUT_ROOT / 'owner-acme-corp')
        self.assertEqual(profile.commands[0].argv[1], 'scripts/getzilla_verify.py')
        with self.assertRaisesRegex(PolicyError, 'not configured'):
            catalog.resolve_repository('someone-else/private-app')
        self.assertEqual(list_customers(after), ['Dimkox', 'acme-corp'])

    def test_adding_or_removing_an_account_keeps_every_other_check_name(self) -> None:
        before = deployed_catalog()
        after = add(before, 'acme-corp')
        old, new = PolicyCatalog.from_dict(before), PolicyCatalog.from_dict(after)
        for repository in ('Dimkox/adaptive-grok-build-pro', 'Dimkox/Getzilla', 'Dimkox/new-repo'):  # predecessor-record
            self.assertEqual(old.resolve_repository(repository).check_name,
                             new.resolve_repository(repository).check_name)
        removed = remove_customer(after, 'acme-corp')
        self.assertEqual(PolicyCatalog.from_dict(removed).digest, old.digest)
        with self.assertRaisesRegex(PolicyError, 'not configured'):
            PolicyCatalog.from_dict(removed).resolve_repository('acme-corp/private-app')

    def test_invalid_duplicate_unknown_and_legacy_inputs_are_refused(self) -> None:
        before = deployed_catalog()
        for owner in ('*', 'acme/app', '', 'a b'):
            with self.subTest(owner=owner), self.assertRaisesRegex(PolicyError, 'login'):
                add(before, owner)
        with self.assertRaisesRegex(PolicyError, 'already'):
            add(add(before, 'acme-corp'), 'ACME-corp')
        with self.assertRaisesRegex(PolicyError, 'no Trust CI access'):
            remove_customer(before, 'acme-corp')
        with self.assertRaisesRegex(PolicyError, 'legacy'):
            add(policy_data(), 'acme-corp')

    def test_cli_writes_a_new_file_and_never_touches_the_deployed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deployed = Path(tmp) / 'policy.json'
            deployed.write_text(json.dumps(deployed_catalog()), encoding='utf-8')
            original = deployed.read_bytes()
            out = Path(tmp) / 'policy.next.json'
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                main(['add', '--policy', str(deployed), '--out', str(out), '--owner', 'acme-corp',
                      '--holdout-root', str(HOLDOUT_ROOT), '--holdout-host-root', str(HOLDOUT_ROOT),
                      '--bundle', str(CONSUMER_BUNDLE)])
            self.assertEqual(deployed.read_bytes(), original)
            report = json.loads(buffer.getvalue())
            self.assertEqual(report['install_bundle']['to'], str(HOLDOUT_ROOT / 'owner-acme-corp'))
            self.assertEqual([item['scope'] for item in report['changed_checks']], ['acme-corp/*'])
            self.assertIsNone(report['changed_checks'][0]['check_before'])
            self.assertIn('acme-corp', list_customers(json.loads(out.read_text(encoding='utf-8'))))
            with self.assertRaises(SystemExit):
                main(['remove', '--policy', str(deployed), '--out', str(out), '--owner', 'acme-corp'])


if __name__ == '__main__':
    unittest.main()
