"""Z05 sensitive-file policy, Z06 fail-closed secret scanner, Z07 immutable admission plan."""
from __future__ import annotations

import gzip
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import source_secrets  # noqa: E402
from getzilla.source_admission import (  # noqa: E402
    classify_entries, plan_source, redact_findings, sensitive_class, validate_plan_approval,
)
from getzilla.source_inventory import inventory_source  # noqa: E402
from getzilla.source_models import FalsePositiveException, IngestPolicy, validate_source_record  # noqa: E402
from tests.zero_git_support import (  # noqa: E402
    FAKE_AWS_ID, FAKE_GITHUB_TOKEN, FAKE_PRIVATE_KEY, clean_source, tree_state, write_tree,
)


class _Case(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix='zg-admission-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.target = self.base / 'adopted'

    def codes(self, plan) -> set[tuple[str, str]]:
        return {(item.path, item.reason_code) for item in plan.blockers}


class SensitivePolicyTests(_Case):
    def test_env_and_private_key_are_blocked_candidates(self) -> None:
        source = write_tree(self.base / 'src', {'.env': 'X=1', 'certs/server.key': 'k', 'id_ed25519': 'k',
                                                 'id_ed25519.pub': 'ssh-ed25519 AAAA', 'app.py': 'x=1'})
        classified = classify_entries(inventory_source(source, IngestPolicy()), IngestPolicy())
        blocked = {(item.path, item.reason_code) for item in classified.blockers}
        self.assertEqual(blocked, {('.env', 'SENSITIVE_ENV_FILE'), ('certs/server.key', 'SENSITIVE_KEY_MATERIAL'),
                                   ('id_ed25519', 'SENSITIVE_KEY_MATERIAL')})
        self.assertEqual([entry.path for entry in classified.candidates], ['app.py', 'id_ed25519.pub'])

    def test_renamed_secret_file_not_implicitly_safe(self) -> None:
        source = write_tree(self.base / 'src', {'notes.txt': FAKE_PRIVATE_KEY, 'app.py': 'x=1'})
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.status, 'BLOCKED_SECURITY')
        self.assertIn(('notes.txt', 'SECRET_PATTERN'), self.codes(plan))

    def test_exclusions_are_visible(self) -> None:
        source = write_tree(self.base / 'src', {'.env': 'X=1', 'app.py': 'x=1'})
        plan = plan_source(source, self.target, IngestPolicy(exclude=('.env',)))
        self.assertEqual(plan.status, 'PLAN_READY', plan.blockers)
        self.assertEqual([(item.path, item.reason_code) for item in plan.exclusions], [('.env', 'POLICY_EXCLUDED')])
        self.assertEqual([entry.path for entry in plan.entries], ['app.py'])

    def test_findings_do_not_include_contents_or_secret_hash(self) -> None:
        source = write_tree(self.base / 'src', {'config.py': f'TOKEN = "{FAKE_GITHUB_TOKEN}"\n'})
        plan = plan_source(source, self.target, IngestPolicy())
        exported = json.dumps(plan.to_dict())
        self.assertNotIn(FAKE_GITHUB_TOKEN, exported)
        self.assertNotIn(FAKE_GITHUB_TOKEN[4:20], exported)
        import hashlib
        self.assertNotIn(hashlib.sha256(FAKE_GITHUB_TOKEN.encode()).hexdigest(), exported)
        self.assertIn({'path': 'config.py', 'reason_code': 'SECRET_PATTERN', 'rule_id': 'github-token', 'line': 1},
                      redact_findings(plan.blockers))
        for finding in redact_findings(plan.blockers):
            self.assertLessEqual(set(finding), {'path', 'reason_code', 'rule_id', 'line'})

    def test_generated_tree_not_silently_ignored(self) -> None:
        source = write_tree(self.base / 'src', {'node_modules/x/index.js': 'x', 'dist/a.js': 'y', 'app.py': 'z'})
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(sorted(entry.path for entry in plan.entries), ['app.py', 'dist/a.js', 'node_modules/x/index.js'])

    def test_global_ignore_all_findings_rejected(self) -> None:
        from getzilla.source_models import ContractError
        with self.assertRaises(ContractError):
            FalsePositiveException(path='a', rule_id='*', sha256='0' * 64)

    def test_example_env_is_content_scanned(self) -> None:
        self.assertIsNone(sensitive_class('.env.example'))
        source = write_tree(self.base / 'src', {'.env.example': f'AWS_KEY={FAKE_AWS_ID}\n'})
        self.assertIn(('.env.example', 'SECRET_PATTERN'), self.codes(plan_source(source, self.target, IngestPolicy())))


class SecretScannerTests(_Case):
    def test_signature_in_unexpected_extension_blocks(self) -> None:
        source = write_tree(self.base / 'src', {'image.png': b'\x89PNG\r\n' + FAKE_PRIVATE_KEY.encode()})
        self.assertIn(('image.png', 'SECRET_PATTERN'), self.codes(plan_source(source, self.target, IngestPolicy())))

    def test_scanner_missing_is_error(self) -> None:
        source = clean_source(self.base / 'src')
        with mock.patch.object(source_secrets, 'read_entry', return_value=(None, 'SCANNER_UNAVAILABLE')):
            plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.status, 'ERROR')
        self.assertEqual(plan.scan['status'], 'error')

    def test_timeout_or_partial_scan_is_not_pass(self) -> None:
        source = clean_source(self.base / 'src')
        real = source_secrets.read_entry
        calls = []

        def partial(root, entry, limit):
            calls.append(entry.path)
            if len(calls) == 2:
                return None, 'SCAN_TIMEOUT'
            return real(root, entry, limit)

        with mock.patch.object(source_secrets, 'read_entry', side_effect=partial):
            plan = plan_source(source, self.target, IngestPolicy())
        self.assertNotEqual(plan.status, 'PLAN_READY')
        self.assertNotEqual(plan.scan['status'], 'pass')

    def test_opaque_archive_requires_exclusion_or_supported_scan(self) -> None:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('inner.txt', 'x')
        source = write_tree(self.base / 'src', {'data.bin': buffer.getvalue(), 'blob.dat': gzip.compress(b'abc'),
                                                 'app.py': 'x=1'})
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.status, 'BLOCKED_SECURITY')
        self.assertTrue({('data.bin', 'OPAQUE_CONTAINER_REQUIRES_EXCLUSION'),
                         ('blob.dat', 'OPAQUE_CONTAINER_REQUIRES_EXCLUSION')} <= self.codes(plan))
        excluded = plan_source(source, self.target, IngestPolicy(exclude=('data.bin', 'blob.dat')))
        self.assertEqual(excluded.status, 'PLAN_READY')

    def test_rules_digest_bound_to_result(self) -> None:
        source = clean_source(self.base / 'src')
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.scan['rules_digest'], source_secrets.rules_digest())
        with mock.patch.object(source_secrets, 'RULES', source_secrets.RULES[:-1]):
            self.assertNotEqual(source_secrets.rules_digest(), plan.scan['rules_digest'])

    def test_no_plaintext_spool_or_log(self) -> None:
        source = write_tree(self.base / 'src', {'config.py': f'TOKEN = "{FAKE_GITHUB_TOKEN}"\n'})
        outside_before = tree_state(self.base)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch('sys.stdout', stdout), mock.patch('sys.stderr', stderr):
            plan_source(source, self.target, IngestPolicy())
        self.assertEqual(tree_state(self.base), outside_before)
        self.assertNotIn(FAKE_GITHUB_TOKEN, stdout.getvalue() + stderr.getvalue())

    def test_narrow_exception_does_not_cover_changed_file(self) -> None:
        source = write_tree(self.base / 'src', {'tests/fixture.py': 'password = "not-a-real-password-123"\n'})
        blocked = plan_source(source, self.target, IngestPolicy())
        self.assertIn(('tests/fixture.py', 'SECRET_PATTERN'), self.codes(blocked))
        digest = inventory_source(source, IngestPolicy()).entries[0].sha256
        exception = FalsePositiveException(path='tests/fixture.py', rule_id='generic-assignment', sha256=digest)
        policy = IngestPolicy(exceptions=(exception,))
        self.assertEqual(plan_source(source, self.target, policy).status, 'PLAN_READY')
        (source / 'tests/fixture.py').write_text('password = "another-not-real-password"\n', encoding='utf-8')
        self.assertEqual(plan_source(source, self.target, policy).status, 'BLOCKED_SECURITY')


class AdmissionPlanTests(_Case):
    def test_plan_is_read_only(self) -> None:
        source = clean_source(self.base / 'src')
        before = tree_state(self.base)
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.status, 'PLAN_READY', plan.blockers)
        self.assertEqual(tree_state(self.base), before)
        self.assertFalse(self.target.exists())
        self.assertTrue(validate_source_record(plan.to_dict()).ok)

    def test_plan_id_changes_on_exclusion_or_policy(self) -> None:
        source = write_tree(self.base / 'src', {'a.txt': 'a', 'b.txt': 'b'})
        first = plan_source(source, self.target, IngestPolicy())
        excluded = plan_source(source, self.target, IngestPolicy(exclude=('b.txt',)))
        limited = plan_source(source, self.target, IngestPolicy(max_files=10))
        self.assertEqual(len({first.plan_id, excluded.plan_id, limited.plan_id}), 3)
        self.assertEqual(first.plan_id, plan_source(source, self.target, IngestPolicy()).plan_id)

    def test_wrong_plan_digest_rejected(self) -> None:
        plan = plan_source(clean_source(self.base / 'src'), self.target, IngestPolicy())
        self.assertTrue(validate_plan_approval(plan, plan.plan_id).ok)
        self.assertIn('PLAN_DIGEST_MISMATCH', validate_plan_approval(plan, '0' * 64).errors)

    def test_failed_scan_cannot_create_ready_plan(self) -> None:
        source = write_tree(self.base / 'src', {'a.py': f'k = "{FAKE_GITHUB_TOKEN}"'})
        plan = plan_source(source, self.target, IngestPolicy())
        self.assertEqual(plan.status, 'BLOCKED_SECURITY')
        self.assertFalse(validate_plan_approval(plan, plan.plan_id).ok)
        self.assertEqual(plan.entries, ())
        self.assertIsNone(plan.source_digest)

    def test_empty_allowlist_blocked(self) -> None:
        source = write_tree(self.base / 'src', {'only.txt': 'x'})
        plan = plan_source(source, self.target, IngestPolicy(exclude=('only.txt',)))
        self.assertIn(('.', 'SOURCE_EMPTY_ALLOWLIST'), self.codes(plan))
        self.assertNotEqual(plan.status, 'PLAN_READY')

    def test_target_inside_source_blocked(self) -> None:
        source = clean_source(self.base / 'src')
        plan = plan_source(source, source / 'adopted', IngestPolicy())
        self.assertIn(('<target>', 'TARGET_INSIDE_SOURCE'), self.codes(plan))
        existing = self.base / 'existing'
        existing.mkdir()
        self.assertIn(('<target>', 'TARGET_EXISTS'), self.codes(plan_source(source, existing, IngestPolicy())))


if __name__ == '__main__':
    unittest.main()
