"""Z01: source/admission/adoption contracts."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.source_models import (  # noqa: E402
    AdmissionPlan, ContractError, GitIdentity, IngestPolicy, ScanReport, SourceEntry, validate_source_record,
)

DIGEST = 'a' * 64


def _receipt(**overrides):
    record = {'schema_version': 'adoption-receipt-v1', 'operation_id': 'op-' + '0' * 32, 'state': 'SNAPSHOT_VERIFIED',
              'source_digest': DIGEST, 'source_baseline': {'object_format': 'sha1', 'commit_oid': None, 'tree_oid': None},
              'git_present_at_ingest': False, 'integrity_status': 'not_verified', 'project_health_status': 'not_run'}
    record.update(overrides)
    return record


class SourceModelTests(unittest.TestCase):
    def test_pre_git_record_accepts_null_git_identity(self) -> None:
        self.assertTrue(validate_source_record(_receipt()).ok)
        identity = GitIdentity('sha1')
        self.assertIsNone(identity.commit_oid)

    def test_committed_state_requires_oid(self) -> None:
        result = validate_source_record(_receipt(state='SOURCE_BASELINE_COMMITTED'))
        self.assertFalse(result.ok)
        committed = _receipt(state='SOURCE_BASELINE_COMMITTED',
                             source_baseline={'object_format': 'sha1', 'commit_oid': 'b' * 40, 'tree_oid': 'c' * 40})
        self.assertTrue(validate_source_record(committed).ok, validate_source_record(committed).errors)
        with self.assertRaises(ContractError):
            GitIdentity('sha1', commit_oid='b' * 64, tree_oid='c' * 64)

    def test_source_digest_is_sha256_not_git_oid(self) -> None:
        self.assertFalse(validate_source_record(_receipt(source_digest='b' * 40)).ok)
        with self.assertRaises(ContractError):
            SourceEntry(path='a', executable=False, size=1, sha256='b' * 40)

    def test_scan_error_cannot_validate_as_admitted(self) -> None:
        with self.assertRaises(ContractError):
            ScanReport(status='pass', scanner='s', scanner_version='1', rules_digest=DIGEST, files_scanned=0,
                       bytes_scanned=0, candidates=1)
        error = ScanReport(status='error', scanner='s', scanner_version='1', rules_digest=DIGEST, files_scanned=0,
                           bytes_scanned=0, candidates=1)
        policy = IngestPolicy()
        plan = AdmissionPlan(status='PLAN_READY', source_root='/s', target='/t', source_digest=DIGEST,
                             path_profile='portable-v1', executable_mode='posix-mode',
                             entries=(SourceEntry('a', False, 0, DIGEST),), exclusions=(), blockers=(),
                             policy=policy.to_dict(), policy_digest=policy.digest(), scan=error.to_dict(),
                             capabilities={})
        plan = AdmissionPlan(**{**plan.__dict__, 'plan_id': plan.compute_id()})
        self.assertFalse(validate_source_record(plan.to_dict()).ok)

    def test_nonpositive_limits_rejected(self) -> None:
        for name in ('max_file_bytes', 'max_files', 'max_total_bytes', 'max_depth'):
            for value in (0, -1):
                with self.subTest(name=name, value=value), self.assertRaises(ContractError):
                    IngestPolicy(**{name: value})

    def test_memory_buffer_limits_required(self) -> None:
        with self.assertRaises(ContractError):
            IngestPolicy(max_buffered_file_bytes=0)
        with self.assertRaises(ContractError):
            IngestPolicy(max_buffered_file_bytes=2, max_total_buffer_bytes=1)
        self.assertGreater(IngestPolicy().to_dict()['max_total_buffer_bytes'], 0)

    def test_unknown_schema_rejected(self) -> None:
        self.assertFalse(validate_source_record({'schema_version': 'source-baseline-v9'}).ok)
        with self.assertRaises(ContractError):
            IngestPolicy.from_dict({'unknown_field': 1})

    def test_global_ignore_is_not_an_exclusion(self) -> None:
        for pattern in ('*', '**', '**/*', ''):
            with self.subTest(pattern=pattern), self.assertRaises(ContractError):
                IngestPolicy(exclude=(pattern,))

    def test_policy_digest_changes_with_exclusions(self) -> None:
        self.assertNotEqual(IngestPolicy().digest(), IngestPolicy(exclude=('dist',)).digest())


if __name__ == '__main__':
    unittest.main()
