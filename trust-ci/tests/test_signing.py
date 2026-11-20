from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

from _support import digest, now, sha
from adaptive_trust_ci.models import ApprovalEnvelope, ApprovalPayload, AttestationEnvelope, AttestationPayload, CommandResult
from adaptive_trust_ci.signing import ApprovalError, Signer, TrustStore, sign_approval, sign_attestation, verify_approval, verify_attestation
from adaptive_trust_ci.store import MemoryStore, ReplayError


class SigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.signer = Signer.generate()
        self.store = TrustStore.from_dict(
            {
                "schema_version": 1,
                "keys": [
                    {
                        "key_id": self.signer.key_id,
                        "actor": "dmitry",
                        "scopes": ["governance", "database"],
                        "public_key_pem": self.signer.public_key_pem().decode(),
                    }
                ],
            }
        )
        self.payload = ApprovalPayload.new(
            actor="dmitry",
            key_id=self.signer.key_id,
            repository="Dimkox/Getzilla",
            pr_number=42,
            base_sha=sha("a"),
            head_sha=sha("b"),
            policy_digest=digest("c"),
            scope="governance",
            reason="reviewed exact governance diff",
            now=now(),
            ttl_seconds=900,
        )
        self.envelope = sign_approval(self.payload, self.signer)

    def verify(self, envelope=None, **overrides):
        values = {
            "expected_repository": self.payload.repository,
            "expected_pr_number": self.payload.pr_number,
            "expected_base_sha": self.payload.base_sha,
            "expected_head_sha": self.payload.head_sha,
            "expected_policy_digest": self.payload.policy_digest,
            "now": now() + timedelta(seconds=1),
            "max_ttl_seconds": 1800,
        }
        values.update(overrides)
        return verify_approval(envelope or self.envelope, self.store, **values)

    def test_valid_signature_verifies(self) -> None:
        self.assertEqual(self.verify().approval_id, self.payload.approval_id)

    def test_optional_command_argv_roundtrip_and_tampering(self) -> None:
        command_args = ('python3', 'scripts/getzilla_audit_bundle.py', '--ci-check')
        for argv in (None, command_args):
            with self.subTest(argv=argv):
                command = CommandResult('eu-ai-act-audit', 'pass', 0, 0.125, 'untrusted output', '', digest('d'), argv)
                result_data = command.attestation_dict()
                expected = {'name': 'eu-ai-act-audit', 'status': 'pass', 'exit_code': 0,
                            'duration_seconds': 0.125, 'output_sha256': digest('d')}
                if argv is not None:
                    expected['argv'] = list(argv)
                self.assertEqual(result_data, expected)
                payload = AttestationPayload(
                    schema_version=2 if argv is not None else 1, attestation_id='argv-attestation', job_id='argv-job',
                    repository='Dimkox/Getzilla', pr_number=42, base_sha=sha('a'), head_sha=sha('b'),
                    policy_digest=digest('c'), status='passed', command_results=(result_data,),
                    changed_files=(), approved_scopes=(), started_at=now().isoformat(),
                    completed_at=now().isoformat(), key_id=self.signer.key_id,
                )
                original = sign_attestation(payload, self.signer).to_dict()
                decoded = AttestationEnvelope.from_dict(json.loads(json.dumps(original)))
                memory = MemoryStore()
                memory.record_attestation('argv-job', decoded)
                stored = memory.get_attestation('argv-job')
                assert stored is not None
                self.assertEqual(stored.to_dict(), original)
                verified = verify_attestation(stored, self.signer.public_key_pem())
                self.assertEqual(verified.command_results, (expected,))
                tampered = json.loads(json.dumps(original))
                tampered['payload']['command_results'][0]['argv'] = ['python3', 'different.py']
                with self.assertRaisesRegex(ApprovalError, 'signature'):
                    verify_attestation(AttestationEnvelope.from_dict(tampered), self.signer.public_key_pem())

    def _v2_attestation_data(self) -> dict:
        return {
            'schema_version': 2, 'attestation_id': 'v2-attestation', 'job_id': 'v2-job',
            'repository': 'Dimkox/Getzilla', 'pr_number': 42,
            'base_sha': sha('a'), 'head_sha': sha('b'), 'policy_digest': digest('c'),
            'status': 'passed', 'command_results': [{
                'name': 'eu-ai-act-audit', 'status': 'pass', 'exit_code': 0,
                'duration_seconds': 0.1, 'output_sha256': digest('d'),
                'argv': ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check'],
            }], 'changed_files': [], 'approved_scopes': [],
            'started_at': now().isoformat(), 'completed_at': now().isoformat(),
            'key_id': self.signer.key_id, 'spec_digest': None,
            'criterion_coverage': {'spec_count': 0, 'criterion_total': 0, 'criterion_mapped': 0, 'unmapped_ids': []},
        }

    def test_attestation_versions_are_strict_integers(self) -> None:
        for version in (True, False, '1', '2', None, 0, 3, 1.0, 2.0):
            with self.subTest(version=version):
                data = self._v2_attestation_data()
                data['schema_version'] = version
                with self.assertRaisesRegex(ValueError, 'schema_version'):
                    AttestationPayload.from_dict(data)

    def test_v2_argv_bounds_and_null_spec_digest(self) -> None:
        for argv in (['python3'], ['x' * 4096] * 128):
            with self.subTest(count=len(argv), length=len(argv[0])):
                data = self._v2_attestation_data()
                data['command_results'][0]['argv'] = argv
                payload = AttestationPayload.from_dict(data)
                self.assertEqual(payload.schema_version, 2)
                self.assertIsNone(payload.spec_digest)
                self.assertEqual(payload.to_dict(), data)
        data = self._v2_attestation_data()
        del data['command_results'][0]['argv']
        self.assertEqual(AttestationPayload.from_dict(data).to_dict(), data)

    def test_v2_argv_rejects_malformed_or_excessive_arguments(self) -> None:
        for argv in (None, [], 'python3', [''], [1], [True], ['x' * 4097], ['x'] * 129, {}):
            with self.subTest(kind=type(argv).__name__, count=len(argv) if isinstance(argv, list) else None):
                data = self._v2_attestation_data()
                data['command_results'][0]['argv'] = argv
                with self.assertRaisesRegex(ValueError, 'argv'):
                    AttestationPayload.from_dict(data)

    def test_v2_requires_both_metadata_keys(self) -> None:
        for missing in (('spec_digest',), ('criterion_coverage',), ('spec_digest', 'criterion_coverage')):
            with self.subTest(missing=missing):
                data = self._v2_attestation_data()
                for field in missing:
                    del data[field]
                with self.assertRaisesRegex(ValueError, 'metadata.*required'):
                    AttestationPayload.from_dict(data)

    def test_v2_rejects_non_integer_command_exit_codes(self) -> None:
        for exit_code in (False, True, 0.0, -1.0, '0', None):
            with self.subTest(exit_code=exit_code):
                data = self._v2_attestation_data()
                data['command_results'][0]['exit_code'] = exit_code
                with self.assertRaisesRegex(ValueError, 'exit_code.*integer'):
                    AttestationPayload.from_dict(data)
        data = self._v2_attestation_data()
        del data['command_results'][0]['exit_code']
        with self.assertRaisesRegex(ValueError, 'exit_code.*integer'):
            AttestationPayload.from_dict(data)

    def test_cli_rejects_non_integer_v2_exit_codes_without_rewriting_v1(self) -> None:
        from adaptive_trust_ci.cli import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_key = root / 'test-attestation-public.pem'
            public_key.write_bytes(self.signer.public_key_pem())
            attestation = root / 'attestation.json'
            cases = (
                (1, False, None), (1, 0.0, None), (2, 0, None),
                (2, False, 'exit_code.*integer'), (2, 0.0, 'exit_code.*integer'),
                (2.0, 0, 'schema_version'), ('2', 0, 'schema_version'), (True, 0, 'schema_version'),
            )
            for version, exit_code, problem in cases:
                with self.subTest(version=version, exit_code=exit_code):
                    data = self._v2_attestation_data()
                    data['schema_version'] = version
                    data['command_results'][0]['exit_code'] = exit_code
                    attestation.write_text(json.dumps({'payload': data, 'signature': self.signer.sign(data)}), encoding='utf-8')
                    output = io.StringIO()
                    argv = ['attestation-verify', '--attestation', str(attestation), '--public-key', str(public_key)]
                    with redirect_stdout(output):
                        if problem:
                            with self.assertRaisesRegex(ValueError, problem):
                                main(argv)
                        else:
                            self.assertEqual(main(argv), 0)
                    if problem:
                        self.assertEqual(output.getvalue(), '')
                    else:
                        verified = json.loads(output.getvalue())
                        self.assertIs(type(verified['schema_version']), int)
                        self.assertEqual(verified['schema_version'], version)
                        actual = verified['command_results'][0]['exit_code']
                        self.assertIs(type(actual), type(exit_code))
                        self.assertEqual(actual, exit_code)

    def test_v2_schema_version_and_arguments_are_signed(self) -> None:
        envelope = sign_attestation(AttestationPayload.from_dict(self._v2_attestation_data()), self.signer)
        verified = verify_attestation(envelope, self.signer.public_key_pem())
        self.assertEqual(verified.schema_version, 2)
        for tamper in ('schema_version', 'argv'):
            with self.subTest(tamper=tamper):
                data = json.loads(json.dumps(envelope.to_dict()))
                if tamper == 'schema_version':
                    data['payload']['schema_version'] = 1
                else:
                    data['payload']['command_results'][0]['argv'][-1] = '--help'
                with self.assertRaisesRegex(ApprovalError, 'signature'):
                    verify_attestation(AttestationEnvelope.from_dict(data), self.signer.public_key_pem())

    def test_legacy_raw_argv_never_upgrades_signed_v1_to_v2(self) -> None:
        data = self._v2_attestation_data()
        data['schema_version'] = 1
        del data['spec_digest']
        del data['criterion_coverage']
        original = {'payload': data, 'signature': self.signer.sign(data)}
        envelope = AttestationEnvelope.from_dict(original)
        verified = verify_attestation(envelope, self.signer.public_key_pem())
        self.assertEqual(verified.schema_version, 1)
        self.assertEqual(envelope.to_dict(), original)
        self.assertNotIn('spec_digest', verified.to_dict())

    def test_payload_tampering_breaks_signature(self) -> None:
        data = self.envelope.to_dict()
        data["payload"]["reason"] = "changed after signature"
        with self.assertRaisesRegex(ApprovalError, "signature"):
            self.verify(ApprovalEnvelope.from_dict(data))

    def test_wrong_head_sha_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "head SHA"):
            self.verify(expected_head_sha=sha("d"))

    def test_wrong_base_sha_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "base SHA"):
            self.verify(expected_base_sha=sha("d"))

    def test_wrong_policy_digest_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "policy digest"):
            self.verify(expected_policy_digest=digest("d"))

    def test_expired_approval_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "expired"):
            self.verify(now=now() + timedelta(seconds=901))

    def test_excessive_ttl_is_rejected(self) -> None:
        with self.assertRaisesRegex(ApprovalError, "TTL"):
            self.verify(max_ttl_seconds=100)

    def test_scope_not_authorized_for_key_is_rejected(self) -> None:
        payload = ApprovalPayload.new(
            actor="dmitry",
            key_id=self.signer.key_id,
            repository=self.payload.repository,
            pr_number=42,
            base_sha=sha("a"),
            head_sha=sha("b"),
            policy_digest=digest("c"),
            scope="production",
            reason="not allowed",
            now=now(),
        )
        with self.assertRaisesRegex(ApprovalError, "scope"):
            self.verify(sign_approval(payload, self.signer))

    def test_actor_must_match_trusted_identity(self) -> None:
        payload = ApprovalPayload.new(
            actor="agent",
            key_id=self.signer.key_id,
            repository=self.payload.repository,
            pr_number=42,
            base_sha=sha("a"),
            head_sha=sha("b"),
            policy_digest=digest("c"),
            scope="governance",
            reason="wrong actor",
            now=now(),
        )
        with self.assertRaisesRegex(ApprovalError, "actor"):
            self.verify(sign_approval(payload, self.signer))

    def test_store_rejects_approval_replay(self) -> None:
        memory = MemoryStore()
        memory.record_approval(self.payload, self.envelope, now=now())
        with self.assertRaises(ReplayError):
            memory.record_approval(self.payload, self.envelope, now=now())

    def test_pre_m1_attestation_signature_and_store_replay_remain_valid(self) -> None:
        legacy = {
            'schema_version': 1, 'attestation_id': 'legacy-attestation', 'job_id': 'job-1',
            'repository': 'Dimkox/Getzilla', 'pr_number': 42,
            'base_sha': sha('a'), 'head_sha': sha('b'), 'policy_digest': digest('c'),
            'status': 'passed', 'command_results': [], 'changed_files': ['docs/x.md'],
            'approved_scopes': [], 'started_at': now().isoformat(), 'completed_at': now().isoformat(),
            'key_id': self.signer.key_id,
        }
        envelope = AttestationEnvelope.from_dict({'payload': legacy, 'signature': self.signer.sign(legacy)})
        verified = verify_attestation(envelope, self.signer.public_key_pem())
        self.assertIsNone(verified.spec_digest)
        memory = MemoryStore()
        memory.record_attestation('job-1', envelope)
        stored = memory.get_attestation('job-1')
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(verify_attestation(stored, self.signer.public_key_pem()).attestation_id, 'legacy-attestation')
        self.assertNotIn('spec_digest', stored.to_dict()['payload'])

    def test_committed_pre_m1_golden_verifies_and_replays_without_rewriting(self) -> None:
        for name in ('pre-m1-attestation.json', 'pre-m1-attestation-postgres.json'):
            with self.subTest(name=name):
                fixture = json.loads((Path(__file__).parent / f'fixtures/{name}').read_text(encoding='utf-8'))
                envelope = AttestationEnvelope.from_dict(fixture['envelope'])
                verified = verify_attestation(envelope, fixture['public_key_pem'].encode())
                self.assertIsNone(verified.spec_digest)
                memory = MemoryStore()
                memory.record_attestation(verified.job_id, envelope)
                stored = memory.get_attestation(verified.job_id)
                assert stored is not None
                self.assertEqual(stored.to_dict(), fixture['envelope'])
                self.assertEqual(verify_attestation(stored, fixture['public_key_pem'].encode()).job_id, verified.job_id)

    def test_attestation_coverage_is_strict_and_bounded(self) -> None:
        legacy = {
            'schema_version': 1, 'attestation_id': 'new-attestation', 'job_id': 'job-1',
            'repository': 'Dimkox/Getzilla', 'pr_number': 42,
            'base_sha': sha('a'), 'head_sha': sha('b'), 'policy_digest': digest('c'),
            'status': 'passed', 'command_results': [], 'changed_files': [], 'approved_scopes': [],
            'started_at': now().isoformat(), 'completed_at': now().isoformat(), 'key_id': self.signer.key_id,
            'spec_digest': digest('d'),
            'criterion_coverage': {'spec_count': 1, 'criterion_total': 2, 'criterion_mapped': 1, 'unmapped_ids': ['AC-002']},
        }
        payload = AttestationPayload.from_dict(legacy)
        self.assertEqual(payload.criterion_coverage['unmapped_ids'], ['AC-002'])
        legacy['criterion_coverage']['extra'] = 1
        with self.assertRaises(ValueError):
            AttestationPayload.from_dict(legacy)

    def test_attestation_coverage_accepts_stable_spec_qualified_ids(self) -> None:
        data = {
            'schema_version': 1, 'attestation_id': 'new-attestation', 'job_id': 'job-1',
            'repository': 'Dimkox/Getzilla', 'pr_number': 42,
            'base_sha': sha('a'), 'head_sha': sha('b'), 'policy_digest': digest('c'),
            'status': 'failed', 'command_results': [], 'changed_files': [], 'approved_scopes': [],
            'started_at': now().isoformat(), 'completed_at': now().isoformat(), 'key_id': self.signer.key_id,
            'spec_digest': digest('d'),
            'criterion_coverage': {
                'spec_count': 2,
                'criterion_total': 2,
                'criterion_mapped': 1,
                'unmapped_ids': ['engineering/changes/20260826-alpha/change-spec.yaml#AC-001'],
            },
        }
        payload = AttestationPayload.from_dict(data)
        self.assertEqual(payload.criterion_coverage['unmapped_ids'], data['criterion_coverage']['unmapped_ids'])

    def test_signed_spec_metadata_detects_digest_and_coverage_tampering(self) -> None:
        data = {
            'schema_version': 1, 'attestation_id': 'new-attestation', 'job_id': 'job-1',
            'repository': 'Dimkox/Getzilla', 'pr_number': 42,
            'base_sha': sha('a'), 'head_sha': sha('b'), 'policy_digest': digest('c'),
            'status': 'passed', 'command_results': [], 'changed_files': [], 'approved_scopes': [],
            'started_at': now().isoformat(), 'completed_at': now().isoformat(), 'key_id': self.signer.key_id,
            'spec_digest': digest('d'),
            'criterion_coverage': {'spec_count': 1, 'criterion_total': 1, 'criterion_mapped': 1, 'unmapped_ids': []},
        }
        envelope = sign_attestation(AttestationPayload.from_dict(data), self.signer)
        self.assertEqual(verify_attestation(envelope, self.signer.public_key_pem()).spec_digest, digest('d'))
        for mutate in (
            lambda payload: payload.update(spec_digest=digest('e')),
            lambda payload: payload['criterion_coverage'].update(criterion_mapped=0, unmapped_ids=['AC-001']),
        ):
            tampered = envelope.to_dict()
            mutate(tampered['payload'])
            with self.assertRaisesRegex(ApprovalError, 'signature'):
                verify_attestation(AttestationEnvelope.from_dict(tampered), self.signer.public_key_pem())


if __name__ == "__main__":
    unittest.main()
