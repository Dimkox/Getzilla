from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import base64
import contextlib
import hashlib
import io
import os
import runpy
import subprocess
import sys
from dataclasses import replace
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from adaptive_trust_ci import security_bundle as bundle


NOW = datetime(2026, 11, 10, 8, tzinfo=timezone.utc)
DIGEST = 'a' * 64
POLICY = 'b' * 64


def local_document():
    return {'version': 1, 'source': {'mode': 'local', 'candidate_digest': DIGEST},
            'policy_sha256': POLICY, 'report': {
                'inventory_sha256': 'c' * 64, 'created_at': NOW.isoformat(),
                'valid_until': (NOW + timedelta(seconds=259200)).isoformat(),
                'checks': [{'name': 'security-inventory', 'status': 'pass', 'outcome': 'pass',
                            'finding_count': 0, 'gap_count': 0, 'source_ids': [],
                            'coverage_sha256': 'c' * 64}]}, 'binding': None, 'integration': None}


def facts_for(document):
    return bundle.ValidationFacts(
        source_digest=bundle.digest(document['source']), policy_digest=POLICY,
        report_digest=bundle.digest(document['report']), inventory_digest='c' * 64,
        required=(bundle.Requirement('security-inventory', True, (), 'c' * 64),),
        sources=(), blockers=(), source_validated=True)


class SecurityBundleTests(unittest.TestCase):
    def decision(self, document, *, facts=None, policy=None, now=NOW):
        parsed = bundle.parse_bundle(json.dumps(document).encode())
        return bundle.evaluate_bundle(policy or bundle.BundlePolicy(POLICY), parsed.source, parsed,
            bundle.ObservedState(parsed.source.mode, bundle.digest(document['source'])), facts or facts_for(document), now=now)

    def test_local_candidate_without_any_remote_identity_can_be_consistent(self):
        document = local_document()
        parsed = bundle.parse_bundle(json.dumps(document).encode())
        decision = bundle.evaluate_bundle(bundle.BundlePolicy(POLICY), parsed.source, parsed,
                                          bundle.ObservedState('local', bundle.digest(document['source'])),
                                          facts_for(document), now=NOW)
        self.assertTrue(decision.consistent)
        self.assertFalse(decision.external_eligible)
        self.assertEqual(decision.provenance, 'local-feedback')
        self.assertNotIn('repository_id', document['source'])
        self.assertNotIn('pr_number', document['source'])

    def test_duplicate_and_unknown_fields_are_not_silently_accepted(self):
        document = local_document()
        unknown = dict(document, unexpected='untrusted')
        encoded = json.dumps(document).encode()
        duplicate = b'{"version":1,' + encoded[1:]
        for raw in (json.dumps(unknown).encode(), duplicate):
            with self.subTest(raw_bytes=len(raw)):
                with self.assertRaises(bundle.BundleError):
                    bundle.parse_bundle(raw)

    def test_exact_freshness_boundary_and_original_source_time(self):
        document = local_document()
        descriptor = bundle.ValidatedSource('osv:PyPI', 'd' * 64, (NOW - timedelta(seconds=259200)).isoformat(), True)
        facts = replace(facts_for(document), sources=(descriptor,))
        self.assertTrue(self.decision(document, facts=facts).consistent)
        for age in (259201, -1):
            with self.subTest(age=age):
                changed = replace(descriptor, acquired_at=(NOW - timedelta(seconds=age)).isoformat())
                self.assertFalse(self.decision(document, facts=replace(facts, sources=(changed,))).consistent)
        self.assertFalse(self.decision(document, now=NOW.replace(tzinfo=None)).consistent)

    def test_complete_named_coverage_and_contradiction_refuse(self):
        document = local_document()
        for field, value in (('finding_count', 1), ('gap_count', 1), ('coverage_sha256', 'f' * 64),
                             ('status', 'skip'), ('source_ids', ['osv:PyPI'])):
            changed = json.loads(json.dumps(document))
            changed['report']['checks'][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(self.decision(changed).consistent)
        facts = replace(facts_for(document), required=(bundle.Requirement('different-check', True, (), 'c' * 64),))
        self.assertFalse(self.decision(document, facts=facts).consistent)
        self.assertFalse(self.decision(document, facts=replace(facts_for(document), source_validated=False)).consistent)
        self.assertFalse(self.decision(document, policy=bundle.BundlePolicy('e' * 64)).consistent)

    def test_limits_and_local_variant_cannot_smuggle_provider_fields(self):
        document = local_document()
        for field, value in (('repository_id', 1), ('pr_number', 1), ('remote', 'not-needed')):
            changed = json.loads(json.dumps(document))
            changed['source'][field] = value
            with self.subTest(field=field), self.assertRaises(bundle.BundleError):
                bundle.parse_bundle(json.dumps(changed).encode())
        for raw in (b' ' * (bundle.BUNDLE_BYTES + 1), b'[' * 25 + b'0' + b']' * 25,
                    b'{"bad":NaN}', b'{"bad":9223372036854775808}', b'{"bad":"' + b'x' * 4097 + b'"}'):
            with self.subTest(size=len(raw)), self.assertRaises(bundle.BundleError):
                bundle.parse_bundle(raw)

    def test_source_replacement_and_unverified_integration_refuse(self):
        document = local_document()
        self.assertFalse(self.decision(document, facts=replace(facts_for(document), source_digest='f' * 64)).consistent)
        document['integration'] = {'merge_sha': '1' * 40, 'tree_sha': '2' * 40, 'parents': ['3' * 40, '4' * 40], 'strategy': 'merge'}
        self.assertFalse(self.decision(document).consistent)

    def test_pure_engine_uses_no_network_process_or_model_callback(self):
        with mock.patch('socket.socket', side_effect=AssertionError('network attempted')), \
             mock.patch('subprocess.Popen', side_effect=AssertionError('process attempted')):
            self.assertTrue(self.decision(local_document()).consistent)

    def test_fixture_signature_binds_current_source_and_never_grants_external_authority(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        # Owned synthetic test key only; no operator/human identity or approval.
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        document = local_document()
        document['source'] = {'mode': 'github', 'repository': 'owner/project', 'repository_id': 1, 'pr_number': 7,
            'target_ref': 'refs/heads/main', 'base_sha': '1' * 40, 'head_sha': '2' * 40, 'tree_sha': '3' * 40,
            'run_id': 11, 'run_attempt': 2}
        document['integration'] = {'merge_sha': '4' * 40, 'tree_sha': '5' * 40, 'parents': ['1' * 40, '2' * 40], 'strategy': 'merge'}
        policy = bundle.BundlePolicy(POLICY, public, 'f' * 64, ('producer',))
        payload = {'version': 1, 'kind': 'getzilla-security-bundle-binding', 'source_sha256': bundle.digest(document['source']),
            'report_sha256': bundle.digest(document['report']), 'policy_sha256': POLICY, 'authority_sha256': 'f' * 64,
            'issued_at': NOW.isoformat(), 'expires_at': (NOW + timedelta(seconds=259200)).isoformat(),
            'integration_sha256': bundle.digest(document['integration'])}
        document['binding'] = {'payload': payload, 'signature': base64.b64encode(key.sign(bundle.canonical_json(payload))).decode()}
        facts = replace(facts_for(document), integration_digest=bundle.digest(document['integration']), integration_validated=True)
        observed = bundle.ObservedState('github', bundle.digest(document['source']), True, 'f' * 64, ('producer',))
        def evaluate():
            parsed = bundle.parse_bundle(json.dumps(document).encode())
            return bundle.evaluate_bundle(policy, parsed.source, parsed, observed, facts, now=NOW)
        self.assertTrue(evaluate().consistent)
        self.assertFalse(evaluate().external_eligible)
        document['binding']['signature'] = base64.b64encode(b'\0' * 64).decode()
        self.assertFalse(evaluate().consistent)


class OwnedValidationBoundaryTests(unittest.TestCase):
    def test_entrypoint_constructs_facts_by_invoking_boundary_validators(self):
        from adaptive_trust_ci import public_admission
        inventory = {'digest': 'c' * 64, 'complete': True, 'files': [], 'dependencies': [], 'tools': [], 'images': []}
        core = SimpleNamespace(inventory=SimpleNamespace(collect_inventory=mock.Mock(return_value=inventory)),
            security=SimpleNamespace(_policy_digest=mock.Mock(return_value=POLICY),
                security_obligations=mock.Mock(return_value=[])), policy_root=Path('.'))
        with tempfile.TemporaryDirectory(prefix='326-boundary-') as directory:
            root = Path(directory)
            parsed = bundle.parse_bundle(json.dumps(local_document()).encode())
            public_admission.validate_local_inputs(bundle.BundlePolicy(POLICY), parsed,
                source_root=root, snapshot_root=None, descriptors=None, now=NOW, core=core)
            core.inventory.collect_inventory.assert_called_once_with(root)
            core.security._policy_digest.assert_called_once()
        self.assertFalse(core.inventory.collect_inventory.call_args is None)

    def test_untrusted_facts_status_cannot_replace_byte_validation(self):
        from adaptive_trust_ci import public_admission
        with tempfile.TemporaryDirectory(prefix='326-boundary-') as directory:
            parsed = bundle.parse_bundle(json.dumps(local_document()).encode())
            result = public_admission.validate_local_inputs(bundle.BundlePolicy(POLICY), parsed,
                source_root=Path(directory), snapshot_root=None,
                descriptors={'validated': True, 'status': 'pass'}, now=NOW, core=None)
            self.assertFalse(result.source_validated)
            self.assertTrue(result.blockers)

    def test_external_wrapper_refuses_local_result_and_unconfigured_app(self):
        from adaptive_trust_ci import public_admission
        result = public_admission.evaluate(None, None, bundle.LocalSource(DIGEST), None, now=NOW)
        self.assertFalse(result.eligible)
        self.assertEqual(result.blockers, ('authority-or-inputs-unconfigured',))

    def test_external_wrapper_observes_latest_scope_after_own_validation(self):
        from adaptive_trust_ci import public_admission
        selector = public_admission.Selector('owner/project', 1, 7, '1' * 40, '2' * 40, '3' * 40, 11, 2)
        document = local_document()
        document['source'] = selector.source().as_dict()
        evidence = public_admission.Evidence(None, document['report'])
        authority = SimpleNamespace(security_core=object(), as_policy=lambda: bundle.BundlePolicy(POLICY))
        order = []
        def validate(*args, **kwargs):
            order.append('validate')
            return facts_for(document)
        def observe(*args, **kwargs):
            order.append('observe')
            return bundle.ObservedState('github', bundle.digest(document['source']))
        with mock.patch.object(public_admission, 'validate_local_inputs', side_effect=validate), \
             mock.patch.object(public_admission, 'observe', side_effect=observe), \
             mock.patch.object(public_admission, 'content_manifest', return_value=[]), \
             mock.patch.object(public_admission, '_source_binding'), \
             mock.patch.object(bundle, 'evaluate_bundle', return_value=bundle.BundleDecision(False, ('fixture-only',))):
            public_admission.evaluate(object(), authority, selector, evidence, now=NOW, candidate_root=Path('.'))
        self.assertEqual(order, ['validate', 'observe'])

    def test_integration_must_preserve_both_parents_and_strategy_tree(self):
        from adaptive_trust_ci import public_admission
        source = bundle.GithubSource('owner/project', 1, 1, 'refs/heads/main', '1' * 40, '2' * 40, '3' * 40, 1, 1)
        value = {'merge_sha': '4' * 40, 'tree_sha': '5' * 40, 'parents': [source.base_sha, source.head_sha], 'strategy': 'merge'}
        commit = ('tree ' + value['tree_sha'] + '\nparent ' + source.base_sha + '\nparent ' + source.head_sha + '\n\nfixture').encode()
        core = SimpleNamespace(git=SimpleNamespace(run_git_bounded=mock.Mock(side_effect=[commit, value['tree_sha'].encode()])))
        self.assertTrue(public_admission._integration(core, source, value, Path('.'))[1])
        core.git.run_git_bounded.side_effect = [commit.replace(source.base_sha.encode(), b'9' * 40), value['tree_sha'].encode()]
        self.assertFalse(public_admission._integration(core, source, value, Path('.'))[1])
        core.git.run_git_bounded.side_effect = [commit, b'conflict']
        self.assertFalse(public_admission._integration(core, source, value, Path('.'))[1])


@unittest.skipUnless(sys.platform.startswith('linux'), 'owned Linux nongit CLI fixture')
class LocalCliOwnedTests(unittest.TestCase):
    def test_local_cli_revalidates_explicit_nongit_bytes_without_app(self):
        from adaptive_trust_ci import public_admission
        # Root's narrow AGENTS workspace exception: ephemeral inert input only.
        # Native hardened Git discards ceiling variables, so a nested Git fixture
        # is not a lawful nongit source. Programs/reports stay in canonical RT.
        with tempfile.TemporaryDirectory(prefix='getzilla-326-cli-', dir='/tmp') as directory:
            parent = Path(directory)
            source, home, snapshots = (parent / name for name in ('source', 'home', 'snapshots'))
            for path in (source, home, snapshots):
                path.mkdir(mode=0o700)
            payload = b'owned inert local fixture\n'
            fd = os.open(source / 'README.txt', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(payload)
            core = public_admission._core()
            commands = [core.git._git_command(args, safe_directory=source) for args in
                        (['rev-parse', '--show-prefix', '--is-inside-work-tree'],
                         ['ls-files', '-z', '--cached', '--others', '--exclude-standard'])]
            real_popen, observed = subprocess.Popen, []
            def owned_git(args, *positional, **options):
                self.assertIn(list(args), commands)
                self.assertEqual(Path(options['cwd']), source)
                self.assertEqual(options['env']['GIT_CONFIG_NOSYSTEM'], '1')
                self.assertEqual(options['env']['GIT_CONFIG_GLOBAL'], os.devnull)
                self.assertNotIn('GIT_DIR', options['env'])
                observed.append(tuple(args[-4:]))
                return real_popen(args, *positional, **options)
            environment = {'HOME': str(home), 'TMPDIR': str(parent), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
            with mock.patch.dict(os.environ, environment, clear=True), \
                 mock.patch('subprocess.Popen', side_effect=owned_git), \
                 mock.patch('socket.socket', side_effect=AssertionError('network denied')), \
                 mock.patch('os.system', side_effect=AssertionError('process denied')):
                inventory = core.inventory.collect_inventory(source)
                self.assertTrue(inventory['complete'])
                self.assertEqual([inventory[k] for k in ('dependencies', 'images', 'tools')], [[], [], []])
                policy = core.security._policy_digest(core.policy_root)
                names = ('security-inventory', 'known-vulnerabilities', 'security-kev', 'security-epss',
                         'security-malicious-packages', 'security-licenses', 'security-container-images',
                         'opengrep', 'secret-scan', 'bandit', 'trivy-config')
                records, normalized = [], []
                for name in names:
                    required = name in ('security-inventory', 'secret-scan')
                    marker = {'kind': 'security-result', 'schema_version': 1,
                              'outcome': 'pass' if required else 'not_applicable',
                              'inventory_sha256': inventory['digest'], 'policy_sha256': policy,
                              'data_sources': [], 'findings': [], 'gaps': [], 'assurance': 'local-input-integrity-only'}
                    records.append({'name': name, 'status': 'pass' if required else 'skip', 'details': [marker]})
                    normalized.append({'name': name, 'status': 'pass' if required else 'skip', 'outcome': marker['outcome'],
                        'finding_count': 0, 'gap_count': 0, 'source_ids': [], 'coverage_sha256': inventory['digest']})
                descriptors = {'checks': records, 'source_descriptors': []}
                now = datetime.now(timezone.utc)
                candidate = bundle.digest([{'path': 'README.txt', 'bytes': len(payload), 'mode': 0o644,
                                           'sha256': hashlib.sha256(payload).hexdigest()}])
                document = {'version': 1, 'source': {'mode': 'local', 'candidate_digest': candidate},
                    'policy_sha256': policy, 'binding': None, 'integration': None,
                    'report': {'inventory_sha256': inventory['digest'], 'created_at': now.isoformat(),
                        'valid_until': (now + timedelta(seconds=259200)).isoformat(), 'checks': normalized,
                        'evidence_sha256': bundle.digest(descriptors)}}
                for name, value in (('bundle.json', document), ('policy.json', {'version': 1, 'policy_sha256': policy}),
                                    ('descriptors.json', descriptors)):
                    fd = os.open(parent / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(bundle.canonical_json(value))
                target = Path(__file__).resolve().parents[1] / 'scripts/check_security_bundle.py'
                command = runpy.run_path(str(target))['main']
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = command(['--bundle', str(parent / 'bundle.json'), '--policy', str(parent / 'policy.json'),
                        '--source-root', str(source), '--snapshot-root', str(snapshots),
                        '--input-descriptors', str(parent / 'descriptors.json')])
                result = json.loads(output.getvalue())
                self.assertEqual(code, 0, result)
                self.assertTrue(result['consistent'])
                self.assertFalse(result['external_eligible'])
                self.assertFalse(result['independent_attestation'])
                self.assertEqual(result['checks_executed_by_cli'], [])
                self.assertEqual(len(observed), 4)  # Two exact Git reads per actual inventory validation.


