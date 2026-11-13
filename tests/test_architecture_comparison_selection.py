"""New tiny Git worlds; no actual-project inventory or verification producer."""
from __future__ import annotations

import json
import copy
import contextlib
from datetime import datetime, timezone
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.architecture_diff import select_architecture_comparison_base
from getzilla.architecture_diff import ArchitectureError, diff_architecture
from getzilla import architecture_diff
from getzilla.architecture import load_architecture
from getzilla.architecture_fitness import _change_separation
from getzilla import receipts, verification_plan
from getzilla.util import tree_fingerprint
from getzilla.verification import _git_range_selection
from tests.test_architecture_model import _system, _rules


class DerivedComparisonTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='393-comparison-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.root, self.home = self.directory / 'source', self.directory / 'home'
        self.root.mkdir(mode=0o700)
        self.home.mkdir(mode=0o700)
        self.environment = {'PATH': os.defpath, 'HOME': str(self.home), 'XDG_CONFIG_HOME': str(self.home),
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}
        self.git('init', '-q', '--initial-branch=candidate')
        self.git('config', 'init.defaultBranch', 'main')
        self.write('app.py', 'value = 1\n')
        self.write('architecture/system.yaml', json.dumps(_system(), sort_keys=True, indent=2) + '\n')
        rules = _rules()
        rules['change_separation_policies'] = [{'id': 'FIT-OWNED-SEPARATION', 'severity': 'error',
            'implementation_prefixes': ['app.py'], 'trust_ci_prefixes': ['trust-ci']}]
        self.write('architecture/rules.yaml', json.dumps(rules, sort_keys=True, indent=2) + '\n')
        self.write('architecture/adoption.json', json.dumps({
            'architecture_id': 'ARCH-TEST', 'schema_version': 1, 'state': 'adopted'}, sort_keys=True, indent=2) + '\n')
        for name in ('architecture-system.schema.json', 'architecture-rules.schema.json'):
            # Fixed SDK grammar definitions, not project inventory/model subsets.
            self.write('schemas/' + name, (ROOT / 'schemas' / name).read_text())
        self.anchor = self.commit('owned adopted anchor')
        self.write('app.py', 'value = 2\n')
        self.target = self.commit('owned accepted prerequisite')
        self.git('update-ref', 'refs/remotes/origin/main', self.target)
        self.git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main')
        self.write('trust-ci/owned.py', 'owned = 1\n')
        self.write('.gitignore', '.getzilla/runtime/\n')
        self.write('tests/test_393_bound.py', 'import unittest\nclass Bound393(unittest.TestCase):\n'
                   '    def test_body(self):\n        self.assertEqual(2 + 2, 4)\n')
        self.head = self.commit('owned trust-only candidate')
        self.route = {'base_commit': self.anchor, 'delivery_expected': True}

    def git(self, *args, input=None):
        result = subprocess.run(['git', '--no-optional-locks', '-c', 'core.hooksPath=' + os.devnull,
            '-c', 'core.fsmonitor=false', '-c', 'commit.gpgsign=false', '-c', 'user.name=fixture',
            '-c', 'user.email=fixture@example.invalid', *args], cwd=self.root, env=self.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input, timeout=10, check=True)
        return result.stdout.decode().strip()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def test_accepted_prerequisite_is_the_architecture_comparison_only(self):
        selected = select_architecture_comparison_base(self.root, self.route)
        self.assertEqual(selected.comparison_base_sha, self.target)
        self.assertEqual(selected.route_base_sha, self.anchor)

    def test_review_union_and_original_anchor_do_not_shrink(self):
        ranges = _git_range_selection(self.root, self.route, 'pr')
        self.assertEqual(ranges.findings, [])
        self.assertEqual({row.comparison_base_sha for row in ranges.bases}, {self.anchor, self.target})
        self.assertEqual(self.route['base_commit'], self.anchor)

    def test_ordinary_fast_keeps_its_worktree_binding_without_a_pr_target(self):
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        ranges = _git_range_selection(self.root, self.route, 'fast')
        self.assertEqual((ranges.bases, ranges.findings), ([], []))
        failure = None
        try:
            binding = receipts.active_architecture_binding(self.root, self.route, _trusted_ranges=ranges)
        except (ArchitectureError, RuntimeError) as exc:
            failure = str(exc)
        self.assertIsNone(failure, 'a valid ordinary-fast invocation must retain its worktree binding')
        self.assertEqual(binding['architecture_head_kind'], 'worktree')
        self.assertEqual(binding['architecture_base_sha'], self.anchor)

    def test_proved_adopted_deletion_is_missing_before_shallow_range_inference(self):
        for name in ('system.yaml', 'rules.yaml', 'adoption.json'):
            (self.root / 'architecture' / name).unlink()
        head = self.commit('owned complete authority deletion')
        self.write('.git/shallow', head + '\n' + self.anchor + '\n')
        with self.assertRaises((ArchitectureError, RuntimeError)) as refusal:
            receipts.active_architecture_binding(self.root, self.route)
        self.assertIn('missing', str(refusal.exception))

    def test_effective_fast_mode_stays_consistent_through_diff_and_governance(self):
        from getzilla.verification import _governance_check
        ranges = _git_range_selection(self.root, self.route, 'fast')
        selection = select_architecture_comparison_base(self.root, self.route, _trusted_ranges=ranges)
        self.assertEqual((selection.range_mode, selection.comparison_base_sha), ('fast', self.anchor))
        difference = diff_architecture(self.root, base_sha=self.anchor, worktree=True,
                                       _trusted_base_selection=selection)
        self.assertEqual((difference.base_sha, difference.head_kind), (self.anchor, 'worktree'))
        binding = receipts.active_architecture_binding(self.root, self.route, _trusted_ranges=ranges)
        summary = {'ok': True, 'findings': [], 'overall_status': 'pass',
                   **{name: 'a' * 64 for name in ('rules_digest', 'debt_digest', 'examples_digest',
                                                 'schema_digest', 'governance_digest')},
                   **{name: [] for name in ('active_rule_ids', 'active_example_ids_versions',
                                           'open_debt_ids', 'overdue_debt_ids')}}
        with patch.object(receipts, '_governance_is_configured', return_value=True), \
             patch.object(receipts, 'load_governance', return_value=object()), \
             patch.object(receipts, 'governance_summary', return_value=summary):
            result, governed = _governance_check(self.root, self.route,
                {'status': 'pass', 'configured': True, **binding}, _trusted_ranges=ranges)
        self.assertEqual(result.status, 'pass', result.summary)
        self.assertEqual(governed['governance_applicable_base_sha'], self.anchor)
        options = receipts._verification_architecture_options(self.root, self.route, 'verification', {'mode': 'fast'})
        self.assertEqual(receipts.active_architecture_binding(self.root, self.route, **options), binding)

    def test_effective_mode_does_not_admit_foreign_stale_or_relabelled_ranges(self):
        ranges = _git_range_selection(self.root, self.route, 'pr')
        ranges.mode = 'fast'
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route, _trusted_ranges=ranges)
        empty = _git_range_selection(self.root, self.route, 'fast')
        empty.mode = 'pr'
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route, _trusted_ranges=empty)
        strict = _git_range_selection(self.root, self.route, 'pr')
        self.git('update-ref', 'refs/remotes/origin/main', self.anchor)
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route, _trusted_ranges=strict)
        for mode in ('unknown', None, ['fast']):
            unproved = _git_range_selection(self.root, self.route, 'fast')
            unproved.mode = mode
            with self.subTest(mode=mode), self.assertRaises(ArchitectureError):
                select_architecture_comparison_base(self.root, self.route, _trusted_ranges=unproved)
            with self.subTest(receipt_mode=mode), self.assertRaises(RuntimeError):
                receipts._verification_architecture_options(self.root, self.route, 'verification', {'mode': mode})
        stale_fast = _git_range_selection(self.root, self.route, 'fast')
        self.git('commit', '--allow-empty', '-qm', 'owned later invocation')
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route, _trusted_ranges=stale_fast)

    def test_fast_light_pr_and_release_keep_strict_missing_target_and_shallow_refusals(self):
        self.git('update-ref', '-d', 'refs/remotes/origin/main')
        for mode, route in (('fast', {**self.route, 'delivery_lane': 'light'}),
                            ('fast', {**self.route, 'delivery_lane': 'full', 'light_lane_candidate': True}),
                            ('pr', self.route), ('release', self.route)):
            with self.subTest(mode=mode):
                ranges = _git_range_selection(self.root, route, mode)
                self.assertNotEqual(ranges.mode, 'fast')
                self.assertTrue(ranges.findings)
                with self.assertRaises(ArchitectureError):
                    receipts.active_architecture_binding(self.root, route, _trusted_ranges=ranges)
        self.git('update-ref', 'refs/remotes/origin/main', self.target)
        self.write('.git/shallow', self.target + '\n')
        for mode in ('pr', 'release'):
            with self.subTest(shallow_mode=mode), self.assertRaises(ArchitectureError):
                select_architecture_comparison_base(self.root, self.route,
                    _trusted_ranges=_git_range_selection(self.root, self.route, mode))

    def test_unknown_shallow_authority_is_not_reported_as_proved_missing(self):
        empty = self.git('mktree', input=b'')
        unknown = self.git('commit-tree', empty, '-m', 'owned shallow unknown history')
        self.git('read-tree', '--reset', '-u', unknown)
        self.git('update-ref', 'refs/heads/candidate', unknown)
        self.write('.git/shallow', unknown + '\n')
        with self.assertRaises((ArchitectureError, RuntimeError)) as refusal:
            receipts.active_architecture_binding(self.root, {'base_commit': unknown})
        self.assertIn('history is incomplete', str(refusal.exception))

    def test_every_fast_selection_refuses_a_later_head_at_diff_consumption(self):
        for bootstrap in (False, True):
            with self.subTest(bootstrap=bootstrap):
                route = self.route
                with contextlib.ExitStack() as stack:
                    if bootstrap:
                        empty = self.git('mktree', input=b'')
                        frozen = self.git('commit-tree', empty, '-m', 'new owned frozen selection')
                        anchor = self.git('commit-tree', empty, '-p', frozen, '-m', 'new owned bootstrap anchor')
                        adopted = self.git('commit-tree', self.head + '^{tree}', '-p', anchor,
                                           '-m', 'new owned bootstrap adoption')
                        self.git('update-ref', 'refs/heads/candidate', adopted)
                        stack.enter_context(patch.object(architecture_diff, 'ADOPTION_BASE_SHA', frozen))
                        route = {'base_commit': anchor}
                    ranges = _git_range_selection(self.root, route, 'fast')
                    selected = select_architecture_comparison_base(self.root, route, _trusted_ranges=ranges)
                    unchanged = diff_architecture(self.root, base_sha=selected.comparison_base_sha,
                        worktree=True, _trusted_base_selection=selected)
                    self.assertEqual(unchanged.head_kind, 'worktree')
                    self.git('commit', '--allow-empty', '-qm', 'new owned later source HEAD')
                    with self.assertRaises(ArchitectureError):
                        diff_architecture(self.root, base_sha=selected.comparison_base_sha,
                                          worktree=True, _trusted_base_selection=selected)

    def test_sufficient_cross_mode_qualification_survives_storage_and_acceptance(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        for mode in ('release', 'pr'):
            plan = verification_plan.current_required_plan(self.root, mode=mode)
            report = copy.deepcopy(proof['details'])
            report.update(mode=mode, required_plan=plan)
            for check in report['checks']:
                check['details'] = [row for row in check['details'] if row.get('kind') != 'required-plan-result']
                verification_plan.bind_result(plan, check)
            ranges = _git_range_selection(self.root, self.route, mode)
            binding = receipts.active_architecture_binding(self.root, self.route, _trusted_ranges=ranges)
            report['architecture'] = {'status': 'pass', 'fitness_status': 'pass', **binding}
            self.assertEqual(verification_plan.report_gaps(self.root, report), [])
            proof = {**proof, **binding, 'details': report}
            self.publish_qualification(proof)
            hydrated = receipts.get_receipt(self.root, 'owned393', 'verification')['details']
            self.assertEqual(verification_plan.report_gaps(self.root, hydrated), [],
                             'a sufficient cross-mode report must remain usable after actual storage')
            self.assertEqual(binding['architecture_base_sha'], self.target)
            self.assertEqual(binding['architecture_range_mode'], mode)
            descendant = self.git('commit-tree', self.head + '^{tree}', '-p', self.head,
                                  '-m', 'new owned accepted cross-mode descendant')
            self.git('update-ref', 'refs/remotes/origin/main', descendant)
            self.assertEqual(verification_plan.report_gaps(self.root, hydrated), [])
            self.assertEqual(receipts.validate_evidence(self.root,
                {**self.route, 'required_evidence': ['verification']}), [],
                'the public receipt consumer must retain the proved publication provenance')

    def test_historical_and_current_provenance_tampering_cannot_supply_a_selection(self):
        from dataclasses import replace
        proof = self.qualification_record()
        selected = select_architecture_comparison_base(self.root, self.route)
        for field, value in (('candidate_sha', None), ('range_mode', 'release'),
                             ('ranges_digest', '0' * 64), ('invocation_mode', 'release'),
                             ('invocation_ranges_digest', '0' * 64)):
            with self.subTest(selection_field=field), self.assertRaises(ArchitectureError):
                diff_architecture(self.root, base_sha=selected.comparison_base_sha, worktree=True,
                                  _trusted_base_selection=replace(selected, **{field: value}))
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        for field, value in (('range_mode', 'release'), ('ranges_digest', '0' * 64),
                             ('invocation_mode', 'release'), ('invocation_ranges_digest', '0' * 64)):
            changed = copy.deepcopy(proof)
            changed['architecture_comparison_witness'][field] = value
            changed['details']['architecture']['architecture_comparison_witness'][field] = value
            self.publish_qualification(changed)
            with self.subTest(stored_field=field), self.assertRaises(ArchitectureError):
                receipts._qualified_architecture_comparison(self.root, self.route, self.head)
        self.publish_qualification(proof)
        self.assertEqual(receipts._qualified_architecture_comparison(self.root, self.route, self.head).comparison_base_sha,
                         self.target)
        reader = receipts.get_receipt
        reads = []
        def changed_observation(root, route_id, kind):
            value = reader(root, route_id, kind)
            if kind == 'verification':
                reads.append(kind)
                # Escalation and waiver previews precede the consumer's read.
                if len(reads) == 3:
                    value['report'] = 'owned mismatched receipt observation'
            return value
        with patch.object(receipts, 'get_receipt', side_effect=changed_observation):
            self.assertTrue(receipts.validate_evidence(self.root,
                {**self.route, 'required_evidence': ['verification']}),
                'publication restoration requires the exact envelope observed by the consumer')

    def test_diff_rejects_target_replacement_after_selection(self):
        selected = select_architecture_comparison_base(self.root, self.route)
        self.git('update-ref', 'refs/remotes/origin/main', self.anchor)
        with self.assertRaises(ArchitectureError):
            diff_architecture(self.root, base_sha=selected.comparison_base_sha, worktree=True,
                              _trusted_base_selection=selected)

    def test_receipt_consumer_rechecks_the_target_after_fingerprinting(self):
        fingerprint = receipts.architecture_fingerprint
        def changed(*args, **kwargs):
            self.git('update-ref', 'refs/remotes/origin/main', self.anchor)
            return fingerprint(*args, **kwargs)
        with patch.object(receipts, 'architecture_fingerprint', side_effect=changed):
            with self.assertRaises((ArchitectureError, RuntimeError)):
                receipts.active_architecture_binding(self.root, self.route)

    def qualification_record(self):
        # Compile actual obligations and consume individual source-owned evidence.
        # Unrelated native observations and feed bytes are explicit owned ports;
        # this is sufficient local contract evidence, never a real-project Gate.
        from getzilla import state, expanded_security, criterion_tests
        import getzilla
        self.route['route_id'] = 'owned393'
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.object(state, 'get_active_route', return_value=self.route))
        self.now = datetime.now(timezone.utc)
        self.database = self.root / '.getzilla/runtime/owned-sources'
        self.database.mkdir(parents=True, mode=0o700)
        self.sources = {}
        self.validated_sources = set()
        ecosystems = ('PyPI', 'npm', 'Go', 'crates.io', 'Packagist', 'RubyGems', 'Maven')
        for ordinal, ecosystem in enumerate(ecosystems):
            source_id = 'osv:' + ecosystem
            payload = ('owned source ' + str(ordinal)).encode()
            (self.database / ecosystem).write_bytes(payload)
            self.sources[source_id] = {'database': '.getzilla/runtime/owned-sources', 'source_id': source_id,
                'source_url': 'https://owned.invalid/' + ecosystem,
                'content_sha256': hashlib.sha256(payload).hexdigest(), 'payload_size': len(payload),
                'acquisition': {'last_verified_sync_utc': self.now.isoformat()}, 'coverage': {'owned': ordinal}}
        def read_source(database, source_id, now):
            self.assertEqual(database, self.database)
            self.validated_sources.add(source_id)
            evidence = copy.deepcopy(self.sources[source_id])
            payload = (database / source_id.removeprefix('osv:')).read_bytes()
            evidence.update(content_sha256=hashlib.sha256(payload).hexdigest(), payload_size=len(payload))
            return {}, {key: evidence[key] for key in expanded_security._SOURCE_FIELDS}
        patches.enter_context(patch.object(expanded_security, '_database', return_value=self.database))
        patches.enter_context(patch.object(expanded_security, '_read_source', side_effect=read_source))
        security = []
        for (name, _family), source in zip(verification_plan.SECURITY_FAMILIES.items(), self.sources.values()):
            row = verification_plan.obligation(name)
            row['data_sources'] = [source]
            security.append(row)
        def sources(root):
            self.assertEqual(root, self.root)
            return copy.deepcopy(security)
        patches.enter_context(patch.object(expanded_security, 'security_obligations', side_effect=sources))
        reference = 'tests/test_393_bound.py::Bound393::test_body'
        document = {'change_id': 'owned393', 'acceptance_criteria': [
            {'id': 'AC-OWNED', 'evidence': [{'test': reference}]}], 'invariants': [], 'forbidden_outcomes': []}
        documents = {'path': '.getzilla/runtime/owned-package', 'spec': document,
                     'spec_digest': verification_plan.digest(document), 'requirements_digest': 'a' * 64}
        patches.enter_context(patch.object(verification_plan, '_plan_documents', return_value=documents))
        # Only policy-source reads use inert owned SourceFileLoader suppliers.
        sdk = self.directory / 'policy-sdk'
        sdk.mkdir(mode=0o700)
        (sdk / 'config').mkdir()
        (sdk / 'config/stacks.json').write_text('{}\n')
        def owned(name, package):
            path = sdk / (name.lstrip('.') + '.py')
            if not path.exists():
                path.write_text('POLICY = 1\n')
            module = ModuleType('getzilla' + name)
            module.__file__ = str(path)
            module.__spec__ = importlib.util.spec_from_file_location(module.__name__, path)
            module.__loader__ = module.__spec__.loader
            return module
        library = SimpleNamespace(import_module=owned, machinery=importlib.machinery, util=importlib.util)
        patches.enter_context(patch.object(verification_plan, 'importlib', library))
        patches.enter_context(patch.object(getzilla, 'STACK_DIR', sdk))
        self.policy_sdk = sdk
        plan = verification_plan.current_required_plan(self.root, mode='pr')
        execution = criterion_tests._execute_references(self.root, [reference])
        self.addCleanup(sys.modules.pop, 'test_393_bound', None)
        self.assertEqual(execution['verified_references'], [reference])
        checks = []
        for name in sorted({row['check_id'] for row in plan['obligations']}):
            rows = [row for row in plan['obligations'] if row['check_id'] == name]
            # Fixture-native providers report against explicit source-derived
            # declarations; they are not vendor/tool or real-feed qualification.
            optional = all(row['applicability'] == 'not_applicable' for row in rows)
            details = []
            if name in verification_plan.SECURITY_FAMILIES:
                details = [{'schema_version': 1, 'kind': 'security-result',
                    'family': verification_plan.SECURITY_FAMILIES[name], 'outcome': 'pass',
                    'data_sources': rows[0]['data_sources']}]
            elif name == 'criterion-tests':
                details = [execution]
            check = {'name': name, 'status': 'skip' if optional else 'pass',
                     'summary': 'owned bounded provider observation', 'details': details}
            verification_plan.bind_result(plan, check)
            checks.append(check)
        self.report = {'mode': 'pr', 'profiles': ['base'], 'status': 'pass', 'terminal_state': 'completed',
                       'required_plan': plan, 'checks': checks}
        self.assertEqual(verification_plan.report_gaps(self.root, self.report), [])
        self.assertEqual(self.validated_sources, set(self.sources))
        binding = receipts.active_architecture_binding(self.root, self.route)
        self.report['architecture'] = {'status': 'pass', 'fitness_status': 'pass', **binding}
        proof = {'schema_version': 1, 'route_id': 'owned393', 'kind': 'verification', 'status': 'pass',
                'created_at': self.now.isoformat(), 'report': None,
                'criterion_ids': [], 'spec_digest': None, 'spec_fingerprint': None,
                'git_head': self.head, 'tree_fingerprint': tree_fingerprint(self.root), **binding,
                'details': self.report}
        self.publish_qualification(proof)
        return proof

    def test_sufficient_plan_and_hydrated_report_stay_current_after_acceptance(self):
        proof = self.qualification_record()
        before = copy.deepcopy(proof['details']['required_plan'])
        publication = receipts._publish_verification_report(self.root, 'owned393', proof, None)
        try:
            envelope = {**proof, 'details': {'_verification_report': publication.reference}}
            path = receipts.receipt_dir(self.root, 'owned393') / 'verification.json'
            receipts._publish_receipt(path, envelope, None)
        finally:
            publication.close()
        self.assertEqual(receipts.get_receipt(self.root, 'owned393', 'verification')['details'], proof['details'])
        for target in (self.head, self.git('commit-tree', self.head + '^{tree}', '-p', self.head,
                                         '-m', 'owned accepted descendant')):
            self.git('update-ref', 'refs/remotes/origin/main', target)
            self.assertEqual(verification_plan.current_required_plan(self.root, mode='pr'), before)
            self.assertEqual(verification_plan.report_gaps(self.root, proof['details']), [])
            selected = select_architecture_comparison_base(self.root, self.route)
            self.assertEqual(selected.comparison_base_sha, self.target)
            self.assertEqual({row.comparison_base_sha for row in _git_range_selection(self.root, self.route, 'pr').bases}
                             - {self.head}, {self.anchor, self.target})
            with patch.object(verification_plan, 'current_required_plan', side_effect=AssertionError('recursive compiler')):
                self.assertEqual(receipts._qualified_architecture_comparison(self.root, self.route, self.head).comparison_base_sha,
                                 self.target)

    def publish_qualification(self, proof):
        publication = receipts._publish_verification_report(self.root, 'owned393', proof, None)
        try:
            envelope = {**proof, 'details': {'_verification_report': publication.reference}}
            path = receipts.receipt_dir(self.root, 'owned393') / 'verification.json'
            receipts._publish_receipt(path, envelope, None)
            return path, self.root / publication.reference['path']
        finally:
            publication.close()

    def test_normal_invalidation_during_validation_cannot_reuse_a_stored_witness(self):
        from getzilla import expanded_security
        proof = self.qualification_record()
        self.publish_qualification(proof)
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        validate = expanded_security.validate_data_source
        def invalidated(source, **kwargs):
            result = validate(source, **kwargs)
            receipts.invalidate_receipts(self.root, 'owned393', 'owned concurrent invalidation')
            return result
        with patch.object(expanded_security, 'validate_data_source', side_effect=invalidated):
            selected = receipts._qualified_architecture_comparison(self.root, self.route, self.head)
        self.assertIs(receipts.get_receipt(self.root, 'owned393', 'verification')['stale'], True)
        self.assertIsNone(selected)

    def test_direct_report_consumer_rechecks_policy_after_source_validation(self):
        from getzilla import expanded_security
        proof = self.qualification_record()
        self.publish_qualification(proof)
        report = receipts.get_receipt(self.root, 'owned393', 'verification')['details']
        self.assertEqual(verification_plan.report_gaps(self.root, report), [])
        validate = expanded_security.validate_data_source
        def changed(source, **kwargs):
            result = validate(source, **kwargs)
            (self.policy_sdk / 'process_limits.py').write_bytes(b'POLICY = 2\n')
            return result
        with patch.object(expanded_security, 'validate_data_source', side_effect=changed):
            self.assertTrue(verification_plan.report_gaps(self.root, report))

    def test_changed_removed_or_replaced_stored_evidence_cannot_reuse_a_witness(self):
        from getzilla import expanded_security
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        validate = expanded_security.validate_data_source
        for mutation in ('envelope-change', 'envelope-replace', 'artifact-replace', 'envelope-remove', 'artifact-remove'):
            path, artifact = self.publish_qualification(proof)
            changed = []
            def altered(source, **kwargs):
                result = validate(source, **kwargs)
                if not changed:
                    if mutation == 'envelope-change':
                        document = json.loads(path.read_bytes())
                        document['stale'] = True
                        receipts._publish_receipt(path, document, None)
                    elif mutation.endswith('replace'):
                        selected = artifact if mutation.startswith('artifact') else path
                        temporary = selected.with_name('owned-replacement.json')
                        temporary.write_bytes(selected.read_bytes())
                        os.replace(temporary, selected)
                    else:
                        (artifact if mutation.startswith('artifact') else path).unlink()
                    changed.append(mutation)
                return result
            with self.subTest(mutation=mutation), \
                 patch.object(expanded_security, 'validate_data_source', side_effect=altered):
                self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
                self.assertEqual(changed, [mutation])

    def test_direct_report_consumer_rechecks_intent_and_source_after_validation(self):
        from getzilla import expanded_security
        proof = self.qualification_record()
        self.publish_qualification(proof)
        report = receipts.get_receipt(self.root, 'owned393', 'verification')['details']
        source_path = self.root / 'trust-ci/owned.py'
        original = source_path.read_bytes()
        validate = expanded_security.validate_data_source
        for mutation in ('intent', 'source'):
            def changed(source, **kwargs):
                result = validate(source, **kwargs)
                if mutation == 'intent':
                    self.route['task'] = 'different owned intent'
                else:
                    source_path.write_bytes(b'owned = 2\n')
                return result
            try:
                with self.subTest(mutation=mutation), \
                     patch.object(expanded_security, 'validate_data_source', side_effect=changed):
                    self.assertTrue(verification_plan.report_gaps(self.root, report))
            finally:
                self.route.pop('task', None)
                source_path.write_bytes(original)
        self.assertEqual(verification_plan.report_gaps(self.root, report), [])

    def test_incomplete_or_unqualified_individual_results_cannot_freeze_ranges(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        variants = []
        for mutation in ('missing', 'duplicate', 'skip', 'unplanned', 'wrong-plan', 'unexecuted', 'wrong-family'):
            value = copy.deepcopy(proof)
            report = value['details']
            criterion = next(row for row in report['checks'] if row['name'] == 'criterion-tests')
            if mutation == 'missing':
                report['checks'].remove(criterion)
            elif mutation == 'duplicate':
                report['checks'].append(copy.deepcopy(criterion))
            elif mutation == 'skip':
                criterion['status'] = 'skip'
            elif mutation == 'unplanned':
                report['checks'].append({'name': 'unplanned-owned', 'status': 'pass', 'details': []})
            elif mutation == 'wrong-plan':
                report['required_plan']['digest'] = 'f' * 64
            elif mutation == 'unexecuted':
                criterion['details'][0]['tests'][0]['status'] = 'skip'
            else:
                source = next(row for row in report['checks'] if row['name'] == 'security-kev')
                source['details'][0]['family'] = 'inventory'
            variants.append((mutation, value))
        for mutation, value in variants:
            with self.subTest(mutation=mutation), patch.object(receipts, 'get_receipt', return_value=value):
                self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))

    def test_current_policy_context_source_and_payload_still_bind_qualification(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            self.assertIsNotNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
            policy = self.policy_sdk / 'process_limits.py'
            original = policy.read_bytes()
            policy.write_bytes(b'POLICY = 2\n')
            self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
            policy.write_bytes(original)
            self.route['task'] = 'changed owned intent'
            self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
            self.route.pop('task')
            source = self.root / 'trust-ci/owned.py'
            original = source.read_bytes()
            source.write_bytes(b'owned = 2\n')
            self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
            source.write_bytes(original)
            payload = self.database / 'PyPI'
            original = payload.read_bytes()
            payload.write_bytes(b'changed owned source')
            self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))
            payload.write_bytes(original)
            self.assertIsNotNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))

    def test_target_race_during_qualification_refuses_after_real_plan_validation(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        compile_plan = verification_plan._compile_required_plan
        def changed(*args, **kwargs):
            plan = compile_plan(*args, **kwargs)
            self.git('update-ref', 'refs/remotes/origin/main', self.anchor)
            return plan
        with patch.object(receipts, 'get_receipt', return_value=proof), \
             patch.object(verification_plan, '_compile_required_plan', side_effect=changed):
            with self.assertRaises(ArchitectureError):
                receipts._qualified_architecture_comparison(self.root, self.route, self.head)

    def test_policy_changed_during_source_validation_cannot_supply_qualification(self):
        from getzilla import expanded_security
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        validate = expanded_security.validate_data_source
        def changed(source, **kwargs):
            result = validate(source, **kwargs)
            (self.policy_sdk / 'process_limits.py').write_bytes(b'POLICY = 2\n')
            return result
        with patch.object(receipts, 'get_receipt', return_value=proof), \
             patch.object(expanded_security, 'validate_data_source', side_effect=changed):
            self.assertIsNone(receipts._qualified_architecture_comparison(self.root, self.route, self.head))

    def test_current_qualified_non_head_comparison_survives_acceptance(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            selected = select_architecture_comparison_base(self.root, self.route)
        self.assertEqual(selected.comparison_base_sha, self.target)
        self.assertNotEqual(selected.comparison_base_sha, self.head)
        self.assertEqual(selected.route_base_sha, self.anchor)

    def test_qualified_acceptance_retains_the_whole_review_union(self):
        proof = self.qualification_record()
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            ranges = _git_range_selection(self.root, self.route, 'pr')
        self.assertEqual(ranges.findings, [])
        self.assertIn(self.anchor, {row.comparison_base_sha for row in ranges.bases})
        self.assertIn(self.target, {row.comparison_base_sha for row in ranges.bases})

    def test_reconcile_only_or_failed_record_cannot_grant_frozen_comparison(self):
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        for record in (None, {'status': 'fail'}):
            with patch.object(receipts, 'get_receipt', return_value=record):
                selected = select_architecture_comparison_base(self.root, self.route)
            self.assertEqual(selected.comparison_base_sha, self.anchor)

    def test_explicit_invalidation_cannot_supply_qualification(self):
        proof = self.qualification_record()
        proof['stale'] = True
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            selected = select_architecture_comparison_base(self.root, self.route)
        self.assertEqual(selected.comparison_base_sha, self.anchor)

    def test_missing_required_plan_cannot_supply_qualification(self):
        proof = self.qualification_record()
        proof['details'].pop('required_plan', None)
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            selected = select_architecture_comparison_base(self.root, self.route)
        self.assertEqual(selected.comparison_base_sha, self.anchor)

    def test_changed_model_identity_cannot_borrow_a_qualified_witness(self):
        proof = self.qualification_record()
        witness = proof.get('architecture_comparison_witness', {})
        witness['model_digest'] = 'f' * 64
        proof['architecture_comparison_witness'] = witness
        self.git('update-ref', 'refs/remotes/origin/main', self.head)
        with patch.object(receipts, 'get_receipt', return_value=proof):
            with self.assertRaises((ArchitectureError, RuntimeError)):
                select_architecture_comparison_base(self.root, self.route)

    def test_foreign_and_nonancestor_operands_refuse(self):
        foreign = self.git('commit-tree', self.head + '^{tree}', '-m', 'owned unrelated root')
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, {'base_commit': foreign})
        self.git('update-ref', 'refs/remotes/origin/main', foreign)
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route)

    def test_malformed_and_ambiguous_operands_refuse(self):
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, {'base_commit': 'main'})
        self.git('symbolic-ref', '--delete', 'refs/remotes/origin/HEAD')
        self.git('config', 'init.defaultBranch', '')
        self.git('update-ref', 'refs/remotes/origin/master', self.anchor)
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route)

    def test_shallow_missing_ancestry_is_not_object_existence_proof(self):
        self.write('.git/shallow', self.target + '\n')
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route)

    def test_untrusted_range_projection_and_head_race_refuse(self):
        ranges = _git_range_selection(self.root, self.route, 'pr')
        ranges.bases.clear()
        with self.assertRaises(ArchitectureError):
            select_architecture_comparison_base(self.root, self.route, _trusted_ranges=ranges)
        selected = select_architecture_comparison_base(self.root, self.route)
        class ForeignSelection(SimpleNamespace):
            def __ne__(self, other):
                return False
        foreign = ForeignSelection(**vars(selected))
        foreign.comparison_base_sha = self.head
        with self.assertRaises(ArchitectureError):
            diff_architecture(self.root, base_sha=self.head, head_sha=self.head, _trusted_base_selection=foreign)
        model_digest = architecture_diff._comparison_model_digest
        def changed(*args, **kwargs):
            result = model_digest(*args, **kwargs)
            self.git('commit', '--allow-empty', '-qm', 'owned racing candidate')
            return result
        with patch.object(architecture_diff, '_comparison_model_digest', side_effect=changed):
            with self.assertRaises(ArchitectureError):
                select_architecture_comparison_base(self.root, self.route)

    def test_bootstrap_keeps_the_frozen_pre_adoption_baseline(self):
        empty = self.git('mktree', input=b'')
        frozen = self.git('commit-tree', empty, '-m', 'owned frozen pre-adoption')
        anchor = self.git('commit-tree', empty, '-p', frozen, '-m', 'owned consumer anchor')
        adopted = self.git('commit-tree', self.head + '^{tree}', '-p', anchor, '-m', 'owned consumer adoption')
        self.git('update-ref', 'refs/heads/candidate', adopted)
        with patch.object(architecture_diff, 'ADOPTION_BASE_SHA', frozen):
            selected = select_architecture_comparison_base(self.root, {'base_commit': anchor})
        self.assertEqual(selected.comparison_base_sha, frozen)
        self.assertEqual(selected.route_base_sha, anchor)
        self.assertTrue(selected.bootstrap_baseline)

    def test_accepted_prerequisite_does_not_exempt_unaccepted_mixed_changes(self):
        selected = select_architecture_comparison_base(self.root, self.route)
        clean = diff_architecture(self.root, base_sha=selected.comparison_base_sha, head_sha=self.head,
                                  _trusted_base_selection=selected)
        self.assertEqual(_change_separation(load_architecture(self.root), clean).status, 'pass')
        self.write('app.py', 'value = 3\n')
        self.head = self.commit('owned unaccepted implementation change')
        selected = select_architecture_comparison_base(self.root, self.route)
        mixed = diff_architecture(self.root, base_sha=selected.comparison_base_sha, head_sha=self.head,
                                  _trusted_base_selection=selected)
        self.assertEqual(_change_separation(load_architecture(self.root), mixed).status, 'fail')

    def test_governance_consumer_uses_the_same_architecture_witness(self):
        binding = receipts.active_architecture_binding(self.root, self.route)
        summary = {'ok': True, 'findings': [], 'overall_status': 'pass',
                   **{name: 'a' * 64 for name in ('rules_digest', 'debt_digest', 'examples_digest',
                                                 'schema_digest', 'governance_digest')},
                   **{name: [] for name in ('active_rule_ids', 'active_example_ids_versions',
                                           'open_debt_ids', 'overdue_debt_ids')}}
        # Only unrelated governance-summary data is controlled. Real tiny Git,
        # model and architecture binding/currentness execute above and below.
        with patch.object(receipts, '_governance_is_configured', return_value=True), \
             patch.object(receipts, 'load_governance', return_value=object()), \
             patch.object(receipts, 'governance_summary', return_value=summary):
            governed = receipts.active_governance_binding(self.root, self.route, binding)
            self.assertEqual(governed['governance_applicable_base_sha'], self.target)
            different = dict(binding)
            different['architecture_comparison_witness'] = dict(binding['architecture_comparison_witness'],
                                                                target_sha=self.head)
            with self.assertRaises(RuntimeError):
                receipts.active_governance_binding(self.root, self.route, different)


class OwnedPolicyProviderTests(unittest.TestCase):
    """No actual-engine policy/required-plan producer; all source ports are owned."""
    def test_changed_and_missing_provider_cannot_borrow_the_importer_hash(self):
        import getzilla
        directory = tempfile.TemporaryDirectory(prefix='393-policy-', dir=ROOT / '.getzilla/runtime')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        sdk = root / 'sdk'
        sdk.mkdir(mode=0o700)
        (sdk / 'config').mkdir()
        (sdk / 'config/stacks.json').write_text('{}\n')
        imported = []
        def owned(name, package):
            imported.append(name)
            path = sdk / (name.lstrip('.') + '.py')
            if not path.exists() and name != '.process_limits':
                path.write_text('raise AssertionError("source must never execute")\n')
            module = ModuleType('getzilla' + name)
            module.__file__ = str(path)
            module.__spec__ = importlib.util.spec_from_file_location(module.__name__, path)
            module.__loader__ = module.__spec__.loader
            return module
        provider = sdk / 'process_limits.py'
        provider.write_text('OUTPUT_LIMIT = 1024\n')
        library = SimpleNamespace(import_module=owned, machinery=importlib.machinery, util=importlib.util)
        with patch.object(verification_plan, 'importlib', library), patch.object(getzilla, 'STACK_DIR', sdk):
            first = verification_plan.policy_binding(root)
            provider.write_text('OUTPUT_LIMIT = 512\n')
            second = verification_plan.policy_binding(root)
            self.assertIn('process_limits.py', first['implementation'])
            self.assertNotEqual(first['implementation']['process_limits.py'], second['implementation']['process_limits.py'])
            self.assertNotEqual(first['digest'], second['digest'])
            self.assertEqual(first['implementation']['verification.py'], second['implementation']['verification.py'])
            provider.unlink()
            with self.assertRaises(ValueError):
                verification_plan.policy_binding(root)
