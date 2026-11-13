"""New tiny Git worlds; no actual-project inventory or verification producer."""
from __future__ import annotations

import json
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
        # Owned metadata model of an existing completed qualification; no Root
        # receipt is written and no execution/qualification credit is claimed.
        self.route['route_id'] = 'owned393'
        binding = receipts.active_architecture_binding(self.root, self.route)
        return {'schema_version': 1, 'route_id': 'owned393', 'kind': 'verification', 'status': 'pass',
                'git_head': self.head, 'tree_fingerprint': tree_fingerprint(self.root), **binding,
                'details': {'mode': 'pr', 'status': 'pass', 'terminal_state': 'completed',
                            'architecture': {'status': 'pass', 'fitness_status': 'pass', **binding}}}

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
