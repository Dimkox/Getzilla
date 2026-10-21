"""Offline CI evidence and the installed verifier boundary. No mocked crypto claim."""
import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from tests.test_eu_ai_act import AuditBundleTests, Repo, ROOT, git


class CiAuditTests(unittest.TestCase):
    def test_ci_cli_does_not_create_python_bytecode_even_when_disabled(self):
        repo = Repo(self, installed=False)
        repo.write('scripts/getzilla_audit_bundle.py', (ROOT / 'scripts/getzilla_audit_bundle.py').read_text(encoding='utf-8'))
        shutil.copytree(ROOT / '.getzilla/getzilla', repo.root / '.getzilla/getzilla',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
        repo.commit('isolated CLI import fixture')
        env = {key: value for key, value in os.environ.items() if key != 'PYTHONDONTWRITEBYTECODE'}
        proc = subprocess.run([sys.executable, str(repo.root / 'scripts/getzilla_audit_bundle.py'),
                               '--ci-check', '--base', repo.base], cwd=repo.root,
                              env=env, capture_output=True, text=True, check=False, timeout=30)
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn('opt-in', proc.stdout)
        self.assertFalse(list(repo.root.rglob('__pycache__')))

    def module(self):
        return AuditBundleTests()._bundle_module()

    def repo(self):
        repo = Repo(self)
        repo.registry()
        repo.fresh_matrix(datetime.now(timezone.utc).date())
        repo.commit('registry')
        return repo

    def test_read_only_ci_check_uses_committed_opt_in_and_no_receipts(self):
        repo = self.repo()
        mod = self.module()
        before = git(repo.root, 'status', '--porcelain', '--untracked-files=all')
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {'TRUST_CI_BASE_SHA': repo.base}):
            self.assertEqual(mod.main(['--root', str(repo.root), '--ci-check']), 0)
        result = json.loads(out.getvalue())
        self.assertEqual(result['decision'], 'pass')
        self.assertEqual(result['authority'], 'evidence-only')
        self.assertNotIn('release_decision', result)
        self.assertNotIn('receipts', result)
        self.assertFalse((repo.root / '.getzilla/runtime').exists())
        self.assertEqual(git(repo.root, 'status', '--porcelain', '--untracked-files=all'), before)

    def test_ci_requires_base_and_opt_in_and_rejects_uncommitted_inputs(self):
        mod = self.module()
        repo = Repo(self, installed=False)
        with self.assertRaisesRegex(RuntimeError, 'opt-in'):
            mod.ci_check(repo.root, repo.base)
        repo.write('.gitignore', '.getzilla/config/\n')
        repo.commit('ignore config')
        repo.write('.getzilla/config/compliance.json', '{"enabled":["eu-ai-act"]}')
        with self.assertRaisesRegex(RuntimeError, 'committed'):
            mod.ci_check(repo.root, repo.base)
        enabled = self.repo()
        with self.assertRaisesRegex((ValueError, RuntimeError), 'base'):
            mod.ci_check(enabled.root, None)
        enabled.write('.getzilla/compliance/eu-ai-act/obligations.json', '{}')
        with self.assertRaisesRegex(RuntimeError, 'clean|committed'):
            mod.ci_check(enabled.root, enabled.base)

    def test_ci_evaluates_release_obligations(self):
        repo = self.repo()
        repo.registry({'id': 'bad', 'class': 'prohibited', 'purpose': 'social scoring', 'role': 'provider'})
        repo.commit('prohibited system')
        result = self.module().ci_check(repo.root, repo.base)
        self.assertEqual(result['decision'], 'block')

    def test_ci_rejects_opt_in_swap_between_inventory_and_capture(self):
        from getzilla import eu_ai_act
        repo = self.repo()
        mod = self.module()
        path = repo.root / eu_ai_act.COMPLIANCE_CONFIG
        enabled = path.read_bytes()
        disabled = json.dumps({'enabled': []}).encode()
        path.write_bytes(disabled)
        head = repo.commit('committed opt-out')
        with self.assertRaisesRegex(RuntimeError, 'opt-in'):
            mod.ci_check(repo.root, repo.base)
        changes, read_bytes = mod._tracked_changes, Path.read_bytes

        def start_swap(root, captured_head):
            result = changes(root, captured_head)
            path.write_bytes(enabled)
            return result

        def restore_after_read(current):
            content = read_bytes(current)
            if current == path:
                path.write_bytes(disabled)
            return content

        # Real file reads and the real evaluator: the old early read saw transient opt-in,
        # then committed capture saw restored opt-out and CI returned PASS with null EU data.
        with mock.patch.object(mod, '_tracked_changes', side_effect=start_swap), \
                mock.patch.object(Path, 'read_bytes', restore_after_read):
            with self.assertRaisesRegex(RuntimeError, 'opt-in|committed'):
                mod.ci_check(repo.root, repo.base)
        self.assertEqual(path.read_bytes(), disabled)
        self.assertEqual(repo.commit_sha(), head)
        self.assertEqual(git(repo.root, 'status', '--porcelain'), '')

    def test_ci_rejects_null_or_skipped_evaluation(self):
        repo = self.repo()
        mod = self.module()
        for report in (None, {'status': 'skip', 'decision': 'pass'}):
            with self.subTest(report=report), mock.patch.object(
                    mod, '_compliance', return_value=({'eu_ai_act': report}, [], [])):
                with self.assertRaisesRegex(RuntimeError, 'evaluat'):
                    mod.ci_check(repo.root, repo.base)

    def test_ignored_registry_and_executable_inputs_cannot_change_signed_source(self):
        for relative in ('.getzilla/config/ai-systems.json', '.getzilla/getzilla/extra.py'):
            with self.subTest(relative=relative):
                repo = Repo(self)
                repo.write('.gitignore', relative + '\n')
                repo.commit('ignored input')
                repo.write(relative, '{"schema_version":"ai-systems-v1","systems":[]}'
                           if relative.endswith('.json') else 'VALUE = True\n')
                with self.assertRaisesRegex(RuntimeError, 'committed'):
                    self.module().ci_check(repo.root, repo.base)

    def test_base_is_resolved_and_iso_cannot_gate(self):
        repo = self.repo()
        mod = self.module()
        git(repo.root, 'tag', 'prior', repo.base)
        result = mod.build(repo.root, 'prior')
        self.assertEqual(result['comparison_base'], repo.base)
        self.assertIn('verification receipt', ' '.join(result['reasons']))
        repo.write('.getzilla/compliance/eu-ai-act/iso42001-map.json', '{')
        repo.commit('invalid informational map')
        result = mod.build(repo.root, 'prior')
        self.assertIsNone(result['compliance']['iso42001'])
        self.assertEqual(len(result['reasons']), 1)

    def test_all_decision_inputs_are_committed_and_present(self):
        paths = ('.getzilla/config/compliance.json', '.getzilla/compliance/eu-ai-act/obligations.json',
                 '.getzilla/config/ai-systems.json', '.getzilla/config/diff-risk-rules.json',
                 '.getzilla/config/cost-providers.json', '.getzilla/getzilla/loaded.py')
        for relative in paths:
            with self.subTest(relative=relative):
                repo = self.repo()
                if relative.endswith('.py'):
                    repo.write(relative, 'VALUE = True\n')
                    repo.commit('module fixture')
                git(repo.root, 'update-index', '--skip-worktree', relative)
                path = repo.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b'\n')
                self.assertEqual(git(repo.root, 'status', '--porcelain'), '')
                with self.assertRaisesRegex(RuntimeError, 'committed'):
                    self.module().ci_check(repo.root, repo.base)
                path.unlink()
                with self.assertRaisesRegex(RuntimeError, 'committed|opt-in'):
                    self.module().ci_check(repo.root, repo.base)

    def test_ignored_rules_and_providers_are_rejected(self):
        for name in ('diff-risk-rules.json', 'cost-providers.json'):
            with self.subTest(name=name):
                repo = self.repo()
                relative = '.getzilla/config/' + name
                git(repo.root, 'rm', '--cached', relative)
                repo.write('.gitignore', relative + '\n')
                repo.commit('ignored decision input')
                with self.assertRaisesRegex(RuntimeError, 'committed'):
                    self.module().ci_check(repo.root, repo.base)

    def test_audit_uses_explicit_rules_and_fresh_providers(self):
        from getzilla import cost_guard
        repo = self.repo()
        rules_path = repo.root / '.getzilla/config/diff-risk-rules.json'
        rules = json.loads(rules_path.read_text())
        rules['tests'] = ['docs/**']
        rules_path.write_text(json.dumps(rules), encoding='utf-8')
        repo.registry({'id': 'bot', 'purpose': 'assistant', 'class': 'limited', 'role': 'provider',
                       'paths': ['src/**'], 'disclosure_symbol': 'AI_DISCLOSURE', 'generates_content': False,
                       'confirmation': {'by': 'Fixture', 'role': 'owner', 'date': '2026-10-21'}})
        repo.write('src/bot.py', 'AI_DISCLOSURE = "fixture"\n')
        repo.write('docs/design.md', 'The application uses AI_DISCLOSURE.\n')
        repo.commit('explicit audited rules')
        result = self.module().ci_check(repo.root, repo.base)
        self.assertEqual(result['decision'], 'pass', result['reasons'])
        provider_path = repo.root / '.getzilla/config/cost-providers.json'
        real = provider_path.read_text(encoding='utf-8')
        empty = json.loads(real)
        empty['python_modules'] = []
        empty['hosts'] = []
        provider_path.write_text(json.dumps(empty), encoding='utf-8')
        cost_guard.load_providers(provider_path)
        self.addCleanup(cost_guard.load_providers.cache_clear)
        provider_path.write_text(real, encoding='utf-8')
        repo.registry()
        repo.write('src/bot.py', 'import openai\nopenai.chat.completions.create(model="fixture", messages=[])\n')
        repo.commit('fresh provider input')
        result = self.module().ci_check(repo.root, repo.base)
        self.assertEqual(result['decision'], 'review')
        self.assertIn('AI_SYSTEM_UNREGISTERED', ' '.join(result['reasons']))

    def test_head_date_and_optional_metadata_use_one_snapshot(self):
        from getzilla import eu_ai_act
        repo = self.repo()
        repo.write('VERSION', 'fixture-version\n')
        repo.write(eu_ai_act.ISO_MAP, '{"map":{"AIA-1":["A.2"]}}')
        head = repo.commit('snapshot metadata')
        tree = git(repo.root, 'rev-parse', head + '^{tree}')
        mod = self.module()
        evaluate = eu_ai_act.evaluate
        observed = []

        def move_head(root, mode, bases, evaluated_head, **kwargs):
            observed.append((evaluated_head, kwargs.get('today')))
            git(repo.root, 'update-ref', 'HEAD', repo.base)
            return evaluate(root, mode, bases, evaluated_head, **kwargs)

        with mock.patch.object(eu_ai_act, 'evaluate', side_effect=move_head):
            result = mod.build(repo.root, repo.base)
        self.assertEqual(result['commit'], head)
        self.assertEqual(result['tree'], tree)
        self.assertEqual(result['version'], 'fixture-version')
        self.assertEqual(result['compliance']['iso42001']['map'], {'AIA-1': ['A.2']})
        self.assertEqual(observed, [(head, datetime.now(timezone.utc).date())])

    def test_git_replacements_and_inherited_git_environment_do_not_change_audit(self):
        from getzilla.util import tree_fingerprint
        repo = self.repo()
        repo.registry({'id': 'bad', 'class': 'prohibited', 'purpose': 'social scoring', 'role': 'provider'})
        head = repo.commit('prohibited system')
        expected_fingerprint = tree_fingerprint(repo.root)
        git(repo.root, 'replace', head, repo.base)
        with mock.patch.dict(os.environ, {'GIT_DIR': str(repo.root / 'absent.git')}):
            result = self.module().ci_check(repo.root, repo.base)
            bundle = self.module().build(repo.root, repo.base)
        self.assertEqual(result['commit'], head)
        self.assertEqual(result['decision'], 'block')
        self.assertEqual(bundle['tree_fingerprint'], expected_fingerprint)

    def test_bundle_receipt_fingerprint_keeps_captured_head_and_existing_grammar(self):
        from getzilla.util import tree_fingerprint
        repo = self.repo()
        repo.write('untracked-note.md', 'fixture note\n')
        head = repo.commit_sha()
        expected = tree_fingerprint(repo.root)
        repo.write('.getzilla/runtime/receipts/fixture/verification.json', json.dumps({
            'kind': 'verification', 'status': 'pass', 'tree_fingerprint': expected}))
        mod = self.module()
        resolve_base = mod._base

        def move_head(root, base, **kwargs):
            resolved = resolve_base(root, base, **kwargs)
            git(root, 'update-ref', 'HEAD', repo.base)
            return resolved

        with mock.patch.object(mod, '_base', side_effect=move_head):
            bundle = mod.build(repo.root, repo.base)
        self.assertEqual(bundle['commit'], head)
        self.assertEqual(bundle['tree_fingerprint'], expected)
        self.assertEqual(bundle['release_decision'], 'eligible', bundle['reasons'])

    @contextlib.contextmanager
    def git_excludes(self, pattern, source='global'):
        with tempfile.TemporaryDirectory() as temporary:
            private = Path(temporary)
            ignore = private / 'fixture.ignore'
            ignore.write_text(pattern + '\n', encoding='utf-8')
            config, empty = private / 'fixture.gitconfig', private / 'empty.gitconfig'
            empty.write_text('', encoding='utf-8')
            git(private, 'config', '--file', str(config), 'core.excludesFile', str(ignore))
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update({'GIT_CONFIG_GLOBAL': str(config if source == 'global' else empty),
                        'GIT_CONFIG_SYSTEM': str(config if source == 'system' else empty),
                        'GIT_CONFIG_NOSYSTEM': '0'})
            with mock.patch.dict(os.environ, env, clear=True):
                yield private

    def test_receipt_keeps_global_and_system_ignored_notes_but_not_source_changes(self):
        from getzilla.util import tree_fingerprint
        for source in ('global', 'system'):
            with self.subTest(source=source), self.git_excludes('editor-note.fixture', source):
                repo = self.repo()
                mod = self.module()
                expected = tree_fingerprint(repo.root)
                repo.write('.getzilla/runtime/receipts/fixture/verification.json', json.dumps({
                    'kind': 'verification', 'status': 'pass', 'tree_fingerprint': expected}))
                self.assertEqual(mod.build(repo.root, repo.base)['release_decision'], 'eligible')
                repo.write('editor-note.fixture', 'private ignored editor state\n')
                self.assertEqual(tree_fingerprint(repo.root), expected)
                bundle = mod.build(repo.root, repo.base)
                self.assertEqual(bundle['tree_fingerprint'], expected)
                self.assertEqual(bundle['release_decision'], 'eligible', bundle['reasons'])
                repo.write('untracked-source.py', 'VALUE = 1\n')
                changed = tree_fingerprint(repo.root)
                self.assertNotEqual(changed, expected)
                bundle = mod.build(repo.root, repo.base)
                self.assertEqual(bundle['tree_fingerprint'], changed)
                self.assertEqual(bundle['release_decision'], 'blocked')

    def test_receipt_global_excludes_cannot_redirect_git_identity(self):
        from getzilla.util import tree_fingerprint
        with self.git_excludes('editor-note.fixture') as private:
            repo, foreign = self.repo(), self.repo()
            repo.write('editor-note.fixture', 'ignored\n')
            repo.write('actual-source.py', 'VALUE = 1\n')
            expected, head = tree_fingerprint(repo.root), repo.commit_sha()
            hijack = private / 'hijack.ignore'
            hijack.write_text('actual-source.py\n', encoding='utf-8')
            with mock.patch.dict(os.environ, {
                    'GIT_DIR': str(foreign.root / '.git'), 'GIT_WORK_TREE': str(foreign.root),
                    'GIT_INDEX_FILE': str(foreign.root / '.git/index'),
                    'GIT_OBJECT_DIRECTORY': str(foreign.root / '.git/objects'),
                    'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.excludesFile',
                    'GIT_CONFIG_VALUE_0': str(hijack),
                    'GIT_CONFIG_PARAMETERS': "'core.excludesFile=" + str(hijack) + "'"}):
                result = self.module().build(repo.root, repo.base)
            self.assertEqual(result['commit'], head)
            self.assertEqual(result['tree_fingerprint'], expected)

    def test_global_ignore_cannot_admit_uncommitted_decision_input(self):
        relative = '.getzilla/config/diff-risk-rules.json'
        repo = self.repo()
        with self.git_excludes(relative):
            git(repo.root, 'rm', '--cached', relative)
            repo.commit('globally ignored decision input')
            self.assertEqual(git(repo.root, 'status', '--porcelain'), '')
            with self.assertRaisesRegex(RuntimeError, 'committed'):
                self.module().ci_check(repo.root, repo.base)

    def test_receipt_untracked_inventory_is_bounded_and_validated(self):
        from getzilla import fsx
        repo = self.repo()
        mod = self.module()
        repo.write('untracked-note.fixture', 'fixture\n')
        with mock.patch.object(mod, 'GIT_PATH_OUTPUT_LIMIT', 4):
            with self.assertRaisesRegex(RuntimeError, 'output.*limit'):
                mod._audit_fingerprint(repo.root, repo.commit_sha())
        spawn = fsx.owned_popen

        def child(body):
            return mock.patch.object(fsx, 'owned_popen', side_effect=lambda argv, **kwargs:
                                     spawn([sys.executable, '-c', body], **kwargs))

        with child('import time; time.sleep(10)'), mock.patch.object(mod, 'GIT_INVENTORY_TIMEOUT', 0.1):
            with self.assertRaisesRegex(RuntimeError, 'timeout'):
                mod._audit_fingerprint(repo.root, repo.commit_sha())
        for raw in (b'no-terminator', b'../outside\0', b'/absolute\0', b'\0', b'a//b\0'):
            with self.subTest(raw=raw), child('import sys; sys.stdout.buffer.write(' + repr(raw) + ')'):
                with self.assertRaisesRegex(RuntimeError, 'path inventory'):
                    mod._audit_fingerprint(repo.root, repo.commit_sha())


class AttestationClaimTests(unittest.TestCase):
    def setUp(self):
        self.mod = AuditBundleTests()._bundle_module()
        self.head, self.base = 'a' * 40, 'b' * 40
        self.payload = {'schema_version': 2, 'status': 'passed', 'head_sha': self.head, 'base_sha': self.base,
                        'repository': 'owner/project', 'attestation_id': 'a1', 'key_id': 'k1',
                        'policy_digest': 'c' * 64,
                        'spec_digest': None,
                        'criterion_coverage': {'spec_count': 0, 'criterion_total': 0,
                                               'criterion_mapped': 0, 'unmapped_ids': []},
                        'command_results': [{'name': 'eu-ai-act-audit', 'status': 'pass', 'exit_code': 0,
                                             'argv': ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check']}]}

    def problem(self, payload):
        return self.mod.attestation_problem(payload, self.head, self.base, 'owner/project')

    def test_exact_successful_execution_is_required(self):
        self.assertIsNone(self.problem(self.payload))
        for version in (1, True, False, '2', 2.0, 3, None):
            self.assertIn('schema_version', self.problem({**self.payload, 'schema_version': version}))
        for key, value in (('status', 'failed'), ('head_sha', 'd' * 40), ('base_sha', 'e' * 40),
                           ('repository', 'other/project')):
            bad = {**self.payload, key: value}
            self.assertIn(key, self.problem(bad))
        for argv in (None, [], ['echo', 'scripts/getzilla_audit_bundle.py', '--ci-check'],
                     ['python3', '-c', 'scripts/getzilla_audit_bundle.py'],
                     ['python3', 'other/getzilla_audit_bundle.py', '--ci-check'],
                     ['python3', 'scripts/getzilla_audit_bundle.py.bak', '--ci-check'],
                     ['python3', 'scripts/getzilla_audit_bundle.py', '--help', '--ci-check'],
                     ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check', '--root', 'other'],
                     ['sh', '-c', 'python3 scripts/getzilla_audit_bundle.py --ci-check'],
                     ['python3', 'scripts/getzilla_audit_bundle.py'],
                     ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check', '--base', '${BASE_SHA}']):
            bad = copy.deepcopy(self.payload)
            bad['command_results'][0]['argv'] = argv
            with self.subTest(argv=argv):
                self.assertIsNotNone(self.problem(bad))
        for key, value in (('status', 'fail'), ('exit_code', 1), ('exit_code', False), ('exit_code', 0.0)):
            bad = copy.deepcopy(self.payload)
            bad['command_results'][0][key] = value
            self.assertIsNotNone(self.problem(bad))

    def test_attestation_cannot_remove_normal_receipt_requirement(self):
        repo = Repo(self)
        repo.registry()
        repo.commit('registry')
        payload = {**self.payload, 'head_sha': repo.commit_sha(), 'base_sha': repo.base}
        with mock.patch.object(self.mod, 'verify_attestation', return_value=payload):
            bundle = self.mod.build(repo.root, repo.base, attestation=Path('envelope.json'),
                                    public_key=Path('public.pem'), verifier=Path('/trusted/bin/adaptive-trust-ci'),
                                    repository='owner/project')
        self.assertEqual(bundle['authority'], 'trust-ci-attested')
        self.assertEqual(bundle['release_decision'], 'blocked')
        self.assertIn('verification receipt', ' '.join(bundle['reasons']))
        with mock.patch.object(self.mod, 'verify_attestation', side_effect=ValueError('bad signature')):
            bundle = self.mod.build(repo.root, repo.base, attestation=Path('envelope.json'),
                                    public_key=Path('public.pem'), verifier=Path('/trusted/bin/adaptive-trust-ci'),
                                    repository='owner/project')
        self.assertNotEqual(bundle['authority'], 'trust-ci-attested')
        self.assertIn('bad signature', ' '.join(bundle['reasons']))

    def test_contract_optional_argv_preserves_legacy_closed_schema(self):
        import jsonschema
        schema = json.loads((ROOT / 'engineering/contracts/schemas/trust-ci-attestation-envelope.v2.json').read_text())
        command = schema['properties']['payload']['properties']['command_results']['items']
        old = {'name': 'x', 'status': 'pass', 'exit_code': 0, 'duration_seconds': 0, 'output_sha256': 'a' * 64}
        jsonschema.validate(old, command)
        jsonschema.validate({**old, 'argv': ['python3', 'scripts/getzilla_audit_bundle.py', '--ci-check']}, command)
        legacy = json.loads((ROOT / 'engineering/contracts/schemas/trust-ci-attestation-envelope.v1.json').read_text())
        old_command = legacy['properties']['payload']['properties']['command_results']['items']
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({**old, 'argv': ['python3']}, old_command)
        payload = {**self.payload, 'job_id': 'j1', 'pr_number': 1, 'changed_files': [], 'approved_scopes': [],
                   'started_at': '2026-10-21T00:00:00Z', 'completed_at': '2026-10-21T00:00:01Z',
                   'command_results': [{**old, 'argv': ['python3']}], 'spec_digest': None,
                   'criterion_coverage': {'spec_count': 0, 'criterion_total': 0, 'criterion_mapped': 0, 'unmapped_ids': []}}
        jsonschema.validate({'payload': payload, 'signature': 'schema-only-fixture'}, schema)
        for missing in (('spec_digest',), ('criterion_coverage',), ('spec_digest', 'criterion_coverage')):
            incomplete = {key: value for key, value in payload.items() if key not in missing}
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({'payload': incomplete, 'signature': 'schema-only-fixture'}, schema)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({'payload': {**payload, 'schema_version': 1}, 'signature': 'schema-only-fixture'}, schema)
        for extra in ({'argv': []}, {'argv': [0]}, {'arbitrary': True}):
            with self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({**old, **extra}, command)


@unittest.skipIf(os.name == 'nt', 'POSIX test executable fixture')
class VerifierProcessTests(unittest.TestCase):
    def test_safe_execution_boundary_and_bounds(self):
        mod = AuditBundleTests()._bundle_module()
        repo = Repo(self)
        with tempfile.TemporaryDirectory() as tmp:
            trusted = Path(tmp)
            exe = trusted / 'adaptive-trust-ci'
            envelope, public = trusted / 'envelope.json', trusted / 'public.pem'
            envelope.write_text('{}', encoding='utf-8')
            public.write_text('public fixture', encoding='utf-8')
            def tool(body):
                exe.write_text('#!' + sys.executable + '\n' + body, encoding='utf-8')
                exe.chmod(0o700)
            tool('import json, os, sys\nassert "PYTHONPATH" not in os.environ\n'
                 'assert sys.argv[1:3] == ["attestation-verify", "--attestation"]\n'
                 'print(json.dumps({"status":"passed"}))\n')
            with mock.patch.dict(os.environ, {'PYTHONPATH': str(repo.root)}):
                self.assertEqual(mod.verify_attestation(repo.root, envelope, public, exe), {'status': 'passed'})
            tool('raise SystemExit(1)\n')
            with self.assertRaisesRegex(ValueError, 'verifier'):
                mod.verify_attestation(repo.root, envelope, public, exe)
            tool('print("x" * 65536)\n')
            with mock.patch.object(mod, 'VERIFIER_OUTPUT_LIMIT', 1024):
                with self.assertRaisesRegex(ValueError, 'output'):
                    mod.verify_attestation(repo.root, envelope, public, exe)
            tool('import time\ntime.sleep(10)\n')
            with mock.patch.object(mod, 'VERIFIER_TIMEOUT', 0.1):
                with self.assertRaisesRegex(ValueError, 'timeout'):
                    mod.verify_attestation(repo.root, envelope, public, exe)
            with self.assertRaisesRegex(ValueError, 'outside|trusted'):
                mod.verify_attestation(repo.root, envelope, public, repo.root / 'verifier')
