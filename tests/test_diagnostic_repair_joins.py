"""NEW closed diagnostic data controls; no Root producer or native command runs."""
import hashlib
import ast
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(W / '.getzilla'))
from getzilla import verification_progress_evidence as progress
from getzilla import security_osv_diagnostics as aliases

ACTIVE = False


def deny(event, args):
    if ACTIVE and (event == 'open' or event.startswith(('subprocess.', 'socket.'))
                   or event in {'os.system', 'os.posix_spawn'}):
        raise AssertionError('all file/process/network I/O denied during pure owned fixture')


sys.addaudithook(deny)


class DiagnosticRepairJoinsTests(unittest.TestCase):
    def owned(self, function):
        global ACTIVE
        ACTIVE = True
        try:
            return function()
        finally:
            ACTIVE = False

    def test_batch_lookup_keeps_two_second_budget_and_source_names(self):
        sources = {'tests/test_own_a.py': 'def test_a():\r\n    pass\r\n',
                   'tests/test_own_b.py': 'class Owned:\n    def test_b(self):\n        pass\n'}
        calls = []
        clock = [0.0]
        head = 'a' * 40

        def git(argv, **kwargs):
            calls.append(argv)
            clock[0] += 0.35
            if argv[1:] == ['rev-parse', 'HEAD']:
                out = head + '\n'
            elif argv[1] == 'ls-files':
                out = '\0'.join(sources) + '\0'
            elif argv[1:3] == ['cat-file', '--batch-check']:
                out = ''.join('b' * 40 + ' blob ' + str(len(v.encode())) + '\n' for v in sources.values())
            elif argv[1:3] == ['cat-file', '--batch']:
                out = ''.join('b' * 40 + ' blob ' + str(len(v.encode())) + '\n' + v + '\n'
                              for v in sources.values())
            elif argv[1:3] == ['cat-file', '-s']:
                out = str(len(sources[argv[-1].split(':', 1)[1]].encode()))
            elif argv[1] == 'show':
                out = sources[argv[-1].split(':', 1)[1]]
            else:
                self.fail('unexpected Git command')
            return types.SimpleNamespace(returncode=0, stdout=out.encode())

        with patch.object(progress, '_observed_run', side_effect=git), \
                patch.object(progress.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.owned(lambda: progress._trusted_progress_metadata(Path('/owned'), list(sources)))
        self.assertEqual(set(result), set(sources))
        self.assertLessEqual(len(calls), 5)
        self.assertLessEqual(clock[0], 2.0)

    def test_unknown_identity_retains_bounded_source_and_refusal(self):
        path = 'tests/test_diagnostic_repair_joins.py'
        node = 'DiagnosticRepairJoinsTests::test_unresolved_owned_node'
        observation = {}
        trusted = progress._trusted_progress_metadata(W, [path], observation=observation)
        self.assertIn(path, trusted)
        self.assertNotIn(node, trusted[path][1])
        self.assertEqual(observation['currentness'], 'verified')
        key = hashlib.sha256((path + '::' + node).encode()).hexdigest()
        raw = dict(selected_workers=1, status='observed',
                   slots=[dict(worker=0, state='active', path=path, key=key)])

        def observed(root, paths, **kwargs):
            self.assertEqual(root, W)
            self.assertEqual(paths, [path])
            kwargs['observation'].update(observation)
            return trusted

        with patch.object(progress, '_trusted_progress_metadata', side_effect=observed):
            result = self.owned(lambda: progress._core_progress_details(W, raw))
        self.assertIsNone(result['slots'][0]['identity'])
        self.assertEqual(result['slots'][0].get('source'), dict(path=path, key=key))
        self.assertEqual(result['source_lookup'], observation)
        self.assertEqual(result['status'], 'partial')
        self.assertLessEqual(len(json.dumps(result).encode()), 16000)

    def test_untrusted_deadline_lookup_omits_source_and_terminal_claims(self):
        path = 'tests/UNTRACKED_PRIVATE_CANARY.py'
        key = hashlib.sha256((path + '::test_unproved').encode()).hexdigest()
        raw = dict(selected_workers=1, status='observed',
                   slots=[dict(worker=0, state='active', path=path, key=key)])

        def unavailable(root, paths, **kwargs):
            self.assertEqual(paths, [path])
            kwargs['observation'].update(status='unavailable', reason='deadline', head=None)
            return {}

        with patch.object(progress, '_trusted_progress_metadata', side_effect=unavailable) as lookup, \
                patch.object(progress, '_observed_run', side_effect=AssertionError('no Git lookup')):
            result = self.owned(lambda: progress._core_progress_details(Path('/owned'), raw))
        self.assertEqual(lookup.call_count, 1)
        self.assertIsNone(result['slots'][0]['identity'])
        self.assertNotIn('source', result['slots'][0])
        self.assertNotIn(path, json.dumps(result))
        self.assertNotIn(key, json.dumps(result))
        self.assertEqual(result['source_lookup']['reason'], 'deadline')
        self.assertEqual(result['source_lookup']['currentness'], 'unknown')
        self.assertEqual(result['status'], 'partial')
        for name in ('failed_tests', 'completed_tests', 'passed_tests', 'exit_code', 'coverage'):
            self.assertNotIn(name, result)
        self.assertLessEqual(len(json.dumps(result).encode()), 16000)

    def test_changed_source_head_never_yields_named_identity(self):
        path = 'tests/test_owned.py'
        source = b'def test_owned():\n    pass\n'
        blob = b'b' * 40
        outputs = [b'a' * 40, path.encode() + b'\0', blob + b' blob ' + str(len(source)).encode() + b'\n',
                   blob + b' blob ' + str(len(source)).encode() + b'\n' + source + b'\n', b'c' * 40]
        observed = {}
        with patch.object(progress, '_observed_run', side_effect=[
                types.SimpleNamespace(returncode=0, stdout=value) for value in outputs]):
            result = self.owned(lambda: progress._trusted_progress_metadata(
                Path('/owned'), [path], observation=observed))
        self.assertEqual(result, {})
        self.assertEqual(observed['reason'], 'source-changed')
        self.assertEqual(observed['currentness'], 'unknown')

    def test_raw_failure_prefix_keeps_original_cap_and_reports_omissions(self):
        path = 'tests/' + 'x' * 190 + '.py'
        rows = [dict(worker=i, sequence=4, overflow=True, dropped=False, partial_tail=False,
                     events=[dict(ordinal=j, phase='call', path=path, key='a' * 64) for j in range(1, 5)])
                for i in range(64)]
        result = self.owned(lambda: progress._failure_progress_details(rows, {}, 64, trusted_paths={path}))
        self.assertLessEqual(len(json.dumps(result).encode()), 8192)
        self.assertTrue(result['render_truncated'])
        self.assertEqual(result.get('omitted_events'), 256 - len(result['events']))
        self.assertEqual(result['events'][0]['source'], dict(path=path, key='a' * 64))
        self.assertIsNone(result['events'][0]['identity'])

    def test_alias_snapshot_preserves_full_hashes_within_original_bound(self):
        formatter = getattr(aliases, 'snapshot_alias_message', None)
        self.assertTrue(callable(formatter), 'missing bounded full-identity snapshot projection')
        record = dict(id='OWNED-' * 20, aliases=[','])
        member = 'OWNED-MEMBER-' * 20
        detail = self.owned(lambda: aliases.alias_rejection(record, 0))
        error = ValueError('closed refusal')
        error.osv_alias_detail = detail
        message = self.owned(lambda: formatter('npm', error, member, record['id']))
        self.assertLess(len(message), 400)
        for value in (member, record['id'], ','):
            self.assertIn(hashlib.sha256(value.encode()).hexdigest(), message)
        self.assertNotIn(member, message)
        self.assertNotIn(record['id'], message)
        body = json.loads(message.partition(': ')[2])
        self.assertEqual(body['reason'], 'charset')
        self.assertEqual(body['type'], 'array/string')
        self.assertEqual((body['count'], body['index']), (1, 0))

    def test_optional_diagnostic_import_is_really_unavailable(self):
        from getzilla import pytest_progress
        import builtins
        original = builtins.__import__
        blocked = []

        def absent(name, globals=None, locals=None, fromlist=(), level=0):
            if name.rsplit('.', 1)[-1] == 'verification_failure_excerpt' or 'verification_failure_excerpt' in fromlist:
                blocked.append(True)
                raise ImportError('owned helper unavailable')
            return original(name, globals, locals, fromlist, level)

        with patch.object(builtins, '__import__', side_effect=absent):
            value = self.owned(lambda: pytest_progress._exception_diagnostic(AssertionError('owned refusal')))
        self.assertIsNone(value)
        self.assertEqual(blocked, [True])

    def test_retained_fixture_calls_have_supported_arguments(self):
        support = ast.parse((W / 'tests/_support.py').read_bytes())
        recovery = ast.parse((W / 'tests/test_verifier_recovery.py').read_bytes())
        hooks = ast.parse((W / 'tests/test_hooks.py').read_bytes())
        interfaces = {
            'project_copy': next(n for n in support.body if isinstance(n, ast.FunctionDef) and n.name == 'project_copy'),
            'routed_fixture': next(n for n in recovery.body if isinstance(n, ast.FunctionDef) and n.name == 'routed_fixture')}

        def check():
            for tree, caller in [(hooks, 'test_parent_contract_stop_allows_current_evidence'),
                                 (recovery, 'test_parent_contract_receipt_failure_keeps_completed_verdict_and_report')]:
                function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == caller)
                for call in ast.walk(function):
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id in interfaces:
                        arguments = interfaces[call.func.id].args
                        accepted = {a.arg for a in [*arguments.args, *arguments.kwonlyargs]}
                        self.assertLessEqual({k.arg for k in call.keywords}, accepted)
        self.owned(check)


if __name__ == '__main__':
    unittest.main(verbosity=2)
