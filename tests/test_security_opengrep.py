from __future__ import annotations

import hashlib
import ctypes
import importlib
import importlib.util
import os
import platform
import shutil
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))


@unittest.skipUnless(os.name == 'posix', 'POSIX FD census profile unavailable')
class SourceCensusTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_opengrep'),
                             'the actual source census/adapter must exist')
        self.scanner = importlib.import_module('getzilla.security_opengrep')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / 'src').mkdir()
        (self.root / 'src/app.py').write_text('print("public")\n')
        (self.root / 'src/app.py').chmod(0o644)

    def test_census_is_independent_of_candidate_ignore_and_preserves_native_exclusions(self):
        (self.root / '.gitignore').write_text('src/\n')
        (self.root / '.semgrepignore').write_text('src/\n')
        (self.root / 'tests').mkdir()
        (self.root / 'tests/omitted.py').write_text('public\n')
        (self.root / 'nested').mkdir()
        (self.root / 'nested/fixtures').mkdir()
        (self.root / 'nested/fixtures/omitted.py').write_text('public\n')
        with self.scanner.SourceCut(self.root, 'native') as cut:
            self.assertEqual([row.path for row in cut.entries], ['src/app.py'])
            self.assertEqual(cut.entries[0].digest,
                             hashlib.sha256(b'print("public")\n').hexdigest())
            cut.assert_current()

    def test_new_missing_and_changed_targets_invalidate_original_cut(self):
        for change in ('add', 'remove', 'modify'):
            with self.subTest(change=change):
                target = self.root / 'src/app.py'
                target.write_text('print("public")\n')
                target.chmod(0o644)
                with self.scanner.SourceCut(self.root, 'native') as cut:
                    if change == 'add':
                        (self.root / 'src/new.py').write_text('print(1)\n')
                    elif change == 'remove':
                        target.unlink()
                    else:
                        target.write_text('print("changed")\n')
                    with self.assertRaisesRegex(self.scanner.OpenGrepError, 'source_changed'):
                        cut.assert_current()
                (self.root / 'src/new.py').unlink(missing_ok=True)

    def test_selected_symlink_hardlink_and_private_leaf_are_refused(self):
        target = self.root / 'src/app.py'
        target.chmod(0o600)
        with self.assertRaises(self.scanner.OpenGrepError):
            self.scanner.SourceCut(self.root, 'native')
        target.chmod(0o644)
        linked = self.root / 'src/linked.py'
        os.link(target, linked)
        with self.assertRaises(self.scanner.OpenGrepError):
            self.scanner.SourceCut(self.root, 'native')
        linked.unlink()
        linked.symlink_to(target)
        with self.assertRaises(self.scanner.OpenGrepError):
            self.scanner.SourceCut(self.root, 'native')

    def test_unknown_profile_and_exhausted_census_do_not_become_empty(self):
        with self.assertRaises(self.scanner.OpenGrepError):
            self.scanner.SourceCut(self.root, 'caller-says-complete')
        with mock.patch.object(self.scanner, 'MAX_ENTRIES', 1), self.assertRaises(self.scanner.OpenGrepError):
            self.scanner.SourceCut(self.root, 'native')

    def test_empty_roster_is_distinct_from_failed_enumeration(self):
        (self.root / 'src/app.py').unlink()
        with self.scanner.SourceCut(self.root, 'native') as cut:
            self.assertEqual(cut.entries, ())
            cut.assert_current()

    def test_foreign_metadata_owner_is_not_admitted(self):
        from types import SimpleNamespace
        info = (self.root / 'src/app.py').stat()
        foreign = SimpleNamespace(**{name: getattr(info, name) for name in (
            'st_mode', 'st_uid', 'st_nlink', 'st_size')})
        foreign.st_uid += 1
        with self.assertRaises(self.scanner.OpenGrepError):
            self.scanner._public(foreign, os.getuid(), 1024)

    def test_replaced_selected_inode_is_refused_before_reading_its_bytes(self):
        original = self.scanner.fsx.open_at
        target = self.root / 'src/app.py'

        def replace_before_open(directory, name, flags, *args, **kwargs):
            target.rename(self.root / 'old-public-source')
            target.write_text('foreign replacement public fixture\n')
            target.chmod(0o644)
            return original(directory, name, flags, *args, **kwargs)

        with mock.patch.object(self.scanner.fsx, 'open_at', side_effect=replace_before_open), \
             mock.patch.object(self.scanner.os, 'read', wraps=os.read) as read:
            with self.assertRaises(self.scanner.OpenGrepError):
                self.scanner.SourceCut(self.root, 'native')
            read.assert_not_called()


class SyntaxProfileTests(unittest.TestCase):
    def setUp(self):
        self.scanner = importlib.import_module('getzilla.security_opengrep')
        self.assertTrue(callable(getattr(self.scanner, 'syntax_frontend', None)),
                        'compatible grammar needs actual protected frontend admission')

    def test_caller_path_and_unproven_languages_cannot_mint_a_frontend(self):
        with mock.patch.dict(os.environ, {'PATH': '/candidate-controlled'}):
            for language in ('go', 'typescript', 'jsx', 'caller-claims-python'):
                with self.subTest(language=language), self.assertRaisesRegex(
                        self.scanner.OpenGrepError, '^syntax_frontend_unavailable$'):
                    self.scanner.syntax_frontend(language)

    def test_root_running_and_unqualified_platform_refuse_protected_boundary(self):
        with mock.patch.object(os, 'geteuid', return_value=0, create=True), self.assertRaises(
                self.scanner.OpenGrepError):
            self.scanner.syntax_frontend('python')
        with mock.patch.object(self.scanner.fsx, 'WINDOWS', True), self.assertRaises(
                self.scanner.OpenGrepError):
            self.scanner.syntax_frontend('python')

    @unittest.skipUnless(os.name == 'posix' and os.getuid() != 0 and Path('/usr/bin/python3.12').exists(),
                         'actual protected Python3.12 frontend unavailable')
    def test_actual_python_compile_rejects_recovery_without_executing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            with self.scanner.syntax_frontend('python') as frontend:
                self.assertEqual(frontend.grammar, 'python3.12')
                self.scanner.syntax_check(frontend, b'raise RuntimeError("must not execute")\n', root)
                with self.assertRaisesRegex(self.scanner.OpenGrepError, '^syntax_incomplete$'):
                    self.scanner.syntax_check(frontend, b'def broken(:\n  print(1)\n', root)

    @unittest.skipUnless(sys.platform.startswith('linux') and os.getuid() != 0
                         and Path('/usr/bin/php8.3').exists() and Path('/usr/bin/node').exists(),
                         'actual protected PHP/Node grammar profiles unavailable')
    def test_actual_php_and_javascript_parse_sealed_bytes_without_source_execution(self):
        fixtures = [('php', b'<?php throw new Exception("must not execute");\n',
                     b'<?php function broken( { echo "inert"; }\n'),
                    ('javascript', b'export const value=1; throw new Error("must not execute");\n',
                     b'function broken( { console.log("inert"); }\n')]
        with tempfile.TemporaryDirectory() as directory:
            for language, valid, invalid in fixtures:
                with self.subTest(language=language), self.scanner.syntax_frontend(language) as frontend:
                    self.scanner.syntax_check(frontend, valid, Path(directory))
                    with self.assertRaisesRegex(self.scanner.OpenGrepError, '^syntax_incomplete$'):
                        self.scanner.syntax_check(frontend, invalid, Path(directory))


@unittest.skipUnless(sys.platform.startswith('linux') and hasattr(os, 'memfd_create'),
                     'sealed Linux executable profile unavailable')
class SealedPublicToolTests(unittest.TestCase):
    def test_tool_snapshot_is_write_sealed_and_runs_exact_held_bytes(self):
        scanner = importlib.import_module('getzilla.security_opengrep')
        self.assertTrue(callable(getattr(scanner, 'sealed_tool', None)),
                        'verified executable bytes need an immutable held handoff')
        from getzilla.python_test_runner import execute
        raw = Path('/usr/bin/true').read_bytes()
        with scanner.sealed_tool(raw) as tool, tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(OSError):
                os.pwrite(tool.descriptor, b'changed', 0)
            with self.assertRaises(OSError):
                os.ftruncate(tool.descriptor, 0)
            tool.assert_current()
            result = execute([tool.path], Path(directory), {}, inherited_fds=(tool.descriptor,))
            self.assertEqual(result.returncode, 0, result.stderr)
            tool.assert_current()


class RuleHeaderProfileTests(unittest.TestCase):
    def setUp(self):
        self.scanner = importlib.import_module('getzilla.security_opengrep')
        self.assertTrue(callable(getattr(self.scanner, 'rule_catalog', None)),
                        'original anchored rule bytes need a closed metadata binding')

    def test_all_four_actual_rule_files_preserve_pattern_anchors_and_unique_ids(self):
        root = Path(__file__).resolve().parents[1] / '.getzilla/sast/rules'
        identifiers = []
        for path in sorted(root.glob('*.yaml')):
            rules = self.scanner.rule_catalog(path.read_bytes())
            self.assertGreater(len(rules), 0)
            identifiers.extend(rule.identifier for rule in rules)
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_duplicate_alias_merge_flow_and_multiline_headers_are_incomplete(self):
        clean = (b'rules:\n  - id: inert\n    languages: [python]\n    severity: WARNING\n'
                 b'    message: inert\n    pattern-sources: &sources\n      - pattern: input()\n'
                 b'    pattern-sinks: *sources\n')
        self.assertEqual(self.scanner.rule_catalog(clean)[0].identifier, 'inert')
        variants = [clean + b'rules: []\n', clean + clean.split(b'\n', 1)[1],
                    clean.replace(b'message: inert', b'message: *alias'),
                    clean.replace(b'languages: [python]', b'languages: *alias'),
                    clean.replace(b'message: inert', b'message: |\n      hidden'),
                    clean.replace(b'  - id: inert', b'  - {id: inert}'),
                    clean.replace(b'    severity: WARNING', b'    mode: *alias\n    severity: WARNING'),
                    clean.replace(b'    severity: WARNING', b'    unknown-header: true\n    severity: WARNING'),
                    clean.replace(b'    severity: WARNING', b'    <<: *merge\n    severity: WARNING'),
                    clean.replace(b'    severity: WARNING', b'    severity: WARNING\n    severity: INFO')]
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(self.scanner.OpenGrepError):
                self.scanner.rule_catalog(raw)


@unittest.skipUnless(sys.platform.startswith('linux'), 'sealed Linux adapter profile unavailable')
class AdapterRefusalTests(unittest.TestCase):
    def setUp(self):
        self.scanner = importlib.import_module('getzilla.security_opengrep')
        self.assertTrue(callable(getattr(self.scanner, 'scan_source', None)),
                        'the real source-bound adapter must consume the contract')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.rules = self.root / '.getzilla/sast/rules'
        shutil.copytree(Path(__file__).resolve().parents[1] / '.getzilla/sast/rules', self.rules)
        (self.root / 'app.py').write_text('print("inert")\n')
        self.binary = self.root / 'opengrep'
        self.binary.write_text('#!/usr/bin/python3\nopen("ran","x").close()\n')
        self.binary.chmod(0o755)

    def test_unpinned_tool_is_never_run(self):
        result = self.scanner.scan_source(self.root, rules_root=self.rules,
                                          executable=self.binary, profile='native')
        self.assertEqual(result['outcome'], 'blocked')
        self.assertFalse((self.root / 'ran').exists())

    def test_selected_unsupported_source_cannot_become_no_applicable_targets(self):
        (self.root / 'app.py').unlink()
        (self.root / 'app.go').write_text('package main\nfunc main(){}\n')
        result = self.scanner.scan_source(self.root, rules_root=self.rules,
                                          executable=self.binary, profile='native')
        self.assertEqual(result['outcome'], 'blocked')
        self.assertIn('syntax_frontend_unavailable', result['summary'])
        self.assertFalse((self.root / 'ran').exists())

    def test_actual_empty_census_needs_no_tool_execution_or_fabricated_pin(self):
        (self.root / 'app.py').unlink()
        result = self.scanner.scan_source(self.root, rules_root=self.rules,
                                          executable=self.root / 'missing-tool', profile='expanded')
        self.assertEqual(result['outcome'], 'not_applicable', result['summary'])
        self.assertEqual(result['coverage'], {'expected': [], 'observed': []})
        self.assertFalse((self.root / 'ran').exists())

    def test_proven_empty_expanded_census_needs_no_checker_rule_installation(self):
        (self.root / 'app.py').unlink()
        (self.root / 'Cargo.toml').write_text('[package]\nname="first-party"\nversion="0.1.0"\n')
        result = self.scanner.scan_source(self.root,
            rules_root=self.root / 'missing-checker/.getzilla/sast/rules',
            executable=self.root / 'missing-tool', profile='expanded')
        self.assertEqual(result['outcome'], 'not_applicable', result['summary'])
        self.assertEqual(result['coverage'], {'expected': [], 'observed': []})
        self.assertEqual(result['finding_count'], 0)
        self.assertFalse((self.root / 'missing-checker').exists())

    def test_missing_rules_never_mint_zero_for_nonempty_or_unqualified_census(self):
        for name, mode in (('app.py', 0o644), ('app.py', 0o600), ('app.go', 0o644)):
            with self.subTest(name=name, mode=mode):
                (self.root / 'app.py').unlink(missing_ok=True)
                target = self.root / name
                target.write_text('public inert source\n')
                target.chmod(mode)
                result = self.scanner.scan_source(self.root,
                    rules_root=self.root / 'missing-checker/.getzilla/sast/rules',
                    executable=self.root / 'missing-tool', profile='expanded')
                self.assertEqual(result['outcome'], 'blocked')
                self.assertIsNone(result['coverage'])
                self.assertIsNone(result['finding_count'])
                target.unlink()


class AdapterCapabilityTests(unittest.TestCase):
    def test_missing_native_platform_capability_is_explicit_incomplete_without_effect(self):
        from getzilla import security_opengrep as scanner
        with mock.patch.object(scanner.sys, 'platform', 'unsupported'), \
             mock.patch.object(scanner.fsx, 'owned_popen') as spawn:
            result = scanner.scan_source(Path('/public-fixture'),
                     rules_root=Path('/public-fixture/.getzilla/sast/rules'),
                     executable=Path('/public-fixture/tool'), profile='native')
        self.assertEqual(result['outcome'], 'blocked')
        self.assertIsNone(result['coverage'])
        self.assertIsNone(result['finding_count'])
        self.assertIn('run_profile_unavailable', result['summary'])
        spawn.assert_not_called()


def _offline_fixture_child():
    # Experiment custody only. Permit local runtime socketpairs; deny network
    # socket creation in this child, without changing host/network profiles.
    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('items', ctypes.POINTER(Filter))]
    rows = [(0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
            (0x20,0,0,0),(0x15,2,0,41),(0x15,1,0,53),(0x06,0,0,0x7fff0000),
            (0x20,0,0,16),(0x15,1,0,1),(0x06,0,0,0x00050001),(0x06,0,0,0x7fff0000)]
    array = (Filter * len(rows))(*(Filter(*row) for row in rows))
    program = Program(len(rows), array)
    libc = ctypes.CDLL(None)
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(22, 2, ctypes.byref(program), 0, 0):
        os._exit(125)


@unittest.skipUnless(sys.platform.startswith('linux') and platform.machine() == 'x86_64'
                     and os.getuid() != 0 and shutil.which('opengrep'),
                     'actual offline pinned scanner profile unavailable')
class ActualPinnedAdapterTests(unittest.TestCase):
    def setUp(self):
        self.scanner = importlib.import_module('getzilla.security_opengrep')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.rules = self.root / '.getzilla/sast/rules'
        shutil.copytree(Path(__file__).resolve().parents[1] / '.getzilla/sast/rules', self.rules)
        original = self.scanner.fsx.owned_popen

        def spawn(command, **kwargs):
            return original(command, preexec_fn=_offline_fixture_child, **kwargs)

        patcher = mock.patch.object(self.scanner.fsx, 'owned_popen', side_effect=spawn)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self):
        return self.scanner.scan_source(self.root, rules_root=self.rules,
                                        executable=Path(shutil.which('opengrep')), profile='native')

    def test_actual_clean_has_complete_source_and_rule_coverage_without_shared_cache(self):
        (self.root / 'app.py').write_text('print("inert")\n')
        result = self.scan()
        self.assertEqual(result['outcome'], 'pass', result['summary'])
        self.assertEqual(result['coverage'], {'expected': ['app.py'], 'observed': ['app.py']})
        self.assertEqual(result['grammars'], ['python3.12'])
        self.assertEqual(list((self.root / '.getzilla/runtime').glob('opengrep-*')), [])

    def test_actual_findings_preserve_all_native_python_rule_ids_and_lines(self):
        (self.root / 'app.py').write_bytes((self.rules / 'python.py.example').read_bytes())
        result = self.scan()
        self.assertEqual(result['outcome'], 'finding', result['summary'])
        expected = {'getzilla.sast.rules.' + rule.identifier
                    for rule in self.scanner.rule_catalog((self.rules / 'python.yaml').read_bytes())}
        self.assertEqual({finding['rule'] for finding in result['findings']}, expected)
        self.assertTrue(all(int(finding['line']) > 0 for finding in result['findings']))
        self.assertEqual(list((self.root / '.getzilla/runtime').glob('opengrep-*')), [])

    def test_actual_native_consumer_distinguishes_complete_clean_finding_and_incomplete(self):
        from getzilla import verification
        target = self.root / 'app.py'
        with mock.patch.object(verification, 'find_tool', return_value=shutil.which('opengrep')):
            target.write_text('print("inert")\n')
            clean = verification._opengrep(self.root)
            self.assertEqual(clean.status, 'pass', clean.summary)
            target.write_bytes((self.rules / 'python.py.example').read_bytes())
            finding = verification._opengrep(self.root)
            self.assertEqual(finding.status, 'fail', finding.summary)
            self.assertTrue(finding.details)
            target.write_text('def broken(:\n  eval(user_input)\n')
            incomplete = verification._opengrep(self.root)
            self.assertEqual(incomplete.status, 'fail', incomplete.summary)
            self.assertIn('syntax_incomplete', incomplete.summary)
            self.assertFalse(incomplete.details)
        self.assertEqual(list((self.root / '.getzilla/runtime').glob('opengrep-*')), [])

    def test_syntax_and_core_share_the_existing_target_deadline(self):
        (self.root / 'app.py').write_text('print("inert")\n')
        syntax = self.scanner.syntax_check
        run = self.scanner._run
        deadlines = []

        def bounded_syntax(*args, **kwargs):
            deadlines.append(kwargs['deadline'])
            self.assertLessEqual(kwargs['deadline'] - time.monotonic(), 30)
            return syntax(*args, **kwargs)

        def bounded_run(command, *args, **kwargs):
            if '-json_nodots' in command:
                self.assertEqual(args[2], deadlines[-1])
            return run(command, *args, **kwargs)

        with mock.patch.object(self.scanner, 'syntax_check', side_effect=bounded_syntax), \
             mock.patch.object(self.scanner, '_run', side_effect=bounded_run):
            result = self.scan()
        self.assertEqual(result['outcome'], 'pass', result['summary'])
        self.assertEqual(len(deadlines), 1)

if __name__ == '__main__':
    unittest.main()
