"""Public local recovery fixtures only; no actual operator, credential or DEV access."""
from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import select
from unittest.mock import patch
from unittest.mock import PropertyMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class RecoveryTests(unittest.TestCase):
    def module(self, name='deploy_recovery'):
        full = 'getzilla.' + name
        if importlib.util.find_spec(full) is None:
            self.fail('Required working Core/CLI recovery consumer is absent')
        return importlib.import_module(full)

    def root(self):
        from getzilla import fsx
        if fsx.WINDOWS or not hasattr(os, 'O_NOFOLLOW'):
            self.skipTest('POSIX recovery fixture profile unavailable; early unsupported-mode control remains mandatory')
        temporary = tempfile.TemporaryDirectory(prefix='public-recovery-test-')
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        return root

    def intent(self, module):
        return module.Intent(digest(b'public-operation'), digest(b'public-binding'),
                             digest(b'public-before'), digest(b'public-after'))

    def child(self, code, root, *arguments):
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
                       'PYTHONPATH': str(ROOT / '.getzilla'),
                       'GETZILLA_SESSION_ID': '01a1a6ba-10e8-7bc1-81b1-684978be3580'}
        return subprocess.run([sys.executable, '-c', code, str(root), *arguments],
                              cwd=ROOT, env=environment, capture_output=True, timeout=15)

    def test_shared_kernel_lease_excludes_peer_and_keeps_legacy_barrier(self):
        module = self.module()
        root = self.root()
        with module.RecoverySession(root, create=True, writable=True):
            with self.assertRaises(module.RecoveryError) as caught:
                with module.RecoverySession(root, writable=True):
                    self.fail('parallel writer admitted')
            self.assertEqual(caught.exception.code, 'LEASE_BUSY')
        self.assertTrue((root / '.release.lock').is_dir())
        with self.assertRaises(FileExistsError):
            (root / '.release.lock').mkdir()

    def test_reentering_session_refuses_without_losing_the_original_lease(self):
        module = self.module()
        root = self.root()
        session = module.RecoverySession(root, create=True, writable=True)
        with session:
            with self.assertRaises(module.RecoveryError):
                session.__enter__()
            session.begin(self.intent(module))
            with self.assertRaises(module.RecoveryError) as caught:
                with module.RecoverySession(root, writable=True):
                    self.fail('original lease was lost during rejected reentry')
            self.assertEqual(caught.exception.code, 'LEASE_BUSY')
        with self.assertRaises(module.RecoveryError):
            session.__enter__()
        with module.RecoverySession(root, writable=True) as replacement:
            replacement.begin(self.intent(module))

    def test_journal_capacity_and_attempt_limits_preserve_completed_history(self):
        module = self.module()
        root = self.root()
        with module.RecoverySession(root, create=True, writable=True) as session:
            for number in range(8):
                intent = module.Intent(digest(str(number).encode('ascii')), digest(b'binding'),
                                       digest(b'before'), digest(b'after'))
                session.begin(intent)
                session.advance('effect_pending', intent.before_sha256)
                session.advance('applied', intent.after_sha256)
                session.advance('verified', intent.after_sha256)
            self.assertEqual(len(session.records), 32)
            before = (root / '.release.lock/journal.jsonl').read_bytes()
            with self.assertRaises(module.RecoveryError) as caught:
                session.begin(self.intent(module))
            self.assertEqual(caught.exception.code, 'JOURNAL_LIMIT')
            self.assertEqual((root / '.release.lock/journal.jsonl').read_bytes(), before)
        root = self.root()
        for number in range(3):
            with module.RecoverySession(root, create=True, writable=True) as session:
                intent = self.intent(module)
                session.begin(intent)
                if number < 2:
                    session.advance('effect_pending', intent.before_sha256)
                else:
                    before = (root / '.release.lock/journal.jsonl').read_bytes()
                    with self.assertRaises(module.RecoveryError) as caught:
                        session.advance('effect_pending', intent.before_sha256)
                    self.assertEqual(caught.exception.code, 'ATTEMPT_LIMIT')
                    self.assertEqual((root / '.release.lock/journal.jsonl').read_bytes(), before)

    def test_rehashed_invalid_transition_and_oversize_journal_are_not_repaired(self):
        module = self.module()
        for defect in ('stage', 'oversize', 'duplicate'):
            with self.subTest(defect=defect):
                root = self.root()
                with module.RecoverySession(root, create=True, writable=True) as session:
                    session.begin(self.intent(module))
                journal = root / '.release.lock/journal.jsonl'
                raw = journal.read_bytes()
                envelope = json.loads(raw)
                if defect == 'stage':
                    envelope['record']['stage'] = 'verified'
                    envelope['record']['current_sha256'] = self.intent(module).after_sha256
                    envelope['sha256'] = module.sha256(module.canonical([envelope['previous'], envelope['record']]))
                    raw = module.canonical(envelope) + b'\n'
                elif defect == 'oversize':
                    raw = b'X' * 65537
                else:
                    raw = raw.replace(b'"seq":1', b'"seq":1,"seq":1')
                journal.write_bytes(raw)
                with self.assertRaises(module.RecoveryError):
                    with module.RecoverySession(root, writable=True):
                        self.fail('invalid history admitted')
                self.assertEqual(journal.read_bytes(), raw)

    def test_unknown_legacy_directory_and_foreign_bytes_are_preserved(self):
        module = self.module()
        root = self.root()
        lock = root / '.release.lock'
        lock.mkdir(mode=0o700)
        foreign = lock / 'foreign'
        foreign.write_bytes(b'public-foreign-state')
        before = foreign.stat()
        with self.assertRaises(module.RecoveryError) as caught:
            with module.RecoverySession(root, create=True, writable=True):
                self.fail('unknown legacy owner admitted')
        self.assertEqual(caught.exception.code, 'LEGACY_OWNER_UNKNOWN')
        self.assertEqual(foreign.read_bytes(), b'public-foreign-state')
        self.assertEqual(foreign.stat().st_ino, before.st_ino)
        self.assertEqual(set(p.name for p in lock.iterdir()), {'foreign'})

    def test_pending_effect_replay_plans_verification_without_a_second_write(self):
        module = self.module()
        root = self.root()
        intent = self.intent(module)
        with module.RecoverySession(root, create=True, writable=True) as session:
            session.begin(intent)
            self.assertEqual(session.plan(intent.before_sha256), 'apply')
            session.advance('effect_pending', intent.before_sha256)
            self.assertEqual(session.plan(intent.after_sha256), 'verify_effect')
            session.advance('applied', intent.after_sha256)
            session.advance('verified', intent.after_sha256)
        with module.RecoverySession(root, writable=True) as session:
            session.begin(intent)
            self.assertEqual(session.plan(intent.after_sha256), 'done')
            self.assertEqual(len(session.records), 4)

    def test_unknown_outcome_cannot_become_ready_from_matching_target_hash(self):
        module = self.module()
        root = self.root()
        intent = self.intent(module)
        with module.RecoverySession(root, create=True, writable=True) as session:
            session.begin(intent)
            session.advance('effect_pending', intent.before_sha256)
            session.advance('unknown', None)
            for current in (intent.before_sha256, intent.after_sha256):
                self.assertEqual(session.plan(current), 'inspect_unknown')
            with self.assertRaises(module.RecoveryError):
                session.advance('verified', intent.after_sha256)

    def test_concurrent_public_journal_append_is_preserved_and_refused(self):
        module = self.module()
        root = self.root()
        with module.RecoverySession(root, create=True, writable=True) as session:
            session.begin(self.intent(module))
            original_write = session._write_all
            foreign = b'PUBLIC-FOREIGN-FRAME\n'
            def interleave(descriptor, content):
                writer = os.open(root / '.release.lock/journal.jsonl', os.O_WRONLY | os.O_APPEND)
                try:
                    os.write(writer, foreign)
                finally:
                    os.close(writer)
                original_write(descriptor, content)
            with patch.object(session, '_write_all', side_effect=interleave):
                with self.assertRaises(module.RecoveryError):
                    session.advance('effect_pending', digest(b'public-before'))
            self.assertIn(foreign, (root / '.release.lock/journal.jsonl').read_bytes())

    def test_replaced_public_guard_cannot_admit_a_second_writer(self):
        module = self.module()
        root = self.root()
        with module.RecoverySession(root, create=True, writable=True):
            guard = root / '.release.lock/lease'
            guard.rename(guard.with_name('retained-original-lease'))
            guard.write_bytes(b'')
            guard.chmod(0o600)
            replacement = guard.stat().st_ino
            with self.assertRaises(module.RecoveryError):
                with module.RecoverySession(root, writable=True):
                    self.fail('a replacement lock split the exclusion domain')
            self.assertEqual(guard.stat().st_ino, replacement)

    def test_replaced_public_journal_is_not_adopted_even_with_identical_bytes(self):
        module = self.module()
        root = self.root()
        with module.RecoverySession(root, create=True, writable=True) as session:
            session.begin(self.intent(module))
        journal = root / '.release.lock/journal.jsonl'
        original = journal.read_bytes()
        journal.rename(journal.with_name('retained-original-journal'))
        journal.write_bytes(original)
        journal.chmod(0o600)
        replacement = journal.stat().st_ino
        with self.assertRaises(module.RecoveryError):
            with module.RecoverySession(root, writable=True):
                self.fail('foreign journal replacement was adopted')
        self.assertEqual(journal.read_bytes(), original)
        self.assertEqual(journal.stat().st_ino, replacement)

    def test_public_fixture_applies_recovers_and_rolls_back_without_dev_authority(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        self.assertEqual(module.initialize_fixture(root)['state'], 'initialized')
        for action in ('apply', 'recover'):
            report = module.run_fixture(root, action)
            self.assertEqual(report['state'], 'fixture_verified')
            self.assertIs(report['dev_verified'], False)
            self.assertIs(report['operational_grant'], False)
            self.assertIs(report['dispatch_permitted'], False)
            self.assertEqual(report['delivery'], 'not_attempted')
        report = module.run_fixture(root, 'rollback')
        self.assertEqual(report['state'], 'fixture_rolled_back')
        self.assertEqual((root / 'target/application.txt').read_bytes(), module.BEFORE)

    def test_public_fixture_init_refuses_nonempty_root_before_writes(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        (root / 'foreign').write_bytes(b'untouched-public-value')
        report = module.initialize_fixture(root)
        self.assertEqual(report['state'], 'blocked')
        self.assertEqual(report['diagnostics'], ['ROOT_NOT_EMPTY'])
        self.assertEqual(set(p.name for p in root.iterdir()), {'foreign'})
        self.assertEqual((root / 'foreign').read_bytes(), b'untouched-public-value')

    def test_unexpected_public_effect_fault_retains_unknown_and_never_logs_canary(self):
        module = self.module('deploy_rehearsal')
        canary = 'PUBLIC-SYNTHETIC-EXCEPTION-CANARY-300'
        for fault in (RuntimeError, KeyboardInterrupt, SystemExit, BaseException):
            with self.subTest(fault=fault.__name__):
                root = self.root()
                self.assertEqual(module.initialize_fixture(root)['state'], 'initialized')
                original = module._Target.apply
                def uncertain(target, expected, content):
                    original(target, expected, content)
                    raise fault(canary)
                with patch.object(module._Target, 'apply', uncertain):
                    report = module.run_fixture(root, 'apply')
                self.assertEqual(report['state'], 'unknown')
                self.assertNotIn(canary, json.dumps(report))
                journal = (root / '.release.lock/journal.jsonl').read_bytes()
                self.assertNotIn(canary.encode(), journal)
                retry = module.run_fixture(root, 'recover')
                self.assertEqual(retry['state'], 'unknown')
                self.assertEqual(retry['diagnostics'], ['OUTCOME_UNKNOWN'])
                self.assertEqual((root / 'target/application.txt').read_bytes(), module.AFTER)

    def test_public_native_crash_before_and_after_effect_recovers_without_duplicate_write(self):
        module = self.module('deploy_rehearsal')
        script = '''
import os, sys
from pathlib import Path
from getzilla import deploy_rehearsal as fixture
original = fixture._Target.apply
def cut(target, expected, content):
    if sys.argv[2] == 'before': os._exit(71)
    original(target, expected, content)
    os._exit(72)
fixture._Target.apply = cut
fixture.run_fixture(Path(sys.argv[1]), 'apply')
raise SystemExit(3)
'''
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                root = self.root()
                module.initialize_fixture(root)
                result = self.child(script, root, phase)
                self.assertEqual(result.returncode, 71 if phase == 'before' else 72)
                self.assertEqual((root / 'target/application.txt').read_bytes(),
                                 module.BEFORE if phase == 'before' else module.AFTER)
                original = module._Target.apply
                with patch.object(module._Target, 'apply', autospec=True, side_effect=original) as effect:
                    self.assertEqual(module.run_fixture(root, 'recover')['state'], 'fixture_verified')
                    self.assertEqual(effect.call_count, 1 if phase == 'before' else 0)
                journal = (root / '.release.lock/journal.jsonl').read_bytes()
                with patch.object(module._Target, 'apply', side_effect=AssertionError('duplicate public write')):
                    self.assertEqual(module.run_fixture(root, 'recover')['state'], 'fixture_verified')
                self.assertEqual((root / '.release.lock/journal.jsonl').read_bytes(), journal)
                self.assertEqual((root / 'public/original.txt').read_bytes(), module.BEFORE)

    def test_repeated_crash_during_verification_and_rollback_preserves_original(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        module.initialize_fixture(root)
        after_effect = '''
import os, sys
from pathlib import Path
from getzilla import deploy_rehearsal as fixture
original = fixture._Target.apply
def cut(target, expected, content):
    original(target, expected, content)
    os._exit(72)
fixture._Target.apply = cut
fixture.run_fixture(Path(sys.argv[1]), sys.argv[2])
raise SystemExit(3)
'''
        after_record = '''
import os, sys
from pathlib import Path
from getzilla import deploy_rehearsal as fixture
original = fixture.RecoverySession.advance
def cut(session, stage, current):
    original(session, stage, current)
    if stage == sys.argv[2]: os._exit(73)
fixture.RecoverySession.advance = cut
fixture.run_fixture(Path(sys.argv[1]), 'recover')
raise SystemExit(3)
'''
        self.assertEqual(self.child(after_effect, root, 'apply').returncode, 72)
        self.assertEqual(self.child(after_record, root, 'applied').returncode, 73)
        with patch.object(module._Target, 'apply', side_effect=AssertionError('duplicate public effect')):
            self.assertEqual(module.run_fixture(root, 'recover')['state'], 'fixture_verified')
        self.assertEqual(self.child(after_effect, root, 'rollback').returncode, 72)
        self.assertEqual(self.child(after_record, root, 'rolled_back').returncode, 73)
        with patch.object(module._Target, 'apply', side_effect=AssertionError('duplicate public rollback')):
            for action in ('recover', 'rollback'):
                self.assertEqual(module.run_fixture(root, action)['state'], 'fixture_rolled_back')
        self.assertEqual((root / 'target/application.txt').read_bytes(), module.BEFORE)
        self.assertEqual((root / 'public/original.txt').read_bytes(), module.BEFORE)

    def test_remaining_child_keeps_exclusion_after_creator_closes_descriptors(self):
        module = self.module()
        root = self.root()
        release_read, release_write = os.pipe()
        ready_read, ready_write = os.pipe()
        process = None
        try:
            with module.RecoverySession(root, create=True, writable=True) as session:
                inherited = session.inherit_lease()
                try:
                    code = 'import os,sys;os.write(int(sys.argv[2]),b"R");os.read(int(sys.argv[1]),1)'
                    process = subprocess.Popen([sys.executable, '-c', code, str(release_read), str(ready_write)],
                                               pass_fds=(inherited, release_read, ready_write),
                                               env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'},
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                finally:
                    os.close(inherited)
                self.assertTrue(select.select([ready_read], [], [], 5)[0])
                self.assertEqual(os.read(ready_read, 1), b'R')
            self.assertIsNone(process.poll())
            with self.assertRaises(module.RecoveryError) as caught:
                with module.RecoverySession(root, writable=True):
                    self.fail('live descendant lease ignored')
            self.assertEqual(caught.exception.code, 'LEASE_BUSY')
            os.write(release_write, b'X')
            self.assertEqual(process.wait(timeout=5), 0)
            with module.RecoverySession(root, writable=True):
                pass
        finally:
            os.close(release_read)
            os.close(release_write)
            os.close(ready_read)
            os.close(ready_write)
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_partial_or_tampered_journal_refuses_without_rewriting_bytes(self):
        module = self.module()
        for suffix in (b'{', b'{}\n', b'PUBLIC-NON-JSON\n'):
            with self.subTest(suffix=suffix):
                root = self.root()
                with module.RecoverySession(root, create=True, writable=True) as session:
                    session.begin(self.intent(module))
                journal = root / '.release.lock/journal.jsonl'
                with journal.open('ab') as stream:
                    stream.write(suffix)
                before = journal.read_bytes()
                with self.assertRaises(module.RecoveryError):
                    with module.RecoverySession(root, writable=True):
                        self.fail('uncertain journal accepted')
                self.assertEqual(journal.read_bytes(), before)

    def test_current_binding_conflict_never_renews_the_original_operation(self):
        module = self.module()
        root = self.root()
        original = self.intent(module)
        with module.RecoverySession(root, create=True, writable=True) as session:
            session.begin(original)
            session.advance('effect_pending', original.before_sha256)
        changed = module.Intent(original.operation_sha256, digest(b'changed-public-source'),
                                original.before_sha256, original.after_sha256)
        before = (root / '.release.lock/journal.jsonl').read_bytes()
        with module.RecoverySession(root, writable=True) as session:
            with self.assertRaises(module.RecoveryError) as caught:
                session.begin(changed)
            self.assertEqual(caught.exception.code, 'INTENT_CONFLICT')
        self.assertEqual((root / '.release.lock/journal.jsonl').read_bytes(), before)

    def test_deadline_intersection_and_unsupported_mode_refuse_before_root_access(self):
        module = self.module()
        root = self.root()
        with patch.object(module.time, 'monotonic', side_effect=[10.0, 13.0]):
            with patch.object(module, 'BoundRoot', side_effect=AssertionError('late root open')):
                with self.assertRaises(module.RecoveryError) as caught:
                    with module.RecoverySession(root, create=True, writable=True, deadline=12.0):
                        pass
            self.assertEqual(caught.exception.code, 'BUDGET_EXCEEDED')
        with patch.object(module.fsx, 'WINDOWS', True):
            with patch.object(module, 'BoundRoot', side_effect=AssertionError('unsupported root open')):
                with self.assertRaises(module.RecoveryError) as caught:
                    with module.RecoverySession(root):
                        pass
            self.assertEqual(caught.exception.code, 'MODE_UNSUPPORTED')
        self.assertEqual(list(root.iterdir()), [])

    def test_positive_report_never_survives_a_failed_final_journal_observation(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        module.initialize_fixture(root)
        with patch.object(module.RecoverySession, 'journal_sha256', new_callable=PropertyMock,
                          side_effect=module.RecoveryError('FILE_CHANGED')):
            report = module.run_fixture(root, 'apply')
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['fixture_effect'], 'not_verified')
        self.assertIs(report['dispatch_permitted'], False)

    def test_secondary_public_journal_interruption_preserves_tail_and_refuses_recovery(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        module.initialize_fixture(root)
        original_effect = module._Target.apply
        original_write = module.RecoverySession._write_all
        def effect(target, expected, content):
            original_effect(target, expected, content)
            raise RuntimeError('PUBLIC-FIRST-CANARY')
        def torn(descriptor, content):
            if b'"stage":"unknown"' in content:
                os.write(descriptor, content[:7])
                raise KeyboardInterrupt('PUBLIC-SECOND-CANARY')
            return original_write(descriptor, content)
        with patch.object(module._Target, 'apply', effect):
            with patch.object(module.RecoverySession, '_write_all', side_effect=torn):
                report = module.run_fixture(root, 'apply')
        self.assertEqual(report['state'], 'unknown')
        journal = root / '.release.lock/journal.jsonl'
        before = journal.read_bytes()
        self.assertFalse(before.endswith(b'\n'))
        self.assertNotIn(b'CANARY', before)
        self.assertNotIn('CANARY', json.dumps(report))
        retry = module.run_fixture(root, 'recover')
        self.assertEqual(retry['state'], 'unknown')
        self.assertEqual(retry['diagnostics'], ['JOURNAL_INCOMPLETE'])
        self.assertEqual(journal.read_bytes(), before)

    def test_foreign_target_replacement_at_write_cut_is_not_overwritten(self):
        module = self.module('deploy_rehearsal')
        root = self.root()
        module.initialize_fixture(root)
        original_write = module.RecoverySession._write_all
        foreign = b'public-foreign-replacement'
        def replace_at_cut(descriptor, content):
            if content == module.AFTER:
                target = root / 'target/application.txt'
                target.rename(target.with_name('retained-owned-original'))
                target.write_bytes(foreign)
                target.chmod(0o600)
            return original_write(descriptor, content)
        with patch.object(module.RecoverySession, '_write_all', side_effect=replace_at_cut):
            report = module.run_fixture(root, 'apply')
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual((root / 'target/application.txt').read_bytes(), foreign)
        self.assertEqual((root / 'public/original.txt').read_bytes(), module.BEFORE)

    def test_unsupported_profile_refusal_is_portable_and_precedes_input_access(self):
        module = self.module()
        with patch.object(module.fsx, 'WINDOWS', True):
            with patch.object(module, 'BoundRoot', side_effect=AssertionError('unsupported input access')):
                with self.assertRaises(module.RecoveryError) as caught:
                    with module.RecoverySession(Path('public-unused-root')):
                        pass
            self.assertEqual(caught.exception.code, 'MODE_UNSUPPORTED')

    def test_closed_report_schema_rejects_authority_and_extra_payload_fields(self):
        import jsonschema
        module = self.module('deploy_rehearsal')
        schema = json.loads((ROOT / 'schemas/deploy-recovery-report-v1.schema.json').read_bytes())
        validator = jsonschema.Draft202012Validator(schema)
        validator.check_schema(schema)
        root = self.root()
        reports = [module.initialize_fixture(root), module.run_fixture(root, 'inspect'),
                   module.run_fixture(root, 'apply'), module.run_fixture(root, 'rollback')]
        for report in reports:
            validator.validate(report)
            for name in ('operational_grant', 'dispatch_permitted', 'dev_verified'):
                bad = dict(report, **{name: True})
                self.assertTrue(list(validator.iter_errors(bad)))
            self.assertTrue(list(validator.iter_errors(dict(report, raw_stderr='public-canary'))))

    def test_installed_file_and_compressed_engines_expose_the_working_consumer(self):
        from tests.test_install_on_demand import INSTALL
        environment = {'PATH': os.path.dirname(sys.executable), 'PYTHONDONTWRITEBYTECODE': '1',
                       'GETZILLA_SESSION_ID': '01a1a6ba-10e8-7bc1-81b1-684978be3580'}
        for name in ('SYSTEMROOT', 'WINDIR'):
            if name in os.environ:
                environment[name] = os.environ[name]
        with tempfile.TemporaryDirectory(prefix='public-installed-recovery-') as temporary:
            for archive in (False, True):
                with self.subTest(archive=archive):
                    target = Path(temporary) / ('archive' if archive else 'files')
                    INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                             selection=INSTALL.PayloadSelection((), engine_archive=archive))
                    for relative in ('docs/deploy-recovery.md', 'schemas/deploy-recovery-report-v1.schema.json'):
                        self.assertEqual((target / relative).read_bytes(), (ROOT / relative).read_bytes())
                    self.assertEqual((target / '.getzilla/getzilla/deploy_recovery.py').exists(), not archive)
                    fixture = Path(temporary) / ('fixture-archive' if archive else 'fixture-files')
                    fixture.mkdir(mode=0o700)
                    fixture.chmod(0o700)
                    script = target / 'scripts/getzilla_deploy.py'
                    actions = ('init',) if os.name == 'nt' else ('init', 'apply', 'inspect', 'recover', 'rollback')
                    for action in actions:
                        result = subprocess.run([sys.executable, str(script), 'recovery', '--root', str(fixture),
                                                 '--action', action, '--json'], cwd=target, env=environment,
                                                capture_output=True, timeout=30)
                        report = json.loads(result.stdout)
                        self.assertIs(report['dev_verified'], False)
                        self.assertIs(report['operational_grant'], False)
                        self.assertIs(report['dispatch_permitted'], False)
                        self.assertEqual(report['delivery'], 'not_attempted')
                        if os.name == 'nt':
                            self.assertEqual(result.returncode, 1)
                            self.assertEqual(report['diagnostics'], ['MODE_UNSUPPORTED'])
                        else:
                            self.assertEqual(result.returncode, 0, report)
                            self.assertEqual(report['state'], {'init': 'initialized', 'apply': 'fixture_verified',
                                                              'inspect': 'review_only', 'recover': 'fixture_verified',
                                                              'rollback': 'fixture_rolled_back'}[action])

    def test_existing_deploy_cli_exposes_new_recovery_without_loosening_preflight(self):
        command = [sys.executable, str(ROOT / 'scripts/getzilla_deploy.py'), 'recovery', '--help']
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1',
                       'GETZILLA_SESSION_ID': '01a1a6ba-10e8-7bc1-81b1-684978be3580'}
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, 'versioned recovery CLI is unavailable')
        self.assertIn(b'--action', result.stdout)
        preflight = subprocess.run([*command[:2], 'preflight', '--help'], cwd=ROOT,
                                  env=environment, capture_output=True, timeout=10)
        self.assertEqual(preflight.returncode, 0)
        self.assertIn(b'--manifest', preflight.stdout)


if __name__ == '__main__':
    unittest.main()
