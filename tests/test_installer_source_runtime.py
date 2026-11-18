"""Own source/hash fixtures and inert configure/make effects, no real build."""
import hashlib
import io
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.latest_releases import Target
from getzilla.managed_source_build import install_source


class SourceRuntimeTests(unittest.TestCase):
    def git_fixture(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            item = tarfile.TarInfo('git-2.56.1/configure')
            item.size, item.mode = 5, 0o755
            archive.addfile(item, io.BytesIO(b'owned'))
        raw = stream.getvalue()
        return Target('git', '2.56.1', 'https://owned.invalid/git-2.56.1.tar.gz',
                      sha256=hashlib.sha256(raw).hexdigest(), filename='git-2.56.1.tar.gz'), raw

    def test_git_uses_documented_optional_c_mode_in_both_make_commands(self):
        target, raw = self.git_fixture()
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-git-c-mode-', dir=scratch) as owned:
            calls, prefix = [], None
            def run(command, cwd=None, **kwargs):
                nonlocal prefix
                calls.append(command)
                if command[0] == './configure':
                    prefix = Path(command[1].removeprefix('--prefix='))
                elif command[0] == 'make':
                    if 'NO_RUST=YesPlease' not in command:
                        return subprocess.CompletedProcess(command, 1, '',
                            'rustup could not choose a version of cargo: no default is configured')
                    if command[1] == 'install':
                        (prefix/'bin').mkdir(parents=True)
                        (prefix/'bin/git').write_bytes(b'owned inert current Git')
                return subprocess.CompletedProcess(command, 0, 'git version 2.56.1', '')
            path = install_source(target, raw, Path(owned), run=run)
            self.assertEqual([c for c in calls if c[0] == 'make'], [
                ['make', '-j4', 'NO_TCLTK=YesPlease', 'NO_GETTEXT=YesPlease', 'NO_RUST=YesPlease'],
                ['make', 'install', 'NO_TCLTK=YesPlease', 'NO_GETTEXT=YesPlease', 'NO_RUST=YesPlease']])
            self.assertEqual(calls[-1], [str(path), '--version'])
            self.assertEqual(install_source(target, raw, Path(owned), run=run), path)
            self.assertEqual(len([c for c in calls if c[0] == 'make']), 2)

    def test_git_c_mode_preserves_integrity_preflight_and_each_native_failure(self):
        target, raw = self.git_fixture()
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        for failure in (0, 1, 2):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix='owned-git-failure-', dir=scratch) as owned:
                calls = []
                def run(command, cwd=None, **kwargs):
                    calls.append(command)
                    return subprocess.CompletedProcess(command, 9 if len(calls)-1 == failure else 0,
                                                       '', 'owned native step failed')
                with self.assertRaisesRegex(ValueError, 'integrity mismatch'):
                    install_source(target, raw+b'tamper', Path(owned), run=run)
                self.assertEqual(calls, [])
                self.assertFalse((Path(owned)/'source-builds').exists())
                with self.assertRaisesRegex(ValueError, 'verified source build failed'):
                    install_source(target, raw, Path(owned), run=run)
                self.assertEqual(len(calls), failure+1)
                self.assertFalse(any(c[0].endswith('/bin/git') for c in calls))
                self.assertFalse((Path(owned)/'source-builds'/('git-'+target.sha256+'.json')).exists())

    def test_verified_source_build_probes_actual_prefix_and_never_uses_old_runtime(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:xz') as archive:
            item = tarfile.TarInfo('source/configure')
            item.size = 4
            item.mode = 0o755
            archive.addfile(item, io.BytesIO(b'data'))
        raw = stream.getvalue()
        target = Target('python', '4.0.0', 'https://www.python.org/fixture.tar.xz',
                        sha256=hashlib.sha256(raw).hexdigest(), filename='fixture.tar.xz')
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-source-build-', dir=scratch) as owned:
            calls = []
            def run(command, cwd=None, **kwargs):
                calls.append(command)
                if command[0] == './configure':
                    prefix = Path(command[1].removeprefix('--prefix='))
                    (prefix/'bin').mkdir(parents=True)
                    (prefix/'bin/python3').write_bytes(b'inert compiled fixture')
                return subprocess.CompletedProcess(command, 0, 'Python 4.0.0', '')
            path = install_source(target, raw, Path(owned), run=run)
            self.assertTrue(path.is_relative_to(Path(owned)))
            self.assertEqual(calls[-1], [str(path), '--version'])
            with self.assertRaises(ValueError):
                install_source(target, raw+b'tamper', Path(owned), run=lambda *a, **kw: self.fail())
