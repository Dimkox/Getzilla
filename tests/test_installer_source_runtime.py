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
