"""Run actual updater bytes in direct and lean SDK layouts without installation."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]

PROBE = '''import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import getzilla.updater as updater
consumer = Path(sys.argv[1]).parent
assert ('getzilla.zip/getzilla/updater.py' in updater.__file__.replace('\\\\', '/')) == (sys.argv[2] == 'sdk')
state = consumer / 'inert-state'
def forbidden(*args, **kwargs):
    raise AssertionError('native effect is forbidden')
which = lambda name: '/inert/codex' if name == 'codex' else None
fetch = object()
for status in ('complete', 'failed'):
    with patch('getzilla.managed_software.install_software', return_value={
            'components': [{'component': 'fixture', 'status': status}]}) as install:
        agents = updater.update_agents(forbidden, which, root=state, fetch=fetch)
        tools = updater.update_jscpd(forbidden, which, root=state, fetch=fetch)
    assert install.call_count == 2
    for call in install.call_args_list:
        assert call.args == (state, consumer), (updater.__file__, call.args, consumer)
        assert call.kwargs['run'] is forbidden
        assert call.kwargs['fetch'] is fetch
        assert call.kwargs['which'] is which
    assert install.call_args_list[0].kwargs['agent'] == 'codex'
    assert install.call_args_list[1].kwargs['tools'] == ('jscpd',)
    assert [row.status for row in agents + tools] == [('ok' if status == 'complete' else 'fail')] * 2
assert not state.exists()
print('actual-source updater roots and status propagation pass:', sys.argv[2])
'''


class UpdaterSDKRootTests(unittest.TestCase):
    def test_actual_source_from_direct_and_sdk_absolute_invocation(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(exist_ok=True)
        source = ROOT / '.getzilla/getzilla'
        with tempfile.TemporaryDirectory(prefix='updater-layout-', dir=runtime) as temporary:
            base = Path(temporary).resolve()
            probe = base / 'absolute_probe.py'
            probe.write_text(PROBE, encoding='utf-8')
            unrelated = base / 'unrelated'
            unrelated.mkdir()
            for layout in ('direct', 'sdk'):
                with self.subTest(layout=layout):
                    stack = base / layout / '.getzilla'
                    package = stack / 'getzilla'
                    package.mkdir(parents=True)
                    if layout == 'direct':
                        shutil.copytree(source, package, dirs_exist_ok=True,
                                        ignore=shutil.ignore_patterns('__pycache__'))
                    else:
                        (package / '__init__.py').write_bytes((source / '__init__.py').read_bytes())
                        with zipfile.ZipFile(stack / 'getzilla.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
                            for path in sorted(source.rglob('*.py')):
                                archive.writestr('getzilla/' + path.relative_to(source).as_posix(), path.read_bytes())
                    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(probe), str(stack), layout],
                                            cwd=unrelated, capture_output=True, text=True, timeout=30,
                                            check=False)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('actual-source updater roots and status propagation pass', result.stdout)
