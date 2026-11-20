"""Import-only worker probes. No main, provider, request or service runs."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / '.getzilla/optional-modules/mcp-jira/0.1.0'
PROBE = '''import json, os, resource, runpy, sys, types
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
if hasattr(os, 'sched_getaffinity'):
    os.sched_setaffinity(0, set(sorted(os.sched_getaffinity(0))[:2]))
worker, stack, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
def audit(event, args):
    if event in {'subprocess.Popen', 'os.system', 'socket.connect', 'socket.getaddrinfo'}:
        raise AssertionError('external effect forbidden')
sys.addaudithook(audit)
if mode == 'foreign-loaded':
    sys.path.insert(0, str(stack.parent.parent))
    import getzilla
elif mode in {'own-loaded', 'foreign-path'}:
    sys.path.insert(0, str(stack))
    import getzilla
    import getzilla.execution
    if mode == 'foreign-path':
        getzilla.__path__.append(str(stack.parent.parent / 'getzilla'))
elif mode == 'foreign-submodule':
    foreign = types.ModuleType('getzilla.execution')
    sys.modules[foreign.__name__] = foreign
# Optional host dependencies stay inert. Core itself uses actual engine bytes.
for name, attrs in [('runtime', ('Runtime', 'Backend')), ('admission', ('HostBudget',))]:
    module = types.ModuleType('getzilla_mcp_worker.' + name)
    for attr in attrs:
        setattr(module, attr, type(attr, (), {}))
    sys.modules[module.__name__] = module
runpy.run_path(str(worker), run_name='import_only_worker_probe')
import getzilla, getzilla.execution
assert getzilla.STACK_DIR == stack
assert Path(getzilla.execution.__file__).is_relative_to(stack)
print(json.dumps({'package': getzilla.__file__, 'execution': getzilla.execution.__file__}))
'''


class JiraWorkerBootstrapTests(unittest.TestCase):
    def test_full_module_payload_and_catalog_hashes_match_source(self):
        manifest_path = MODULE / 'module.json'
        manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        catalog = json.loads((ROOT / '.getzilla/config/optional-modules.json').read_text(encoding='utf-8'))
        descriptor = catalog['modules']['mcp-jira']['versions']['0.1.0']
        self.assertEqual(ROOT / descriptor['manifest'], manifest_path)
        self.assertEqual(descriptor['sha256'], hashlib.sha256(manifest_path.read_bytes()).hexdigest())
        for row in manifest['files']:
            with self.subTest(path=row['path']):
                self.assertEqual(row['sha256'], hashlib.sha256((MODULE / row['path']).read_bytes()).hexdigest())

    @unittest.skipUnless(os.name == 'posix', 'worker import probe uses POSIX resource bounds')
    def test_exact_own_core_layouts_and_closed_failures(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='worker-bootstrap-', dir=runtime) as temporary:
            base = Path(temporary).resolve()
            (base / 'getzilla').mkdir()
            (base / 'getzilla/__init__.py').write_text('FOREIGN = True\n', encoding='utf-8')
            probe = base / 'absolute_probe.py'
            probe.write_text(PROBE, encoding='utf-8')
            unrelated = base / 'unrelated'
            unrelated.mkdir()
            cases = [('loose', 'installed', 'normal', None), ('sdk', 'installed', 'normal', None),
                     ('loose', 'source', 'normal', None), ('sdk', 'source', 'normal', None),
                     ('sdk', 'installed', 'own-loaded', None),
                     ('sdk', 'installed', 'foreign-loaded', 'worker_core_foreign'),
                     ('sdk', 'installed', 'foreign-submodule', 'worker_core_foreign'),
                     ('sdk', 'installed', 'foreign-path', 'worker_core_foreign'),
                     ('missing', 'installed', 'normal', 'worker_core_missing'),
                     ('ambiguous', 'installed', 'normal', 'worker_core_ambiguous')]
            for index, (layout, placement, mode, error) in enumerate(cases):
                with self.subTest(layout=layout, placement=placement, mode=mode):
                    stack = base / str(index) / '.getzilla'
                    target = stack / ('modules/mcp-jira' if placement == 'installed'
                                      else 'optional-modules/mcp-jira/0.1.0')
                    shutil.copytree(MODULE, target, ignore=shutil.ignore_patterns('__pycache__'))
                    package = stack / 'getzilla'
                    source = ROOT / '.getzilla/getzilla'
                    if layout in ('loose', 'ambiguous'):
                        shutil.copytree(source, package, ignore=shutil.ignore_patterns('__pycache__'))
                    if layout in ('sdk', 'ambiguous'):
                        package.mkdir(exist_ok=True)
                        (package / '__init__.py').write_bytes((source / '__init__.py').read_bytes())
                        with zipfile.ZipFile(stack / 'getzilla.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
                            for path in sorted(source.rglob('*.py')):
                                archive.writestr('getzilla/' + path.relative_to(source).as_posix(), path.read_bytes())
                    result = subprocess.run([sys.executable, '-I', '-S', '-B', str(probe),
                                             str(target / 'worker.py'), str(stack), mode],
                                            cwd=unrelated, capture_output=True, text=True, timeout=20, check=False)
                    if error:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(error, result.stderr)
                    else:
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        origins = json.loads(result.stdout)
                        self.assertTrue(origins['package'].startswith(str(stack) + os.sep))
