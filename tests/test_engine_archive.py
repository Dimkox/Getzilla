"""Source archives preserve code without depending on installer interpreter state."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROBE = '''\
import hashlib, importlib.util, io, json, sys, zipfile, zipimport
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root), str(root / '.getzilla')]
spec = importlib.util.spec_from_file_location('archive_installer', root / 'scripts/install_into.py')
installer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = installer
spec.loader.exec_module(installer)
source = b'VALUE = "original"\\ndef choose(x):\\n    return x in {"alpha", "beta", "gamma"}\\ndef middle(x):\\n    return x[1:3]\\n'
entries = [installer.InstallEntry(path.relative_to(root).as_posix(), path.read_bytes(), 0o644)
           for path in sorted((root / '.getzilla/getzilla').rglob('*.py'))]
entries += [installer.InstallEntry('.getzilla/archive_probe/__init__.py', source, 0o644)]
before = installer.engine_archive_entry(entries).content
for point in (91, 93, 123, 125):
    sys.intern(chr(point))
import getzilla.spec, getzilla.python_test_runner
after = installer.engine_archive_entry(list(reversed(entries))).content
with zipfile.ZipFile(io.BytesIO(after)) as archive:
    assert set(archive.namelist()) == {entry.path[len('.getzilla/'):] for entry in entries}
    assert not any(name.endswith('.pyc') for name in archive.namelist())
    for entry in entries:
        name = entry.path[len('.getzilla/'):]
        assert archive.read(name) == entry.content
        assert archive.getinfo(name).external_attr >> 16 == 0o644
        assert archive.getinfo(name).date_time == (1980, 1, 1, 0, 0, 0)
path = Path(sys.argv[2]) / 'engine.zip'
path.write_bytes(after)
for entry in entries:
    name = entry.path[len('.getzilla/'):]
    parts = name.split('/')
    if parts[-1] == '__init__.py':
        fullname, parent = '.'.join(parts[:-1]), '/'.join(parts[:-2])
    else:
        fullname, parent = '.'.join(parts)[:-3], '/'.join(parts[:-1])
    loader = zipimport.zipimporter(str(path) + ('/' + parent if parent else ''))
    code = loader.get_code(fullname)
    assert code == compile(entry.content, code.co_filename, 'exec', dont_inherit=True)
sys.path.insert(0, str(path))
import archive_probe
assert archive_probe.VALUE == 'original' and archive_probe.choose('beta')
assert archive_probe.middle([0, 1, 2, 3]) == [1, 2]
assert archive_probe.__file__.endswith('engine.zip/archive_probe/__init__.py')
changed = entries[:-1] + [installer.InstallEntry(entries[-1].path, source.replace(b'original', b'changed'), 0o644)]
mutation = installer.engine_archive_entry(changed).content
print(json.dumps({'before': hashlib.sha256(before).hexdigest(), 'after': hashlib.sha256(after).hexdigest(),
                  'mutation': hashlib.sha256(mutation).hexdigest(), 'zipimport': archive_probe.__file__,
                  'python': sys.version.split()[0]}))
'''


class EngineArchiveTests(unittest.TestCase):
    def probe(self, seed):
        with tempfile.TemporaryDirectory(prefix='getzilla-archive-proof-') as directory:
            driver = Path(directory) / 'probe.py'
            driver.write_text(PROBE, encoding='utf-8')
            result = subprocess.run([sys.executable, str(driver), str(ROOT), directory],
                                    env={**os.environ, 'PYTHONHASHSEED': str(seed), 'PYTHONDONTWRITEBYTECODE': '1'},
                                    capture_output=True, text=True, timeout=25, check=False)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            return json.loads(result.stdout)

    def test_intern_import_state_and_entry_permutation_do_not_change_archive(self):
        proof = self.probe(17)
        self.assertEqual(proof['before'], proof['after'])
        self.assertNotEqual(proof['after'], proof['mutation'])

    def test_fresh_processes_and_hash_seeds_agree_with_real_zipimport(self):
        proofs = [self.probe(seed) for seed in (0, 41, 41)]
        self.assertEqual(1, len({item['before'] for item in proofs}))
        self.assertEqual(1, len({item['after'] for item in proofs}))
        self.assertTrue(all(item['zipimport'].endswith('/archive_probe/__init__.py') for item in proofs))

    def test_invalid_engine_source_refuses_before_publication(self):
        from tests.test_install_extras import MODULE
        with self.assertRaises(SyntaxError):
            MODULE.engine_archive_entry([MODULE.InstallEntry('.getzilla/getzilla/broken.py', b'def broken(', 0o644)])


if __name__ == '__main__':
    unittest.main()
