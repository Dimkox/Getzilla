"""Compressed bytecode must not depend on an installer's interpreter history."""
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
import hashlib, importlib.util, io, json, marshal, sys, zipfile
from pathlib import Path
root = Path(sys.argv[1])
sys.path[:0] = [str(root), str(root / '.getzilla')]
spec = importlib.util.spec_from_file_location('archive_installer', root / 'scripts/install_into.py')
installer = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = installer
spec.loader.exec_module(installer)
source = b'VALUE = "original"\\ndef choose(x):\\n    return x in {"alpha", "beta", "gamma"}\\n'
entries = [installer.InstallEntry(path.relative_to(root).as_posix(), path.read_bytes(), 0o644)
           for path in sorted((root / '.getzilla/getzilla').rglob('*.py'))]
entries += [installer.InstallEntry('.getzilla/archive_probe/__init__.py', source, 0o644)]
before = installer.engine_archive_entry(entries).content
for point in (91, 93, 123, 125):
    sys.intern(chr(point))
import getzilla.spec, getzilla.python_test_runner
after = installer.engine_archive_entry(list(reversed(entries))).content
with zipfile.ZipFile(io.BytesIO(after)) as archive:
    pyc = archive.read('archive_probe/__init__.pyc')
    code = marshal.loads(pyc[16:])
    namespace = {}
    exec(code, namespace)
    assert namespace['VALUE'] == 'original' and namespace['choose']('alpha')
    assert not namespace['choose']('other')
    assert pyc[:4] == importlib.util.MAGIC_NUMBER
    assert pyc[4:8] == (1).to_bytes(4, 'little')
    assert pyc[8:16] == importlib.util.source_hash(source)
    assert archive.read('archive_probe/__init__.py') == source
    for entry in entries:
        name = entry.path[len('.getzilla/'):]
        body = archive.read(name[:-3] + '.pyc')
        assert archive.read(name) == entry.content
        assert body[8:16] == importlib.util.source_hash(entry.content)
        assert marshal.loads(body[16:]) == compile(entry.content, name, 'exec', dont_inherit=True)
path = Path(sys.argv[2]) / 'engine.zip'
path.write_bytes(after)
sys.path.insert(0, str(path))
import archive_probe
assert archive_probe.VALUE == 'original' and archive_probe.choose('beta')
assert archive_probe.__file__.endswith('engine.zip/archive_probe/__init__.pyc')
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
        self.assertTrue(all(item['zipimport'].endswith('/archive_probe/__init__.pyc') for item in proofs))


if __name__ == '__main__':
    unittest.main()
