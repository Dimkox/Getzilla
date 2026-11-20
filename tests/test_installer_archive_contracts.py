"""Owned fixtures from verified Git2.56.1/Node26.13.1 archive member shapes."""
import hashlib
import io
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from itertools import product
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import managed_runtime, managed_software
from getzilla.latest_releases import Target
from getzilla.managed_source_build import install_source


def archive(component, rows, filename=None):
    version = '26.13.1' if component == 'node' else '2.56.1'
    filename = filename or component+'-'+version+'.tar.gz'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as handle:
        for name, body in rows:
            item = tarfile.TarInfo(name)
            item.mode = 0o755
            if isinstance(body, str):
                item.type, item.linkname = tarfile.SYMTYPE, body
                handle.addfile(item)
            else:
                item.size = len(body)
                handle.addfile(item, io.BytesIO(body))
    raw = stream.getvalue()
    return Target(component, version, 'https://owned.invalid/archive',
                  sha256=hashlib.sha256(raw).hexdigest(), filename=filename), raw


class ArchiveContractTests(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'Unix source links remain unsupported on Windows')
    def test_git_real_directory_alias_shapes_reach_inert_build_then_preserve_custody(self):
        rows = [('git-2.56.1/configure', b'owned'),
                ('git-2.56.1/Documentation/RelNotes/2.56.1.adoc', b'owned'),
                ('git-2.56.1/RelNotes', 'Documentation/RelNotes/2.56.1.adoc'),
                ('git-2.56.1/git-gui/git-gui.sh', b'owned'),
                ('git-2.56.1/gitk-git/gitk', b'owned'),
                ('git-2.56.1/subprojects/git-gui', '../git-gui'),
                ('git-2.56.1/subprojects/gitk', '../gitk-git')]
        target, raw = archive('git', rows)
        scratch = ROOT/'.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='owned-git-alias-', dir=scratch) as owned:
            calls = []
            def run(command, cwd=None, **kwargs):
                calls.append(command)
                if command[0] == './configure':
                    self.assertEqual((cwd/'subprojects/git-gui/git-gui.sh').read_bytes(), b'owned')
                    self.assertEqual((cwd/'subprojects/gitk/gitk').read_bytes(), b'owned')
                    (cwd/'config.mak.autogen').write_text('NO_CURL=\n')
                    prefix = Path(command[1].removeprefix('--prefix='))
                    (prefix/'bin').mkdir(parents=True)
                    (prefix/'bin/git').write_bytes(b'owned inert executable')
                return subprocess.CompletedProcess(command, 0, 'git version 2.56.1', '')
            with patch('getzilla.architecture_diff._run_capped', return_value=(0, b'fetch\noption\n\n', b'')) as probe:
                path = install_source(target, raw, Path(owned), run=run)
                self.assertEqual(install_source(target, raw, Path(owned), run=run), path)
                path.write_bytes(b'user change')
                with self.assertRaisesRegex(ValueError, 'conflict'):
                    install_source(target, raw, Path(owned), run=lambda *a, **kw: self.fail('user bytes must stay'))
            self.assertTrue(probe.called)
            self.assertTrue(all(call.kwargs['stdin_data'] == b'capabilities\n\n' for call in probe.call_args_list))

    def test_directory_alias_rejects_non_git_and_open_or_ambiguous_subtrees(self):
        cases = [
            [('root/alias', '../outside')],
            [('root/alias', 'missing')],
            [('root/alias', 'alias')],
            [('root/alias', 'second'), ('root/second', 'alias')],
            [('root/alias', 'dest'), ('root/dest/child', '../alias')],
            [('root/alias', 'dest'), ('root/dest/child', '../file')],
            [('root/alias', 'dest'), ('root/alias/member', b'conflict')],
            [('root/alias', 'dest'), ('root/alias/child', 'file')],
            [('root/alias', '../other/dest'), ('other/dest/file', b'crossroot')],
            [('root/alias', 'dest'), ('root/alias', 'dest')],
            [('root/alias', 'dest'), ('root/ALIAS', 'dest')],
            [('root/bad\\alias', 'dest')],
        ]
        for rows in cases:
            with self.subTest(rows=rows):
                target, raw = archive('git', [('root/file', b'owned'), ('root/dest/file', b'owned'), *rows])
                with self.assertRaises(ValueError):
                    managed_runtime.entries(target, raw)
        target, raw = archive('node', [('root/dest/file', b'owned'), ('root/alias', 'dest')])
        with self.assertRaises(ValueError):
            managed_runtime.entries(target, raw)

    def test_only_exact_node_binary_gets_larger_limit_and_all_other_bounds_remain(self):
        filename = 'node-v26.13.1-linux-x64.tar.gz'
        member = 'node-v26.13.1-linux-x64/bin/node'
        # Scale the two per-member bounds only; real150348872-byte RED/positive
        # archive controls run separately from the portable fixture suite.
        with patch.object(managed_runtime, 'MAX_FILE_BYTES', 32), \
                patch.object(managed_runtime, 'MAX_NODE_EXECUTABLE_BYTES', 64, create=True):
            target, raw = archive('node', [(member, b'n'*48)], filename)
            self.assertEqual(len(managed_runtime.entries(target, raw)[0]['bin/node'][0]), 48)
            for component, name, size in [('node', member, 65), ('node', member+'/other', 48),
                    ('node', member.replace('26.13.1', '26.13.0'), 48),
                    ('node', member.replace('linux-x64', 'linux-arm64'), 48), ('git', member, 48)]:
                with self.subTest(component=component, name=name, size=size):
                    target, raw = archive(component, [(name, b'n'*size)], filename)
                    with self.assertRaisesRegex(ValueError, 'bound'):
                        managed_runtime.entries(target, raw)
            target, raw = archive('node', [(member, b'n'*48), ('node-v26.13.1-linux-x64/README', b'n'*32)], filename)
            with patch.object(managed_runtime, 'MAX_BYTES', 72), self.assertRaisesRegex(ValueError, 'bound'):
                managed_runtime.entries(target, raw)
            with patch.object(managed_runtime, 'MAX_FILES', 1), self.assertRaisesRegex(ValueError, 'bound'):
                managed_runtime.entries(target, raw)

    def test_oversize_node_header_refuses_before_read_and_accepted_read_is_bounded(self):
        filename = 'node-v26.13.1-linux-x64.tar.gz'
        member = 'node-v26.13.1-linux-x64/bin/node'
        with patch.object(managed_runtime, 'MAX_FILE_BYTES', 32), \
                patch.object(managed_runtime, 'MAX_NODE_EXECUTABLE_BYTES', 64, create=True):
            target, raw = archive('node', [(member, b'n'*65)], filename)
            with patch.object(tarfile.TarFile, 'extractfile', side_effect=AssertionError('oversize header reached body')):
                with self.assertRaisesRegex(ValueError, 'bound'):
                    managed_runtime.entries(target, raw)
            target, raw = archive('node', [(member, b'n'*48)], filename)
            reads = []
            class OwnedStream(io.BytesIO):
                def read(self, size=-1):
                    reads.append(size)
                    if size < 0 or size > 65:
                        raise AssertionError('unbounded archive member read')
                    return super().read(size)
            with patch.object(tarfile.TarFile, 'extractfile', return_value=OwnedStream(b'n'*48)):
                self.assertEqual(len(managed_runtime.entries(target, raw)[0]['bin/node'][0]), 48)
            self.assertEqual(reads, [65])

    def test_windows_node_binary_contract_uses_exact_zip_root(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as handle:
            handle.writestr('node-v26.13.1-win-x64/node.exe', b'n'*48)
        raw = stream.getvalue()
        target = Target('node', '26.13.1', 'https://owned.invalid/archive',
                        sha256=hashlib.sha256(raw).hexdigest(), filename='node-v26.13.1-win-x64.zip')
        with patch.object(managed_runtime, 'MAX_FILE_BYTES', 32), \
                patch.object(managed_runtime, 'MAX_NODE_EXECUTABLE_BYTES', 64, create=True):
            self.assertEqual(len(managed_runtime.entries(target, raw)[0]['node.exe'][0]), 48)

    def test_missing_verified_prerequisites_stop_dependent_fetch_and_execution(self):
        cases = [('npm', None, (), 'node'),
                ('jscpd', None, ('jscpd',), 'node, npm'),
                ('agent:qwen', 'qwen', (), 'node, npm'), ('composer', None, ('composer',), 'php')]
        for (component, agent, tools, expected), verify_only in product(cases, (False, True)):
            with self.subTest(component=component, verify_only=verify_only):
                target = Target(component, '1.0.0', 'https://owned.invalid/must-not-fetch', sha256='a'*64)
                scratch = ROOT/'.getzilla/runtime/scratch'
                scratch.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(prefix='owned-dependency-', dir=scratch) as owned, \
                        patch.object(managed_software, 'plan', return_value=({component: target}, [])), \
                        patch.object(managed_software, 'verify_environment', return_value={'status': 'complete'}):
                    result = managed_software.install_software(Path(owned)/'state', Path(owned),
                        agent=agent, tools=tools, system='linux', architecture='x64',
                        verify_only=verify_only, which=lambda _: self.fail('missing dependency must stop lookup'),
                        fetch=lambda *a: self.fail('missing dependency must stop fetch'),
                        run=lambda *a, **kw: self.fail('missing dependency must stop execution'))
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['components'][0]['error'], 'missing verified prerequisite: '+expected)
