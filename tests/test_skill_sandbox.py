from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import skill_sandbox as sandbox  # noqa: E402
from getzilla import fsx  # noqa: E402
from getzilla.architecture_diff import _run_capped  # noqa: E402


_INERT_NODE_PROBE = r"""
(async () => {
  const fs = require('node:fs');
  const facts = {};
  try { facts.cjs = require('getzilla_fixture_graft_cjs_161_v1') === 'CJS'; }
  catch { facts.cjs = false; }
  try { facts.esm = (await import('getzilla_fixture_graft_esm_161_v1')).default === 'ESM'; }
  catch { facts.esm = false; }
  for (const [path, key] of [
    ['/source/public-644', 'source_644'],
    ['/deps/getzilla_fixture_graft_cjs_161_v1/index.cjs', 'deps_664'],
    ['/deps/getzilla_fixture_graft_esm_161_v1/index.js', 'deps_666'],
    ['/source/node_modules/getzilla_fixture_graft_cjs_161_v1/index.cjs', 'graft_664'],
    ['/source/node_modules/getzilla_fixture_graft_esm_161_v1/index.js', 'graft_666']
  ]) {
    try { fs.appendFileSync(path, '!'); facts[key] = false; }
    catch (error) { facts[key] = error.code === 'EROFS'; }
  }
  fs.mkdirSync('/work/_bmad');
  fs.writeFileSync('/work/_bmad/public-canary', 'OWNED');
  facts.work = true;
  process.stdout.write(JSON.stringify(facts));
})().catch(() => { process.exitCode = 1; });
"""


def _public_snapshots(paths):
    result = {}
    for path in paths:
        descriptor = os.open(path, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            content = os.read(descriptor, 65536)
            after = os.fstat(descriptor)
            named = path.lstat()
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mode)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mode)
                    or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)):
                raise AssertionError('public fixture changed')
            result[path] = (content, stat.S_IMODE(after.st_mode), after.st_dev, after.st_ino)
        finally:
            os.close(descriptor)
    return result


class SandboxContracts(unittest.TestCase):
    def test_command_has_no_workspace_credentials_network_or_ambient_installer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('source', 'deps', 'work'):
                (root / name).mkdir()
            (root / 'source/node_modules').mkdir()
            if sys.platform != 'linux':
                with self.assertRaisesRegex(ValueError, 'UNQUALIFIED_NATIVE_GENERATOR'):
                    sandbox.sandbox_command('bmad', root / 'source', root / 'deps', root / 'work', 'claude-code')
                return
            command = sandbox.sandbox_command('bmad', root / 'source', root / 'deps', root / 'work', 'claude-code')
            self.assertIn('--unshare-all', command)
            self.assertIn('--clearenv', command)
            self.assertIn('--cap-drop', command)
            self.assertIn('--ignore-agent-tools', sandbox.sandbox_command('spec-kit', root / 'source', root / 'deps', root / 'work', 'claude'))
            self.assertIn('/source/tools/installer/bmad-cli.js', command)
            self.assertNotIn('npx', command)
            self.assertNotIn('specify', command)
            self.assertNotIn(str(Path.home()), command)

    def test_unknown_tool_adapter_or_outside_stage_refuses_before_execution(self):
        for component, agent in (('unknown', 'claude'), ('bmad', '../../shell'), ('spec-kit', 'unknown')):
            with self.assertRaises(ValueError):
                sandbox.sandbox_command(component, Path('/source'), Path('/deps'), Path('/work'), agent)

    def test_stage_output_snapshot_rejects_link_escape_oversize_and_executable_activation(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            root = parent / 'work'
            root.mkdir()
            outside = parent / 'outside-public-canary'
            outside.write_bytes(b'owned public fixture')
            (root / '.specify').mkdir()
            (root / '.specify/config.md').write_bytes(b'pinned-output')
            result = sandbox.read_stage(root)
            self.assertEqual(dict(result)['.specify/config.md'], b'pinned-output')
            (root / '.specify/escape').symlink_to(outside)
            with self.assertRaises(ValueError):
                sandbox.read_stage(root)
            (root / '.specify/escape').unlink()
            (root / '.env').write_text('credential-like output')
            with self.assertRaises(ValueError):
                sandbox.read_stage(root)

    def test_dependency_lock_requires_integrity_and_exact_official_origins(self):
        lock = {'lockfileVersion': 3, 'packages': {'': {}, 'node_modules/a': {
            'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
            'integrity': 'sha512-' + 'A' * 86 + '=='}}}
        sandbox.validate_npm_lock(lock)
        for key, value in (('integrity', ''), ('resolved', 'https://example.invalid/a.tgz'),
                           ('resolved', 'git+https://github.com/example/a')):
            changed = {**lock, 'packages': {'': {}, 'node_modules/a': {**lock['packages']['node_modules/a'], key: value}}}
            with self.assertRaises(ValueError):
                sandbox.validate_npm_lock(changed)


@unittest.skipUnless(sys.platform == 'linux', 'Linux-only generation profile')
class BmadDependencyGraft(unittest.TestCase):
    def _roots(self, parent):
        roots = [parent / name for name in ('source', 'deps', 'work')]
        for root in roots:
            root.mkdir(mode=0o700)
        return roots

    def _command(self, source, deps, work):
        return sandbox.sandbox_command('bmad', source, deps, work, 'codex')

    def test_missing_target_refuses_without_creating_source_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, deps, work = self._roots(Path(tmp))
            with self.assertRaises(ValueError):
                self._command(source, deps, work)
            self.assertEqual(list(source.iterdir()), [])

    def test_link_file_and_unrelated_nonempty_targets_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, deps, work = self._roots(Path(tmp))
            target = source / 'node_modules'
            target.symlink_to(deps, target_is_directory=True)
            with self.assertRaises(ValueError):
                self._command(source, deps, work)
            target.unlink()
            target.write_bytes(b'public')
            with self.assertRaises(ValueError):
                self._command(source, deps, work)
            target.unlink()
            target.mkdir()
            (target / 'public').write_bytes(b'public')
            with self.assertRaises(ValueError):
                self._command(source, deps, work)

    def test_unrelated_ancestry_and_linked_root_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            source, deps, work = self._roots(parent)
            (source / 'node_modules').mkdir()
            (source / 'other-deps').mkdir()
            with self.assertRaises(ValueError):
                self._command(source, source / 'other-deps', work)
            alias = parent / 'linked-deps'
            alias.symlink_to(deps, target_is_directory=True)
            with self.assertRaises(ValueError):
                self._command(source, alias, work)

    def test_target_replacement_during_inspection_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, deps, work = self._roots(Path(tmp))
            target = source / 'node_modules'
            target.mkdir()
            original = fsx.scandir

            @contextmanager
            def replace_before_listing(handle):
                target.rmdir()
                target.mkdir()
                with original(handle) as entries:
                    yield entries

            with patch.object(fsx, 'scandir', replace_before_listing):
                with self.assertRaises(ValueError):
                    self._command(source, deps, work)

    def test_exact_nested_caller_keeps_profile_without_new_input_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, unused, work = self._roots(Path(tmp))
            deps = source / 'node_modules'
            deps.mkdir()
            with (deps / 'public-sparse-data').open('wb') as stream:
                stream.truncate(sandbox.MAX_TOTAL_BYTES + 1)
            command = self._command(source, deps, work)
            self.assertNotIn('/source/node_modules', command)
            self.assertEqual(command[command.index('/usr/bin/node'):], [
                '/usr/bin/node', '--jitless', '--max-old-space-size=128', '--v8-pool-size=1',
                '/source/tools/installer/bmad-cli.js', 'install', '--directory', '/work',
                '--tools', 'codex', '--yes'])

    def _inert_modules(self, source, deps):
        (source / 'node_modules').mkdir(mode=0o700)
        (source / 'tools/installer').mkdir(parents=True)
        (source / 'tools/installer/bmad-cli.js').write_text(_INERT_NODE_PROBE)
        public = source / 'public-644'
        public.write_bytes(b'public')
        public.chmod(0o644)
        paths = [public]
        for name, filename, package, body, mode in (
                ('getzilla_fixture_graft_cjs_161_v1', 'index.cjs', {'main': 'index.cjs'},
                 "module.exports = 'CJS';", 0o664),
                ('getzilla_fixture_graft_esm_161_v1', 'index.js', {'type': 'module', 'exports': './index.js'},
                 "export default 'ESM';", 0o666)):
            folder = deps / name
            folder.mkdir()
            (folder / 'package.json').write_text(json.dumps({'name': name, **package}))
            path = folder / filename
            path.write_text(body)
            path.chmod(mode)
            paths.append(path)
        return paths

    def test_synthetic_cjs_esm_load_and_all_input_mounts_are_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, deps, work = self._roots(Path(tmp))
            paths = self._inert_modules(source, deps)
            before = _public_snapshots(paths)
            command = self._command(source, deps, work)
            code, out, err = _run_capped(
                command, cwd=Path(tmp), env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                stdout_limit=65536, stderr_limit=8192, timeout=40)
            self.assertEqual(code, 0)
            self.assertLessEqual(len(err), 8192)
            self.assertEqual(json.loads(out), dict.fromkeys((
                'cjs', 'esm', 'source_644', 'deps_664', 'deps_666',
                'graft_664', 'graft_666', 'work'), True))
            self.assertEqual(_public_snapshots(paths), before)
            self.assertEqual((work / '_bmad/public-canary').read_bytes(), b'OWNED')

    def test_output_group_and_world_write_modes_still_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '_bmad').mkdir()
            output = root / '_bmad/public-output'
            output.write_bytes(b'public output')
            for mode in (0o664, 0o666):
                output.chmod(mode)
                with self.assertRaisesRegex(ValueError, 'UNSAFE_STAGE_MODE'):
                    sandbox.read_stage(root)
