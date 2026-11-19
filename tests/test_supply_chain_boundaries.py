"""Decoder and public-source custody boundaries use owned, inert fixtures only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import supply_chain
from tests._support import project_copy

SOURCE = '.getzilla/config/toolchain.json'


class PayloadBoundaryTests(unittest.TestCase):
    def raw_hook(self, root, raw):
        result = subprocess.run([sys.executable, '-B', str(root / '.getzilla/hooks/pre_tool_use.py')],
                                cwd=root, input=raw, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b'PRIVATE-SENTINEL', result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_unclassified_decoder_failures_deny_without_echoing_input(self):
        deep = b'[' * 20_000 + b'0' + b']' * 20_000
        invalid = (
            b'{"tool_name":"mcp__unknown__get_status","tool_input":' + deep + b'}',
            b'{"tool_name":"Read","toolArgs":' + json.dumps(deep.decode()).encode() + b'}',
            b'{"tool_name":"Read","tool_input":{"value":"\xffPRIVATE-SENTINEL"}}',
            b'{"tool_name":"Read",PRIVATE-SENTINEL', b'[]', b'null', b'1', b'"Read"', b'',
            b'{"tool_name":[]}', b'{"tool_name":false}', b'{"tool_input":{}}',
            b'{"tool_name":"Read","toolName":"mcp__unknown__get_status"}',
            b'{"tool_name":"Read","tool_name":"Read"}',
            b'{"tool_name":"Read","tool_input":[]}',
            b'{"tool_name":"Read","tool_input":{"value":1e999}}',
            b'{"tool_name":"Read","tool_input":{"value":"\\ud800"}}',
            b' ' * 1_048_577,
        )
        with project_copy() as root:
            for raw in invalid:
                with self.subTest(case=invalid.index(raw)):
                    result = self.raw_hook(root, raw)
                    self.assertEqual(result['decision'], 'deny', result)
                    self.assertIn('invalid_tool_request', result.get('reason', ''))

    def test_bootstrap_decoder_failure_denies_when_library_is_unavailable(self):
        with project_copy() as root:
            (root / '.getzilla/hooks/_lib.py').write_text('raise ImportError("fixture failure")\n')
            result = self.raw_hook(root, b'{"tool_name":"Read",PRIVATE-SENTINEL')
            self.assertEqual(result['decision'], 'deny', result)
            self.assertIn('invalid_tool_request', result.get('reason', ''))

    def test_bootstrap_denial_uses_each_native_harness_verdict_schema(self):
        with project_copy() as root:
            (root / '.getzilla/hooks/_lib.py').write_text('raise ImportError("fixture failure")\n')
            for harness in ('grok', 'claude', 'qwen', 'codex', 'gemini', 'copilot'):
                with self.subTest(harness=harness):
                    result = subprocess.run([sys.executable, '-B', str(root / '.getzilla/hooks/pre_tool_use.py'),
                                             '--harness', harness], cwd=root,
                                            input=b'{"tool_name":"Read",PRIVATE-SENTINEL',
                                            capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0)
                    data = json.loads(result.stdout)
                    self.assertNotIn(b'PRIVATE-SENTINEL', result.stdout + result.stderr)
                    if harness in {'claude', 'qwen', 'codex'}:
                        self.assertNotIn('decision', data)
                        self.assertEqual(data['hookSpecificOutput']['permissionDecision'], 'deny')
                    elif harness == 'copilot':
                        self.assertEqual(data.get('permissionDecision'), 'deny')
                    else:
                        self.assertEqual(data['decision'], 'deny')


@unittest.skipIf(os.name == 'nt', 'POSIX public mode/owner custody; unsupported Windows ACL evidence stays unqualified')
class PublicSourceBoundaryTests(unittest.TestCase):
    def entry(self, root):
        return next(item for item in supply_chain.audit(root)['sources'] if item['path'] == SOURCE)

    def assert_unqualified(self, entry):
        self.assertEqual(entry['state'], 'unqualified')
        self.assertIsNone(entry['sha256'])
        self.assertIsNone(entry['bytes'])

    def test_private_single_link_and_private_or_public_hardlinks_never_export_digest(self):
        with project_copy() as root:
            source = root / SOURCE
            source.write_bytes(b'PRIVATE-SENTINEL')
            source.chmod(0o600)
            self.assert_unqualified(self.entry(root))
            outside = root.parent / 'owned-private-fixture'
            outside.write_bytes(b'PRIVATE-SENTINEL')
            source.unlink()
            for mode in (0o600, 0o644):
                outside.chmod(mode)
                os.link(outside, source)
                self.assertEqual(source.stat().st_nlink, 2)
                self.assert_unqualified(self.entry(root))
                source.unlink()

    def test_known_private_or_linked_metadata_is_rejected_before_any_read(self):
        with project_copy() as root:
            source = root / SOURCE
            source.chmod(0o600)
            with patch.object(os, 'read', side_effect=AssertionError('source bytes must not be read')):
                with self.assertRaises(supply_chain.PublicSourceError):
                    supply_chain.read_public_source(root, SOURCE, 262144)
            source.chmod(0o644)
            os.link(source, root.parent / 'public-alias')
            with patch.object(os, 'read', side_effect=AssertionError('source bytes must not be read')):
                with self.assertRaises(supply_chain.PublicSourceError):
                    supply_chain.read_public_source(root, SOURCE, 262144)

    def test_foreign_owner_metadata_is_rejected_before_reading(self):
        from getzilla import fsx
        with project_copy() as root:
            original_stat = fsx.lstat_at
            def foreign_metadata(parent, name):
                info = original_stat(parent, name)
                if name != 'toolchain.json':
                    return info
                attributes = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                              'st_size', 'st_mtime_ns', 'st_ctime_ns')
                value = SimpleNamespace(**{key: getattr(info, key) for key in attributes})
                value.st_uid += 1  # Synthetic stat boundary; no privileged chown or foreign file access.
                return value
            with patch.object(fsx, 'lstat_at', foreign_metadata), \
                    patch.object(os, 'read', side_effect=AssertionError('source bytes must not be read')):
                with self.assertRaises(supply_chain.PublicSourceError):
                    supply_chain.read_public_source(root, SOURCE, 262144)

    def test_root_ancestor_symlink_is_not_followed(self):
        with project_copy() as root:
            alias = root.parent / 'alias'
            alias.symlink_to(root.parent, target_is_directory=True)
            self.assert_unqualified(self.entry(alias / root.name))

    def test_actual_cli_refuses_private_file_without_exporting_its_hash_or_size(self):
        with project_copy() as root:
            source = root / SOURCE
            source.write_bytes(b'PRIVATE-SENTINEL')
            source.chmod(0o600)
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/getzilla_cli.py'),
                                     'trust', 'audit', '--json'], cwd=root,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 1, result.stderr)
            entry = next(item for item in json.loads(result.stdout)['sources'] if item['path'] == SOURCE)
            self.assert_unqualified(entry)
            self.assertNotIn('PRIVATE-SENTINEL', result.stdout + result.stderr)
            self.assertNotIn(hashlib.sha256(b'PRIVATE-SENTINEL').hexdigest(), result.stdout)

    def test_ordinary_public_modes_remain_observed(self):
        with project_copy() as root:
            source = root / SOURCE
            source.write_bytes(b'{"tools":[]}\n')
            for mode in (0o444, 0o644, 0o555, 0o755):
                source.chmod(mode)
                entry = self.entry(root)
                self.assertEqual(entry['state'], 'observed')
                self.assertEqual(entry['sha256'], hashlib.sha256(b'{"tools":[]}\n').hexdigest())

    def test_special_files_symlinks_and_writable_public_modes_are_unqualified(self):
        with project_copy() as root:
            source = root / SOURCE
            source.chmod(0o666)
            self.assert_unqualified(self.entry(root))
            source.unlink()
            os.mkfifo(source, 0o644)
            self.assert_unqualified(self.entry(root))
            source.unlink()
            source.symlink_to(root / 'AGENTS.md')
            self.assert_unqualified(self.entry(root))

    def test_replaced_inode_is_rejected_and_owned_descriptor_is_closed(self):
        from getzilla import fsx
        with project_copy() as root:
            original_open = fsx.open_at
            descriptors = []
            def replace_after_open(parent, name, flags, *args):
                fd = original_open(parent, name, flags, *args)
                if name == 'toolchain.json':
                    descriptors.append(fd)
                    replacement = root / '.getzilla/config/replacement.json'
                    replacement.write_text('{"tools":[]}', encoding='utf-8')
                    replacement.chmod(0o644)
                    replacement.replace(root / SOURCE)
                return fd
            with patch.object(fsx, 'open_at', replace_after_open):
                self.assert_unqualified(self.entry(root))
            self.assertTrue(descriptors)
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_mode_and_size_change_during_read_never_export_a_digest(self):
        from getzilla import fsx
        for change in ('mode', 'size'):
            with self.subTest(change=change), project_copy() as root:
                source = root / SOURCE
                original_open, original_read = fsx.open_at, os.read
                selected = set()
                changed = False
                def remember(parent, name, flags, *args):
                    fd = original_open(parent, name, flags, *args)
                    if name == 'toolchain.json':
                        selected.add(fd)
                    return fd
                def change_after_read(fd, count):
                    nonlocal changed
                    value = original_read(fd, count)
                    if fd in selected and not changed:
                        changed = True
                        if change == 'mode':
                            source.chmod(0o600)
                        else:
                            with source.open('ab') as stream:
                                stream.write(b' ')
                    return value
                with patch.object(fsx, 'open_at', remember), patch.object(os, 'read', change_after_read):
                    self.assert_unqualified(self.entry(root))
                self.assertTrue(changed)


if __name__ == '__main__':
    unittest.main()
