from __future__ import annotations

import dataclasses
import importlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / '.getzilla'))
from getzilla import state
from getzilla.router import build_route


@unittest.skipUnless(sys.platform == 'linux', 'named Linux AF_UNIX profile only')
class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module('getzilla_delivery.local_preview')
        scratch = PROJECT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        for command in (['git', 'init', '-q'], ['git', 'config', 'user.email', 'test@example.invalid'],
                        ['git', 'config', 'user.name', 'Preview Test']):
            subprocess.run(command, cwd=self.root, check=True, capture_output=True)
        (self.root / 'source.txt').write_text('owned source\n')
        subprocess.run(['git', 'add', 'source.txt'], cwd=self.root, check=True)
        subprocess.run(['git', 'commit', '-qm', 'fixture'], cwd=self.root, check=True)
        self.enterContext(patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'preview-test-owner'}))
        state.bind_session('preview-test-owner')
        route = build_route(self.root, 'Preview this local static artifact', 'preview-test-owner').to_dict()
        state.set_active_route(self.root, route)
        self.adapter = self.module.NativeLocalPreview(self.root, enabled=True)
        self.addCleanup(self.adapter.close)
        self.files = {'index.html': b'<h1>exact preview</h1>', 'a.css': b'h1{color:blue}'}

    def manifest(self, **kwargs):
        return self.adapter.manifest(self.files, generation=1, key='first', **kwargs)

    def test_disabled_has_zero_effects_even_with_unreadable_arguments(self):
        disabled = self.module.NativeLocalPreview(self.root, enabled=False)
        class Unreadable:
            def __iter__(self):
                raise AssertionError('inspected disabled input')
        with patch('subprocess.Popen', side_effect=AssertionError('spawned')), \
                patch('socket.socket', side_effect=AssertionError('socket')), \
                self.assertRaisesRegex(self.module.PreviewError, 'preview_disabled'):
            disabled.create(Unreadable(), Unreadable())
        self.assertFalse((self.root / '.getzilla/runtime/previews').exists())

    def test_invalid_limits_unsupported_profiles_and_artifact_tamper_fail_before_spawn(self):
        manifest = self.manifest()
        with patch('getzilla.fsx.owned_popen', side_effect=AssertionError('spawned')):
            for value in (0, 301, True, float('nan')):
                with self.subTest(ttl=value), self.assertRaises(self.module.PreviewError):
                    self.manifest(ttl=value)
            for profile in ('web-api', 'worker', 'database'):
                with self.assertRaisesRegex(self.module.PreviewError, 'unsupported_profile'):
                    self.adapter.create(dataclasses.replace(manifest, profile=profile), self.files)
            with self.assertRaisesRegex(self.module.PreviewError, 'artifact_mismatch'):
                self.adapter.create(manifest, {'index.html': b'changed'})
            with self.assertRaisesRegex(self.module.PreviewError, 'artifact_path'):
                self.adapter.manifest({'../outside': b'x'}, generation=1, key='x')

    def test_real_create_get_revoke_cleanup_and_preserve_neighbor(self):
        manifest = self.manifest()
        handle = self.adapter.create(manifest, self.files)
        neighbor = handle.directory / 'user-work.txt'
        neighbor.write_text('keep')
        status, body = handle.request('/index.html')
        self.assertEqual((status, body), (200, self.files['index.html']))
        self.assertEqual(handle.request('/a.css'), (200, self.files['a.css']))
        self.assertEqual(handle.request('/../source.txt')[0], 404)
        self.assertEqual(handle.request('/absent')[0], 404)
        result = handle.revoke()
        self.assertEqual(result['state'], 'destroyed')
        self.assertEqual(result['reason'], 'revoked')
        self.assertTrue(result['process_reaped'])
        self.assertFalse(handle.socket_path.exists())
        self.assertEqual(neighbor.read_text(), 'keep')
        with self.assertRaises(self.module.PreviewError):
            handle.request('/index.html')

    def test_duplicate_recovery_quota_and_generation_fencing(self):
        manifest = self.manifest()
        first = self.adapter.create(manifest, self.files)
        recovered = self.module.NativeLocalPreview(self.root, enabled=True)
        self.addCleanup(recovered.close)
        duplicate = recovered.create(manifest, self.files)
        self.assertEqual(first.pid, duplicate.pid)
        self.assertEqual(duplicate.request('/')[1], self.files['index.html'])
        with self.assertRaisesRegex(self.module.PreviewError, 'project_busy'):
            recovered.create(dataclasses.replace(manifest, generation=2, key='second'), self.files)
        with self.assertRaisesRegex(self.module.PreviewError, 'intent_conflict'):
            recovered.create(dataclasses.replace(manifest, ttl=30), self.files)
        first.revoke()
        self.assertEqual(recovered.create(manifest, self.files).observe()['state'], 'destroyed')
        second = recovered.create(dataclasses.replace(manifest, generation=2, key='second'), self.files)
        with self.assertRaises(self.module.PreviewError):
            first.request('/')
        second.revoke()

    def test_ttl_expires_without_parent_polling_and_does_not_reset_on_replay(self):
        manifest = self.manifest(ttl=1)
        first = self.adapter.create(manifest, self.files)
        time.sleep(1.3)
        result = first.observe()
        self.assertEqual(result['state'], 'destroyed')
        self.assertEqual(result['reason'], 'expired')
        self.assertTrue(result['process_reaped'])
        self.assertFalse(first.socket_path.exists())
        self.assertEqual(self.adapter.create(manifest, self.files).observe()['state'], 'destroyed')

    def test_foreign_tenant_and_revoked_epoch_do_not_release_content(self):
        manifest = self.manifest()
        with self.assertRaisesRegex(self.module.PreviewError, 'binding_mismatch'):
            self.adapter.create(dataclasses.replace(manifest, tenant='foreign'), self.files)
        handle = self.adapter.create(manifest, self.files)
        route = state.get_active_route(self.root)
        from getzilla.continuity import submit
        submit(self.root, '', 'replacement-owner', continue_route=route['route_id'],
               expected_epoch=route['authority_epoch'], expected_revision=route['state_revision'],
               request_id='preview-revoke-handoff')
        state.bind_session('preview-test-owner')
        with self.assertRaises(self.module.PreviewError):
            handle.request('/')
        time.sleep(.3)
        self.assertEqual(handle.observe()['reason'], 'authority_revoked')

    def test_linked_worktree_cannot_bypass_repository_project_quota(self):
        handle = self.adapter.create(self.manifest(), self.files)
        linked = self.root / 'linked'
        subprocess.run(['git', 'worktree', 'add', '-qb', 'preview-linked', str(linked)],
                       cwd=self.root, check=True, capture_output=True)
        route = build_route(linked, 'Preview the same project', 'preview-test-owner').to_dict()
        state.set_active_route(linked, route)
        other = self.module.NativeLocalPreview(linked, enabled=True)
        self.addCleanup(other.close)
        candidate = other.manifest(self.files, generation=2, key='other')
        with self.assertRaisesRegex(self.module.PreviewError, 'project_busy'):
            other.create(candidate, self.files)
        handle.revoke()

    def test_dead_child_reconciles_owned_socket_without_touching_user_data(self):
        handle = self.adapter.create(self.manifest(), self.files)
        neighbor = handle.directory / 'unique.txt'
        neighbor.write_text('preserve')
        process = self.adapter.processes[handle.pid]
        process.kill()
        process.wait(timeout=2)
        result = handle.reconcile()
        self.assertEqual(result['state'], 'destroyed')
        self.assertEqual(result['reason'], 'child_failed')
        self.assertFalse(handle.socket_path.exists())
        self.assertEqual(neighbor.read_text(), 'preserve')

    def test_request_budget_is_real_and_slow_client_cannot_extend_ttl(self):
        handle = self.adapter.create(self.manifest(ttl=1), self.files)
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(handle.socket_address)
            client.sendall(b'GET / HTTP/1.0\r\n')
            time.sleep(1.2)
        self.assertEqual(handle.observe()['reason'], 'expired')
        self.assertFalse(handle.socket_path.exists())

    def test_artifact_limits_and_resource_caps_are_observed_in_real_child(self):
        with self.assertRaisesRegex(self.module.PreviewError, 'artifact_limits'):
            self.adapter.manifest({'index.html': b'x' * (256 * 1024 + 1)}, generation=1, key='big')
        handle = self.adapter.create(self.manifest(), self.files)
        limits = Path(f'/proc/{handle.pid}/limits').read_text()
        self.assertRegex(limits, r'Max cpu time\s+2\s+2')
        self.assertRegex(limits, r'Max address space\s+134217728\s+134217728')
        self.assertRegex(limits, r'Max open files\s+32\s+32')
        self.assertEqual(handle.observe()['egress_probe'], {'AF_INET': 'denied', 'AF_INET6': 'denied'})
        for _ in range(256):
            try:
                handle.request('/absent')
            except self.module.PreviewError:
                break
        time.sleep(.1)
        self.assertEqual(handle.observe()['reason'], 'quota_exhausted')
        self.assertLessEqual(handle.observe()['requests'], 256)

    def test_unbound_http_and_oversized_request_never_serve_artifact(self):
        handle = self.adapter.create(self.manifest(), self.files)
        for request in (b'GET / HTTP/1.0\r\n\r\n', b'GET / HTTP/1.0\r\nX:' + b'a' * 2000):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(1)
                client.connect(handle.socket_address)
                client.sendall(request)
                try:
                    response = client.recv(4096)
                except ConnectionResetError:
                    response = b''
                self.assertNotIn(self.files['index.html'], response)
        handle.revoke()


if __name__ == '__main__':
    unittest.main()
