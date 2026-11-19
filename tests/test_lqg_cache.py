from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))

from getzilla.language_quality import core
from getzilla.language_quality.models import ToolOutput
from getzilla.language_quality.sandbox import Execution


def binding():
    return {'repository_id': 'a' * 64, 'local_account_id': 'uid:1000', 'commit_sha': 'b' * 40,
            'base_sha': 'c' * 40, 'package': 'web', 'tool_id': 'eslint', 'tool_version': '9.0.0',
            'sdk_identity': 'image@sha256:' + 'd' * 64, 'input_digest': 'e' * 64,
            'config_digest': 'f' * 64, 'dependency_digest': '1' * 64, 'policy_digest': '2' * 64,
            'scope': 'changed', 'requested_scope': 'changed', 'files': ['app.ts'],
            'argv': ['/opt/eslint', './app.ts'], 'executor_identity': 'docker:image-id',
            'implementation_digest': '3' * 64, 'platform': 'linux',
            'sandbox': {'image': 'image@sha256:' + 'd' * 64, 'cpus': 2}, 'effective_cpus': 2}


def observation(status='PASS'):
    return {'reported_status': status, 'summary': 'fixture finding' if status == 'FAIL' else 'fixture clean',
            'diagnostics': [], 'claimed_source_evidence_digest': '4' * 64}


@unittest.skipUnless(os.name == 'posix', 'cache requires POSIX no-follow descriptors')
class ShadowCacheTests(unittest.TestCase):
    def setUp(self):
        from getzilla.language_quality.cache import ShadowCache, cache_key
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.now = 1000000.0
        self.cache = ShadowCache(self.root, clock=lambda: self.now)
        self.key = cache_key(binding())

    def path(self):
        return self.root / '.getzilla/runtime/lqg/cache-v1' / (self.key + '.json')

    def rewrite(self, entry):
        body = {k: v for k, v in entry.items() if k != 'payload_digest'}
        entry['payload_digest'] = core.digest(body)
        self.path().write_text(json.dumps(entry))

    def test_full_binding_invalidates_each_input_and_repository(self):
        from getzilla.language_quality.cache import cache_key
        self.assertEqual(self.cache.write(self.key, observation()), 'written')
        value, status = self.cache.read(self.key)
        self.assertEqual((value['reported_status'], status), ('PASS', 'hit-unverified'))
        for field, value in binding().items():
            changed = binding()
            changed[field] = value + ['changed'] if isinstance(value, list) else {**value, 'cpus': 1} if isinstance(value, dict) else value + 1 if isinstance(value, int) else value + '-changed'
            with self.subTest(field=field):
                self.assertIsNone(self.cache.read(cache_key(changed))[0])
        missing = binding()
        del missing['executor_identity']
        with self.assertRaises(ValueError):
            cache_key(missing)
        with tempfile.TemporaryDirectory() as other:
            from getzilla.language_quality.cache import ShadowCache
            self.assertIsNone(ShadowCache(Path(other), clock=lambda: self.now).read(self.key)[0])

    def test_tampered_authority_fields_and_malformed_entries_are_misses(self):
        self.cache.write(self.key, observation())
        original = json.loads(self.path().read_text())
        for field, value in (('enforcement', 'blocking'), ('execution_status', 'PASS'),
                             ('schema_version', 99), ('reported_status', 'ERROR'),
                             ('key_digest', '0' * 64), ('created_at', self.now + 1),
                             ('created_at', self.now - 90000), ('diagnostics', [{}])):
            entry = {**original, field: value}
            self.rewrite(entry)
            with self.subTest(field=field):
                self.assertIsNone(self.cache.read(self.key)[0])
        for raw in ('{', '{"schema_version":1,"schema_version":1}', 'x' * (256 * 1024 + 1)):
            self.path().write_text(raw)
            self.assertIsNone(self.cache.read(self.key)[0])
        self.rewrite(original)
        self.now += 90000
        self.assertIsNone(self.cache.read(self.key)[0])

    def test_storage_rejects_symlink_hardlink_fifo_and_unsafe_permissions(self):
        self.cache.write(self.key, observation())
        target = self.root / 'unrelated'
        target.write_text('must stay unchanged')
        for kind in ('symlink', 'hardlink', 'fifo', 'permissions'):
            self.path().unlink(missing_ok=True)
            if kind == 'symlink':
                self.path().symlink_to(target)
            elif kind == 'hardlink':
                os.link(target, self.path())
            elif kind == 'fifo':
                os.mkfifo(self.path())
            else:
                self.path().write_text('{}')
                self.path().chmod(0o666)
            with self.subTest(kind=kind):
                self.assertIsNone(self.cache.read(self.key)[0])
                self.assertNotEqual(self.cache.write(self.key, observation()), 'written')
                self.assertEqual(target.read_text(), 'must stay unchanged')
        self.path().unlink()
        self.path().parent.chmod(0o777)
        self.assertIsNone(self.cache.read(self.key)[0])
        self.assertNotEqual(self.cache.write(self.key, observation()), 'written')
        self.path().parent.chmod(0o700)
        self.path().parent.rmdir()
        self.path().parent.symlink_to(self.root, target_is_directory=True)
        self.assertIsNone(self.cache.read(self.key)[0])
        self.assertNotEqual(self.cache.write(self.key, observation()), 'written')

    def test_eviction_enforces_entry_and_total_byte_bounds(self):
        from getzilla.language_quality.cache import cache_key
        with patch('getzilla.language_quality.cache.MAX_ENTRIES', 2), \
             patch('getzilla.language_quality.cache.MAX_TOTAL_BYTES', 4096):
            for count in range(4):
                self.now += 1
                key = cache_key({**binding(), 'tool_version': str(count)})
                self.assertEqual(self.cache.write(key, observation()), 'written')
            entries = list(self.path().parent.glob('*.json'))
            self.assertLessEqual(len(entries), 2)
            self.assertLessEqual(sum(p.stat().st_size for p in entries), 4096)
            self.assertIsNone(self.cache.read(cache_key({**binding(), 'tool_version': '0'}))[0])
            self.assertIsNotNone(self.cache.read(cache_key({**binding(), 'tool_version': '3'}))[0])
        one_entry_limit = max(p.stat().st_size for p in entries) + 32
        with patch('getzilla.language_quality.cache.MAX_TOTAL_BYTES', one_entry_limit):
            key = cache_key({**binding(), 'tool_version': 'byte-limit'})
            self.assertEqual(self.cache.write(key, observation()), 'written')
            remaining = list(self.path().parent.glob('*.json'))
            self.assertEqual(len(remaining), 1)
            self.assertLessEqual(sum(p.stat().st_size for p in remaining), one_entry_limit)
        with patch('getzilla.language_quality.cache.MAX_TOTAL_BYTES', 64):
            self.assertEqual(self.cache.write(self.key, observation()), 'write-error')


class FixtureExecutor:
    def __init__(self):
        self.calls = 0
        self.identity = 'fixture:immutable-image'

    def cache_identity(self, root, *, cancellation=None):
        return self.identity

    def execute(self, root, package, files, argv, **kwargs):
        self.calls += 1
        payload = [{'filePath': '/workspace/app.js', 'messages': [], 'errorCount': 0,
                    'warningCount': 0, 'fatalErrorCount': 0}]
        return Execution('COMPLETED', ToolOutput(0, json.dumps(payload), ''), identity=self.identity)


@unittest.skipUnless(os.name == 'posix', 'registry snapshot requires POSIX')
class CacheRegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / '.getzilla/config').mkdir(parents=True)
        (self.root / 'app.js').write_text('const answer=42;')
        (self.root / 'eslint.config.js').write_text('export default [];')
        self.section = {'sandbox': {'image': 'fixture@sha256:' + 'a' * 64},
                        'tools': {'eslint': {'launcher': ['/opt/eslint'], 'version': '9.0.0'}}}
        self.backend = FixtureExecutor()
        for target, value in (('inventory', ('app.js', 'eslint.config.js')), ('git_head', 'b' * 40),
                              ('changed_file_statuses', [{'path': 'app.js', 'status': 'M', 'source': 'range:' + 'c' * 40}])):
            p = patch('getzilla.language_quality.core.' + target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def run_gate(self, **kwargs):
        (self.root / '.getzilla/config/policy.json').write_text(json.dumps({'language_quality_gates': self.section}))
        return next(r for r in core.run_registry(self.root, 'c' * 40, executor=self.backend, **kwargs) if r['tool_id'] == 'eslint')

    def test_hit_is_unverified_observation_and_never_fresh_execution(self):
        fresh = self.run_gate()
        hit = self.run_gate()
        self.assertEqual(fresh['execution_status'], 'PASS')
        self.assertEqual(hit['execution_status'], 'CACHED_UNVERIFIED', hit)
        self.assertEqual(self.backend.calls, 1)
        self.assertTrue(hit['cache_hit'])
        self.assertFalse(hit['execution_performed'])
        self.assertEqual(hit['evidence_kind'], 'cached-unverified')
        self.assertEqual(hit['cached_observation']['reported_status'], 'PASS')
        self.assertEqual(hit['cached_observation']['claimed_source_evidence_digest'], fresh['evidence_digest'])
        self.assertIsNone(hit['execution_fingerprint'])
        self.assertIsNone(hit['executor_identity'])
        self.assertEqual(core.project_checks([hit]), [])
        forged = {**hit, 'enforcement': 'blocking', 'execution_status': 'PASS'}
        self.assertEqual(core.project_checks([forged])[0]['status'], 'fail')

    def test_blocking_and_off_bypass_cache_completely(self):
        from getzilla.language_quality.cache import ShadowCache
        for changes in ({'enforcement': 'blocking'}, {'cache': 'off'}):
            with self.subTest(changes=changes), \
                 patch.object(ShadowCache, 'read', side_effect=AssertionError('cache read bypassed')) , \
                 patch.object(ShadowCache, 'write', side_effect=AssertionError('cache write bypassed')):
                self.section = {**self.section, 'enforcement': 'shadow', 'cache': 'shadow', **changes}
                first = self.run_gate()
                second = self.run_gate()
                self.assertEqual((first['execution_status'], second['execution_status']), ('PASS', 'PASS'))
                self.assertFalse(second['cache_hit'])

    def test_dirty_content_image_change_cancellation_and_cache_io_do_not_reuse(self):
        from getzilla.language_quality.cache import ShadowCache
        self.run_gate()
        (self.root / 'app.js').write_text('const answer=43;')
        self.assertEqual(self.run_gate()['execution_status'], 'PASS')
        self.backend.identity = 'fixture:new-immutable-image'
        self.assertEqual(self.run_gate()['execution_status'], 'PASS')
        self.assertEqual(self.run_gate(cancellation=lambda: True)['execution_status'], 'CANCELLED')
        with patch.object(ShadowCache, 'read', return_value=(None, 'miss-invalid')), \
             patch.object(ShadowCache, 'write', return_value='write-error'):
            result = self.run_gate()
            self.assertEqual(result['execution_status'], 'PASS')
            self.assertEqual(result['cache_write_status'], 'write-error')

    def test_forged_disk_pass_stays_unverified_and_source_race_cannot_reuse(self):
        from getzilla.language_quality.cache import ShadowCache
        self.run_gate()
        path = next((self.root / '.getzilla/runtime/lqg/cache-v1').glob('*.json'))
        entry = json.loads(path.read_text())
        entry['reported_status'] = 'PASS'
        entry['summary'] = 'forged clean result'
        entry['payload_digest'] = core.digest({k: v for k, v in entry.items() if k != 'payload_digest'})
        path.write_text(json.dumps(entry))
        hit = self.run_gate()
        self.assertEqual(hit['execution_status'], 'CACHED_UNVERIFIED')
        self.assertEqual(hit['cached_observation']['summary'], 'forged clean result')
        original = ShadowCache.read
        def race(cache, key):
            result = original(cache, key)
            (self.root / 'app.js').write_text('changed during cache lookup')
            return result
        with patch.object(ShadowCache, 'read', race):
            result = self.run_gate()
        self.assertEqual(result['execution_status'], 'ERROR')
        self.assertFalse(result['cache_hit'])


if __name__ == '__main__':
    unittest.main()
