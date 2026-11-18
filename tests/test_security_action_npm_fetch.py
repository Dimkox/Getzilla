"""Default npm acquisition uses original official bytes, never an RT authority."""
from datetime import datetime, timezone, timedelta
import importlib.util
import unittest

from tests import test_security_action_npm as owned

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


class NpmFetchTests(unittest.TestCase):
    setUp = owned.NpmSourceTests.setUp
    world = owned.NpmSourceTests.world

    def adapter(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_action_npm_fetch'), 'missing hosted npm source acquisition')
        from getzilla import security_action_npm_fetch
        return security_action_npm_fetch

    def test_fresh_exact_sources_are_acquired_and_cache_does_not_renew_clock(self):
        npm, source, expected, metadata = self.world()
        acquire = self.adapter()
        raw = (self.root / source['path']).read_bytes()
        calls = []
        def fetch(url, *, maximum):
            calls.append(url)
            self.assertEqual(url, source['url'])
            self.assertLessEqual(len(raw), maximum)
            return raw
        first = acquire.acquire_sources({source['url']: expected}, self.root, fetch=fetch, now=NOW)
        self.assertEqual(first['gaps'], [], first)
        self.assertEqual(len(calls), 1)
        second = acquire.acquire_sources({source['url']: expected}, self.root,
                                         fetch=lambda *a, **k: self.fail('unexpected cache renewal'), now=NOW + timedelta(hours=1))
        self.assertEqual(second['sources'][source['url']]['acquired_at'], first['sources'][source['url']]['acquired_at'])
        self.assertEqual(second['gaps'], [])

    def test_legacy_lock_gets_strong_official_metadata_and_missing_sha512_refuses(self):
        npm, source, expected, metadata = self.world(sha1=True)
        acquire = self.adapter()
        raw = (self.root / source['path']).read_bytes()
        import json
        def fetch(url, *, maximum):
            return raw if url.endswith('.tgz') else json.dumps(metadata).encode()
        report = acquire.acquire_sources({source['url']: expected}, self.root, fetch=fetch, now=NOW)
        self.assertEqual(report['gaps'], [], report)
        self.assertEqual(len(report['responses']), 2)
        selected = report['sources'][source['url']]
        self.assertIsNotNone(selected['strong_metadata'])
        self.assertEqual(len(npm.verify_source(self.root, selected, expected, now=NOW)['components']), 1)
