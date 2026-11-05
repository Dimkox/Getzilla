import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'factory/src'))

from factory.tests.public_fixture_startup import observe_fixture_startup
from factory.tests.test_landing_provider import clock, landing_input, profile
from getzilla_factory.landing_provider import FixedCommandLandingProvider, LandingNormalizationRequest


class PublicFixtureStartupTests(unittest.TestCase):
    def _request(self):
        configured = profile()
        provider = FixedCommandLandingProvider(configured, clock=clock())
        requests = []

        class RequestCaptured(Exception):
            pass

        def capture(request_bytes):
            requests.append(request_bytes)
            raise RequestCaptured()

        with patch.object(provider, '_run', side_effect=capture), self.assertRaises(RequestCaptured):
            provider.normalize(LandingNormalizationRequest(landing_input(), configured.profile_digest),
                               lambda: b'same semantic request')
        self.assertEqual(len(requests), 1)
        return configured, requests[0]

    @unittest.skipUnless(os.name == 'posix', 'canonical executable fixture requires POSIX shebang support')
    def test_canonical_startup_is_observed_before_environment_clear(self):
        configured, request_bytes = self._request()
        actual_popen = subprocess.Popen

        def start(command, **kwargs):
            self.assertEqual(kwargs.get('env'), {})
            return actual_popen(command, **kwargs)

        with patch('subprocess.Popen', side_effect=start):
            observed = observe_fixture_startup(Path(configured.executable), request_bytes)
        # This direct Core test reaches the existing native CI core-tests.log.
        # It does not depend on nested Factory exception-message serialization.
        print('public-fixture-startup ' + json.dumps(observed, sort_keys=True), flush=True)
        self.assertEqual(set(observed), {'cases', 'canonical_body_exact', 'resources_removed'})
        self.assertTrue(observed['canonical_body_exact'])
        self.assertTrue(observed['resources_removed'])
        self.assertEqual([row['case'] for row in observed['cases']],
                         ['exact-direct', 'diagnostic-direct', 'diagnostic-after-startup-clear'])
        for row in observed['cases']:
            with self.subTest(case=row['case']):
                self.assertTrue(row['reaped'])
                self.assertFalse(row['timed_out'])
                self.assertEqual(row['returncode'], 0, row)
                self.assertEqual(row['guard'], 'other')
        self.assertEqual(len({row['stdout_sha256'] for row in observed['cases']}), 1)

    @unittest.skipUnless(os.name == 'posix', 'canonical executable fixture requires POSIX shebang support')
    def test_noncanonical_request_keeps_guard32_and_value_free_facts(self):
        configured, request_bytes = self._request()
        observed = observe_fixture_startup(Path(configured.executable), request_bytes + b' ')
        self.assertEqual([row['returncode'] for row in observed['cases']], [32, 32, 32])
        self.assertEqual([row['guard'] for row in observed['cases']], ['32', '32', '32'])
        for row in observed['cases'][1:]:
            self.assertEqual(row['guard_facts'][-1], {
                'canonical_request': False, 'locale_admitted': True,
                'unexpected_environment_names': [],
            })
        self.assertNotIn(request_bytes.decode(), json.dumps(observed))

    @unittest.skipUnless(os.name == 'posix', 'canonical executable fixture requires POSIX shebang support')
    def test_start_failure_is_reported_without_exception_values(self):
        configured, request_bytes = self._request()
        with patch('subprocess.Popen', side_effect=PermissionError('public-exception-marker')):
            try:
                observed = observe_fixture_startup(Path(configured.executable), request_bytes)
            except OSError:
                self.fail('public fixture startup failure escaped without a closed observation')
        self.assertEqual([row['start_error'] for row in observed['cases']], ['os_error'] * 3)
        self.assertEqual([row['returncode'] for row in observed['cases']], [None] * 3)
        self.assertNotIn('public-exception-marker', json.dumps(observed))
