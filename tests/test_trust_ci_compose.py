"""Production Compose separates the online image fetch from offline execution."""
import re
import unittest
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / 'trust-ci/compose.yaml'


def service(name):
    pattern = rf'^  {name}:\n((?:(?:    .*|)\n)*)'
    matches = re.findall(pattern, COMPOSE.read_text(), re.MULTILINE)
    if len(matches) != 1:
        raise AssertionError(f'expected one service {name}')
    return matches[0]


class RunnerLoaderComposeTests(unittest.TestCase):
    def test_online_fetch_has_no_engine_access(self):
        fetch = service('runner-fetch')
        self.assertIn('networks: [registry]', fetch)
        self.assertIn('command: ["fetch"]', fetch)
        for value in ('/api', 'DOCKER_HOST', 'docker.sock', 'executor'):
            self.assertNotIn(value, fetch)

    def test_offline_loader_waits_for_verified_input(self):
        loader = service('runner-loader')
        for value in ('network_mode: none', 'command: ["load"]', 'DOCKER_HOST: unix:///api/engine.sock',
                      'trust-ci-transfer:/var/lib/trust-ci-transfer:ro', 'runner-fetch:', 'service_completed_successfully'):
            self.assertIn(value, loader)
        self.assertNotIn('docker pull', loader)

    def test_daemon_has_only_an_internal_network_and_unix_listener(self):
        engine = service('docker-engine')
        for value in ('--host=unix:///api/engine.sock', 'networks:\n      - executor',
                      'trust-ci-transfer:/var/lib/trust-ci-transfer:ro'):
            self.assertIn(value, engine)
        self.assertRegex(COMPOSE.read_text(), r'  executor:\n    driver: bridge\n    internal: true\n')
        for value in ('2375', '2376', 'ports:', 'expose:', 'registry'):
            self.assertNotIn(value, engine)
