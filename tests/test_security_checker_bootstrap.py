"""Inactive checker import boundary; no operator rollout is implied."""
from pathlib import Path
import ast
import copy
from dataclasses import replace
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class CheckerAcquisitionArchitectureTests(unittest.TestCase):
    SOURCES = ('.getzilla/getzilla/security_acquisition.py',
               '.getzilla/getzilla/security_license_acquisition.py',
               '.getzilla/getzilla/security_osv_snapshot.py')

    def test_only_optional_acquisition_modules_own_declared_public_endpoints(self):
        from getzilla.architecture import load_architecture
        from getzilla.architecture_fitness import _owner_for_path
        snapshot = load_architecture(ROOT)
        owner = next((node for node in snapshot.system['nodes']
                      if node['id'] == 'NODE-OPTIONAL-SECURITY-ACQUISITION'), None)
        self.assertIsNotNone(owner)
        self.assertEqual(set(owner['repository_paths']), set(self.SOURCES))
        self.assertEqual(owner['runtime']['network'], 'declared_egress')
        for source in self.SOURCES:
            self.assertEqual(_owner_for_path(snapshot, source)['id'], owner['id'])
        for identifier, network in (('NODE-LOCAL-ROUTE-POLICY', 'none'),
                                    ('NODE-LOCAL-VERIFIER', 'local_only')):
            self.assertEqual(next(node for node in snapshot.system['nodes']
                                  if node['id'] == identifier)['runtime']['network'], network)
        edges = [edge for edge in snapshot.system['edges'] if edge['from'] == owner['id']]
        self.assertEqual({edge['to'] for edge in edges}, {
            'NODE-OSV-API', 'NODE-OSV-ADVISORY-BUCKET', 'NODE-GITHUB',
            'NODE-CISA-SECURITY-FEED', 'NODE-EPSS-SECURITY-FEED', 'NODE-PYPI-REGISTRY'})
        for edge in edges:
            self.assertEqual((edge['protocol'], edge['authentication']), ('https', 'none'))
            self.assertEqual(edge['failure_behavior']['max_retries'], 0)
            self.assertEqual(edge['failure_behavior']['timeout_ms'],
                             60000 if edge['to'] == 'NODE-OSV-API' else 10000)

    def test_actual_sources_need_their_narrow_https_edges(self):
        from getzilla.architecture import load_architecture
        from getzilla import architecture_fitness as fitness
        snapshot = load_architecture(ROOT)
        fixture = 'tests/test_security_license_acquisition.py'
        paths = (*self.SOURCES, fixture)
        trees = {path: ast.parse((ROOT / path).read_bytes(), filename=path) for path in paths}
        diff = SimpleNamespace(artifacts=tuple(SimpleNamespace(path=path, status='modified') for path in paths))
        inventory = SimpleNamespace(root=ROOT, tree=trees.__getitem__)
        with mock.patch.object(fitness, '_repository_paths', return_value=paths):
            result = fitness._network_clients(snapshot, diff, inventory)
            self.assertEqual(result.status, 'pass', result.findings)
            changed = copy.deepcopy(snapshot.system)
            changed['edges'] = [edge for edge in changed['edges']
                                if edge['from'] != 'NODE-OPTIONAL-SECURITY-ACQUISITION']
            denied = fitness._network_clients(replace(snapshot, system=changed), diff, inventory)
        self.assertEqual(denied.status, 'fail')
        self.assertTrue(all(any(path in finding for finding in denied.findings) for path in self.SOURCES))
        self.assertFalse(any(fixture in finding for finding in denied.findings))


class CheckerBootstrapTests(unittest.TestCase):
    def test_imports_do_not_contact_network_or_execute_processes(self):
        code = '''
import importlib, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / '.getzilla'))
def refuse(event, args):
    if event in {'socket.connect', 'socket.getaddrinfo', 'urllib.Request', 'subprocess.Popen'}:
        raise RuntimeError('unexpected import side effect: ' + event)
sys.addaudithook(refuse)
for name in ('security_osv_snapshot', 'security_data', 'security_acquisition',
             'security_artifacts', 'security_cli', 'security_deliveries',
             'security_intelligence', 'security_inventory', 'security_license_acquisition',
             'security_license_texts', 'security_licenses', 'security_tools', 'expanded_security'):
    importlib.import_module('getzilla.' + name)
print('checker imports completed without network or process execution')
'''
        result = subprocess.run([sys.executable, '-I', '-c', code, str(ROOT)],
                                capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('imports completed without network or process execution', result.stdout)
