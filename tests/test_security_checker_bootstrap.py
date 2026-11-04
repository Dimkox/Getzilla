"""Inactive checker import boundary; no operator rollout is implied."""
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


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
