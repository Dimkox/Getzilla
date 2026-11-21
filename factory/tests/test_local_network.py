"""Actual inherited Linux network controls; no external connection is made."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest


class LocalNetworkTests(unittest.TestCase):
    def test_guard_exists_before_a_local_profile_can_launch(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('getzilla_factory.local_network'))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux Landlock profile')
    def test_real_child_and_descendant_cannot_bypass_proxy_to_backend(self):
        listeners = [socket.socket() for _ in range(2)]
        for listener in listeners:
            listener.bind(('127.0.0.1', 0))
            listener.listen(2)
            self.addCleanup(listener.close)
        proxy, backend = [listener.getsockname()[1] for listener in listeners]
        child = '''
import errno,json,socket,subprocess,sys
from getzilla_factory.local_network import restrict_tcp_ports
restrict_tcp_ports((int(sys.argv[1]),))
def result(port):
 s=socket.socket(); s.settimeout(2); value=s.connect_ex(('127.0.0.1',port)); s.close(); return value
allowed=result(int(sys.argv[1])); denied=result(int(sys.argv[2]))
code="import socket,sys;s=socket.socket();s.settimeout(2);print(s.connect_ex(('127.0.0.1',int(sys.argv[1]))))"
descendant=subprocess.check_output([sys.executable,'-c',code,sys.argv[2]],timeout=3,text=True)
print(json.dumps({'proxy':allowed,'backend':denied,'descendant_backend':int(descendant)}))
assert allowed==0 and denied==errno.EACCES and int(descendant)==errno.EACCES
'''
        environment = {'PATH': os.defpath, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
        process = subprocess.run([sys.executable, '-c', child, str(proxy), str(backend)],
                                 env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout), {'proxy': 0, 'backend': 13, 'descendant_backend': 13})

    def test_invalid_ports_never_restrict_parent(self):
        from getzilla_factory.local_network import restrict_tcp_ports
        for ports in ((), (0,), (65536,), (True,), (11435, 11435), [11435], ('11435',)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                restrict_tcp_ports(ports)
