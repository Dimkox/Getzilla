"""Real local plaintext delivery; inert clients are not model/provider qualification."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/getzilla_context.py'


class ContextTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, *args, text=''):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *args], input=text,
                              capture_output=True, text=True, timeout=10)

    def test_plain_stdin_reaches_real_local_client_without_tools(self):
        client = self.root / 'client.py'
        client.write_text('import sys\nprint(sys.stdin.read(), end="")\n')
        text = 'Original task\nEvidence gaps OPEN\n[public.py:1-2]\ndef answer():\n    return 42\n'
        result = self.run_cli('deliver', '--transport', 'stdin', '--', sys.executable, str(client), text=text)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, text)
        self.assertFalse((self.root / '.getzilla/index').exists())

    def test_file_delivery_uses_private_ephemeral_file_and_cleans_it(self):
        client = self.root / 'client.py'
        observed = self.root / 'observed.json'
        client.write_text('import json,pathlib,stat,sys\np=pathlib.Path(sys.argv[1])\n'
                          'pathlib.Path(sys.argv[2]).write_text(json.dumps({"path":str(p),"mode":stat.S_IMODE(p.stat().st_mode),'
                          '"parent_mode":stat.S_IMODE(p.parent.stat().st_mode),"text":p.read_text()}))\n')
        scratch = self.root / 'runtime'
        result = self.run_cli('deliver', '--transport', 'file', '--scratch', str(scratch), '--',
                              sys.executable, str(client), '{context_file}', str(observed), text='task and code\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(observed.read_text())
        self.assertEqual(data['text'], 'task and code\n')
        self.assertEqual(data['mode'], 0o600)
        self.assertEqual(data['parent_mode'], 0o700)
        self.assertFalse(Path(data['path']).exists())

    def test_unsupported_transport_and_overflow_never_start_client(self):
        sentinel = self.root / 'started'
        command = [sys.executable, '-c', 'import pathlib,sys;pathlib.Path(sys.argv[1]).touch()', str(sentinel)]
        for options, text in ((['--transport', 'prompt'], 'x'), (['--transport', 'stdin'], 'x' * 262145)):
            result = self.run_cli('deliver', *options, '--', *command, text=text)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(sentinel.exists())
        self.assertIn('context_bytes_exceeded', result.stderr)

    def test_query_without_native_port_never_reads_source_or_claims_success(self):
        result = self.run_cli('query', '--root', str(self.root), '--query', 'answer')
        self.assertNotEqual(result.returncode, 0)
        response = json.loads(result.stdout)
        self.assertEqual(response['reason'], 'authority_unavailable')
        self.assertFalse((self.root / '.getzilla/index').exists())
