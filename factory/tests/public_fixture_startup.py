"""Public test-only observation of canonical fixture process startup."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


_ENTRY = '''
def _public_fixture_audit(event, args):
    if event.startswith('socket.') or event == 'urllib.Request':
        raise RuntimeError('public_fixture_network_forbidden')
sys.addaudithook(_public_fixture_audit)
sys.stderr.write('PUBLIC_ENTRY ' + json.dumps({
    'environment_names': sorted(os.environ),
    'isolated': bool(sys.flags.isolated),
    'utf8_mode': bool(sys.flags.utf8_mode),
}, sort_keys=True) + '\\n')
sys.stderr.flush()
'''
_GUARD = '''    sys.stderr.write('PUBLIC_GUARD ' + json.dumps({
        'canonical_request': raw_request == canonical_request,
        'unexpected_environment_names': sorted(runtime_environment_names - allowed_environment_names),
        'locale_admitted': locale_admitted,
    }, sort_keys=True) + '\\n')
    sys.stderr.flush()
    raise SystemExit(32)'''


def observe_fixture_startup(executable, request_bytes):
    """Observe only the known public normal-mode fixture; never live execution."""
    executable = Path(executable)
    canonical = Path(__file__).parent / 'fixtures/landing_provider_fixture.py'
    header, _, body = executable.read_bytes().partition(b'\n')
    expected_header = b'#!' + os.fsencode(Path(sys.executable).resolve()) + b' -I'
    if header != expected_header or body != canonical.read_bytes().partition(b'\n')[2]:
        raise AssertionError('public startup fixture binding changed')
    # The direct case keeps the canonical body exact. The paired derivative adds
    # no module imports and records only public names and boolean guard facts.
    text = body.decode('utf-8')
    if text.count('def emit(value):') != 1 or text.count('    raise SystemExit(32)') != 1:
        raise AssertionError('public startup diagnostic insertion changed')
    diagnostic = text.replace('def emit(value):', _ENTRY + '\ndef emit(value):').replace(
        '    raise SystemExit(32)', _GUARD)
    bootstrap = "import os,runpy,sys;os.environ.clear();sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
    rows = []
    with tempfile.TemporaryDirectory(prefix='public-startup-', dir=executable.parent) as directory:
        derivative = Path(directory) / 'diagnostic.py'
        derivative.write_bytes(header + b'\n' + diagnostic.encode('utf-8'))
        derivative.chmod(0o755)
        commands = (
            ('exact-direct', [str(executable), '--mode=normal']),
            ('diagnostic-direct', [str(derivative), '--mode=normal']),
            ('diagnostic-after-startup-clear', [str(Path(sys.executable).resolve()), '-I', '-c',
                                               bootstrap, str(derivative), '--mode=normal']),
        )
        for name, command in commands:
            try:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env={}, shell=False,
                                           start_new_session=True, close_fds=True)
            except OSError:
                rows.append({'case': name, 'returncode': None, 'guard': 'other',
                             'start_error': 'os_error', 'child_started': False,
                             'timed_out': False, 'reaped': True, 'stderr_public': '',
                             'stderr_truncated': False, 'guard_facts': [],
                             'stdout_sha256': hashlib.sha256(b'').hexdigest()})
                continue
            timed_out = False
            try:
                stdout, stderr = process.communicate(request_bytes, timeout=2)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=2)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            # Normal-mode source is fixed and finite. Reports retain only bounded
            # stderr from this public fixture/interpreter, never its request/body.
            if len(stdout) > 262_144 or len(stderr) > 65_536:
                raise AssertionError('public startup observation exceeded fixture output bound')
            guard = {31: '31', 32: '32', 33: '33'}.get(
                process.returncode, 'other')
            facts = []
            for line in stderr[:4096].splitlines():
                if line.startswith((b'PUBLIC_ENTRY ', b'PUBLIC_GUARD ')):
                    facts.append(json.loads(line.split(b' ', 1)[1]))
            rows.append({'case': name, 'returncode': process.returncode, 'guard': guard,
                         'start_error': None, 'child_started': True,
                         'timed_out': timed_out, 'reaped': process.poll() is not None,
                         'stderr_public': stderr[:4096].decode('utf-8', errors='replace'),
                         'stderr_truncated': len(stderr) > 4096, 'guard_facts': facts,
                         'stdout_sha256': hashlib.sha256(stdout).hexdigest()})
    return {'cases': rows, 'canonical_body_exact': True,
            'resources_removed': not Path(directory).exists()}
