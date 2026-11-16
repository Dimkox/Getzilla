"""Optional bounded GET observation, with explicit per-request worker ownership."""
import os
from pathlib import Path
import selectors
import signal
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The same installed file is the fixed one-shot worker, never candidate code.
if __name__ == '__main__' and not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = 'adaptive_trust_ci'

from .security_bundle import BundleError, GithubSource, ObservedState, bounded_json, digest, exact_sha
from .models import canonical_json


class ObservationError(ValueError):
    pass


def _wire_size_ok(response_bytes, total_bytes):
    return response_bytes <= 1048576 and total_bytes <= 4194304


def _suite_matches(run, expected):
    return type(run.get('check_suite_id')) is int and run['check_suite_id'] > 0 and run['check_suite_id'] == expected


def _check_time(clock, deadline):
    if clock() > deadline:
        raise ObservationError('observation-deadline')


def _read_response(opener, url, headers, deadline, clock, maximum):
    """Worker reader. Parent containment also bounds blocking DNS/buffered reads."""
    _check_time(clock, deadline)
    remaining = deadline - clock()
    if remaining <= 0:
        raise ObservationError('observation-deadline')
    request = urllib.request.Request(url, headers={**headers, 'Accept-Encoding': 'identity'}, method='GET')
    with opener.open(request, timeout=min(5, remaining)) as response:
        _check_time(clock, deadline)
        if not 200 <= response.status < 300:
            raise ObservationError('provider-status')
        if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
            raise ObservationError('response-encoding')
        blocks, length = [], 0
        while True:
            _check_time(clock, deadline)
            remaining = deadline - clock()
            if remaining <= 0:
                raise ObservationError('observation-deadline')
            # Standard urllib returns HTTPResponse with fp.raw._sock while open.
            # Missing/closed handles are not evidence of a hard deadline: the
            # parent still owns and kills the entire worker on its absolute limit.
            sock = getattr(getattr(getattr(response, 'fp', None), 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(min(5, remaining))
            block = response.read(min(65536, maximum - length + 1))
            _check_time(clock, deadline)  # Includes EOF after a blocking read.
            if not isinstance(block, bytes):
                raise ObservationError('response-type')
            length += len(block)
            if length > maximum:
                raise ObservationError('response-size')
            if not block:
                break
            blocks.append(block)
        _check_time(clock, deadline)
        value = bounded_json(b''.join(blocks), maximum=maximum)
        _check_time(clock, deadline)
        return response.status, canonical_json(value), length


def _run_owned(command, payload, deadline):
    """Bounded IPC; signal only the owned unreaped leader/group, then reap."""
    if os.name != 'posix' or len(payload) > 65536 or deadline - time.monotonic() <= 0.2:
        raise ObservationError('worker-boundary-unavailable')
    proc = None
    streams = []
    output, error = bytearray(), bytearray()
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        streams = [proc.stdin, proc.stdout, proc.stderr]
        work_deadline = deadline - 0.15  # Reserve the request's final interval for kill/reap.
        with selectors.DefaultSelector() as selector:
            for stream, name, events in ((proc.stdin, 'input', selectors.EVENT_WRITE),
                                         (proc.stdout, 'output', selectors.EVENT_READ),
                                         (proc.stderr, 'error', selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, events, name)
            sent = 0
            while selector.get_map():
                remaining = work_deadline - time.monotonic()
                if remaining <= 0:
                    raise ObservationError('worker-deadline')
                for key, _ in selector.select(remaining):
                    stream, name = key.fileobj, key.data
                    try:
                        if name == 'input':
                            sent += os.write(stream.fileno(), payload[sent:sent + 65536])
                            if sent == len(payload):
                                selector.unregister(stream)
                                stream.close()
                        else:
                            data = os.read(stream.fileno(), 65536)
                            target, maximum = (output, 1048576 + 8) if name == 'output' else (error, 256)
                            if len(target) + len(data) > maximum:
                                raise ObservationError('worker-output-limit')
                            target.extend(data)
                            if not data:
                                selector.unregister(stream)
                    except BlockingIOError:
                        continue
            remaining = work_deadline - time.monotonic()
            if remaining <= 0:
                raise ObservationError('worker-deadline')
            code = proc.wait(timeout=remaining)
            if code != 0 or error:
                raise ObservationError('provider-worker-refused')
            if time.monotonic() > deadline:
                raise ObservationError('worker-deadline')
            return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ObservationError('provider-worker-unavailable') from exc
    finally:
        try:
            if proc is not None and proc.returncode is None:
                # No poll/wait has released this owned PID before required signals.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as exc:
                    raise ObservationError('worker-cleanup-uncertain') from exc
        finally:
            for stream in streams:
                if stream is not None:
                    stream.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ObservationError('redirect-refused')


class BoundedGetTransport:
    """Enforce bytes on the wire before JSON, including all final rereads."""
    def __init__(self, *, clock=time.monotonic):
        self.clock, self.deadline = clock, clock() + 20
        self.calls = self.raw_bytes = 0

    def _exchange(self, url, headers, deadline, maximum):
        payload = canonical_json({'url': url, 'headers': headers,
                                  'remaining_ns': int((deadline - self.clock()) * 1000000000), 'maximum': maximum})
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--get-worker']
        output = _run_owned(command, payload, deadline)
        if len(output) < 8:
            raise ObservationError('worker-framing')
        status, raw_bytes = struct.unpack('!II', output[:8])
        if not 200 <= status < 300 or raw_bytes > maximum:
            raise ObservationError('worker-framing')
        return status, output[8:], raw_bytes

    def request(self, method, url, headers, body=None):
        parsed = urllib.parse.urlsplit(url)
        if (method != 'GET' or body is not None or parsed.scheme != 'https' or parsed.netloc != 'api.github.com'
                or parsed.fragment or parsed.username or not parsed.path.startswith('/repos/') or len(url) > 2048):
            raise ObservationError('request-scope')
        started = self.clock()
        request_deadline = min(self.deadline, started + 5)
        remaining = request_deadline - started
        if self.calls >= 14 or remaining <= 0:
            raise ObservationError('observation-limit')
        self.calls += 1
        try:
            maximum = min(1048576, 4194304 - self.raw_bytes)
            if maximum <= 0:
                raise ObservationError('response-size')
            status, encoded, raw_bytes = self._exchange(url, headers, request_deadline, maximum)
            _check_time(self.clock, request_deadline)
            self.raw_bytes += raw_bytes
            if not _wire_size_ok(raw_bytes, self.raw_bytes):
                raise ObservationError('response-size')
            value = bounded_json(encoded, maximum=1048576)
            _check_time(self.clock, request_deadline)
            return status, value
        except (OSError, ValueError, urllib.error.URLError, BundleError) as exc:
            if isinstance(exc, ObservationError):
                raise
            raise ObservationError('provider-response-unavailable') from exc


def _worker_main():
    """One fixed GET. No user code, provider effects, descendants or diagnostics."""
    try:
        request = bounded_json(sys.stdin.buffer.read(65537), maximum=65536)
        if type(request) is not dict or set(request) != {'url', 'headers', 'remaining_ns', 'maximum'}:
            raise ObservationError('worker-input')
        parsed = urllib.parse.urlsplit(request['url'])
        if (parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or parsed.fragment or parsed.username or
                not parsed.path.startswith('/repos/') or len(request['url']) > 2048):
            raise ObservationError('request-scope')
        if (type(request['headers']) is not dict or len(request['headers']) > 64 or
                any(type(k) is not str or type(v) is not str or len(k) > 128 or len(v) > 4096 or
                    '\r' in k + v or '\n' in k + v for k, v in request['headers'].items()) or
                type(request['remaining_ns']) is not int or not 0 < request['remaining_ns'] <= 5000000000 or
                type(request['maximum']) is not int or not 0 < request['maximum'] <= 1048576):
            raise ObservationError('worker-input')
        def no_children(event, args):
            if event in {'subprocess.Popen', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'os.posix_spawnp', 'os.system'}:
                raise ObservationError('worker-descendant-refused')
        sys.addaudithook(no_children)
        deadline = time.monotonic() + request['remaining_ns'] / 1000000000
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        status, encoded, raw_bytes = _read_response(opener, request['url'], request['headers'], deadline,
                                                   time.monotonic, request['maximum'])
        _check_time(time.monotonic, deadline)
        sys.stdout.buffer.write(struct.pack('!II', status, raw_bytes) + encoded)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        sys.stderr.write('get-worker-refused\n')
        return 1


def observe(client, authority, selector, *, deadline=None):
    """Read the entire pinned producer graph and recheck current PR/run scope."""
    if (not isinstance(selector, GithubSource) or client.api_url != 'https://api.github.com'
            or type(client.transport) is not BoundedGetTransport):
        raise ObservationError('observer-unconfigured')
    if deadline is not None:
        client.transport.deadline = min(client.transport.deadline, deadline)
    policy = authority.as_policy()
    jobs_required = policy.required_jobs
    if (not 1 <= len(jobs_required) <= 100 or len(set(jobs_required)) != len(jobs_required)
            or any(type(name) is not str or not 0 < len(name) <= 160 for name in jobs_required)):
        raise ObservationError('producer-jobs-unconfigured')
    if selector.repository != authority.repository or selector.repository_id != authority.repository_id:
        raise ObservationError('repository-mismatch')
    for value in (authority.runner_sha, authority.runner_tree_sha, authority.checker_sha,
                  authority.checker_tree_sha, authority.workflow_blob_sha):
        exact_sha(value)
    if (not authority.workflow_path.startswith('.github/workflows/') or '..' in authority.workflow_path.split('/')
            or any(char not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-' for char in authority.workflow_path)
            or not authority.branch or authority.target_branch != 'main'):
        raise ObservationError('producer-pin-unconfigured')
    def get(path):
        value = client._request('GET', path)
        if type(value) is not dict:
            raise ObservationError('provider-shape')
        return value
    def require(condition):
        if not condition:
            raise ObservationError('provider-identity-or-completeness')
    source_root, runner_root = '/repos/' + authority.repository, '/repos/' + authority.runner_repository
    repo = get(source_root)
    require(repo.get('id') == authority.repository_id and repo.get('full_name') == authority.repository)
    def pr_scope(pr):
        return (pr['number'], pr['state'], pr['head']['sha'], pr['base']['sha'], pr['base']['ref'],
                pr['head']['repo']['id'], pr['base']['repo']['id'], pr['head']['ref'])
    try:
        pr = get(f'{source_root}/pulls/{selector.pr_number}')
        scope = pr_scope(pr)
        require(scope[:7] == (selector.pr_number, 'open', selector.head_sha, selector.base_sha,
                             'main', authority.repository_id, authority.repository_id) and scope[7] != 'main' and bool(scope[7]))
        for repository, sha, tree in ((authority.repository, selector.head_sha, selector.tree_sha),
                                     (authority.repository, authority.checker_sha, authority.checker_tree_sha),
                                     (authority.runner_repository, authority.runner_sha, authority.runner_tree_sha)):
            commit = get(f'/repos/{repository}/git/commits/{sha}')
            require(commit['sha'] == sha and commit['tree']['sha'] == tree)
        def latest_run():
            current = get(f'{runner_root}/actions/workflows/{authority.workflow_id}/runs?branch={urllib.parse.quote(authority.branch, safe="")}&per_page=1')
            require(type(current.get('total_count')) is int and current['total_count'] >= 1 and
                    len(current['workflow_runs']) == 1 and current['workflow_runs'][0]['id'] == selector.run_id and
                    current['workflow_runs'][0]['run_attempt'] == selector.run_attempt)
            return current['workflow_runs'][0]
        latest = latest_run()
        attempt = get(f'{runner_root}/actions/runs/{selector.run_id}/attempts/{selector.run_attempt}')
        expected = {'id': selector.run_id, 'run_attempt': selector.run_attempt, 'workflow_id': authority.workflow_id,
                    'event': authority.event, 'head_sha': authority.runner_sha, 'head_branch': authority.branch,
                    'status': 'completed', 'conclusion': 'success'}
        def run_valid(run):
            return (all(run.get(key) == value for key, value in expected.items()) and
                    run.get('path') in (authority.workflow_path, authority.workflow_path + '@' + authority.branch,
                                        authority.workflow_path + '@' + authority.runner_sha) and
                    all(run[key]['id'] == authority.runner_repository_id and run[key]['full_name'] == authority.runner_repository
                        for key in ('repository', 'head_repository')))
        require(run_valid(latest) and run_valid(attempt) and _suite_matches(latest, attempt['check_suite_id']))
        jobs = get(f'{runner_root}/actions/runs/{selector.run_id}/attempts/{selector.run_attempt}/jobs?per_page=100')
        values = jobs.get('jobs')
        require(type(jobs.get('total_count')) is int and type(values) is list and
                jobs['total_count'] == len(values) == len(jobs_required) and
                sorted(job.get('name', '') for job in values) == sorted(jobs_required) and
                all(type(job.get('id')) is int and job['id'] > 0 and job.get('run_id') == selector.run_id and
                    job.get('head_sha') == authority.runner_sha and job.get('status') == 'completed' and
                    job.get('conclusion') == 'success' for job in values))
        workflow = get(f'{runner_root}/actions/workflows/{authority.workflow_id}')
        require(workflow['id'] == authority.workflow_id and workflow['path'] == authority.workflow_path and workflow['state'] == 'active')
        suite = get(f"{runner_root}/check-suites/{attempt['check_suite_id']}")
        require(suite['id'] == attempt['check_suite_id'] and suite['app']['id'] == authority.producer_app_id and
                suite['head_sha'] == authority.runner_sha and suite['repository']['id'] == authority.runner_repository_id and
                suite['status'] == 'completed' and suite['conclusion'] == 'success')
        blob = get(f'{runner_root}/contents/{authority.workflow_path}?ref={authority.runner_sha}')
        require(blob['type'] == 'file' and blob['path'] == authority.workflow_path and blob['sha'] == authority.workflow_blob_sha)
        current = latest_run()
        require(run_valid(current) and _suite_matches(current, attempt['check_suite_id']))
        require(pr_scope(get(f'{source_root}/pulls/{selector.pr_number}')) == scope)
        final = get(f'{runner_root}/actions/runs/{selector.run_id}')
        require(run_valid(final) and _suite_matches(final, attempt['check_suite_id']))
        return ObservedState('github', digest(selector.as_dict()), True, policy.authority_digest,
                             tuple(sorted(jobs_required)))
    except (KeyError, TypeError, IndexError) as exc:
        raise ObservationError('provider-shape') from exc


if __name__ == '__main__':
    raise SystemExit(_worker_main() if sys.argv[1:] == ['--get-worker'] else 1)
