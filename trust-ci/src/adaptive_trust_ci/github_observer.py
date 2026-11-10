"""Optional bounded GET observation. No publication or final-write capability."""
import time
import urllib.error
import urllib.parse
import urllib.request

from .security_bundle import BundleError, GithubSource, ObservedState, bounded_json, digest, exact_sha


class ObservationError(ValueError):
    pass


def _wire_size_ok(response_bytes, total_bytes):
    return response_bytes <= 1048576 and total_bytes <= 4194304


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ObservationError('redirect-refused')


class BoundedGetTransport:
    """Enforce bytes on the wire before JSON, including all final rereads."""
    def __init__(self, *, opener=None, clock=time.monotonic):
        self.opener = opener or urllib.request.build_opener(_NoRedirect())
        self.clock, self.deadline = clock, clock() + 20
        self.calls = self.raw_bytes = 0

    def request(self, method, url, headers, body=None):
        parsed = urllib.parse.urlsplit(url)
        if (method != 'GET' or body is not None or parsed.scheme != 'https' or parsed.netloc != 'api.github.com'
                or parsed.fragment or parsed.username or not parsed.path.startswith('/repos/') or len(url) > 2048):
            raise ObservationError('request-scope')
        remaining = self.deadline - self.clock()
        if self.calls >= 14 or remaining <= 0:
            raise ObservationError('observation-limit')
        self.calls += 1
        try:
            with self.opener.open(urllib.request.Request(url, headers=headers, method='GET'),
                                  timeout=min(5, remaining)) as response:
                if not 200 <= response.status < 300:
                    raise ObservationError('provider-status')
                if response.headers.get('Content-Encoding', 'identity').lower() != 'identity':
                    raise ObservationError('response-encoding')
                blocks, length = [], 0
                while True:
                    if self.clock() >= self.deadline:
                        raise ObservationError('observation-deadline')
                    limit = min(1048576 - length, 4194304 - self.raw_bytes)
                    block = response.read(min(65536, limit + 1))
                    if not isinstance(block, bytes):
                        raise ObservationError('response-type')
                    length += len(block)
                    self.raw_bytes += len(block)
                    if not _wire_size_ok(length, self.raw_bytes):
                        raise ObservationError('response-size')
                    if not block:
                        break
                    blocks.append(block)
                return response.status, bounded_json(b''.join(blocks), maximum=1048576)
        except (OSError, ValueError, urllib.error.URLError, BundleError) as exc:
            if isinstance(exc, ObservationError):
                raise
            raise ObservationError('provider-response-unavailable') from exc


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
        current = get(f'{runner_root}/actions/workflows/{authority.workflow_id}/runs?branch={urllib.parse.quote(authority.branch, safe="")}&per_page=1')
        require(type(current.get('total_count')) is int and current['total_count'] >= 1 and
                len(current['workflow_runs']) == 1 and current['workflow_runs'][0]['id'] == selector.run_id and
                current['workflow_runs'][0]['run_attempt'] == selector.run_attempt)
        latest = get(f'{runner_root}/actions/runs/{selector.run_id}')
        attempt = get(f'{runner_root}/actions/runs/{selector.run_id}/attempts/{selector.run_attempt}')
        expected = {'id': selector.run_id, 'run_attempt': selector.run_attempt, 'workflow_id': authority.workflow_id,
                    'event': authority.event, 'head_sha': authority.runner_sha, 'head_branch': authority.branch,
                    'path': authority.workflow_path, 'status': 'completed', 'conclusion': 'success'}
        def run_valid(run):
            return (all(run.get(key) == value for key, value in expected.items()) and
                    all(run[key]['id'] == authority.runner_repository_id and run[key]['full_name'] == authority.runner_repository
                        for key in ('repository', 'head_repository')))
        require(run_valid(latest) and run_valid(attempt) and latest['check_suite_id'] == attempt['check_suite_id'])
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
        require(pr_scope(get(f'{source_root}/pulls/{selector.pr_number}')) == scope)
        require(run_valid(get(f'{runner_root}/actions/runs/{selector.run_id}')))
        return ObservedState('github', digest(selector.as_dict()), True, policy.authority_digest,
                             tuple(sorted(jobs_required)))
    except (KeyError, TypeError, IndexError) as exc:
        raise ObservationError('provider-shape') from exc
