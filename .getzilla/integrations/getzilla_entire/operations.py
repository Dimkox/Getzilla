"""Explicit, scoped Entire operations. Provider display checks never authorize merge."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from getzilla.git_platforms import parse_remote
from getzilla.state import has_valid_approval
from .client import EntireClient, EntireError, Repository, SHA, ULID, reject_git_overrides
from .journal import RequestJournal


def assess_checks(value: object, expected_head: str) -> dict:
    """Conservative display of the provider snapshot, explicitly without CI authority."""
    reasons = []
    if not isinstance(value, dict):
        value = {}
    if not SHA.fullmatch(expected_head) or value.get('head_sha') != expected_head:
        reasons.append('head_mismatch_or_unknown')
    if value.get('mergeable') is not True or value.get('conflict_status') != 'clean':
        reasons.append('mergeability_blocked_or_unknown')
    if value.get('comparison_status') != 'available' or type(value.get('behind_by')) is not int or value['behind_by'] != 0:
        reasons.append('base_comparison_stale_or_unknown')
    checks = value.get('checks')
    runs = checks.get('runs') if isinstance(checks, dict) else None
    if (not isinstance(checks, dict) or checks.get('availability') != 'available'
            or not isinstance(runs, list) or not runs or len(runs) > 1000
            or any(not isinstance(run, dict) or run.get('status') != 'completed'
                   or run.get('conclusion') != 'success' for run in runs)):
        reasons.append('checks_unavailable_empty_or_not_successful')
    gates = value.get('gates')
    if not isinstance(gates, list) or not gates or len(gates) > 1000:
        reasons.append('gates_unknown')
        gates = []
    required_checks = False
    for gate in gates:
        if not isinstance(gate, dict) or type(gate.get('blocking')) is not bool:
            reasons.append('gate_schema_unknown')
            continue
        if gate['blocking']:
            required_checks |= gate.get('gate_type') == 'checks'
            if (gate.get('status') != 'passed' or gate.get('state') != 'evaluated'
                    or gate.get('head_sha') != expected_head or gate.get('evaluated_at_sha') != expected_head
                    or gate.get('stale_reason')):
                reasons.append('required_gate_not_fresh_and_passed')
    if not required_checks:
        reasons.append('required_checks_gate_missing')
    return {'provider_preflight': 'passed' if not reasons else 'blocked', 'reasons': sorted(set(reasons)),
            'expected_head': expected_head, 'trusted_ci_verified': False, 'merge_supported': False,
            'notice': 'Entire check names and app_name do not identify a trusted CI producer.'}


class EntireAdapter:
    def __init__(self, root: Path, client: EntireClient, *, authorize: Callable = has_valid_approval):
        self.root, self.client, self.authorize = root, client, authorize
        self.journal = RequestJournal(root)

    def git(self, *args: str, allowed_codes: tuple[int, ...] = (0,)):
        return self.client.run([self.client.executable('git'), '-c', 'protocol.allow=never',
                                '-c', 'protocol.entire.allow=always', *args], allowed_codes=allowed_codes)

    @staticmethod
    def text(result) -> str:
        try:
            return result.stdout.decode('utf-8').strip()
        except UnicodeError as exc:
            raise EntireError('invalid_output', 'Git returned unsupported output encoding') from exc

    def identity(self):
        values = self.text(self.git('config', '--get-all', 'remote.origin.url')).splitlines()
        identity = parse_remote(values[0]) if len(values) == 1 else None
        if identity is None or identity.provider != 'entire':
            raise EntireError('unsupported_remote', 'origin must contain one credential-free entire:// URL')
        return identity

    def branch(self, value: str) -> str:
        if not isinstance(value, str) or not value or len(value) > 255 or value.startswith('-'):
            raise EntireError('branch', 'a literal valid branch name is required')
        self.git('check-ref-format', '--branch', value)
        return value

    def local_head(self) -> str:
        head = self.text(self.git('rev-parse', '--verify', 'HEAD^{commit}'))
        if not SHA.fullmatch(head):
            raise EntireError('head', 'the local HEAD must identify a commit')
        return head

    def transport_guard(self, *, pushing: bool = False) -> None:
        rewrites = self.git('config', '--get-regexp', r'^url\..*\.(insteadof|pushinsteadof)$', allowed_codes=(0, 1))
        if rewrites.returncode == 0 and rewrites.stdout:
            raise EntireError('url_rewrite', 'Git URL rewrites are configured; the adapter cannot attest the exact destination')
        if pushing:
            value = self.text(self.git('rev-parse', '--git-path', 'hooks/pre-push'))
            hook = Path(value) if Path(value).is_absolute() else self.root / value
            if hook.exists() or hook.is_symlink():
                raise EntireError('hook_side_effects', 'an existing pre-push hook may publish session evidence or other refs; '
                                  'the adapter preserves it and refuses automatic push; use your reviewed manual push workflow')

    def remote_head(self, repository: Repository, branch: str) -> str:
        self.transport_guard()
        ref = f'refs/heads/{branch}'
        result = self.text(self.git('ls-remote', '--exit-code', '--refs', repository.identity.clone_url, ref))
        fields = result.split('\t')
        if len(fields) != 2 or fields[1] != ref or not SHA.fullmatch(fields[0]):
            raise EntireError('remote_head', 'Entire did not return one exact branch HEAD')
        return fields[0]

    def status(self) -> dict:
        repo = self.client.discover(self.identity())
        return {'provider': 'entire', 'mode': repo.identity.mode, 'repository': repo.identity.resource,
                'authoritative_forge': repo.identity.authoritative_forge, 'repo_id': repo.repo_id,
                'api_url': repo.api_url, 'visibility': repo.visibility, 'can_push': repo.can_push,
                'context': self.client.context, 'hosted_e2e_verified': False, 'merge_supported': False}

    def clone(self, url: str, target: Path) -> dict:
        identity = parse_remote(url)
        self.client.discover(identity)
        target = target.absolute()
        if target.exists() or target.is_symlink() or not target.parent.is_dir():
            raise EntireError('clone_target', 'clone target must be absent with an existing parent directory')
        self.transport_guard()
        self.git('clone', '--no-checkout', '--no-recurse-submodules', '--', identity.clone_url, str(target))
        return {'status': 'cloned', 'repository': identity.resource, 'target': str(target),
                'checkout': False, 'notice': 'No checkout, submodule initialization, hooks or session setup was requested.'}

    def fetch(self, branch: str) -> dict:
        branch = self.branch(branch)
        repo = self.client.discover(self.identity())
        self.transport_guard()
        self.git('fetch', '--no-tags', '--no-recurse-submodules', '--', repo.identity.clone_url,
                 f'refs/heads/{branch}:refs/remotes/origin/{branch}')
        return {'status': 'fetched', 'repository': repo.identity.resource, 'branch': branch,
                'upstream_verified': False}

    def guard_write(self, repo: Repository, head: str, scope: str, action: str, resource: str) -> None:
        reject_git_overrides()
        if not SHA.fullmatch(head) or self.local_head() != head or self.identity() != repo.identity:
            raise EntireError('stale_source', 'local HEAD or remote identity changed after approval')
        if repo.identity.mode == 'native' and repo.can_push is not True:
            raise EntireError('permission_unknown', 'native Entire write permission is absent or unknown')
        if not self.authorize(self.root, scope, action=action, resource=resource):
            raise EntireError('grant_required', f'an existing exact {scope} grant for {action} and this resource is required: {resource}')

    def write(self, request_id: str, intent: dict, operation: Callable) -> dict:
        previous = self.journal.begin(request_id, intent)
        if previous is not None:
            return {**previous, 'replayed': True}
        try:
            result = operation()
        except BaseException as exc:
            self.journal.finish(request_id, intent, 'unknown', {'reason': getattr(exc, 'code', 'interrupted')})
            raise
        self.journal.finish(request_id, intent, 'succeeded', result)
        return result

    def intent(self, repo: Repository, operation: str, branch: str, head: str, **extra) -> dict:
        return {'operation': operation, 'repository': repo.identity.resource, 'repo_id': repo.repo_id,
                'api_url': repo.api_url, 'context': self.client.context, 'branch': branch, 'head': head, **extra}

    def push(self, branch: str, expected_head: str, request_id: str) -> dict:
        branch = self.branch(branch)
        if not branch.startswith('getzilla/'):
            raise EntireError('branch_scope', 'automatic push is restricted to explicit getzilla/ task branches')
        repo = self.client.discover(self.identity())
        resource = repo.identity.resource + '#refs/heads/' + branch
        self.guard_write(repo, expected_head, 'production', 'git-push-branch', resource)
        self.transport_guard(pushing=True)
        def operation():
            self.guard_write(repo, expected_head, 'production', 'git-push-branch', resource)
            self.transport_guard(pushing=True)
            self.git('push', '--porcelain', '--no-follow-tags', '--recurse-submodules=no', '--',
                     repo.identity.clone_url, f'{expected_head}:refs/heads/{branch}')
            if self.remote_head(repo, branch) != expected_head:
                raise EntireError('remote_head_changed', 'push outcome requires reconciliation: remote HEAD differs')
            return {'status': 'pushed', 'repository': repo.identity.resource, 'branch': branch,
                    'head': expected_head, 'upstream_verified': False}
        return self.write(request_id, self.intent(repo, 'push', branch, expected_head), operation)

    @staticmethod
    def trail_summary(data: dict, repo: Repository, *, trail_id: str | None = None) -> dict:
        if (not isinstance(data, dict) or not ULID.fullmatch(str(data.get('id', '')))
                or not ULID.fullmatch(str(data.get('projectId', '')))
                or (trail_id is not None and data.get('id') != trail_id)
                or type(data.get('number')) is not int or data['number'] < 1
                or not isinstance(data.get('repoIds'), list) or repo.repo_id not in data['repoIds']
                or data.get('status') not in {'open', 'closed'}):
            raise EntireError('trail_schema', 'Entire returned an unsupported or mismatched project Trail')
        title = data.get('title', '')
        if not isinstance(title, str) or len(title) > 4096:
            raise EntireError('trail_schema', 'Entire Trail title exceeds supported limits')
        return {'trail_id': data['id'], 'trail_number': data['number'], 'status': data['status'], 'title': title}

    @staticmethod
    def trail_record(data: dict, repo: Repository, *, branch: str | None = None, trail_id: str | None = None) -> dict:
        summary = EntireAdapter.trail_summary(data, repo, trail_id=trail_id)
        if not isinstance(data.get('changes'), list) or len(data['changes']) > 1000:
            raise EntireError('trail_schema', 'Entire Trail detail has no supported repository changes')
        changes = [item for item in data['changes'] if isinstance(item, dict)
                   and item.get('repositoryId') == repo.repo_id and (branch is None or item.get('branch') == branch)]
        if len(changes) != 1:
            raise EntireError('trail_scope', 'Trail does not identify exactly one change for this repository and branch')
        change = changes[0]
        if (type(change.get('number')) is not int or change['number'] < 1
                or not isinstance(change.get('branch'), str) or not 1 <= len(change['branch']) <= 255
                or not ULID.fullmatch(str(change.get('id', '')))
                or change.get('status') not in {'open', 'closed', 'merged'}):
            raise EntireError('trail_schema', 'Entire change schema is unsupported')
        return {**summary, 'change_id': change['id'],
                'change_number': change['number'], 'branch': change['branch'], 'status': data['status'],
                'change_status': change['status']}

    def show(self, repo: Repository, trail_id: str) -> dict:
        if not ULID.fullmatch(trail_id):
            raise EntireError('trail_id', 'use the project Trail ULID, not a repository change number')
        data = self.client.command_json(['trail', 'show', trail_id, '--project', repo.project, '--json'])
        return self.trail_record(data, repo, trail_id=trail_id)

    def trails(self, trail_id: str | None = None) -> dict:
        repo = self.client.discover(self.identity())
        if trail_id:
            return self.show(repo, trail_id)
        items, token, seen = [], None, set()
        for _ in range(20):
            args = ['trail', 'list', '--project', repo.project, '--repo', repo.selector,
                    '--status', 'open', '--limit', '100', '--json']
            if token:
                args += ['--page-token', token]
            data = self.client.command_json(args)
            page = data.get('items')
            if not isinstance(page, list) or len(page) > 100:
                raise EntireError('trail_schema', 'Entire returned an unsupported Trail page')
            items.extend(self.trail_summary(item, repo) for item in page)
            token = data.get('nextPageToken')
            if token in (None, ''):
                return {'items': items, 'complete': True}
            if not isinstance(token, str) or len(token) > 2048 or token in seen:
                raise EntireError('pagination', 'Entire pagination is malformed or repeated')
            seen.add(token)
        raise EntireError('pagination_limit', 'Trail listing exceeded 20 pages; narrow the request before retrying')

    def create_trail(self, branch: str, base: str, title: str, body: str, expected_head: str, request_id: str) -> dict:
        branch, base = self.branch(branch), self.branch(base)
        if (not title.strip() or len(title) > 256 or len(body.encode('utf-8')) > 16384
                or '\0' in title or '\0' in body):
            raise EntireError('trail_input', 'Trail title/body is empty, oversized or contains a NUL')
        repo = self.client.discover(self.identity())
        resource = repo.identity.resource + '#trails/' + branch
        self.guard_write(repo, expected_head, 'external-write', 'external-write', resource)
        # --repo parsing drops the clone host. Refuse if context-based resolution picks another placement.
        unqualified = self.client.discover(repo.identity, qualified=False)
        if (unqualified.repo_id, unqualified.api_url) != (repo.repo_id, repo.api_url):
            raise EntireError('placement_mismatch', 'context-based Trail resolution differs from the selected clone placement')
        if self.remote_head(repo, branch) != expected_head:
            raise EntireError('unpublished_head', 'publish and verify the exact branch HEAD in a separate authorized push first')
        payload_digest = hashlib.sha256(json.dumps([base, title, body], ensure_ascii=True).encode()).hexdigest()
        def operation():
            self.guard_write(repo, expected_head, 'external-write', 'external-write', resource)
            if self.remote_head(repo, branch) != expected_head:
                raise EntireError('remote_head_changed', 'branch changed before Trail creation')
            data = self.client.command_json(['trail', 'create', '--project', repo.project, '--repo', repo.selector,
                                             '--branch', branch, '--base', base, '--branch-action', 'link',
                                             '--title=' + title, '--body=' + body,
                                             '--idempotency-key', request_id, '--json'])
            record = self.trail_record(data, repo, branch=branch)
            if record['status'] != 'open' or record['change_status'] != 'open' or self.remote_head(repo, branch) != expected_head:
                raise EntireError('creation_unverified', 'Trail creation requires reconciliation; the returned state or branch HEAD differs')
            return {**{key: value for key, value in record.items() if key != 'title'},
                    'status': 'created', 'repository': repo.identity.resource, 'head': expected_head,
                    'notice': 'Branch link is not an atomic HEAD CAS; merge remains unsupported.'}
        return self.write(request_id, self.intent(repo, 'trail-create', branch, expected_head,
                                                  payload_digest=payload_digest), operation)

    def checks(self, trail_id: str, expected_head: str) -> dict:
        if not SHA.fullmatch(expected_head):
            raise EntireError('head', 'provide the original reviewed commit SHA')
        repo = self.client.discover(self.identity())
        record = self.show(repo, trail_id)
        detail = self.client.change_detail(repo, record['change_number'])
        parent = detail.get('parent')
        if (detail.get('id') != record['change_id'] or detail.get('number') != record['change_number']
                or detail.get('branch') != record['branch'] or not isinstance(parent, dict)
                or parent.get('id') != trail_id):
            raise EntireError('change_mismatch', 'Entire change detail does not match this project Trail')
        result = assess_checks(detail.get('mergeability'), expected_head)
        actions = detail.get('actions', {})
        merge = actions.get('merge', {}) if isinstance(actions, dict) else {}
        if not isinstance(merge, dict) or merge.get('state') != 'enabled':
            result['provider_preflight'] = 'blocked'
            result['reasons'].append('merge_action_blocked_or_unknown')
        return {**record, **result}

    def merge(self, trail_id: str, expected_head: str) -> dict:
        raise EntireError('unsupported', 'Entire automated merge is unsupported: a trusted external CI producer '
                          'bound to this forge, repository, Trail and exact commit is not implemented; '
                          'Entire checks and local grants cannot substitute for that authority')
