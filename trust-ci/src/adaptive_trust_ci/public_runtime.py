"""Explicit opt-in composition for the existing public API and worker.

Webhook bytes are wakeups only. Operator-protected files/pins and the one
canonical verifier decide publication. No merge authority or App activation.
"""
from __future__ import annotations

import asyncio
from contextlib import aclosing
from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import threading
import time
from types import SimpleNamespace

from .github import GitHubClient
from .github_observer import BoundedGetTransport
from .models import utc_now, require_repository
from .public_admission import Authority, Evidence, Selector, read_file
from .public_http import BoundedHTTPPort, issue_scoped_token
from .public_producer import load_checker, refresh_for_pr
from .public_process import ProducerCleanupUnknown, ProducerEnvelope
from .public_merge import BoundPublicVerifier, ObservationSessions
from .public_publisher import (Publication, PublicationJournal, PublisherConfig, PublicWakeupQueue,
                               publish, verify_webhook)
from .security_bundle import CONTROL_TOTAL, bounded_json, canonical_json


@dataclass(frozen=True)
class PublicConfig:
    publisher: PublisherConfig
    authority: Authority
    producer_key_path: Path
    app_key_path: Path
    journal_path: Path
    input_root: Path
    scope: str
    config_path: Path
    producer: dict


def _validate_authority(authority):
    from .security_bundle import SNAPSHOT_PROFILES
    if type(authority.snapshot_profile) is not str or authority.snapshot_profile not in SNAPSHOT_PROFILES:
        raise ValueError('public-authority-snapshot-profile')
    for name in ('repository', 'runner_repository'):
        if require_repository(getattr(authority, name)) != getattr(authority, name):
            raise ValueError('public-authority-repository')
    for name in ('repository_id', 'runner_repository_id', 'workflow_id', 'producer_app_id'):
        if type(getattr(authority, name)) is not int or getattr(authority, name) <= 0:
            raise ValueError('public-authority-identity')
    for name in ('runner_sha', 'runner_tree_sha', 'checker_sha', 'checker_tree_sha', 'workflow_blob_sha'):
        value = getattr(authority, name)
        if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
            raise ValueError('public-authority-source-pin')
    if (authority.event not in ('workflow_dispatch', 'repository_dispatch') or authority.target_branch != 'main'
            or not isinstance(authority.branch, str) or not 0 < len(authority.branch) <= 256
            or any(c.isspace() for c in authority.branch)
            or not isinstance(authority.workflow_path, str) or not authority.workflow_path.startswith('.github/workflows/')
            or '..' in authority.workflow_path.split('/')
            or re.fullmatch('[A-Za-z0-9_./-]{1,256}', authority.workflow_path) is None
            or not 1 <= len(authority.required_jobs) <= 100
            or any(not isinstance(name, str) or not 0 < len(name) <= 160 for name in authority.required_jobs)
            or len(set(authority.required_jobs)) != len(authority.required_jobs)):
        raise ValueError('public-authority-producer-profile')


def load_config(path, *, enabled=False):
    if enabled is not True:
        return None
    if path is None:
        raise ValueError('explicit-public-configuration-required')
    if not Path(path).is_absolute() or '..' in Path(path).parts:
        raise ValueError('absolute-public-configuration-required')
    raw = read_file(Path(path), 65536)
    value = bounded_json(raw, maximum=65536)
    fields = {'schema_version', 'publisher', 'authority', 'producer_key_path', 'app_key_path', 'journal_path', 'input_root', 'producer'}
    if type(value) is not dict or set(value) != fields or type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('public-configuration-shape')
    paths = {}
    for name in ('producer_key_path', 'app_key_path', 'journal_path', 'input_root'):
        text = value[name]
        if not isinstance(text, str) or not Path(text).is_absolute() or '..' in Path(text).parts or Path(text) == Path('/'):
            raise ValueError('public-configuration-path')
        paths[name] = Path(text)
    if (Path(path).is_relative_to(paths['input_root'])
            or any(paths[name].is_relative_to(paths['input_root'])
                   for name in ('app_key_path', 'producer_key_path', 'journal_path'))):
        raise ValueError('operator-authority-must-stay-outside-candidate-input-root')
    producer = value['producer']
    if type(producer) is not dict or set(producer) != {'snapshot_root', 'machine_key_path', 'image_artifacts', 'cgroup_root', 'dispatch'}:
        raise ValueError('public-producer-configuration')
    for name in ('snapshot_root', 'machine_key_path', 'image_artifacts', 'cgroup_root'):
        text = producer[name]
        if name == 'image_artifacts' and text is None:
            continue
        if (not isinstance(text, str) or not Path(text).is_absolute() or '..' in Path(text).parts
                or Path(text) == Path('/') or Path(text).is_relative_to(paths['input_root'])):
            raise ValueError('public-producer-path')
    if (any(path.is_relative_to(Path(producer['snapshot_root'])) for path in
            (Path(path), paths['app_key_path'], paths['producer_key_path'], paths['journal_path'], paths['input_root']))
            or Path(producer['machine_key_path']) in (paths['app_key_path'], paths['producer_key_path'])
            or Path(producer['machine_key_path']).is_relative_to(Path(producer['snapshot_root']))
            or producer['image_artifacts'] is not None
            and not Path(producer['image_artifacts']).is_relative_to(Path(producer['snapshot_root']))):
        raise ValueError('public-producer-key-or-snapshot-scope')
    dispatch = producer['dispatch']
    if type(dispatch) is not dict or type(dispatch.get('enabled')) is not bool:
        raise ValueError('public-dispatch-configuration')
    if dispatch['enabled']:
        if (set(dispatch) != {'enabled', 'app_id', 'installation_id', 'key_path'}
                or any(type(dispatch[name]) is not int or dispatch[name] <= 0 for name in ('app_id', 'installation_id'))
                or type(dispatch['key_path']) is not str or not Path(dispatch['key_path']).is_absolute()
                or '..' in Path(dispatch['key_path']).parts
                or any(Path(dispatch['key_path']).is_relative_to(root) for root in
                       (paths['input_root'], Path(producer['snapshot_root'])))):
            raise ValueError('public-dispatch-role')
    elif set(dispatch) != {'enabled'}:
        raise ValueError('public-dispatch-disabled-shape')
    publisher = PublisherConfig(**value['publisher'])
    authority = dict(value['authority'])
    if 'security_core' in authority or 'public_key_pem' in authority:
        raise ValueError('public-configuration-authority')
    if type(authority.get('required_jobs')) is not list:
        raise ValueError('public-producer-jobs-required')
    authority['required_jobs'] = tuple(authority['required_jobs'])
    authority = Authority(**authority, public_key_pem=b'')
    _validate_authority(authority)
    if dispatch['enabled'] and authority.event != 'workflow_dispatch':
        raise ValueError('automatic-dispatch-requires-workflow-dispatch-profile')
    if (authority.repository != publisher.repository or authority.repository_id != publisher.repository_id
            or authority.policy_digest != publisher.policy_digest):
        raise ValueError('public-configuration-policy-mismatch')
    return PublicConfig(publisher, authority, **paths, scope=hashlib.sha256(canonical_json(value)).hexdigest(),
                        config_path=Path(path), producer=producer)


def open_queue(config):
    journal = PublicationJournal(config.journal_path)  # Existing schema only, no implicit create/reset.
    queue = PublicWakeupQueue(journal, config.scope)
    queue.ready()
    return journal, queue


def initialize_journal(path):
    config = load_config(path, enabled=True)
    journal = (PublicationJournal(config.journal_path) if config.journal_path.exists()
               else PublicationJournal.create(config.journal_path))
    PublicWakeupQueue(journal, config.scope).initialize()


class PublicIngress:
    def __init__(self, config, queue, secret):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('public-webhook-secret-unconfigured')
        self.config, self.queue, self.secret = config, queue, secret

    def accept(self, raw, signature, event, delivery):
        if not verify_webhook(raw, signature, self.secret):
            raise ValueError('public-webhook-authentication-refused')
        if event not in ('pull_request', 'workflow_run', 'check_run'):
            return {'accepted': False, 'reason': 'ignored-event'}
        if not isinstance(delivery, str) or re.fullmatch('[A-Za-z0-9-]{1,128}', delivery) is None:
            raise ValueError('public-webhook-delivery-required')
        value = bounded_json(raw, maximum=1048576)
        repo = value.get('repository')
        expected = self.config.publisher
        runner = getattr(self.config, 'authority', None)
        runner_event = (runner is not None and event == 'workflow_run' and type(repo) is dict
                        and repo.get('full_name') == runner.runner_repository
                        and type(repo.get('id')) is int and repo['id'] == runner.runner_repository_id)
        if (not runner_event and (type(repo) is not dict or repo.get('full_name') != expected.repository
                or type(repo.get('id')) is not int or repo['id'] != expected.repository_id)):
            raise ValueError('public-webhook-repository-mismatch')
        if event == 'pull_request':
            request = value.get('pull_request')
            targets = [request.get('number')] if type(request) is dict else []
        else:
            request = value.get(event)
            requests = request.get('pull_requests') if type(request) is dict else None
            if not isinstance(requests, list) or len(requests) > 100:
                raise ValueError('public-webhook-targets')
            targets = [item.get('number') if type(item) is dict else None for item in requests]
        if not targets and runner_event:
            targets = self.queue.blocked_targets()
        if not targets:
            return {'accepted': False, 'reason': 'no-pr-wakeup'}
        if any(type(pr) is not int or not 0 < pr <= 2147483647 for pr in targets):
            raise ValueError('public-webhook-targets')
        # All other input, including run/report/evidence/authority claims, is ignored.
        jobs = self.queue.enqueue(delivery, tuple(sorted(set(targets))))
        return {'accepted': True, 'created': len(jobs), 'job_ids': jobs}


async def receive_webhook(ingress, request, signature, event, delivery, *, maximum=1048576):
    if type(maximum) is not int or not 0 < maximum <= 1048576:
        raise ValueError('public-webhook-bound')
    raw = bytearray()
    async with asyncio.timeout(5), aclosing(request.stream()) as stream:
        async for chunk in stream:
            if type(chunk) is not bytes or len(raw) + len(chunk) > maximum:
                raise ValueError('public-webhook-body-bound')
            raw.extend(chunk)
    return ingress.accept(bytes(raw), signature, event, delivery)


def load_ingress(path, secret):
    config = load_config(path, enabled=True)
    _, queue = open_queue(config)
    return PublicIngress(config, queue, secret)


class PublicWorker:
    def __init__(self, config, queue, *, operation=None, journal=None, clock=time.monotonic, kill_switch_path=None):
        self.config, self.queue, self.journal = config, queue, journal
        self.operation = operation or self.publish_for_pr
        self.clock = clock
        self.stop_event = threading.Event()
        self.kill_switch_path = kill_switch_path
        self._pending_pr, self._pending_parts = None, None
        self._active_job = None

    @classmethod
    def load(cls, path):
        config = load_config(path, enabled=True)
        with ProducerEnvelope(config.producer['cgroup_root'], time.monotonic() + 5):
            pass
        journal, queue = open_queue(config)
        return cls(config, queue, journal=journal, kill_switch_path=Path(
            os.environ.get('TRUST_CI_KILL_SWITCH_PATH', '/run/adaptive-trust-ci/STOP')))

    def _stopped(self):
        return self.stop_event.is_set() or self.kill_switch_path is not None and self.kill_switch_path.exists()

    def _publication_clock(self):
        if self._stopped():
            raise ValueError('global-kill-switch-active')
        return utc_now()

    def _prepare_publication(self, pr):
        self._publication_clock()
        if type(pr) is not int or not 0 < pr <= 2147483647:
            raise ValueError('public-wakeup-target')
        self.queue.require_refresh_safe(self._active_job)
        prepared = refresh_for_pr(self.config, pr, clock=self.clock, before_sign=self._publication_clock)
        root = prepared.root
        record = bounded_json(read_file(root / 'record.json', CONTROL_TOTAL), maximum=CONTROL_TOTAL)
        if type(record) is not dict or set(record) != {'selector', 'evidence'}:
            raise ValueError('public-producer-record')
        selector = Selector(**record['selector'])
        selector.source()  # Closed source shape; still not authority.
        if (selector.repository != self.config.publisher.repository
                or selector.repository_id != self.config.publisher.repository_id or selector.pr_number != pr):
            raise ValueError('public-producer-target-mismatch')
        evidence = Evidence(**record['evidence'])
        authority = replace(self.config.authority, public_key_pem=read_file(self.config.producer_key_path, 65536),
                            security_core=load_checker(self.config.authority))
        authority.as_policy()
        holder = []
        def unissued():
            raise ValueError('public-token-not-issued')
        original = GitHubClient(token_provider=unissued, transport=BoundedGetTransport(clock=self.clock))
        def observe(deadline, maximum):
            if not holder:
                raise ValueError('public-token-not-issued')
            return GitHubClient(token=holder[0], transport=BoundedGetTransport(clock=self.clock))
        budget = ObservationSessions(original, observe, purpose='publisher')
        holder.append(issue_scoped_token(self.config.publisher, self.config.app_key_path, budget, now=self._publication_clock(), purpose='observer',
                                        observer_repository_id=authority.runner_repository_id))
        client = GitHubClient(token=holder[0], transport=BoundedGetTransport(clock=self.clock))
        verifier = BoundPublicVerifier(client, authority, evidence, candidate_root=root / 'candidate',
                                       snapshot_root=Path(self.config.producer['snapshot_root']), observations=budget, measurement=prepared.measurement)
        publication_client = []
        def factory(installation, request):
            if installation != self.config.publisher.installation_id or request != self.config.publisher.token_request():
                raise ValueError('public-token-scope-mismatch')
            if not publication_client:
                token = issue_scoped_token(self.config.publisher, self.config.app_key_path, budget,
                                           now=self._publication_clock(), purpose='publisher')
                publication_client.append(GitHubClient(token=token, transport=BoundedGetTransport(clock=self.clock)))
            return publication_client[0]
        return SimpleNamespace(selector=selector, verifier=verifier, client_factory=factory,
            request_port=BoundedHTTPPort(self.config.publisher.repository, clock=self.clock), clock=self._publication_clock)

    def publish_for_pr(self, pr):
        recovery = self._pending_parts is not None
        if recovery and self._pending_pr != pr:
            return Publication('blocked', 'prior-public-operation-unresolved')
        if recovery:
            parts = self._pending_parts
        else:
            try:
                parts = self._prepare_publication(pr)
            except ProducerCleanupUnknown:
                raise
            except (OSError, ValueError, TypeError, KeyError, RuntimeError):
                self.queue.require_refresh_safe(self._active_job)
                from .public_dispatch import request_producer
                return request_producer(self.config, pr, self.queue, guard=self._publication_clock)
        self._pending_pr, self._pending_parts = pr, parts
        result = publish(self.config.publisher, self.journal, parts.verifier, parts.selector,
                         client_factory=parts.client_factory, request_port=parts.request_port,
                         clock=parts.clock, enabled=True)
        if recovery and result.state == 'blocked':
            return Publication('unknown', 'prior-public-operation-unresolved', result.check_id)
        if result.state != 'unknown':
            self._pending_pr, self._pending_parts = None, None
        return result

    def run_once(self):
        if self._stopped():
            return None
        job = self.queue.claim()
        if job is None:
            return None
        key, pr = job
        self._active_job = key
        try:
            result = self.operation(pr)
            if type(result) is not Publication or result.state not in ('published', 'blocked', 'unknown'):
                result = Publication('unknown', 'public-operation-unconfirmed')
        except ProducerCleanupUnknown:
            result = Publication('unknown', 'producer-cleanup-unconfirmed')
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            result = Publication('blocked', 'public-input-unavailable')
        except BaseException:
            self.queue.finish(key, 'unknown', 'public-operation-interrupted')
            raise
        finally:
            self._active_job = None
        self.queue.finish(key, result.state, result.reason)
        return {'job_id': key, 'state': result.state, 'reason': result.reason}

    def run(self, *, once=False):
        while not self.stop_event.is_set():
            result = self.run_once()
            if once:
                return 0 if result is None or result['state'] == 'published' else 1
            if result is None:
                self.stop_event.wait(2)
        return 0
