"""Working public fixture consumer of preflight and shared recovery, never a DEV adapter.

Initialization requires an explicitly empty owned directory. Fixed inert inputs and
recovery data remain there for inspection; this module never deletes any pathname.
The target effect changes a retained owned inode, not an atomic pathname exchange.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import stat
import time
import uuid

from . import fsx
from .component_state import BoundRoot
from .deploy_preflight import prepare_preflight, recheck_preflight, _strict_json
from .deploy_recovery import (CODES, SCHEMA, WORK_SECONDS, Intent, RecoveryError,
                              RecoverySession, canonical, identity, sha256)

REPORT = 'getzilla-deploy-recovery-report-v1'
PROFILE = 'getzilla-public-deploy-fixture-v1'
MARKER = 'public-fixture.json'
BEFORE = b'public fixture before\n'
AFTER = b'public fixture after\n'
OPERATOR = b'# Public inert placeholder. It is never imported or executed.\n'
POLICY = canonical({'secret_consumers': [{'script': 'deploy/operator.py',
                                         'secrets': ['fixture-selector-reference']}]})
EXTRA_CODES = frozenset({'ROOT_NOT_EMPTY', 'PROFILE_UNAVAILABLE', 'PROFILE_CHANGED',
                          'PREFLIGHT_BLOCKED', 'FIXTURE_INITIALIZED', 'FIXTURE_ONLY',
                          'FIXTURE_VERIFIED', 'FIXTURE_ROLLED_BACK', 'REVIEW_ONLY'})
NEXT = {
    'LEGACY_OWNER_UNKNOWN': 'coordinated_legacy_migration',
    'LEASE_BUSY': 'wait_for_shared_lease_then_recheck',
    'OUTCOME_UNKNOWN': 'qualified_outcome_inspection',
    'JOURNAL_INCOMPLETE': 'preserve_state_and_inspect_journal',
    'JOURNAL_INVALID': 'preserve_state_and_inspect_journal',
    'JOURNAL_IO': 'preserve_state_and_inspect_journal',
    'PROFILE_UNAVAILABLE': 'qualify_exact_real_adapter_or_initialize_empty_public_fixture',
    'PROFILE_CHANGED': 'review_current_fixture_inputs',
    'TARGET_CHANGED': 'inspect_target_without_overwrite',
}


def _report(state, code, *, stage='inspection', session=None, intent=None):
    safe = code if type(code) is str and code in CODES | EXTRA_CODES else 'INTERNAL_ERROR'
    journal = None
    if session is not None:
        try:
            journal = session.journal_sha256
        except BaseException:
            journal = None
            if state in {'fixture_verified', 'fixture_rolled_back', 'review_only'}:
                state, safe = 'unknown', 'JOURNAL_IO'
    return dict(schema_version=REPORT, profile='public_fixture_only', state=state,
                algorithm_revision=SCHEMA, stage=stage,
                attempt_sha256=sha256(session._generation.encode()) if session else None,
                source_binding_sha256=intent.binding_sha256 if intent else None,
                operator_identity_sha256=sha256(OPERATOR) if intent else None,
                policy_sha256=sha256(POLICY) if intent else None,
                journal_sha256=journal, package='matched' if intent else 'not_evaluated',
                registration='matched' if intent else 'not_evaluated',
                admission='fixture_only' if intent else 'unavailable',
                recovery=('unknown' if state == 'unknown' else
                          session.records[-1]['stage'] if session and session.records else 'unavailable'),
                provenance='unverified', connection='not_attempted', delivery='not_attempted',
                fixture_effect=('verified' if state == 'fixture_verified' else
                                'rolled_back' if state == 'fixture_rolled_back' else 'not_verified'),
                operational_grant=False, dispatch_permitted=False, dev_verified=False,
                missing_condition=NEXT.get(safe, 'review_exact_fixed_diagnostic'), diagnostics=[safe])


def _clock():
    now = time.monotonic()
    if type(now) not in (int, float) or not math.isfinite(now):
        raise RecoveryError('CLOCK_UNCERTAIN')
    return now


def _manifest(nonce):
    revision = {'label': 'public-fixture-v1', 'git': None}
    return canonical(dict(
        schema_version='getzilla-deploy-preflight-v1', project_id='public-fixture',
        operation='dev-delivery',
        operator=dict(path='deploy/operator.py', sha256=sha256(OPERATOR), mode=0o644, revision=revision),
        artifacts=[dict(path='public/application.txt', sha256=sha256(AFTER), mode=0o644),
                   dict(path='public/original.txt', sha256=sha256(BEFORE), mode=0o644)],
        artifact_revision=revision,
        target=dict(identity='fixture-' + nonce, destination_id='fixed-owned-file', transport='local-fixture'),
        credential_selector='fixture-selector-reference',
        recovery=dict(protocol_id='shared-mkdir-retained-lease', version='v1',
                      descriptor_sha256=sha256(canonical([SCHEMA, PROFILE])))))


class _Fixture:
    def __init__(self, root):
        self.started = _clock()
        self.deadline = self.started + WORK_SECONDS
        self.root, self.bound, self.marker = root, None, None

    def budget(self):
        now = _clock()
        if now < self.started:
            raise RecoveryError('CLOCK_UNCERTAIN')
        if now >= self.deadline:
            raise RecoveryError('BUDGET_EXCEEDED')

    def __enter__(self):
        if fsx.WINDOWS or not isinstance(self.root, Path):
            raise RecoveryError('MODE_UNSUPPORTED')
        self.budget()
        self.bound = BoundRoot(self.root)
        info = os.fstat(self.bound.handle)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            self.close()
            raise RecoveryError('ROOT_UNSAFE')
        return self

    def read(self, path):
        self.budget()
        self.bound.check()
        value = self.bound.read(path, limit=4096)
        self.budget()
        if value is None:
            raise RecoveryError('PROFILE_UNAVAILABLE')
        return value

    def load(self):
        marker = _strict_json(self.read(MARKER).content)
        if (type(marker) is not dict or set(marker) != {'schema_version', 'nonce', 'root_identity', 'target_identity'}
                or marker['schema_version'] != PROFILE or type(marker['nonce']) is not str
                or len(marker['nonce']) != 32 or any(c not in '0123456789abcdef' for c in marker['nonce'])
                or marker['root_identity'] != list(identity(os.fstat(self.bound.handle)))
                or type(marker['target_identity']) is not list or len(marker['target_identity']) != 3
                or any(type(i) is not int or i < 0 for i in marker['target_identity'])):
            raise RecoveryError('PROFILE_UNAVAILABLE')
        expected = {'deploy/operator.py': OPERATOR, 'public/application.txt': AFTER,
                    'public/original.txt': BEFORE, '.getzilla/config/project-policy.json': POLICY,
                    'fixture-manifest.json': _manifest(marker['nonce'])}
        for path, content in expected.items():
            if self.read(path).content != content:
                raise RecoveryError('PROFILE_CHANGED')
        self.marker = marker
        observed = prepare_preflight(self.root, 'fixture-manifest.json')
        self.recheck(observed)
        return observed

    def recheck(self, observed):
        self.budget()
        report = recheck_preflight(self.root, observed, 'fixture-manifest.json').to_dict()
        if report['package'] != 'matched' or report['registration'] != 'matched':
            raise RecoveryError('PREFLIGHT_BLOCKED')
        self.budget()

    def current(self):
        value = self.read('target/application.txt')
        if value.mode != 0o600 or list(value.identity[:3]) != self.marker['target_identity']:
            raise RecoveryError('TARGET_CHANGED')
        return sha256(value.content)

    def close(self):
        if self.bound is not None:
            bound, self.bound = self.bound, None
            bound.close()

    def __exit__(self, *_args):
        self.close()


def _create(parent, name, content, mode):
    descriptor = fsx.open_at(parent, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, mode)
    try:
        RecoverySession._write_all(descriptor, content)
        os.fsync(descriptor)
        return identity(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def initialize_fixture(root):
    """Only an explicitly empty owned root is initialized; no existing policy is changed."""
    try:
        with _Fixture(root) as fixture:
            if fsx.listdir(fixture.bound.handle):
                return _report('blocked', 'ROOT_NOT_EMPTY', stage='initialization')
            nonce = uuid.uuid4().hex
            directories = {}
            try:
                for name in ('deploy', 'public', 'target', '.getzilla'):
                    fixture.budget()
                    fsx.mkdir_at(fixture.bound.handle, name, 0o700)
                    directories[name] = fsx.open_dir_at(fixture.bound.handle, name, flags=os.O_CLOEXEC)
                fsx.mkdir_at(directories['.getzilla'], 'config', 0o700)
                directories['config'] = fsx.open_dir_at(directories['.getzilla'], 'config', flags=os.O_CLOEXEC)
                _create(directories['deploy'], 'operator.py', OPERATOR, 0o644)
                _create(directories['public'], 'application.txt', AFTER, 0o644)
                _create(directories['public'], 'original.txt', BEFORE, 0o644)
                target = _create(directories['target'], 'application.txt', BEFORE, 0o600)
                _create(directories['config'], 'project-policy.json', POLICY, 0o644)
                _create(fixture.bound.handle, 'fixture-manifest.json', _manifest(nonce), 0o644)
                marker = canonical(dict(schema_version=PROFILE, nonce=nonce,
                                        root_identity=list(identity(os.fstat(fixture.bound.handle))),
                                        target_identity=list(target)))
                # Published last. A partial initializer is never silently adopted.
                _create(fixture.bound.handle, MARKER, marker, 0o600)
                for descriptor in directories.values():
                    os.fsync(descriptor)
                os.fsync(fixture.bound.handle)
                fixture.budget()
            finally:
                for descriptor in directories.values():
                    os.close(descriptor)
        return _report('initialized', 'FIXTURE_INITIALIZED', stage='initialization')
    except BaseException as error:
        return _report('blocked', error.code if isinstance(error, RecoveryError) else 'INTERNAL_ERROR',
                       stage='initialization')


class _Target:
    """Fixed public target, held inode; no arbitrary destination or callback runner."""
    def __init__(self, fixture):
        self.fixture, self.directory, self.descriptor = fixture, None, None

    def __enter__(self):
        self.fixture.bound.check()
        self.directory = fsx.open_dir_at(self.fixture.bound.handle, 'target', flags=os.O_CLOEXEC)
        try:
            self.descriptor = fsx.open_at(self.directory, 'application.txt',
                                           os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            self.check()
            return self
        except BaseException:
            self.close()
            raise

    def check(self):
        self.fixture.budget()
        self.fixture.bound.check()
        opened = os.fstat(self.descriptor)
        named = fsx.lstat_at(self.directory, 'application.txt')
        if (identity(opened) != identity(named) or list(identity(opened)) != self.fixture.marker['target_identity']
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != os.getuid() or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size > 4096):
            raise RecoveryError('TARGET_CHANGED')

    def apply(self, expected, content):
        self.check()
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        if sha256(os.read(self.descriptor, 4097)) != expected:
            raise RecoveryError('TARGET_CHANGED')
        self.check()
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        RecoverySession._write_all(self.descriptor, content)
        os.ftruncate(self.descriptor, len(content))
        os.fsync(self.descriptor)
        self.check()

    def close(self):
        for name in ('descriptor', 'directory'):
            value = getattr(self, name)
            if value is not None:
                setattr(self, name, None)
                os.close(value)

    def __exit__(self, *_args):
        self.close()


def _consume(fixture, session, intent, action, observed, context):
    fixture.recheck(observed)
    session.begin(intent)
    current = fixture.current()
    plan = session.plan(current)
    if plan in {'inspect_unknown', 'inspect_target'}:
        raise RecoveryError('OUTCOME_UNKNOWN' if plan == 'inspect_unknown' else 'TARGET_CHANGED')
    with _Target(fixture) as target:
        if action == 'rollback' or plan in {'retry_rollback', 'verify_rollback', 'done_rollback'}:
            context['stage'] = 'rollback'
            if plan == 'done_rollback':
                return _report('fixture_rolled_back', 'FIXTURE_ROLLED_BACK',
                               stage='rollback', session=session, intent=intent)
            fixture.recheck(observed)
            if session.records[-1]['stage'] != 'rollback_pending' or plan == 'retry_rollback':
                session.advance('rollback_pending', current)
            if current == intent.after_sha256:
                target.apply(current, BEFORE)
            if fixture.current() != intent.before_sha256:
                raise RecoveryError('TARGET_CHANGED')
            fixture.recheck(observed)
            session.advance('rolled_back', intent.before_sha256)
            return _report('fixture_rolled_back', 'FIXTURE_ROLLED_BACK',
                           stage='rollback', session=session, intent=intent)
        context['stage'] = 'effect'
        if plan in {'apply', 'retry_effect'}:
            fixture.recheck(observed)
            session.advance('effect_pending', current)
            target.apply(intent.before_sha256, AFTER)
        current = fixture.current()  # independent descriptor-based readback
        if current != intent.after_sha256:
            raise RecoveryError('TARGET_CHANGED')
        context['stage'] = 'verification'
        fixture.recheck(observed)
        if plan != 'done':
            if session.records[-1]['stage'] == 'effect_pending':
                session.advance('applied', current)
            session.advance('verified', current)
        return _report('fixture_verified', 'FIXTURE_VERIFIED',
                       stage='verification', session=session, intent=intent)


def run_fixture(root, action='inspect'):
    """Concrete fixture consumer. Real DEV admission and delivery always stay false."""
    session, intent = None, None
    context = {'stage': 'preflight'}
    try:
        if type(action) is not str or action not in {'inspect', 'apply', 'recover', 'rollback'}:
            raise RecoveryError('INPUT_INVALID')
        with _Fixture(root) as fixture:
            observed = fixture.load()
            intent = Intent(sha256(('public-fixture:' + fixture.marker['nonce']).encode()),
                            observed.inputs_digest, sha256(BEFORE), sha256(AFTER))
            context['stage'] = 'lease'
            if action == 'inspect':
                try:
                    fsx.lstat_at(fixture.bound.handle, '.release.lock')
                except FileNotFoundError:
                    return _report('review_only', 'REVIEW_ONLY', intent=intent)
            with RecoverySession(root, create=action != 'inspect', writable=action != 'inspect',
                                 deadline=fixture.deadline) as session:
                fixture.budget()
                if action == 'inspect':
                    fixture.recheck(observed)
                    return _report('review_only', 'REVIEW_ONLY', stage='inspection', session=session, intent=intent)
                try:
                    return _consume(fixture, session, intent, action, observed, context)
                except BaseException:
                    if session.records and session.records[-1]['stage'] in {
                            'effect_pending', 'applied', 'rollback_pending'}:
                        try:
                            session.advance('unknown', None)
                        except BaseException:
                            context['journal_fault'] = True
                    raise
    except BaseException as error:
        code = error.code if isinstance(error, RecoveryError) else 'INTERNAL_ERROR'
        if context.get('journal_fault'):
            code = 'JOURNAL_IO'
        # No arbitrary error object, message, stdout or stderr is persisted.
        uncertain = (context['stage'] in {'effect', 'verification', 'rollback'}
                     or code in {'JOURNAL_INCOMPLETE', 'JOURNAL_INVALID', 'JOURNAL_IO',
                                 'FILE_CHANGED', 'LEASE_CHANGED'}
                     or session and session.records and session.records[-1]['stage'] in {
                         'effect_pending', 'applied', 'rollback_pending', 'unknown'})
        return _report('unknown' if uncertain else 'blocked', code, stage=context['stage'],
                       session=session, intent=None if code == 'PREFLIGHT_BLOCKED' else intent)
