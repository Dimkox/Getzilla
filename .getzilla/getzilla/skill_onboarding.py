"""Zero-effect interviews and explicit, canonically authorized local publication.

No native skill evaluation, process launch, dependency install or network operation
exists here. A successful copy does not activate or grant any tool capability.
"""
from __future__ import annotations

from pathlib import Path
import os

from . import fsx, state
from .component_state import BoundRoot, component_transaction, mode_matches, path_parts
from .continuity import has_task_context
from .policy import evaluate_pre_tool
from .publication_metadata import mark_publication_unknown
from .skill_preflight import (CATALOG_PATH, DESCRIPTOR, MAX_DESCRIPTOR_BYTES, MAX_SKILLS,
                              MAX_TOTAL_BYTES, SkillSnapshot, assess, canonical, digest, read_snapshot)
from .skill_preflight import native_contract


def interview(snapshot: SkillSnapshot, descriptor: bytes, catalog: bytes, *, requests=(), answers=None,
              existing=()) -> dict:
    assessment = assess(snapshot, descriptor, catalog, existing=existing)
    if type(requests) not in (list, tuple) or len(requests) > 32:
        raise ValueError('interview round limit')
    answers = {} if answers is None else answers
    constraints = dict(assessment.constraints)
    if (type(answers) is not dict or len(answers) > 32
            or any(key not in constraints or value != constraints[key] for key, value in answers.items())):
        raise ValueError('interview answers are not matching declared facts')
    declared = {(operation, resource) for operation, resource, _ in assessment.capabilities}
    outcomes = []
    for request in requests:
        if (type(request) is not dict or set(request) != {'operation', 'resource'}
                or any(type(value) is not str or len(value) > 240 for value in request.values())):
            raise ValueError('invalid interview action')
        outcome = 'DENIED_UNSUPPORTED_ACTION'
        if request['operation'] == 'read' and (request['operation'], request['resource']) in declared:
            outcome = 'SIMULATED_DECLARED_READ'
        outcomes.append(outcome)
    return {'schema_version': 1, 'assessment': assessment.to_dict(),
            'questions': sorted(constraints), 'unanswered': sorted(set(constraints) - set(answers)),
            'outcomes': outcomes, 'protected_calls': 0, 'approved': False,
            'native_isolation_qualified': False, 'mode': 'declarative-zero-effect'}


def _read(binding: BoundRoot, relative: str, limit: int) -> bytes:
    snapshot = binding.read(relative, limit=limit)
    if snapshot is None:
        raise ValueError('MISSING_SOURCE_METADATA')
    return snapshot.content


def _owner(root: Path, expected=None):
    route = state.require_route_owner(root)
    if not has_task_context(route) or route.get('workspace') != str(root.resolve()):
        raise ValueError('CANONICAL_TASK_REQUIRED')
    canonical = state.canonical_route(root, route['route_id'])
    state.require_route_owner(root, canonical)
    binding = tuple(canonical.get(key) for key in ('route_id', 'logical_task_id', 'authority_epoch', 'session_id'))
    if expected is not None and binding != expected:
        raise ValueError('STALE_TASK_AUTHORITY')
    if canonical.get('status') != 'routed' or canonical.get('context', {}).get('pending'):
        raise ValueError('TASK_CONTEXT_NOT_CURRENT')
    return binding


def installation_context(root, catalog, candidate_id):
    with BoundRoot(root) as binding:
        names = binding.files('.agents/skills', recursive=True)
    identifiers = sorted({name.split('/')[2] for name in names})
    if len(identifiers) > MAX_SKILLS:
        raise ValueError('EXISTING_SKILL_LIMIT')
    results = []
    for identifier in identifiers:
        # Inert retries are outside native discovery. A matching native ID is
        # still part of the real instruction context and cannot be skipped.
        relative = '.agents/skills/' + identifier
        with BoundRoot(root) as binding:
            metadata = binding.read(relative + '/' + DESCRIPTOR, limit=MAX_DESCRIPTOR_BYTES)
        if metadata is None:
            raise ValueError('PREFLIGHT_REFUSED: UNQUALIFIED_EXISTING_SKILL')
        snapshot = read_snapshot(root, relative)
        assessment = assess(snapshot, metadata.content, catalog)
        if assessment.verdict != 'allow':
            raise ValueError('PREFLIGHT_REFUSED: UNQUALIFIED_EXISTING_SKILL')
        results.append(assessment)
    return results


def install_external(root: Path, relative: str) -> dict:
    """Stage one explicit local intake outside every native skill discovery tree.

    Read the host catalog only from its fixed protected path. Canonical grants bind
    that catalog and every exact destination. Refuse unmodeled semantics even when
    a write grant exists. Publication is per-file durable, not a batch transaction;
    interrupted copies require explicit inspection, and existing different bytes refuse.
    """
    path_parts(relative)
    if relative.startswith(('.agents/', '.getzilla/', '.grok/', '.claude/', '.qwen/', '.gemini/')):
        raise ValueError('INTAKE_MUST_BE_SEPARATE_FROM_ACTIVE_CONTEXT')
    with state.task_transition(root):
        owner = _owner(root)
    snapshot = read_snapshot(root, relative)
    with BoundRoot(root) as binding:
        descriptor = _read(binding, relative + '/' + DESCRIPTOR, MAX_DESCRIPTOR_BYTES)
        catalog = _read(binding, CATALOG_PATH, MAX_TOTAL_BYTES)
    first = assess(snapshot, descriptor, catalog)
    if first.verdict != 'allow':
        raise ValueError('PREFLIGHT_REFUSED: ' + ','.join(first.reasons))
    if native_contract(dict(snapshot.files)['SKILL.md']) is None:
        raise ValueError('NATIVE_SKILL_FORMAT_REQUIRED')
    with state.task_transition(root):
        _owner(root, owner)
        existing = installation_context(root, catalog, first.skill_id)
    assessment = assess(snapshot, descriptor, catalog, existing=existing)
    trial = interview(snapshot, descriptor, catalog, existing=existing)
    if assessment.verdict != 'allow':
        raise ValueError('PREFLIGHT_REFUSED: ' + ','.join(assessment.reasons))
    for operation, resource, _ in assessment.capabilities:
        allowed, _reason = evaluate_pre_tool(root, {'tool_name': 'Read', 'tool_input': {'file_path': resource}})
        if operation != 'read' or not allowed:
            raise ValueError('CURRENT_POLICY_DENIED')
    native_destination = '.agents/skills/' + assessment.skill_id
    destination = '.getzilla/runtime/skill-intake/' + assessment.skill_id
    intent_path = '.getzilla/runtime/skill-publications/' + assessment.skill_id + '.json'
    payload = (*snapshot.files, (DESCRIPTOR, descriptor))

    def check_authority():
        _owner(root, owner)
        with BoundRoot(root) as binding:
            if _read(binding, CATALOG_PATH, MAX_TOTAL_BYTES) != catalog:
                raise ValueError('CATALOG_CHANGED')
            if _read(binding, relative + '/' + DESCRIPTOR, MAX_DESCRIPTOR_BYTES) != descriptor:
                raise ValueError('SOURCE_CHANGED')
        if read_snapshot(root, relative).digest != snapshot.digest:
            raise ValueError('SOURCE_CHANGED')
        current = installation_context(root, catalog, assessment.skill_id)
        current_assessment = assess(snapshot, descriptor, catalog, existing=current)
        if current_assessment.verdict != 'allow':
            raise ValueError('PREFLIGHT_REFUSED: CONTEXT_CHANGED')
        for operation, resource, _ in assessment.capabilities:
            allowed, _reason = evaluate_pre_tool(root, {'tool_name': 'Read', 'tool_input': {'file_path': resource}})
            if operation != 'read' or not allowed:
                raise ValueError('CURRENT_POLICY_DENIED')
        for name, _ in payload:
            if not state.has_valid_approval(root, 'protected-path', action='protected-path-write',
                                            resource=native_destination + '/' + name):
                raise ValueError('APPROVAL_REQUIRED')

    with state.task_transition(root):
        check_authority()
    with component_transaction(root) as transaction:
        diagnostic = transaction.read(intent_path, limit=4096)
        expected_record = {'schema_version': 1, 'status': 'complete', 'snapshot_digest': snapshot.digest,
                           'descriptor_digest': digest(descriptor)}
        if diagnostic is not None:
            if diagnostic.content != canonical(expected_record) or not mode_matches(diagnostic.mode, 0o600):
                raise ValueError('PUBLICATION_REQUIRES_INSPECTION')
        present = transaction.files(destination, recursive=True)
        allowed = {destination + '/' + name for name, _ in payload}
        if set(present) - allowed:
            raise ValueError('EXISTING_SKILL_CONFLICT')
        previous = {}
        for name, content in payload:
            target = destination + '/' + name
            current = transaction.read(target)
            if current is not None and (current.content != content or not mode_matches(current.mode, 0o644)):
                raise ValueError('EXISTING_SKILL_CONFLICT')
            previous[target] = current
        if diagnostic is None and present:
            # Unrecorded staged files do not establish a complete owned attempt.
            raise ValueError('PUBLICATION_REQUIRES_INSPECTION')
        pending = {**expected_record, 'status': 'incomplete'}
        transaction.write(intent_path, canonical(pending), 0o600, expected=diagnostic)
        pending_snapshot = transaction.read(intent_path, limit=4096)
        if pending_snapshot is None or pending_snapshot.content != canonical(pending) or not mode_matches(pending_snapshot.mode, 0o600):
            raise ValueError('PUBLICATION_CUSTODY_CHANGED')
        identities = {}
        for name, content in payload:
            target = destination + '/' + name
            with state.task_transition(root):
                check_authority()
                current = transaction.read(target)
                if current != previous[target]:
                    raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                if current is not None:
                    if current.content != content or not mode_matches(current.mode, 0o644):
                        raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                    identities[target] = current.identity[:2]
                    continue
                with transaction.binding.parent(target, create=True, before_write=check_authority) as (parent, basename, check):
                    # Create the inert target exclusively and write through its held
                    # descriptor. Never link or delete a later staged basename.
                    # A named replacement is retained and makes completion fail.
                    descriptor_fd = fsx.open_at(parent, basename, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                                | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
                    try:
                        identity = os.fstat(descriptor_fd)
                        identities[target] = (identity.st_dev, identity.st_ino)
                        remaining = memoryview(content)
                        while remaining:
                            written = os.write(descriptor_fd, remaining)
                            if written <= 0:
                                raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                            remaining = remaining[written:]
                        fsx.fchmod(descriptor_fd, 0o644)
                        os.fsync(descriptor_fd)
                    finally:
                        os.close(descriptor_fd)
                    fsx.fsync_dir(parent)
                    check()
                    transaction.check()
                    current = transaction.read(target)
                    if (current is None or current.content != content or not mode_matches(current.mode, 0o644)
                            or current.identity[:2] != identities[target]):
                        raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                    check_authority()
        with state.task_transition(root):
            check_authority()
            proof = {}
            for name, content in payload:
                target = destination + '/' + name
                current = transaction.read(target)
                if (current is None or current.content != content or not mode_matches(current.mode, 0o644)
                        or current.identity[:2] != identities[target]):
                    raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                proof[name] = {'sha256': current.sha256, 'mode': current.mode}
            if set(transaction.files(destination, recursive=True)) != allowed:
                raise ValueError('PUBLICATION_CUSTODY_CHANGED')
            try:
                transaction.write(intent_path, canonical(expected_record), 0o600, expected=pending_snapshot)
                completed = transaction.read(intent_path, limit=4096)
                if completed is None or completed.content != canonical(expected_record) or not mode_matches(completed.mode, 0o600):
                    raise ValueError('PUBLICATION_CUSTODY_CHANGED')
                for name, content in payload:
                    current = transaction.read(destination + '/' + name)
                    if (current is None or current.content != content or not mode_matches(current.mode, 0o644)
                            or current.identity[:2] != identities[destination + '/' + name]):
                        raise ValueError('PUBLICATION_CUSTODY_CHANGED')
            except BaseException as interrupted:
                # Completion can be interrupted after its write by SystemExit,
                # KeyboardInterrupt or another BaseException. Preserve that exact
                # exception while boundedly verifying the owned denial restoration.
                restored = False
                for _attempt in range(2):
                    try:
                        current_record = transaction.read(intent_path, limit=4096)
                        if current_record is None or not mode_matches(current_record.mode, 0o600):
                            break
                        if current_record.content == canonical(pending):
                            restored = True
                            break
                        if current_record.content != canonical(expected_record):
                            break  # Preserve foreign records; they are not ours to replace.
                        transaction.write(intent_path, canonical(pending), 0o600, expected=current_record)
                        observed = transaction.read(intent_path, limit=4096)
                        if (observed is not None and observed.content == canonical(pending)
                                and mode_matches(observed.mode, 0o600)):
                            restored = True
                            break
                    except BaseException:
                        # One fresh bounded observation also handles a lost
                        # restoration response. Never replace the original exit.
                        continue
                if not restored:
                    mark_publication_unknown(interrupted)
                raise
    return {'schema_version': 1, 'status': 'staged', 'destination': destination,
            'snapshot_digest': snapshot.digest, 'descriptor_digest': digest(descriptor),
            'materialized_digest': digest(canonical(proof)), 'files': proof,
            'assessment': assessment.to_dict(), 'interview': trial,
            'permissions_granted': False, 'activated': False, 'activation': 'unsupported', 'evidence_valid': False}
