"""Zero-effect interviews and explicit, canonically authorized local publication.

No native skill evaluation, process launch, dependency install or network operation
exists here. A successful copy does not activate or grant any tool capability.
"""
from __future__ import annotations

from pathlib import Path
import uuid

from . import fsx, state
from .component_state import BoundRoot, component_transaction, path_parts
from .continuity import has_task_context
from .policy import evaluate_pre_tool
from .skill_preflight import (CATALOG_PATH, DESCRIPTOR, MAX_DESCRIPTOR_BYTES, MAX_SKILLS,
                              MAX_TOTAL_BYTES, SkillSnapshot, assess, digest, read_snapshot)
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
        # The same ID is never overwritten. Identical retry is handled separately.
        if identifier == candidate_id:
            continue
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
    """Install one explicit local intake, never acquiring or executing its dependencies.

    Read the host catalog only from its fixed protected path. Canonical grants bind
    that catalog and every exact destination. Refuse unmodeled semantics even when
    a write grant exists. Publication is per-file durable, not a batch transaction;
    interrupted copies require explicit retry, and existing different bytes refuse.
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
    destination = '.agents/skills/' + assessment.skill_id
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
                                            resource=destination + '/' + name):
                raise ValueError('APPROVAL_REQUIRED')

    with state.task_transition(root):
        check_authority()
    with component_transaction(root) as transaction:
        present = transaction.files(destination, recursive=True)
        allowed = {destination + '/' + name for name, _ in payload}
        if set(present) - allowed:
            raise ValueError('EXISTING_SKILL_CONFLICT')
        for name, content in payload:
            current = transaction.read(destination + '/' + name)
            if current is not None and current.content != content:
                raise ValueError('EXISTING_SKILL_CONFLICT')
        for name, content in payload:
            target = destination + '/' + name
            if transaction.read(target) is not None:
                with state.task_transition(root):
                    check_authority()
                continue
            # Stage outside the grant's product-tree binding. An adjacent temporary
            # file would invalidate the exact canonical grant during publication.
            # Never relax grant binding to accommodate an internal temporary file.
            staging_root = '.getzilla/runtime/skill-staging'
            if len(transaction.files(staging_root)) >= 16:
                raise ValueError('INTERRUPTED_STAGING_LIMIT')
            staged = staging_root + '/' + uuid.uuid4().hex + '.tmp'
            transaction.binding.write(staged, content, 0o644, expected=None, before_publish=transaction.check)
            with state.task_transition(root):
                check_authority()
                with transaction.binding.parent(staged) as (stage_parent, stage_name, stage_check):
                    with transaction.binding.parent(target, create=True, before_write=check_authority) as (parent, basename, check):
                        stage_check()
                        check()
                        transaction.check()
                        if transaction.read(target) is not None:
                            raise ValueError('EXISTING_SKILL_CONFLICT')
                        staged_snapshot = transaction.read(staged)
                        if staged_snapshot is None or staged_snapshot.content != content:
                            raise ValueError('STAGING_CHANGED')
                        check_authority()
                        # Atomic no-replace publication; no execution or backend call
                        # occurs while the short canonical owner lock is held.
                        fsx.link_at(stage_parent, stage_name, parent, basename)
                        fsx.unlink_at(stage_parent, stage_name)
                        fsx.fsync_dir(stage_parent)
                        fsx.fsync_dir(parent)
                        stage_check()
                        check()
                        check_authority()
    return {'schema_version': 1, 'status': 'installed', 'destination': destination,
            'snapshot_digest': snapshot.digest, 'descriptor_digest': digest(descriptor),
            'assessment': assessment.to_dict(), 'interview': trial,
            'permissions_granted': False, 'activated': False, 'evidence_valid': False}
