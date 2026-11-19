"""Exact committed-source review planning; operational authority is never changed."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .diff_risk import ORDER, classify_diff, load_rules, parse_rules
from .project_ingestion import _git
from .state import serialized_task
from .util import git_head, tree_fingerprint, unique_ordered

RULE_PATH = '.getzilla/config/diff-risk-rules.json'
DEFAULT_AUDITS = {
    'security': {'minimum_risk': 'medium', 'rules': ['AUTH_PATH', 'MONEY_PATH', 'SECRET_PATH', 'CONTROL_PLANE', 'RISK_POLICY', 'ARCHITECTURE_SECRET_NODE']},
    'data': {'minimum_risk': 'medium', 'rules': ['DATA_MIGRATION', 'DATA_SCHEMA', 'ARCHITECTURE_RESTRICTED_NODE']},
    'release': {'minimum_risk': 'medium', 'rules': ['DEPENDENCY_OR_CI', 'RELEASE_PATH']},
}
_SHA = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')
# Binary files that run or unpack into code stay blocked; only inert assets take the full profile (#209).
_EXECUTABLE_BINARY = ('.so', '.dll', '.dylib', '.exe', '.bin', '.pyc', '.pyo', '.class', '.jar', '.war', '.whl',
                      '.egg', '.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.wasm', '.node', '.a', '.o')


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def _document(root: Path, ref: str, path: str) -> bytes | None:
    listing = _git(root, 'ls-tree', '-z', ref, '--', path).stdout
    if not listing:
        return None
    mode, kind, _oid = listing.split(b'\t', 1)[0].split()
    if mode != b'100644' or kind != b'blob':
        raise ValueError(f'unsafe policy mode: {path}')
    value = _git(root, 'show', f'{ref}:{path}').stdout
    if len(value) > 1_048_576:
        raise ValueError(f'policy exceeds byte bound: {path}')
    return value


def _engine_source(root: Path, ref: str) -> tuple[dict, dict]:
    """Read the complete managed source container from immutable regular Git blobs."""
    from .baseline_assets import ARCHIVE_LIMIT, ENGINE_ARCHIVE, archive_entries, validate_resources
    from .skill_sandbox import MAX_FILE_BYTES

    def read(path: str, limit: int = MAX_FILE_BYTES) -> bytes | None:
        listing = _git(root, 'ls-tree', '-z', ref, '--', path).stdout
        if not listing:
            return None
        rows = listing.rstrip(b'\0').split(b'\0')
        meta, actual = rows[0].split(b'\t', 1)
        mode, kind, oid = meta.split()
        if len(rows) != 1 or actual != path.encode() or mode != b'100644' or kind != b'blob':
            raise ValueError('UNSAFE_ENGINE_SOURCE_MODE')
        size = int(_git(root, 'cat-file', '-s', oid.decode('ascii')).stdout)
        if not 0 <= size <= limit:
            raise ValueError('ENGINE_SOURCE_BOUNDS')
        body = _git(root, 'cat-file', 'blob', oid.decode('ascii')).stdout
        if len(body) != size:
            raise ValueError('ENGINE_SOURCE_CHANGED')
        return body

    raw = read(ENGINE_ARCHIVE, ARCHIVE_LIMIT)
    if raw is None:
        return {'ref': ref, 'sha256': None, 'bytes': 0, 'mode': None, 'members': []}, {}
    entries = archive_entries(raw, canonical=True)

    def required(path: str) -> bytes:
        value = read(path)
        if value is None:
            raise ValueError('MISSING_ENGINE_RESOURCE')
        return value

    validate_resources(entries, required)
    for path, (body, _mode) in entries.items():
        loose = read(path)
        if loose is not None and loose != body:
            raise ValueError('ENGINE_LOOSE_SOURCE_CONFLICT')
    members = [{'path': path, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body), 'mode': '100644'}
               for path, (body, _mode) in sorted(entries.items())]
    return {'ref': ref, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'mode': '100644', 'members': members}, {item['path']: item for item in members}


def _model(root: Path, ref: str) -> dict:
    system = _document(root, ref, 'architecture/system.yaml')
    rules = _document(root, ref, 'architecture/rules.yaml')
    if system is None and rules is None:
        return {'system': {}, 'rules': {}}
    if system is None or rules is None:
        raise ValueError('partial architecture policy')
    result = {'system': json.loads(system), 'rules': json.loads(rules)}
    if not all(isinstance(item, dict) for item in result.values()):
        raise ValueError('invalid architecture policy')
    return result


def _audits(rules: dict) -> dict:
    configured = rules.get('audits', DEFAULT_AUDITS)
    if not isinstance(configured, dict) or set(configured) != set(DEFAULT_AUDITS):
        raise ValueError('audit categories must be security, data and release')
    for name, policy in configured.items():
        if (not isinstance(policy, dict) or set(policy) != {'minimum_risk', 'rules'}
                or policy['minimum_risk'] not in ORDER or not isinstance(policy['rules'], list)
                or not policy['rules'] or any(not isinstance(rule, str) or not rule for rule in policy['rules'])):
            raise ValueError(f'invalid audit threshold: {name}')
    return configured


def _policy_review_floor(raw: bytes | None, route: dict | None, profile: str) -> list[str]:
    from .router import REVIEW_EVIDENCE
    configured = json.loads(raw) if raw is not None else {}
    if not isinstance(configured, dict):
        raise ValueError('invalid routing policy')
    floors = configured.get('review_floors', {})
    if not isinstance(floors, dict):
        raise ValueError('invalid review floors')
    for values in floors.values():
        if not isinstance(values, list) or any(name not in REVIEW_EVIDENCE for name in values):
            raise ValueError('invalid review floor agent')
    groups = ['delivery']
    if profile == 'trivial':
        groups += ['docs', 'trivial']
    if (route or {}).get('delivery_lane') == 'light':
        groups.append('light')
    if (route or {}).get('intent') == 'review':
        groups.append('review_intent')
    # An operational release keeps its configured release floor. Intent does
    # not turn unrelated ordinary work into an audit.
    if (route or {}).get('intent') == 'release':
        groups.append('release')
    return unique_ordered(name for group in groups for name in floors.get(group, []))


def assess(root: Path, route: dict | None, selection: Any, fingerprint: str | None = None) -> dict:
    """Classify both baseline and candidate policy; an edited policy cannot lower itself."""
    from .router import REVIEW_EVIDENCE
    head = git_head(root)
    entries = selection.bases
    # An accepted target can descend from this frozen HEAD. Its empty comparison
    # repeats candidate policy already read with every other base. Route anchors
    # and all non-HEAD comparisons remain exact, including equal-tree commits.
    if not selection.findings and any(item.comparison_base_sha != head for item in entries):
        entries = [item for item in entries if item.kind != 'pr-target' or item.comparison_base_sha != head]
    bases = sorted({item.comparison_base_sha for item in entries})
    gaps = [str(item.get('code', 'untrusted_base')) for item in selection.findings]
    reasons, policies, risks, audit_categories = [], [], [], set()
    floor_reviewers: list[str] = []
    engine_sources, engine_members, engine_comparisons = {}, {}, []
    historical_sources, historical_comparisons = {}, []
    fingerprint = fingerprint or tree_fingerprint(root)
    tree = None
    try:
        if not head or not _SHA.fullmatch(head) or not bases:
            raise ValueError('exact source and trusted comparison base are required')
        tree = _git(root, 'rev-parse', 'HEAD^{tree}').stdout.decode().strip()
        if _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout:
            gaps.append('UNCOMMITTED_INVENTORY')
        for base in bases:
            if not _SHA.fullmatch(base):
                raise ValueError('malformed comparison base')
            _git(root, 'merge-base', '--is-ancestor', base, head)
            stats = _git(root, 'diff', '--numstat', '-z', '--no-renames', '--no-textconv', '--no-ext-diff', base, head, '--').stdout
            if len(stats) > 4_194_304:
                raise ValueError('changed inventory exceeds byte bound')
            binaries, changed_paths = [], set()
            for row in stats.split(b'\0'):
                if row:
                    added, removed, name = row.split(b'\t', 2)
                    changed_paths.add(name.decode('utf-8', 'strict'))
                    if added == removed == b'-':
                        binaries.append(name.decode('utf-8', 'strict'))
                    elif not added.isdigit() or not removed.isdigit():
                        gaps.append('BINARY_OR_UNKNOWN_INVENTORY')
            modes = {}
            for ref in (base, head):
                for row in _git(root, 'ls-tree', '-r', '-z', ref).stdout.split(b'\0'):
                    if row:
                        meta, name = row.split(b'\t', 1)
                        modes.setdefault(name.decode('utf-8', 'strict'), set()).add(meta.split()[0])
            engine_valid = False
            if '.getzilla/getzilla.zip' in changed_paths:
                try:
                    for ref in (base, head):
                        if ref not in engine_sources:
                            engine_sources[ref], engine_members[ref] = _engine_source(root, ref)
                    before, after = engine_members[base], engine_members[head]
                    deltas = [{'path': path, 'status': 'A' if path not in before else 'D' if path not in after else 'M'}
                              for path in sorted(before.keys() | after.keys()) if before.get(path) != after.get(path)]
                    engine_comparisons.append({'base': base, 'head': head, 'changed_members': deltas})
                    reasons.append({'rule': 'MANAGED_ENGINE_SOURCE', 'path': '.getzilla/getzilla.zip', 'risk': 'high'})
                    audit_categories.update(DEFAULT_AUDITS)
                    engine_valid = True
                except (ValueError, OSError, KeyError, TypeError):
                    gaps.extend(['BINARY_OR_UNKNOWN_INVENTORY', 'INVALID_MANAGED_ENGINE_SOURCE'])
            # One closed historical source publication is data for inspection,
            # never runtime code authority. Its full original tree and bounded
            # member catalogue remain part of this exact-source assessment.
            from .historical_data import SOURCE_PATH, issue170_source
            historical_valid = False
            if SOURCE_PATH in changed_paths:
                try:
                    for ref in (base, head):
                        if ref not in historical_sources:
                            historical_sources[ref] = issue170_source(root, ref)
                    if historical_sources[head] is None:
                        raise ValueError('HISTORICAL_SOURCE_MISSING')
                    historical_comparisons.append({'base': base, 'head': head, 'path': SOURCE_PATH})
                    reasons.append({'rule': 'HISTORICAL_SOURCE_DATA', 'path': SOURCE_PATH, 'risk': 'high'})
                    audit_categories.update(DEFAULT_AUDITS)
                    historical_valid = True
                except (ValueError, OSError, KeyError, TypeError):
                    gaps.extend(['BINARY_OR_UNKNOWN_INVENTORY', 'INVALID_HISTORICAL_SOURCE_DATA'])
            # A file Git itself calls binary (a PDF, an image) cannot be read line by line, so it takes
            # the full review profile; it no longer blocks delivery outright (#209). Any other
            # unreadable row, an executable or archive binary, or a binary that is not a regular
            # file stays an incomplete inventory.
            for name in binaries:
                if name == '.getzilla/getzilla.zip' and engine_valid:
                    continue
                if name == SOURCE_PATH and historical_valid:
                    continue
                # A binary with no extension is a program as often as not, whatever its mode (#215).
                extensionless = '.' not in name.rsplit('/', 1)[-1].lstrip('.')
                executable = (name.lower().endswith(_EXECUTABLE_BINARY) or extensionless
                              or b'100755' in modes.get(name, set()))
                if modes.get(name) and modes[name] <= {b'100644', b'100755'} and not executable:
                    reason = {'rule': 'BINARY_FILE', 'path': name, 'risk': 'high'}
                    if reason not in reasons:
                        reasons.append(reason)
                else:
                    gaps.append('BINARY_OR_UNKNOWN_INVENTORY')
            for ref in (base, head):
                raw = _document(root, ref, RULE_PATH)
                rules = parse_rules(raw) if raw is not None else load_rules()
                model = _model(root, ref)
                audit_rules = _audits(rules)
                policies.append({'ref': ref, 'rules': _digest(rules), 'architecture': _digest(model), 'audits': _digest(audit_rules)})
                risk = classify_diff(root, base, head, rules=rules, architecture=model)
                routing = _document(root, ref, '.getzilla/config/routing.json')
                floor = _policy_review_floor(routing, route, risk.profile_candidate)
                floor_reviewers.extend(floor)
                policies[-1]['review_floors'] = _digest(floor)
                risks.append(risk)
                gaps.extend(risk.gaps)
                for change in risk.changed:
                    for path in filter(None, (change.path, change.old_path)):
                        if path.startswith('/') or any(part in ('', '.', '..') for part in path.split('/')):
                            gaps.append('MALFORMED_CHANGED_PATH')
                        if not modes.get(path) or not modes[path] <= {b'100644', b'100755'}:
                            gaps.append('UNSAFE_CHANGED_MODE')
                    if change.status not in {'A', 'M', 'D', 'R', 'C'}:
                        gaps.append('UNKNOWN_CHANGED_STATUS')
                reasons.extend(dict(reason) for reason in risk.reasons if dict(reason) not in reasons)
                # A baseline can predate the secret-node audit mapping. Preserve
                # its security meaning even if the candidate removes the secret.
                if any(reason['rule'].startswith('ARCHITECTURE_SECRET_NODE:') for reason in risk.reasons):
                    audit_categories.add('security')
                for category, policy in audit_rules.items():
                    for reason in risk.reasons:
                        matched = reason['rule'].split(':')[0] in policy['rules']
                        if reason['rule'].startswith('DEPENDENT_IN_HIGH_RISK_PATH:'):
                            matched = reason['rule'].split(':')[1] in policy['rules']
                        if matched and ORDER[reason['risk']] >= ORDER[policy['minimum_risk']]:
                            audit_categories.add(category)
        # Classification policy changes always require security scrutiny, even if
        # the candidate deletes the corresponding rule/category from its policy.
        if any(change.path == RULE_PATH or change.old_path == RULE_PATH for item in risks for change in item.changed):
            audit_categories.add('security')
            reasons.append({'rule': 'RISK_POLICY', 'path': RULE_PATH, 'risk': 'high'})
    except Exception as exc:  # classification is fail-closed, including Git/parse failures
        gaps.append(f'ASSESSMENT_UNAVAILABLE:{type(exc).__name__}:{str(exc)[:200]}')
    status = 'incomplete' if gaps else 'complete'
    risk_level = max((item['risk'] for item in reasons), key=ORDER.get, default='low')
    if gaps:
        risk_level = 'high'
    explicit = list((route or {}).get('explicit_review_agents', []))
    # Existing records remain readable and retain their explicitly selected wave.
    if route and 'risk_assessment' not in route:
        explicit = unique_ordered([*explicit, *route.get('review_agents', [])])
    reviewers = unique_ordered(['code_reviewer', *floor_reviewers, *explicit, *(name + '_reviewer' for name in sorted(audit_categories))])
    reviewers = [name for name in reviewers if name in REVIEW_EVIDENCE]
    evidence = ['verification', *(REVIEW_EVIDENCE[name] for name in reviewers)]
    profile = 'full' if risk_level == 'high' else ('trivial' if risks and all(item.profile_candidate == 'trivial' for item in risks) else 'standard')
    assessment = {'schema_version': 1, 'status': status, 'bases': bases, 'head': head, 'tree': tree,
                  'tree_fingerprint': fingerprint, 'risk': risk_level, 'rules_digest': _digest(policies),
                  'reasons': reasons, 'gaps': sorted(set(gaps)), 'categories': sorted(audit_categories), 'profile_candidate': profile}
    if engine_comparisons:
        assessment['engine_sources'] = {'containers': [engine_sources[ref] for ref in sorted(engine_sources)],
                                        'comparisons': engine_comparisons}
    if historical_comparisons:
        assessment['historical_data'] = {'catalogue_version': 1,
            'sources': [{'ref': ref, 'catalogue': historical_sources[ref]} for ref in sorted(historical_sources)],
            'comparisons': historical_comparisons}
    plan = {'schema_version': 1, 'assessment_digest': _digest(assessment), 'review_agents': reviewers, 'required_evidence': evidence}
    plan['digest'] = _digest(plan)
    return {'risk': risk_level, 'risk_assessment': assessment, 'review_plan': plan, 'explicit_review_agents': explicit,
            'review_agents': reviewers, 'required_evidence': evidence,
            'allowed_agents': unique_ordered([*(agent for agent in (route or {}).get('allowed_agents', []) if agent not in REVIEW_EVIDENCE),
                *((route or {}).get('analysis_agents') or []),
                *([route['write_agent']] if route and route.get('write_agent') else []), *reviewers])}


@serialized_task
def reconcile_route(root: Path, *, selection: Any = None, fingerprint: str | None = None,
                    additional_reviewers: tuple[str, ...] = ()) -> dict:
    from .state import get_active_route, update_route, task_transition
    from .package_status import synchronize_review_accounting
    from .git_ranges import _git_range_selection
    route = get_active_route(root)
    if not route:
        raise ValueError('no active route to reconcile')
    if route.get('status') == 'cancelled':
        from .continuity import assert_finishable
        with task_transition(root):
            if get_active_route(root) != route:
                raise ValueError('route changed during reconciliation')
            assert_finishable(root, route, cancel=True)
            return route
    from .router import REVIEW_EVIDENCE
    if any(name not in REVIEW_EVIDENCE for name in additional_reviewers):
        raise ValueError('unknown explicit reviewer')
    selected = dict(route)
    if additional_reviewers:
        selected['explicit_review_agents'] = unique_ordered([*route.get('explicit_review_agents', []),
            *(route.get('review_agents', []) if 'risk_assessment' not in route else []), *additional_reviewers])
    selection = selection if selection is not None else _git_range_selection(root, route, 'pr')
    updates = assess(root, selected, selection, fingerprint)
    # Preserve the complete catalogue, and refuse before package accounting can change.
    prospective = {**route, **updates, 'updated_at': '9999-12-31T23:59:59+00:00',
                   'state_revision': route.get('state_revision', 0) + 1}
    if len((json.dumps(prospective, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()) > 1_048_576:
        raise ValueError('complete source review plan exceeds route byte bound')
    with task_transition(root):
        current = get_active_route(root)
        if current != route or tree_fingerprint(root) != updates['risk_assessment']['tree_fingerprint'] or git_head(root) != updates['risk_assessment']['head']:
            raise ValueError('route or source changed during reconciliation')
        from .state import _route_document, get_active_change, open_change_binding
        from .workflow_storage import valid_package_path
        package = get_active_change(root)
        if (package is not None or route.get('change_id') is not None) and (
                not isinstance(package, dict) or set(package) != {'change_id', 'path'}
                or package['change_id'] != route.get('change_id')
                or not valid_package_path(package['path'], package['change_id'])):
            raise ValueError('selected accounting package does not match task')
        # Validate the closed state binding without requiring a cancelled draft
        # to have completed its spec or earned review receipts.
        open_change_binding(root)
        if package and _route_document(root, root / package['path'] / 'state.json').get('status') == 'cancelled':
            raise ValueError('attached package is cancelled; use route --cancel, then --new-task to retry; cancellation is terminal')
        check_package = synchronize_review_accounting(root, route, updates['required_evidence'])
        if (tree_fingerprint(root) != updates['risk_assessment']['tree_fingerprint']
                or git_head(root) != updates['risk_assessment']['head']):
            raise ValueError('source changed during accounting synchronization')
        check_package()
        published = update_route(root, expected_route=route, **updates)
        if (get_active_route(root) != published or tree_fingerprint(root) != updates['risk_assessment']['tree_fingerprint']
                or git_head(root) != updates['risk_assessment']['head']):
            raise ValueError('route or source changed during reconciliation publication')
        check_package()
        return published


def validate_review_plan(root: Path, route: dict) -> list[str]:
    if 'risk_assessment' not in route:
        return []  # legacy records keep their original receipt contract
    from .git_ranges import _git_range_selection
    expected = assess(root, route, _git_range_selection(root, route, 'pr'))
    if expected['risk_assessment']['status'] != 'complete':
        return ['review plan has incomplete source assessment']
    fields = ('risk', 'risk_assessment', 'review_plan', 'review_agents', 'required_evidence', 'allowed_agents')
    return [] if all(route.get(field) == expected[field] for field in fields) else ['review plan is missing, stale or contradictory']
