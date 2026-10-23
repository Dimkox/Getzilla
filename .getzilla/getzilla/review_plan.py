"""Exact committed-source review planning; operational authority is never changed."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .diff_risk import ORDER, classify_diff, load_rules, parse_rules
from .project_ingestion import _git
from .util import git_head, tree_fingerprint, unique_ordered

RULE_PATH = '.getzilla/config/diff-risk-rules.json'
DEFAULT_AUDITS = {
    'security': {'minimum_risk': 'medium', 'rules': ['AUTH_PATH', 'MONEY_PATH', 'SECRET_PATH', 'CONTROL_PLANE', 'RISK_POLICY', 'ARCHITECTURE_SECRET_NODE']},
    'data': {'minimum_risk': 'medium', 'rules': ['DATA_MIGRATION', 'DATA_SCHEMA', 'ARCHITECTURE_RESTRICTED_NODE']},
    'release': {'minimum_risk': 'medium', 'rules': ['DEPENDENCY_OR_CI', 'RELEASE_PATH']},
}
_SHA = re.compile(r'[0-9a-f]{40}|[0-9a-f]{64}')


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
    bases = sorted({item.comparison_base_sha for item in selection.bases})
    gaps = [str(item.get('code', 'untrusted_base')) for item in selection.findings]
    reasons, policies, risks, audit_categories = [], [], [], set()
    floor_reviewers: list[str] = []
    head = git_head(root)
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
            for row in stats.split(b'\0'):
                if row:
                    added, removed, name = row.split(b'\t', 2)
                    if not added.isdigit() or not removed.isdigit():
                        gaps.append('BINARY_OR_UNKNOWN_INVENTORY')
            modes = {}
            for ref in (base, head):
                for row in _git(root, 'ls-tree', '-r', '-z', ref).stdout.split(b'\0'):
                    if row:
                        meta, name = row.split(b'\t', 1)
                        modes.setdefault(name.decode('utf-8', 'strict'), set()).add(meta.split()[0])
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
    plan = {'schema_version': 1, 'assessment_digest': _digest(assessment), 'review_agents': reviewers, 'required_evidence': evidence}
    plan['digest'] = _digest(plan)
    return {'risk': risk_level, 'risk_assessment': assessment, 'review_plan': plan, 'explicit_review_agents': explicit,
            'review_agents': reviewers, 'required_evidence': evidence,
            'allowed_agents': unique_ordered([*(agent for agent in (route or {}).get('allowed_agents', []) if agent not in REVIEW_EVIDENCE),
                *((route or {}).get('analysis_agents') or []),
                *([route['write_agent']] if route and route.get('write_agent') else []), *reviewers])}


def reconcile_route(root: Path, *, selection: Any = None, fingerprint: str | None = None,
                    additional_reviewers: tuple[str, ...] = ()) -> dict:
    from .state import get_active_route, update_route
    from .verification import _git_range_selection
    route = get_active_route(root)
    if not route:
        raise ValueError('no active route to reconcile')
    from .router import REVIEW_EVIDENCE
    if any(name not in REVIEW_EVIDENCE for name in additional_reviewers):
        raise ValueError('unknown explicit reviewer')
    selected = dict(route)
    if additional_reviewers:
        selected['explicit_review_agents'] = unique_ordered([*route.get('explicit_review_agents', []),
            *(route.get('review_agents', []) if 'risk_assessment' not in route else []), *additional_reviewers])
    selection = selection if selection is not None else _git_range_selection(root, route, 'pr')
    updates = assess(root, selected, selection, fingerprint)
    current = get_active_route(root)
    if current != route or tree_fingerprint(root) != updates['risk_assessment']['tree_fingerprint'] or git_head(root) != updates['risk_assessment']['head']:
        raise ValueError('route or source changed during reconciliation')
    return update_route(root, expected_route=route, **updates)


def validate_review_plan(root: Path, route: dict) -> list[str]:
    if 'risk_assessment' not in route:
        return []  # legacy records keep their original receipt contract
    from .verification import _git_range_selection
    expected = assess(root, route, _git_range_selection(root, route, 'pr'))
    if expected['risk_assessment']['status'] != 'complete':
        return ['review plan has incomplete source assessment']
    fields = ('risk', 'risk_assessment', 'review_plan', 'review_agents', 'required_evidence', 'allowed_agents')
    return [] if all(route.get(field) == expected[field] for field in fields) else ['review plan is missing, stale or contradictory']
