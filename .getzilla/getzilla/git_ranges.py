"""Shared exact Git comparison ranges without verifier implementation imports."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .architecture import ArchitectureError

from .util import command_exists, run, tree_fingerprint

_EXACT_SHA = re.compile(r'^[0-9a-fA-F]{40}$')


@dataclass(frozen=True)
class GitRangeBase:
    kind: str
    source: str
    target_sha: str
    comparison_base_sha: str


@dataclass
class GitRangeSelection:
    bases: list[GitRangeBase] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)
    qualification_bases: tuple[GitRangeBase, ...] | None = None
    mode: str = 'pr'
    head_sha: str | None = None


FOCUSED_STATIC_SEO_LANDING_MODE = 'focused-static-seo-landing'
_RANGE_MODES = {'pr', 'release', FOCUSED_STATIC_SEO_LANDING_MODE}


def _resolve_commit(root: Path, ref: str) -> str | None:
    proc = run(
        ['git', 'rev-parse', '--verify', '--quiet', '--end-of-options', f'{ref}^{{commit}}'],
        cwd=root,
        timeout=30,
    )
    resolved = proc.stdout.strip()
    if proc.returncode != 0 or not _EXACT_SHA.fullmatch(resolved):
        return None
    return resolved.lower()


def _existing_ref_candidates(root: Path, refs: list[str]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ref in refs:
        resolved = _resolve_commit(root, ref)
        if resolved is None or (ref, resolved) in seen:
            continue
        seen.add((ref, resolved))
        candidates.append((ref, resolved))
    return candidates


def _select_local_pr_target(root: Path) -> tuple[str, str] | dict[str, str] | None:
    symbolic = run(
        ['git', 'symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD'],
        cwd=root,
        timeout=30,
    )
    if symbolic.returncode == 0 and symbolic.stdout.strip():
        source = symbolic.stdout.strip()
        if not source.startswith('refs/remotes/origin/'):
            return {
                'severity': 'error',
                'code': 'pr-base-untrusted-symbolic-target',
                'path': 'refs/remotes/origin/HEAD',
                'message': f'origin/HEAD points outside refs/remotes/origin: {source}',
            }
        resolved = _resolve_commit(root, source)
        if resolved is None:
            return {
                'severity': 'error',
                'code': 'pr-base-unresolvable',
                'path': source,
                'message': 'configured origin/HEAD does not resolve to a local commit',
            }
        return source, resolved

    configured = run(
        ['git', 'config', '--get', 'init.defaultBranch'],
        cwd=root,
        timeout=30,
    )
    configured_name = configured.stdout.strip() if configured.returncode == 0 else ''
    if configured_name:
        valid_name = run(
            ['git', 'check-ref-format', '--branch', configured_name],
            cwd=root,
            timeout=30,
        )
        if valid_name.returncode != 0:
            return {
                'severity': 'error',
                'code': 'pr-base-invalid-default-branch',
                'path': 'git-config:init.defaultBranch',
                'message': 'configured default branch is not a valid Git branch name',
            }

    # Remote-tracking refs come first: init.defaultBranch names new repositories (Git for Windows
    # sets master system wide), so a local branch of that name must not outrank origin/main.
    for configured_ref, refs in (
        (f'refs/remotes/origin/{configured_name}', ['refs/remotes/origin/main', 'refs/remotes/origin/master']),
        (f'refs/heads/{configured_name}', ['refs/heads/main', 'refs/heads/master']),
    ):
        if configured_name:
            configured_candidates = _existing_ref_candidates(root, [configured_ref])
            if configured_candidates:
                return configured_candidates[0]
        candidates = _existing_ref_candidates(root, refs)
        distinct = {resolved for _, resolved in candidates}
        if len(distinct) > 1:
            rendered = ', '.join(f'{ref}={sha}' for ref, sha in candidates)
            return {
                'severity': 'error',
                'code': 'pr-base-ambiguous',
                'path': 'git-refs',
                'message': f'multiple local PR target candidates disagree: {rendered}',
            }
        if candidates:
            return candidates[0]
    return None


def _git_range_selection(
    root: Path,
    route: dict[str, object] | None,
    mode: str,
) -> GitRangeSelection:
    mode = 'pr' if mode == 'fast' and ((route or {}).get('delivery_lane') == 'light'
                                      or (route or {}).get('light_lane_candidate') is True) else mode
    selection = GitRangeSelection(mode=mode)
    if mode not in _RANGE_MODES or not command_exists('git'):
        if mode == 'fast' and command_exists('git'):
            selection.head_sha = _resolve_commit(root, 'HEAD')
        return selection
    selection.head_sha = _resolve_commit(root, 'HEAD')

    if route:
        raw_route_base = route.get('base_commit')
        if not isinstance(raw_route_base, str) or not _EXACT_SHA.fullmatch(raw_route_base):
            selection.findings.append({
                'severity': 'error',
                'code': 'route-base-malformed',
                'path': '.getzilla/runtime/active-route.json',
                'message': 'PR verification requires route.base_commit as an exact 40-hex SHA',
            })
        else:
            route_base = _resolve_commit(root, raw_route_base)
            if route_base is None:
                selection.findings.append({
                    'severity': 'error',
                    'code': 'route-base-unresolvable',
                    'path': '.getzilla/runtime/active-route.json',
                    'message': f'route base is not a locally available commit: {raw_route_base}',
                })
            else:
                ancestor = run(
                    ['git', 'merge-base', '--is-ancestor', route_base, 'HEAD'],
                    cwd=root,
                    timeout=30,
                )
                if ancestor.returncode != 0:
                    selection.findings.append({
                        'severity': 'error',
                        'code': 'route-base-non-ancestor',
                        'path': '.getzilla/runtime/active-route.json',
                        'message': f'route base is not an ancestor of HEAD: {route_base}',
                    })
                else:
                    selection.bases.append(GitRangeBase(
                        kind='route',
                        source='route.base_commit',
                        target_sha=route_base,
                        comparison_base_sha=route_base,
                    ))

    pr_target = _select_local_pr_target(root)
    if isinstance(pr_target, dict):
        selection.findings.append(pr_target)
    elif pr_target is not None:
        source, target_sha = pr_target
        merge_base = run(
            ['git', 'merge-base', '--all', target_sha, 'HEAD'],
            cwd=root,
            timeout=30,
        )
        raw_bases = [line.strip() for line in merge_base.stdout.splitlines() if line.strip()]
        bases = sorted({line.lower() for line in raw_bases})
        if (
            merge_base.returncode != 0
            or len(bases) != 1
            or any(not _EXACT_SHA.fullmatch(line) for line in raw_bases)
        ):
            selection.findings.append({
                'severity': 'error',
                'code': 'pr-base-no-merge-base',
                'path': source,
                'message': f'local PR target has no unique merge base with HEAD: {target_sha}',
            })
        else:
            selection.bases.append(GitRangeBase(
                kind='pr-target',
                source=source,
                target_sha=target_sha,
                comparison_base_sha=bases[0],
            ))
            if bases[0] == _resolve_commit(root, 'HEAD') and route:
                qualified = _qualified_architecture_comparison(root, route, bases[0])
                if qualified is not None and qualified.comparison_base_sha not in {item.comparison_base_sha for item in selection.bases}:
                    selection.bases.append(GitRangeBase('qualified-pr-target', qualified.target_ref,
                                                       qualified.target_sha, qualified.comparison_base_sha))
                    # The live target remains in the full review union. A prior
                    # qualifying plan retains its exact range metadata separately.
                    selection.qualification_bases = (
                        GitRangeBase('route', 'route.base_commit', qualified.route_base_sha, qualified.route_base_sha),
                        GitRangeBase('pr-target', qualified.target_ref, qualified.target_sha, qualified.comparison_base_sha),
                    )
    elif route and route.get('delivery_expected') is True:
        selection.findings.append({
            'severity': 'error',
            'code': 'pr-base-unavailable',
            'path': 'git-refs',
            'message': 'delivery verification requires a locally resolvable PR target',
        })
    return selection


def _qualified_architecture_comparison(root: Path, route: dict[str, Any], head: str):
    """Reuse an exact completed qualification, never a reconcile-only assessment.

    This reads existing workflow evidence; it grants no new PASS or independent
    authority. Git ancestry/model/ref currentness is revalidated by the selector.
    """
    from .receipts import _receipt_storage_identity, get_receipt, _active_spec_binding, _exact_head
    route_id = route.get('route_id')
    if not isinstance(route_id, str):
        return None
    try:
        stored_identity = _receipt_storage_identity(root, route_id)
        receipt = get_receipt(root, route_id, 'verification')
        if stored_identity is None or _receipt_storage_identity(root, route_id) != stored_identity:
            return None
    except (OSError, RuntimeError):
        return None
    required = {'schema_version', 'route_id', 'kind', 'status', 'created_at', 'tree_fingerprint',
                'report', 'details', 'criterion_ids', 'spec_digest', 'spec_fingerprint'}
    if (not isinstance(receipt, dict) or not required.issubset(receipt)
            or type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1
            or not isinstance(receipt.get('created_at'), str) or not isinstance(receipt.get('criterion_ids'), list)
            or receipt.get('status') != 'pass' or receipt.get('stale') is True):
        return None
    from .continuity import receipt_context_current
    if (receipt.get('route_id') != route_id or receipt.get('kind') != 'verification'
            or receipt.get('git_head') != head or receipt.get('tree_fingerprint') != tree_fingerprint(root)
            or receipt.get('architecture_route_base_sha') != route.get('base_commit')
            or not receipt_context_current(root, route, receipt)
            or receipt.get('review_plan_digest') != (route.get('review_plan') or {}).get('digest')):
        return None
    report = receipt.get('details')
    if (not isinstance(report, dict) or report.get('status') != 'pass'
            or report.get('mode') not in ('pr', 'release') or report.get('terminal_state') != 'completed'):
        return None
    architecture = report.get('architecture')
    if (not isinstance(architecture, dict) or architecture.get('status') != 'pass'
            or architecture.get('fitness_status') != 'pass'):
        return None
    witness = receipt.get('architecture_comparison_witness')
    if witness is None:
        return None
    from .architecture_diff import ArchitectureBaseSelection, _comparison_model_digest, _comparison_ranges_digest, _git
    names = set(ArchitectureBaseSelection.__dataclass_fields__)
    if (type(witness) is not dict or set(witness) != names
            or architecture.get('architecture_comparison_witness') != witness
            or witness.get('candidate_sha') != head or witness.get('route_base_sha') != route.get('base_commit')
            or witness.get('base_kind') != 'accepted_target' or witness.get('bootstrap_baseline') is not False
            or witness.get('range_mode') != report['mode']
            or witness.get('range_mode') != receipt.get('architecture_range_mode')
            or witness.get('range_mode') != architecture.get('architecture_range_mode')
            or 'architecture_invocation_ranges_digest' in receipt
            or 'architecture_invocation_ranges_digest' in architecture
            or witness.get('comparison_base_sha') != witness.get('target_sha')
            or witness.get('comparison_base_sha') == head
            or receipt.get('architecture_base_sha') != witness.get('comparison_base_sha')
            or not all(isinstance(witness.get(key), str) and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', witness[key])
                       for key in ('route_base_sha', 'comparison_base_sha', 'candidate_sha', 'target_sha'))
            or not all(isinstance(witness.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', witness[key])
                       for key in ('ranges_digest', 'model_digest'))
            or not isinstance(witness.get('target_ref'), str)
            or not witness['target_ref'].startswith(('refs/remotes/origin/', 'refs/heads/'))):
        raise ArchitectureError('qualified architecture comparison witness is malformed', code='git')
    old_range = {'bases': [
        {'kind': 'route', 'source': 'route.base_commit', 'target_sha': witness['route_base_sha'],
         'comparison_base_sha': witness['route_base_sha']},
        {'kind': 'pr-target', 'source': witness['target_ref'], 'target_sha': witness['target_sha'],
         'comparison_base_sha': witness['comparison_base_sha']}], 'findings': []}
    anchor = _git(root, ['merge-base', '--all', witness['route_base_sha'], witness['target_sha']])
    contained = _git(root, ['merge-base', '--all', witness['target_sha'], head])
    if (anchor is None or anchor.decode().splitlines() != [witness['route_base_sha']]
            or contained is None or contained.decode().splitlines() != [witness['target_sha']]
            or _comparison_ranges_digest(ArchitectureBaseSelection(**witness)) != witness['ranges_digest']
            or _comparison_model_digest(root, (witness['route_base_sha'], witness['target_sha'], head)) != witness['model_digest']):
        raise ArchitectureError('qualified architecture comparison identity is stale', code='git')
    for name in ('architecture_base_sha', 'architecture_base_kind', 'architecture_bootstrap_baseline',
                 'architecture_route_base_sha', 'architecture_head_commit'):
        if architecture.get(name) != receipt.get(name):
            raise ArchitectureError('qualification architecture bindings disagree', code='git')
    # Prove live acceptance separately from the frozen plan's binding ranges.
    # This lower-level compiler never calls the range/witness reader again.
    target = _select_local_pr_target(root)
    if not isinstance(target, tuple) or target[0] != witness['target_ref']:
        return None
    accepted = _git(root, ['merge-base', '--all', head, target[1]])
    if accepted is None or accepted.decode().splitlines() != [head]:
        return None
    frozen = GitRangeSelection([GitRangeBase(**row) for row in old_range['bases']], mode=witness['range_mode'], head_sha=head)
    try:
        from .verification_plan import _compile_required_plan, _report_plan_gaps, requested_profiles_from_report
        current = _compile_required_plan(root, mode=report.get('mode'), profiles=requested_profiles_from_report(report),
                                         docs_scope=None, route=route, ranges=frozen)
        if _report_plan_gaps(root, report, current):
            return None
        if _compile_required_plan(root, mode=report.get('mode'), profiles=requested_profiles_from_report(report),
                                  docs_scope=None, route=route, ranges=frozen) != current:
            return None
        spec = _active_spec_binding(root, route, 'verification')
        if spec is not None and any(receipt.get(key) != value for key, value in spec.items()):
            return None
    except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
        return None
    if (_exact_head(root) != head or _select_local_pr_target(root) != target
            or _resolve_commit(root, witness['target_ref']) != target[1]
            or tree_fingerprint(root) != receipt['tree_fingerprint']
            or not receipt_context_current(root, route, receipt)):
        raise ArchitectureError('qualified comparison changed during validation', code='git')
    try:
        if (get_receipt(root, route_id, 'verification') != receipt
                or _receipt_storage_identity(root, route_id) != stored_identity):
            return None
    except (OSError, RuntimeError):
        return None
    return ArchitectureBaseSelection(**witness)


