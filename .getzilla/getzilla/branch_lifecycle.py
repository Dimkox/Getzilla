"""Branch lifecycle: classify refs by ancestry, plan retention as a dry run, delete only with an exact-OID lease.

Merged means the branch tip is an ancestor of the target tip, or its tree is proven equal to a
target commit (squash/rebase); a commit date never decides anything. Default, protected, release,
support and keep refs, refs with an open pull request and refs from an incomplete snapshot are
kept. A plan is bound to the policy digest and the refs snapshot; applying it re-reads the refs,
needs an explicit capability and a backend that deletes only when the ref still has the expected OID.
"""
from __future__ import annotations

import fnmatch
import os
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Protocol

from .source_models import canonical_json, domain_digest

PLAN_DOMAIN = 'getzilla-branch-retention-plan-v1'
POLICY_DOMAIN = 'getzilla-branch-policy-v1'
SNAPSHOT_DOMAIN = 'getzilla-branch-snapshot-v1'


class BranchLifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class BranchPolicy:
    default_branch: str
    protected_patterns: tuple[str, ...] = ('release/*', 'support/*')
    keep: tuple[str, ...] = ()
    retention_days: int = 14
    experimental_patterns: tuple[str, ...] = ('experiment/*', 'exp/*')
    experimental_ttl_days: int = 30
    owner: str | None = None
    deletion_enabled: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'BranchPolicy':
        allowed = set(cls.__dataclass_fields__)
        unknown = set(data) - allowed
        if unknown:
            raise BranchLifecycleError(f'unknown policy fields: {sorted(unknown)}')
        if not data.get('default_branch'):
            raise BranchLifecycleError('policy.default_branch is required; it is never guessed from dates')
        values = dict(data)
        for key in ('protected_patterns', 'keep', 'experimental_patterns'):
            if key in values:
                values[key] = tuple(values[key])
        policy = cls(**values)
        if policy.retention_days < 0 or policy.experimental_ttl_days < 0:
            raise BranchLifecycleError('retention periods must be non-negative')
        return policy

    def to_dict(self) -> dict[str, Any]:
        return {'default_branch': self.default_branch, 'protected_patterns': list(self.protected_patterns),
                'keep': list(self.keep), 'retention_days': self.retention_days,
                'experimental_patterns': list(self.experimental_patterns),
                'experimental_ttl_days': self.experimental_ttl_days, 'owner': self.owner,
                'deletion_enabled': self.deletion_enabled}

    def digest(self) -> str:
        return domain_digest(POLICY_DOMAIN, self.to_dict())


@dataclass(frozen=True)
class MergeProof:
    kind: str  # ancestor, tree_equal
    target_commit: str
    merged_at: str | None = None  # confirmed merge time (pull request record); never a commit date

    def to_dict(self) -> dict[str, Any]:
        return {'kind': self.kind, 'target_commit': self.target_commit, 'merged_at': self.merged_at}


@dataclass(frozen=True)
class RefInfo:
    name: str
    oid: str
    committed_at: str | None = None  # informational only
    merge_proof: MergeProof | None = None
    created_at: str | None = None  # confirmed ref creation time, for experimental TTL notices

    def to_dict(self) -> dict[str, Any]:
        return {'name': self.name, 'oid': self.oid, 'committed_at': self.committed_at,
                'merge_proof': None if self.merge_proof is None else self.merge_proof.to_dict(),
                'created_at': self.created_at}


@dataclass(frozen=True)
class RefsSnapshot:
    target: str
    target_oid: str
    refs: tuple[RefInfo, ...]
    open_pull_requests: frozenset[str] = frozenset()
    protected: frozenset[str] = frozenset()
    complete: bool = True  # False when a listing was paginated partially or a source was unavailable
    unknown: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {'target': self.target, 'target_oid': self.target_oid,
                'refs': [ref.to_dict() for ref in sorted(self.refs, key=lambda ref: ref.name)],
                'open_pull_requests': sorted(self.open_pull_requests), 'protected': sorted(self.protected),
                'complete': self.complete, 'unknown': sorted(self.unknown)}

    def digest(self) -> str:
        return domain_digest(SNAPSHOT_DOMAIN, self.to_dict())

    def ref(self, name: str) -> RefInfo | None:
        return next((ref for ref in self.refs if ref.name == name), None)


@dataclass(frozen=True)
class BranchRecord:
    name: str
    expected_oid: str
    state: str  # merged, unmerged, unknown
    merge_proof: MergeProof | None
    keep_reasons: tuple[str, ...]

    @property
    def deletable_candidate(self) -> bool:
        return self.state == 'merged' and not self.keep_reasons

    def to_dict(self) -> dict[str, Any]:
        return {'name': self.name, 'expected_oid': self.expected_oid, 'state': self.state,
                'merge_proof': None if self.merge_proof is None else self.merge_proof.to_dict(),
                'keep_reasons': list(self.keep_reasons), 'deletable_candidate': self.deletable_candidate}


@dataclass(frozen=True)
class BranchInventory:
    target: str
    target_oid: str
    snapshot_digest: str
    policy_digest: str
    complete: bool
    unknown_coverage: tuple[str, ...]
    branches: tuple[BranchRecord, ...]

    @property
    def clean(self) -> bool:
        return self.complete and not self.unknown_coverage

    def to_dict(self) -> dict[str, Any]:
        return {'target': self.target, 'target_oid': self.target_oid, 'snapshot_digest': self.snapshot_digest,
                'policy_digest': self.policy_digest, 'complete': self.complete, 'clean': self.clean,
                'unknown_coverage': list(self.unknown_coverage),
                'branches': [branch.to_dict() for branch in self.branches]}


def _matches(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def classify_branches(snapshot: RefsSnapshot, policy: BranchPolicy) -> BranchInventory:
    if snapshot.target != policy.default_branch:
        raise BranchLifecycleError('snapshot target is not the policy default branch')
    unknown = list(snapshot.unknown)
    if not snapshot.complete:
        unknown.append('INCOMPLETE_REFS_SNAPSHOT')
    records = []
    for ref in sorted(snapshot.refs, key=lambda item: item.name):
        reasons: list[str] = []
        if ref.name == policy.default_branch:
            reasons.append('DEFAULT_BRANCH')
        if ref.name in snapshot.protected or _matches(ref.name, policy.protected_patterns):
            reasons.append('PROTECTED')
        if ref.name in policy.keep:
            reasons.append('KEEP_LIST')
        if ref.name in snapshot.open_pull_requests:
            reasons.append('OPEN_PULL_REQUEST')
        if not snapshot.complete:
            reasons.append('INVENTORY_INCOMPLETE')
        proof = ref.merge_proof
        if proof is not None and proof.kind in ('ancestor', 'tree_equal') and proof.target_commit == snapshot.target_oid:
            state = 'merged'
        elif proof is not None:
            state, proof = 'unknown', None
            reasons.append('MERGE_PROOF_FOR_OTHER_TARGET')
        else:
            state = 'unmerged'
        records.append(BranchRecord(ref.name, ref.oid, state, proof, tuple(reasons)))
    return BranchInventory(snapshot.target, snapshot.target_oid, snapshot.digest(), policy.digest(),
                           snapshot.complete, tuple(unknown), tuple(records))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


@dataclass(frozen=True)
class PlanEntry:
    name: str
    expected_oid: str
    action: str  # eligible_for_delete, keep, wait, notice
    reasons: tuple[str, ...]
    eligible_at: str | None

    def to_dict(self) -> dict[str, Any]:
        return {'name': self.name, 'expected_oid': self.expected_oid, 'action': self.action,
                'reasons': list(self.reasons), 'eligible_at': self.eligible_at}


@dataclass(frozen=True)
class BranchRetentionPlan:
    plan_id: str
    target: str
    target_oid: str
    policy_digest: str
    snapshot_digest: str
    created_at: str
    entries: tuple[PlanEntry, ...]
    dry_run: bool = True

    def body(self) -> dict[str, Any]:
        return {'schema_version': PLAN_DOMAIN, 'target': self.target, 'target_oid': self.target_oid,
                'policy_digest': self.policy_digest, 'snapshot_digest': self.snapshot_digest,
                'created_at': self.created_at, 'entries': [entry.to_dict() for entry in self.entries]}

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), 'plan_id': self.plan_id, 'dry_run': self.dry_run}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> 'BranchRetentionPlan':
        entries = tuple(PlanEntry(item['name'], item['expected_oid'], item['action'], tuple(item['reasons']),
                                  item['eligible_at']) for item in data['entries'])
        plan = cls(data['plan_id'], data['target'], data['target_oid'], data['policy_digest'],
                   data['snapshot_digest'], data['created_at'], entries, bool(data.get('dry_run', True)))
        if domain_digest(PLAN_DOMAIN, plan.body()) != plan.plan_id:
            raise BranchLifecycleError('plan_id does not match the plan body')
        return plan

    @property
    def eligible(self) -> tuple[PlanEntry, ...]:
        return tuple(entry for entry in self.entries if entry.action == 'eligible_for_delete')


def build_branch_plan(inventory: BranchInventory, policy: BranchPolicy, now: datetime) -> BranchRetentionPlan:
    """Report-only retention plan. Unknown merge time keeps the ref; TTL only raises a notice."""
    if inventory.policy_digest != policy.digest():
        raise BranchLifecycleError('inventory was classified under another policy')
    entries = []
    for branch in inventory.branches:
        reasons = list(branch.keep_reasons)
        eligible_at = None
        if reasons or not inventory.clean:
            action = 'keep'
            if not inventory.clean and 'INVENTORY_INCOMPLETE' not in reasons:
                reasons.append('INVENTORY_INCOMPLETE')
        elif branch.state != 'merged':
            action = 'keep'
            reasons.append('NOT_PROVEN_MERGED' if branch.state == 'unmerged' else 'MERGE_STATE_UNKNOWN')
            if _matches(branch.name, policy.experimental_patterns):
                action = 'notice'
                reasons.append('EXPERIMENTAL_TTL_REVIEW_BY_OWNER' if policy.owner else 'EXPERIMENTAL_TTL_NO_OWNER')
        else:
            merged_at = _parse_time(branch.merge_proof.merged_at if branch.merge_proof else None)
            if merged_at is None:
                action = 'keep'
                reasons.append('MERGE_TIME_UNKNOWN')
            else:
                eligible = merged_at + timedelta(days=policy.retention_days)
                eligible_at = _iso(eligible)
                if now < eligible:
                    action = 'wait'
                    reasons.append('RETENTION_PERIOD_NOT_ELAPSED')
                else:
                    action = 'eligible_for_delete'
                    reasons.append(f'MERGED_{branch.merge_proof.kind.upper()}')
        entries.append(PlanEntry(branch.name, branch.expected_oid, action, tuple(reasons), eligible_at))
    plan = BranchRetentionPlan('', inventory.target, inventory.target_oid, inventory.policy_digest,
                               inventory.snapshot_digest, _iso(now), tuple(entries))
    return replace(plan, plan_id=domain_digest(PLAN_DOMAIN, plan.body()))


class RefBackend(Protocol):
    supports_atomic_lease: bool

    def snapshot(self) -> RefsSnapshot: ...

    def delete_ref(self, name: str, expected_oid: str) -> bool: ...


@dataclass(frozen=True)
class BranchActionReceipt:
    plan_id: str
    status: str  # dry_run, blocked, applied, partial
    reasons: tuple[str, ...]
    deleted: tuple[Mapping[str, str], ...] = ()
    skipped: tuple[Mapping[str, str], ...] = ()
    refs_before: str | None = None
    refs_after: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-branch-action-receipt-v1', 'plan_id': self.plan_id,
                'status': self.status, 'reasons': list(self.reasons), 'deleted': [dict(item) for item in self.deleted],
                'skipped': [dict(item) for item in self.skipped], 'refs_before': self.refs_before,
                'refs_after': self.refs_after}


def apply_branch_plan(plan: BranchRetentionPlan, backend: RefBackend, policy: BranchPolicy, *,
                      capability_granted: bool, now: datetime) -> BranchActionReceipt:
    """Delete only plan-eligible refs that a fresh re-check still allows, each under an exact-OID lease."""
    if not (capability_granted and policy.deletion_enabled):
        return BranchActionReceipt(plan.plan_id, 'dry_run', ('DELETE_CAPABILITY_NOT_GRANTED',))
    if not backend.supports_atomic_lease:
        return BranchActionReceipt(plan.plan_id, 'blocked', ('BACKEND_HAS_NO_ATOMIC_LEASE',))
    if plan.policy_digest != policy.digest():
        return BranchActionReceipt(plan.plan_id, 'blocked', ('POLICY_CHANGED_AFTER_PLAN',))
    fresh = backend.snapshot()
    if fresh.target != plan.target or fresh.target_oid != plan.target_oid:
        return BranchActionReceipt(plan.plan_id, 'blocked', ('TARGET_MOVED_AFTER_PLAN',), refs_before=fresh.digest())
    recheck = {entry.name: entry for entry in build_branch_plan(classify_branches(fresh, policy), policy, now).entries}
    deleted, skipped = [], []
    for entry in plan.eligible:
        current = fresh.ref(entry.name)
        again = recheck.get(entry.name)
        if current is None:
            skipped.append({'name': entry.name, 'reason': 'REF_GONE'})
        elif current.oid != entry.expected_oid:
            skipped.append({'name': entry.name, 'reason': 'REF_MOVED_AFTER_PLAN'})
        elif again is None or again.action != 'eligible_for_delete':
            skipped.append({'name': entry.name, 'reason': ','.join(again.reasons) if again else 'NOT_RECHECKED'})
        elif entry.name == policy.default_branch or _matches(entry.name, policy.protected_patterns):
            skipped.append({'name': entry.name, 'reason': 'PROTECTED'})
        elif backend.delete_ref(entry.name, entry.expected_oid):
            deleted.append({'name': entry.name, 'oid': entry.expected_oid})
        else:
            skipped.append({'name': entry.name, 'reason': 'LEASE_REJECTED'})
    status = 'applied' if not skipped else ('partial' if deleted else 'blocked')
    return BranchActionReceipt(plan.plan_id, status, (), tuple(deleted), tuple(skipped), fresh.digest(),
                               backend.snapshot().digest())


def _isolated_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
                'LC_ALL': 'C'})
    return env


class LocalGitRefBackend:
    """Refs of one local repository (for example a bare remote); deletion is `update-ref -d <ref> <old>`.

    Pull request state is not in Git: it comes from `pull_requests` (name -> {state, head_oid, merged_at}),
    and `complete=False` marks that listing as partial. Nothing here touches the network.
    """

    supports_atomic_lease = True

    def __init__(self, repo: Path, target: str, *, pull_requests: Mapping[str, Mapping[str, Any]] | None = None,
                 protected: Iterable[str] = (), complete: bool = True, equivalence_depth: int = 500) -> None:
        self.repo, self.target = Path(repo), target
        self.pull_requests = dict(pull_requests or {})
        self.protected, self.complete, self.depth = frozenset(protected), complete, equivalence_depth

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True, text=True, encoding="utf-8", errors="surrogateescape",
                              check=check, env=_isolated_env())

    def snapshot(self) -> RefsSnapshot:
        lines = self._git('for-each-ref', '--format=%(refname:strip=2)%00%(objectname)%00%(committerdate:iso-strict)',
                          'refs/heads').stdout.splitlines()
        heads = [tuple(line.split('\0')) for line in lines if line]
        target_oid = next((oid for name, oid, _ in heads if name == self.target), None)
        if target_oid is None:
            raise BranchLifecycleError(f'target branch {self.target} does not exist')
        target_trees = set(self._git('log', '--first-parent', f'-{self.depth}', '--format=%T', target_oid).stdout.split())
        refs = []
        open_prs = set()
        for name, oid, date in heads:
            pr = self.pull_requests.get(name) or {}
            if pr.get('state') == 'open':
                open_prs.add(name)
            merged_at = pr.get('merged_at') if pr.get('state') == 'merged' and pr.get('head_oid') == oid else None
            proof = None
            if name != self.target:
                if self._git('merge-base', '--is-ancestor', oid, target_oid, check=False).returncode == 0:
                    proof = MergeProof('ancestor', target_oid, merged_at)
                elif self._git('rev-parse', f'{oid}^{{tree}}').stdout.strip() in target_trees:
                    proof = MergeProof('tree_equal', target_oid, merged_at)
            refs.append(RefInfo(name, oid, date or None, proof))
        return RefsSnapshot(self.target, target_oid, tuple(refs), frozenset(open_prs), self.protected, self.complete)

    def delete_ref(self, name: str, expected_oid: str) -> bool:
        return self._git('update-ref', '-d', f'refs/heads/{name}', expected_oid, check=False).returncode == 0


def snapshot_bytes(snapshot: RefsSnapshot) -> bytes:
    return canonical_json(snapshot.to_dict())
