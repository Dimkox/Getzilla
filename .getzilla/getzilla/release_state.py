"""Machine-readable release state, the exact-source release gate and artifact receipts.

`RELEASE_STATE.json` keeps the source candidate and the published release apart: a source
version is never a published artifact by being in VERSION. `decide_release` allows the next,
separately authorised publish step only for the exact commit and tree whose required checks and
source-bound review are green; it publishes nothing. An artifact receipt binds an artifact digest
to that source and lives outside the artifact, so no file ever hashes itself.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA = 'release-state-v1'
OID = re.compile(r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
SHA256 = re.compile(r'^[0-9a-f]{64}$')
VERSION = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
SOURCE_STATES = frozenset({'source_candidate', 'released'})
PASSING = frozenset({'success'})


class ReleaseStateError(ValueError):
    pass


@dataclass(frozen=True)
class ReleaseState:
    source_version: str
    source_state: str
    published: Mapping[str, Any] | None

    @property
    def published_version(self) -> str | None:
        return None if self.published is None else self.published['version']


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: tuple[str, ...] = ()


def _check(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def parse_release_state(data: Mapping[str, Any]) -> ReleaseState:
    errors: list[str] = []
    _check(data.get('schema_version') == SCHEMA, 'unknown schema_version', errors)
    source = data.get('source') or {}
    _check(bool(VERSION.fullmatch(str(source.get('version', '')))), 'source.version must be X.Y.Z', errors)
    _check(source.get('state') in SOURCE_STATES, 'source.state must be source_candidate or released', errors)
    published = data.get('published')
    if published is not None:
        _check(bool(VERSION.fullmatch(str(published.get('version', '')))), 'published.version must be X.Y.Z', errors)
        _check(published.get('tag') == f"v{published.get('version')}", 'published.tag must be v<version>', errors)
        for name in ('tag_object', 'commit', 'tree'):
            _check(bool(OID.fullmatch(str(published.get(name, '')))), f'published.{name} must be a Git object id', errors)
        artifact = published.get('artifact') or {}
        _check(bool(SHA256.fullmatch(str(artifact.get('sha256', '')))), 'published.artifact.sha256 must be SHA-256', errors)
        if source.get('state') == 'released':
            _check(source.get('version') == published.get('version'), 'a released source equals the published version', errors)
    else:
        _check(source.get('state') != 'released', 'a released source needs a published record', errors)
    if errors:
        raise ReleaseStateError('; '.join(errors))
    return ReleaseState(source_version=source['version'], source_state=source['state'], published=published)


def load_release_state(path: Path) -> ReleaseState:
    return parse_release_state(json.loads(path.read_text(encoding='utf-8')))


def validate_release_consistency(state: ReleaseState, root: Path) -> ValidationResult:
    """RELEASE_STATE agrees with VERSION, PROJECT_STATE and the README release line."""
    errors: list[str] = []
    version = (root / 'VERSION').read_text(encoding='utf-8').strip()
    _check(version == state.source_version, f'VERSION {version} != release state source {state.source_version}', errors)
    project = json.loads((root / 'PROJECT_STATE.json').read_text(encoding='utf-8'))
    _check(project.get('product_version') == state.source_version, 'PROJECT_STATE.product_version differs', errors)
    if state.published is not None:
        recorded = project.get('published_release') or {}
        for key, project_key in (('tag', 'tag'), ('tag_object', 'tag_object'), ('commit', 'merge_commit'), ('tree', 'tree')):
            _check(recorded.get(project_key) == state.published.get(key), f'PROJECT_STATE published_release.{project_key} differs', errors)
        _check((recorded.get('artifact') or {}).get('sha256') == state.published['artifact']['sha256'],
               'PROJECT_STATE published artifact digest differs', errors)
        readme = (root / 'README.md').read_text(encoding='utf-8')
        _check(f"Latest published: [{state.published['tag']}]" in readme, 'README does not name the published tag', errors)
        if state.source_state == 'source_candidate':
            _check(f'Current source: **{state.source_version} source candidate**' in readme,
                   'README does not call the source a candidate', errors)
    return ValidationResult(not errors, tuple(errors))


@dataclass(frozen=True)
class CheckRun:
    name: str
    conclusion: str | None  # success, failure, skipped, cancelled, neutral, None (pending/unknown)
    head_sha: str


@dataclass(frozen=True)
class ReleaseDecision:
    allowed: bool
    reasons: tuple[str, ...]
    source_commit: str
    source_tree: str
    version: str

    def to_dict(self) -> dict[str, Any]:
        return {'allowed': self.allowed, 'reasons': list(self.reasons), 'source_commit': self.source_commit,
                'source_tree': self.source_tree, 'version': self.version}


def decide_release(state: ReleaseState, *, source_commit: str, source_tree: str, required_checks: Iterable[str],
                   checks: Iterable[CheckRun], review: Mapping[str, Any] | None,
                   existing_tags: Mapping[str, str], metadata_tree_after_checks: str | None = None) -> ReleaseDecision:
    """Allow the separately authorised publish step only for this exact source; never publishes."""
    reasons: list[str] = []
    tag = f'v{state.source_version}'
    if not (OID.fullmatch(source_commit) and OID.fullmatch(source_tree)):
        reasons.append('SOURCE_IDENTITY_MALFORMED')
    by_name: dict[str, list[CheckRun]] = {}
    for run in checks:
        by_name.setdefault(run.name, []).append(run)
    for name in sorted(set(required_checks)):
        runs = [run for run in by_name.get(name, []) if run.head_sha == source_commit]
        if not runs:
            other = by_name.get(name, [])
            reasons.append(f'REQUIRED_CHECK_FOR_OTHER_HEAD:{name}' if other else f'REQUIRED_CHECK_MISSING:{name}')
        elif any(run.conclusion not in PASSING for run in runs):
            worst = sorted({str(run.conclusion) for run in runs if run.conclusion not in PASSING})
            reasons.append(f'REQUIRED_CHECK_NOT_SUCCESS:{name}:{",".join(worst)}')
    if review is None:
        reasons.append('REVIEW_MISSING')
    else:
        if review.get('tree') != source_tree or review.get('status') != 'pass':
            reasons.append('REVIEW_NOT_BOUND_TO_SOURCE_TREE')
    if metadata_tree_after_checks is not None and metadata_tree_after_checks != source_tree:
        reasons.append('SOURCE_CHANGED_AFTER_CHECKS')
    existing = existing_tags.get(tag)
    if existing is not None and existing != source_commit:
        reasons.append('TAG_POINTS_TO_OTHER_SOURCE')
    if state.published is not None and state.published['version'] == state.source_version \
            and state.published['commit'] != source_commit:
        reasons.append('VERSION_ALREADY_PUBLISHED_FROM_OTHER_SOURCE')
    return ReleaseDecision(allowed=not reasons, reasons=tuple(reasons), source_commit=source_commit,
                           source_tree=source_tree, version=state.source_version)


@dataclass(frozen=True)
class ReleaseArtifactReceipt:
    version: str
    source_commit: str
    source_tree: str
    artifact_name: str
    artifact_sha256: str
    toolchain: Mapping[str, str]
    publication_status: str = 'built'  # built, published, failed
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'release-artifact-receipt-v1', 'version': self.version,
                'source_commit': self.source_commit, 'source_tree': self.source_tree,
                'artifact_name': self.artifact_name, 'artifact_sha256': self.artifact_sha256,
                'toolchain': dict(self.toolchain), 'publication_status': self.publication_status,
                'details': dict(self.details)}


def artifact_receipt(decision: ReleaseDecision, artifact: Path, *, built_from_tree: str,
                     toolchain: Mapping[str, str]) -> ReleaseArtifactReceipt:
    if not decision.allowed:
        raise ReleaseStateError('release decision does not allow building a release artifact')
    if built_from_tree != decision.source_tree:
        raise ReleaseStateError('artifact was built from another tree than the decided source')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    return ReleaseArtifactReceipt(version=decision.version, source_commit=decision.source_commit,
                                  source_tree=decision.source_tree, artifact_name=artifact.name,
                                  artifact_sha256=digest, toolchain=toolchain)


def record_artifact(receipts: Path, receipt: ReleaseArtifactReceipt) -> Path:
    """Store the receipt beside, never inside, the artifact; refuse another digest for one release."""
    receipts.mkdir(parents=True, exist_ok=True)
    path = receipts / f'release-{receipt.version}.json'
    if path.exists():
        existing = json.loads(path.read_text(encoding='utf-8'))
        if existing['artifact_sha256'] != receipt.artifact_sha256 or existing['source_commit'] != receipt.source_commit:
            raise ReleaseStateError('a different artifact is already recorded for this release')
        if existing.get('publication_status') == 'published' and receipt.publication_status != 'published':
            return path
    path.write_text(json.dumps(receipt.to_dict(), sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    return path


def mark_publication(receipts: Path, version: str, *, published: bool, url: str | None = None) -> dict[str, Any]:
    path = receipts / f'release-{version}.json'
    record = json.loads(path.read_text(encoding='utf-8'))
    record['publication_status'] = 'published' if published else 'failed'
    if url:
        record.setdefault('details', {})['url'] = url
    path.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n', encoding='utf-8', newline='\n')
    return record
