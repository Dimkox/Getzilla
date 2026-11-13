from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from collections.abc import Callable

from . import fsx
from .review_source import review_source_binding
from .state import serialized_task, require_route_owner
from .architecture import (
    ArchitectureError,
    RULES_PATH,
    SYSTEM_PATH,
    _read_regular_bytes,
    architecture_digests,
    architecture_fingerprint,
    contract_inventory,
    contract_inventory_digest,
    load_architecture,
    parse_adoption_marker,
)
from .architecture_diff import _exact_commit, _git, _git_blob, select_architecture_comparison_base
from .governance import (
    DEBT_PATH,
    EXAMPLES_PATH,
    RULES_PATH as GOVERNANCE_RULES_PATH,
    GovernanceError,
    governance_summary,
    load_governance,
)
from .spec import canonical_spec_digest, load_spec, spec_fingerprint, validate_spec
from .state import get_active_change, get_active_route
from .util import dump_json, load_json, now_utc, runtime_dir, tree_fingerprint

ADOPTION_PATH = Path("architecture/adoption.json")
_GOVERNANCE_PATHS = (GOVERNANCE_RULES_PATH, DEBT_PATH, EXAMPLES_PATH)
# Keep byte-identical to workflow_artifacts.RECEIPT_KINDS (parity-tested).
# Domain reviewer kinds come from router.py review selection and getzilla_review CLI.
RECEIPT_KINDS = frozenset(
    {
        "verification",
        "code_review",
        "test_review",
        "bitrix_review",
        "security_review",
        "data_review",
        "release_review",
    }
)
MAX_RECEIPT_BYTES = 262_144
MAX_VERIFICATION_REPORT_BYTES = 8_388_608
VERIFICATION_REPORT_CONTRACT = 'adaptive-grok.verification-report/v1'


def _open_receipt_directory_windows(root: Path, route_id: str, *, create: bool) -> fsx.DirHandle:
    """Windows has no directory descriptors: walk lstat-checked paths, refusing links/junctions."""
    handle = fsx.open_dir(root.resolve(strict=True))
    chain = [handle]
    for component in ('.getzilla', 'runtime', 'receipts', route_id):
        if create:
            try:
                fsx.mkdir_at(handle, component, 0o700)
            except FileExistsError:
                pass
        handle = fsx.open_dir_at(handle, component)
        chain.append(handle)
    _windows_confirm_directories(chain)
    return handle


def _windows_confirm_directories(handles: list[fsx.DirHandle]) -> None:
    """Re-check pinned Windows directories; a swapped or relinked one fails closed."""
    for handle in handles:
        current = fsx.fstat_dir(handle)
        if (current.st_dev, current.st_ino) != (handle.info.st_dev, handle.info.st_ino):
            raise OSError(errno.ENOTDIR, 'directory identity changed', fsx.path_of(handle))


def _windows_open_regular(directory: fsx.DirHandle, name: str, flags: int) -> int | None:
    """Windows stand-in for an ``O_NOFOLLOW`` open: refuse links, then pin the opened identity.

    ``None`` marks an existing entry that is neither a link nor a regular file;
    POSIX opens it and the caller's ``S_ISREG`` check rejects it.
    """
    expected = fsx.lstat_at(directory, name)
    if fsx.is_link(expected):
        raise OSError(errno.ELOOP, 'refusing to follow a link or reparse point', name)
    if not stat.S_ISREG(expected.st_mode):
        return None
    descriptor = fsx.open_at(directory, name, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError(errno.ELOOP, 'entry changed between inspection and open', name)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_receipt_directory(root: Path, route_id: str, *, create: bool = False) -> fsx.DirHandle:
    """Pin the route directory; never traverse a runtime symlink."""
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', route_id):
        raise RuntimeError('receipt route is outside the closed set')
    if fsx.WINDOWS:
        return _open_receipt_directory_windows(root, route_id, create=create)
    required_flags = ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')
    if any(not hasattr(os, name) for name in required_flags) or os.open not in getattr(os, 'supports_dir_fd', set()):
        raise RuntimeError('descriptor-safe receipt reads are unavailable')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open(root.resolve(strict=True), flags)
    try:
        for component in ('.getzilla', 'runtime', 'receipts', route_id):
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                os.fsync(descriptor)
            next_fd = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded_json(directory_fd: fsx.DirHandle, name: str, limit: int, label: str,
                       *, _observation: list | None = None) -> tuple[dict[str, Any], bytes]:
    if fsx.WINDOWS:
        opened = _windows_open_regular(directory_fd, name, os.O_RDONLY)
        if opened is None:
            raise RuntimeError(f'{label} is not a bounded regular file')
        descriptor = opened
    else:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RuntimeError(f'{label} is not a bounded regular file')
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise RuntimeError(f'{label} exceeds the byte limit')
        after = os.fstat(descriptor)
        if (_metadata_identity(before), before.st_size) != (_metadata_identity(after), after.st_size):
            raise RuntimeError(f'{label} changed while being read')
        if fsx.WINDOWS:
            _windows_confirm_directories([directory_fd])

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in items:
                if key in value:
                    raise RuntimeError(f'{label} contains a duplicate JSON key')
                value[key] = item
            return value

        content = b''.join(chunks)
        data = json.loads(content.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                          parse_constant=lambda token: (_ for _ in ()).throw(RuntimeError(f'invalid {label} value: {token}')))
        if not isinstance(data, dict):
            raise RuntimeError(f'{label} must be a JSON object')
        if _observation is not None:
            named = fsx.lstat_at(directory_fd, name)
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns')
            if any(getattr(named, key) != getattr(after, key) for key in fields):
                raise RuntimeError(f'{label} name changed while being read')
            directory = fsx.fstat_dir(directory_fd)
            _observation.append((label, name, directory.st_dev, directory.st_ino,
                _metadata_identity(after), after.st_size, after.st_uid, after.st_nlink,
                hashlib.sha256(content).hexdigest()))
        return data, content
    finally:
        os.close(descriptor)


def _verification_report_binding(receipt: dict[str, Any]) -> dict[str, Any]:
    # Explicit invalidation remains on the envelope, not in the immutable artifact.
    return {key: value for key, value in receipt.items() if key not in {'details', 'stale', 'stale_reason', 'stale_at'}}


@dataclass
class _PublishedVerificationReport:
    reference: dict[str, Any]
    route_fd: fsx.DirHandle
    reports_fd: fsx.DirHandle
    owned_file_identity: tuple[int, int] | None = None

    def close(self) -> None:
        fsx.close_dir(self.reports_fd)
        fsx.close_dir(self.route_fd)


def _cleanup_verification_report(publication: _PublishedVerificationReport) -> None:
    """Retire only this attempt's unchanged, unreferenced digest file."""
    if publication.owned_file_identity is None:
        return
    try:
        try:
            envelope, _ = _read_bounded_json(publication.route_fd, 'verification.json', MAX_RECEIPT_BYTES, 'receipt')
        except FileNotFoundError:
            envelope = {}
        if envelope.get('details') == {'_verification_report': publication.reference}:
            return
        filename = f'{publication.reference["sha256"]}.json'
        metadata = fsx.lstat_at(publication.reports_fd, filename)
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != publication.owned_file_identity:
            return
        # Own link/unlink may change ctime; qualify bytes against the staged digest,
        # then require stable metadata throughout this bounded descriptor-safe read.
        _, content = _read_bounded_json(publication.reports_fd, filename, MAX_VERIFICATION_REPORT_BYTES, 'verification report')
        if len(content) != publication.reference['bytes'] or hashlib.sha256(content).hexdigest() != publication.reference['sha256']:
            return
        after = fsx.lstat_at(publication.reports_fd, filename)
        if (_metadata_identity(metadata), metadata.st_size) == (_metadata_identity(after), after.st_size):
            fsx.unlink_at(publication.reports_fd, filename)
            fsx.fsync_dir(publication.reports_fd)
    except (OSError, RuntimeError, ValueError):
        # Unsafe/changed evidence is not ours to delete; preserve the original fault.
        pass


def _publish_verification_report(root: Path, route_id: str, receipt: dict[str, Any], interrupt_check: Callable[[], None] | None) -> _PublishedVerificationReport:
    """Durably publish complete details before any receipt may reference them."""
    artifact = {'schema_version': 1, 'binding': _verification_report_binding(receipt), 'details': receipt['details']}
    content = json.dumps(artifact, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
    payload = content.encode('utf-8')
    if len(payload) > MAX_VERIFICATION_REPORT_BYTES:
        raise ValueError('verification report exceeds the byte limit')
    digest = hashlib.sha256(payload).hexdigest()
    filename = f'{digest}.json'
    route_fd = _open_receipt_directory(root, route_id, create=True)
    reports_fd = None
    temporary = None
    publication = None
    completed = False
    try:
        try:
            fsx.mkdir_at(route_fd, 'reports', 0o700)
        except FileExistsError:
            pass
        fsx.fsync_dir(route_fd)
        reports_fd = fsx.open_dir_at(route_fd, 'reports', flags=fsx.O_CLOEXEC)
        temporary = f'.{digest}.{secrets.token_hex(16)}.tmp'
        descriptor = fsx.open_at(reports_fd, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW | fsx.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            _write_receipt_bytes(handle, content)
            staged_metadata = os.fstat(handle.fileno())
        if interrupt_check:
            interrupt_check()
        reference = {'contract': VERIFICATION_REPORT_CONTRACT, 'path': f'.getzilla/runtime/receipts/{route_id}/reports/{filename}', 'sha256': digest, 'bytes': len(payload)}
        publication = _PublishedVerificationReport(reference, route_fd, reports_fd)
        # Pin ownership before publication, including a fault immediately after link.
        publication.owned_file_identity = (staged_metadata.st_dev, staged_metadata.st_ino)
        try:
            # Atomic no-clobber publication: an existing digest is reused, never replaced.
            # Windows: an NTFS hard link has the same contract (fails if the name exists).
            fsx.link_at(reports_fd, temporary, reports_fd, filename)
        except FileExistsError:
            publication.owned_file_identity = None
            _, existing = _read_bounded_json(reports_fd, filename, MAX_VERIFICATION_REPORT_BYTES, 'verification report')
            if existing != payload:
                raise RuntimeError('existing verification report differs from its digest')
        else:
            metadata = fsx.lstat_at(reports_fd, filename)
            if (metadata.st_dev, metadata.st_ino) != (staged_metadata.st_dev, staged_metadata.st_ino):
                raise RuntimeError('published verification report identity changed')
        fsx.unlink_at(reports_fd, temporary)
        temporary = None
        if publication.owned_file_identity is not None:
            metadata = fsx.lstat_at(reports_fd, filename)
            if (metadata.st_dev, metadata.st_ino) != (staged_metadata.st_dev, staged_metadata.st_ino):
                raise RuntimeError('published verification report identity changed')
        fsx.fsync_dir(reports_fd)
        if interrupt_check:
            interrupt_check()
        completed = True
        return publication
    except BaseException:
        if publication is not None:
            _cleanup_verification_report(publication)
        raise
    finally:
        try:
            if temporary is not None:
                try:
                    fsx.unlink_at(reports_fd, temporary)
                except FileNotFoundError:
                    pass
        finally:
            if not completed:
                if reports_fd is not None:
                    fsx.close_dir(reports_fd)
                fsx.close_dir(route_fd)


def _hydrate_verification_report(directory_fd: fsx.DirHandle, route_id: str, receipt: dict[str, Any],
                                  *, _observation: list | None = None) -> None:
    details = receipt.get('details')
    if not isinstance(details, dict) or '_verification_report' not in details:
        return
    reference = details['_verification_report']
    if set(details) != {'_verification_report'} or not isinstance(reference, dict) or set(reference) != {'contract', 'path', 'sha256', 'bytes'}:
        raise RuntimeError('verification report reference has an invalid schema')
    digest = reference['sha256']
    size = reference['bytes']
    if (reference['contract'] != VERIFICATION_REPORT_CONTRACT or not isinstance(digest, str)
            or not re.fullmatch(r'[0-9a-f]{64}', digest) or type(size) is not int
            or not 0 < size <= MAX_VERIFICATION_REPORT_BYTES
            or reference['path'] != f'.getzilla/runtime/receipts/{route_id}/reports/{digest}.json'):
        raise RuntimeError('verification report reference is outside the closed contract')
    reports_fd = None
    try:
        reports_fd = fsx.open_dir_at(directory_fd, 'reports', flags=fsx.O_CLOEXEC)
        artifact, content = _read_bounded_json(reports_fd, f'{digest}.json', MAX_VERIFICATION_REPORT_BYTES,
                                              'verification report', _observation=_observation)
    except FileNotFoundError as exc:
        raise RuntimeError('referenced verification report is missing') from exc
    finally:
        if reports_fd is not None:
            fsx.close_dir(reports_fd)
    if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
        raise RuntimeError('verification report digest or byte count does not match')
    if (set(artifact) != {'schema_version', 'binding', 'details'} or type(artifact['schema_version']) is not int
            or artifact['schema_version'] != 1 or not isinstance(artifact['details'], dict)
            or artifact['binding'] != _verification_report_binding(receipt)):
        raise RuntimeError('verification report binding does not match its receipt')
    receipt['details'] = artifact['details']
    receipt['details_reference'] = reference


def _exact_head(root: Path) -> str | None:
    try:
        raw = _git(root, ["rev-parse", "--verify", "HEAD^{commit}"], allow_failure=True)
    except ValueError:
        return None
    if raw is None:
        return None
    value = raw.decode("ascii", "strict").strip()
    if len(value) == 40 and all(character in "0123456789abcdef" for character in value):
        return value
    return None


@dataclass(frozen=True)
class _AuthorityState:
    entries: tuple[bool, bool, bool]
    root_identity: tuple[int, int, int, int, int]
    architecture_identity: tuple[int, int, int, int, int] | None


def _authority_presence(root: Path, *, root_fd: int | None = None) -> _AuthorityState:
    """Establish stable fixed-entry absence without requiring byte-read primitives."""
    resolved = root.resolve(strict=True)
    architecture = resolved / "architecture"
    try:
        root_before = os.lstat(resolved)
        try:
            before = os.lstat(architecture)
        except FileNotFoundError:
            try:
                os.lstat(architecture)
            except FileNotFoundError:
                root_after = os.lstat(resolved)
                if _metadata_identity(root_before) != _metadata_identity(root_after):
                    raise ArchitectureError(
                        "architecture authority changed during absence inspection", code="io"
                    )
                return _AuthorityState(
                    entries=(False, False, False),
                    root_identity=_metadata_identity(root_before),
                    architecture_identity=None,
                )
            raise ArchitectureError(
                "architecture authority appeared during absence inspection", code="io"
            )
        # fsx.is_link is S_ISLNK on POSIX and also catches junctions/reparse points on Windows.
        if not stat.S_ISDIR(before.st_mode) or fsx.is_link(before):
            raise ArchitectureError("architecture authority directory is unsafe", code="io")
        present: list[bool] = []
        for path in (ADOPTION_PATH, SYSTEM_PATH, RULES_PATH):
            try:
                os.lstat(resolved / path)
            except FileNotFoundError:
                present.append(False)
            except OSError as exc:
                raise ArchitectureError(
                    f"architecture authority cannot be inspected: {exc}", code="io"
                ) from exc
            else:
                present.append(True)
        try:
            after = os.lstat(architecture)
        except OSError as exc:
            raise ArchitectureError(
                f"architecture authority changed during inspection: {exc}", code="io"
            ) from exc
        if _metadata_identity(before) != _metadata_identity(after):
            raise ArchitectureError("architecture authority changed during inspection", code="io")
        root_after = os.lstat(resolved)
        if _metadata_identity(root_before) != _metadata_identity(root_after):
            raise ArchitectureError("repository root changed during authority inspection", code="io")
        return _AuthorityState(
            entries=tuple(present),  # type: ignore[arg-type]
            root_identity=_metadata_identity(root_before),
            architecture_identity=_metadata_identity(before),
        )
    except OSError as exc:
        raise ArchitectureError(f"architecture authority cannot be inspected: {exc}", code="io") from exc


def _metadata_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _confirm_legacy_absence(
    root: Path,
    root_fd: int | None,
    initial: _AuthorityState,
) -> None:
    current = _authority_presence(root, root_fd=root_fd)
    if current != initial or current.entries != (False, False, False):
        raise RuntimeError("architecture authority appeared during legacy detection")


def _architecture_adoption(root: Path, *, present: bool | None = None) -> dict[str, str] | None:
    if present is None:
        present = _authority_presence(root).entries[0]
    if not present:
        return None
    data = _read_regular_bytes(
        root,
        ADOPTION_PATH.as_posix(),
        label="architecture adoption",
    )
    return parse_adoption_marker(data)


def _exact_tree_has_architecture(root: Path, sha: str) -> bool:
    return any(
        _git_blob(root, sha, path) is not None
        for path in (ADOPTION_PATH.as_posix(), SYSTEM_PATH.as_posix(), RULES_PATH.as_posix())
    )


def _exact_history_has_architecture(root: Path, head: str) -> bool:
    raw = _git(
        root,
        [
            "rev-list",
            "--full-history",
            "--max-count=64",
            head,
            "--",
            ADOPTION_PATH.as_posix(),
        ],
        limit=64 * 41,
    )
    if raw is None:
        raise ArchitectureError("cannot inspect bounded architecture history", code="git")
    commits = raw.decode("ascii", "strict").splitlines()
    if len(commits) > 64:
        raise ArchitectureError("architecture history inventory is unbounded", code="limit")
    for value in commits:
        if len(value) != 40 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ArchitectureError("architecture history contains an invalid commit", code="git")
    return bool(commits)


def _history_is_shallow(root: Path) -> bool:
    raw = _git(root, ["rev-parse", "--is-shallow-repository"], limit=16)
    if raw not in {b"true\n", b"false\n"}:
        raise ArchitectureError("cannot determine repository history completeness", code="git")
    return raw == b"true\n"


def _qualified_architecture_comparison(root: Path, route: dict[str, Any], head: str):
    """Reuse an exact completed qualification, never a reconcile-only assessment.

    This reads existing workflow evidence; it grants no new PASS or independent
    authority. Git ancestry/model/ref currentness is revalidated by the selector.
    """
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
    from .architecture_diff import ArchitectureBaseSelection, _comparison_model_digest, _digest as comparison_digest, _git
    names = set(ArchitectureBaseSelection.__dataclass_fields__)
    if (type(witness) is not dict or set(witness) != names
            or architecture.get('architecture_comparison_witness') != witness
            or witness.get('candidate_sha') != head or witness.get('route_base_sha') != route.get('base_commit')
            or witness.get('base_kind') != 'accepted_target' or witness.get('bootstrap_baseline') is not False
            or witness.get('range_mode') != report['mode']
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
            or comparison_digest(old_range) != witness['ranges_digest']
            or _comparison_model_digest(root, (witness['route_base_sha'], witness['target_sha'], head)) != witness['model_digest']):
        raise ArchitectureError('qualified architecture comparison identity is stale', code='git')
    for name in ('architecture_base_sha', 'architecture_base_kind', 'architecture_bootstrap_baseline',
                 'architecture_route_base_sha', 'architecture_head_commit'):
        if architecture.get(name) != receipt.get(name):
            raise ArchitectureError('qualification architecture bindings disagree', code='git')
    # Prove live acceptance separately from the frozen plan's binding ranges.
    # This lower-level compiler never calls the range/witness reader again.
    from .verification import GitRangeBase, GitRangeSelection, _select_local_pr_target, _resolve_commit
    target = _select_local_pr_target(root)
    if not isinstance(target, tuple) or target[0] != witness['target_ref']:
        return None
    accepted = _git(root, ['merge-base', '--all', head, target[1]])
    if accepted is None or accepted.decode().splitlines() != [head]:
        return None
    frozen = GitRangeSelection([GitRangeBase(**row) for row in old_range['bases']], mode=witness['range_mode'], head_sha=head)
    try:
        from .verification_plan import _compile_required_plan, _report_plan_gaps
        current = _compile_required_plan(root, mode=report.get('mode'), profiles=report.get('profiles'),
                                         docs_scope=None, route=route, ranges=frozen)
        if _report_plan_gaps(root, report, current):
            return None
        if _compile_required_plan(root, mode=report.get('mode'), profiles=report.get('profiles'),
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


def _active_architecture_binding(
    root: Path,
    route: dict[str, Any],
    root_fd: int | None,
    *,
    _trusted_ranges: Any = None,
) -> dict[str, Any] | None:
    authority = _authority_presence(root, root_fd=root_fd)
    adoption = _architecture_adoption(root, present=authority.entries[0])
    present = authority.entries[1:]
    if adoption is None:
        if present != (False, False):
            raise RuntimeError("architecture adoption marker is missing")
        head = _exact_head(root)
        if head is None:
            _confirm_legacy_absence(root, root_fd, authority)
            return None
        route_base = _exact_commit(root, route.get('base_commit', head), label='architecture_route_base_sha')
        exact_evidence = _exact_tree_has_architecture(root, head) or _exact_tree_has_architecture(
            root, route_base
        )
        if not exact_evidence:
            exact_evidence = _exact_history_has_architecture(root, head)
        if exact_evidence:
            raise RuntimeError("adopted architecture marker and model are missing")
        if _history_is_shallow(root):
            raise RuntimeError(
                "architecture adoption history is incomplete in a shallow repository"
            )
        _confirm_legacy_absence(root, root_fd, authority)
        return None
    if present == (False, False):
        raise RuntimeError("adopted architecture model is missing")
    if present != (True, True):
        raise RuntimeError("adopted architecture model is partially missing")
    snapshot = load_architecture(root)
    if snapshot.system["architecture_id"] != adoption["architecture_id"]:
        raise RuntimeError("architecture adoption marker id does not match the model")
    records = contract_inventory(root, snapshot)
    digests = architecture_digests(snapshot)
    head = _exact_head(root)
    if head is None:
        raise RuntimeError("architecture binding requires an exact Git HEAD")
    base_selection = select_architecture_comparison_base(root, route, _trusted_ranges=_trusted_ranges)
    fingerprint = architecture_fingerprint(
        root,
        snapshot,
        base_sha=base_selection.comparison_base_sha,
        head_sha=f"worktree:{head}",
        contract_digests={record.path: record.digest for record in records},
    )
    if select_architecture_comparison_base(root, route, _trusted_ranges=_trusted_ranges) != base_selection:
        raise RuntimeError('architecture comparison changed during binding')
    return {
        "architecture_adoption_digest": adoption["digest"],
        "architecture_base_sha": base_selection.comparison_base_sha,
        "architecture_base_kind": base_selection.base_kind,
        "architecture_bootstrap_baseline": base_selection.bootstrap_baseline,
        "architecture_contract_digests": {record.path: record.digest for record in records},
        "architecture_contract_inventory_digest": contract_inventory_digest(records),
        "architecture_digest": digests["architecture_digest"],
        "architecture_fingerprint": fingerprint,
        "architecture_head_commit": head,
        "architecture_head_kind": "worktree",
        "architecture_range_mode": base_selection.range_mode,
        "architecture_route_base_sha": base_selection.route_base_sha,
        "architecture_rules_digest": digests["rules_digest"],
        "architecture_schema_digest": digests["schema_digest"],
        "architecture_system_digest": digests["system_digest"],
        **({'architecture_comparison_witness': asdict(base_selection)} if base_selection.candidate_sha else {}),
    }


def active_architecture_binding(root: Path, route: dict[str, Any], *, _trusted_ranges: Any = None) -> dict[str, Any] | None:
    try:
        return _active_architecture_binding(root, route, None, _trusted_ranges=_trusted_ranges)
    except NotImplementedError as exc:
        raise ArchitectureError(
            f"architecture authority metadata is unavailable: {exc}", code="io"
        ) from exc


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ) + "\n"
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _governance_history_has_authority(root: Path) -> bool:
    head = _exact_head(root)
    if head is None:
        return False
    if any(_git_blob(root, head, path.as_posix()) is not None for path in _GOVERNANCE_PATHS):
        return True
    raw = _git(
        root,
        [
            "rev-list",
            "--full-history",
            "--max-count=64",
            head,
            "--",
            *(path.as_posix() for path in _GOVERNANCE_PATHS),
        ],
        limit=64 * 41,
    )
    if raw is None:
        raise RuntimeError("cannot inspect bounded governance history")
    commits = raw.decode("ascii", "strict").splitlines()
    if len(commits) > 64 or any(
        len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
        for value in commits
    ):
        raise RuntimeError("governance history inventory is invalid")
    if commits:
        return True
    if _history_is_shallow(root):
        raise RuntimeError(
            "governance adoption history is incomplete in a shallow repository"
        )
    return False


def _require_legacy_governance_absence(root: Path) -> None:
    if _governance_history_has_authority(root):
        raise RuntimeError("adopted governance registries are missing")
    for path in _GOVERNANCE_PATHS:
        try:
            os.lstat(root / path)
        except FileNotFoundError:
            continue
        raise RuntimeError("governance authority appeared during absence inspection")


def _governance_is_configured(root: Path) -> bool:
    resolved = root.resolve(strict=True)
    root_before = os.lstat(resolved)
    authority_root = resolved / "governance"
    try:
        authority_before = os.lstat(authority_root)
    except FileNotFoundError:
        try:
            os.lstat(authority_root)
        except FileNotFoundError:
            root_after = os.lstat(resolved)
            if _metadata_identity(root_before) != _metadata_identity(root_after):
                raise RuntimeError(
                    "repository root changed during governance absence inspection"
                )
            _require_legacy_governance_absence(root)
            return False
        raise RuntimeError("governance authority appeared during absence inspection")
    if not stat.S_ISDIR(authority_before.st_mode) or fsx.is_link(authority_before):
        raise RuntimeError("governance authority directory is unsafe")

    present: list[bool] = []
    directory_identities: list[tuple[Path, tuple[int, int, int, int, int]]] = []
    for relative in _GOVERNANCE_PATHS:
        directory = resolved / relative.parent
        try:
            directory_before = os.lstat(directory)
        except FileNotFoundError:
            present.append(False)
            continue
        except OSError as exc:
            raise RuntimeError(f"governance authority cannot be inspected: {exc}") from exc
        if not stat.S_ISDIR(directory_before.st_mode) or fsx.is_link(directory_before):
            raise RuntimeError(f"governance directory is unsafe: {relative.parent}")
        directory_identities.append((directory, _metadata_identity(directory_before)))
        try:
            os.lstat(resolved / relative)
        except FileNotFoundError:
            present.append(False)
        except OSError as exc:
            raise RuntimeError(f"governance authority cannot be inspected: {exc}") from exc
        else:
            present.append(True)
    for directory, identity in directory_identities:
        if _metadata_identity(os.lstat(directory)) != identity:
            raise RuntimeError("governance authority changed during inspection")
    if _metadata_identity(os.lstat(authority_root)) != _metadata_identity(
        authority_before
    ):
        raise RuntimeError("governance authority changed during inspection")
    if _metadata_identity(os.lstat(resolved)) != _metadata_identity(root_before):
        raise RuntimeError("repository root changed during governance inspection")
    if not any(present):
        _require_legacy_governance_absence(root)
        return False
    if not all(present):
        raise RuntimeError("governance registries are partially configured")
    return True


def active_governance_binding(
    root: Path,
    route: dict[str, Any],
    architecture: dict[str, Any] | None = None,
    *,
    _trusted_ranges: Any = None,
) -> dict[str, Any] | None:
    if not _governance_is_configured(root):
        return None
    try:
        current_architecture = (active_architecture_binding(root, route) if _trusted_ranges is None else
                                active_architecture_binding(root, route, _trusted_ranges=_trusted_ranges))
        if current_architecture is None:
            raise RuntimeError("governance requires adopted executable architecture")
        if architecture is not None and any(
            architecture.get(field) != current_architecture.get(field)
            for field in (
                "architecture_digest",
                "architecture_base_sha",
                "architecture_head_commit",
                "architecture_route_base_sha",
                "architecture_base_kind",
                "architecture_comparison_witness",
                "architecture_range_mode",
            )
        ):
            raise RuntimeError(
                "governance architecture binding differs from the checked snapshot"
            )
        architecture_binding = current_architecture
        snapshot = load_governance(root)
        summary = governance_summary(snapshot, now=datetime.now(timezone.utc))
        if not summary["ok"]:
            codes = ", ".join(item["code"] for item in summary["findings"])
            raise RuntimeError(f"governance validation failed: {codes}")
        evidence_core = {
            "contract": "adaptive-grok.governance-receipt-evidence/v1",
            "rules_digest": summary["rules_digest"],
            "debt_digest": summary["debt_digest"],
            "examples_digest": summary["examples_digest"],
            "schema_digest": summary["schema_digest"],
            "active_rule_ids": summary["active_rule_ids"],
            "active_example_ids_versions": summary[
                "active_example_ids_versions"
            ],
            "open_debt_ids": summary["open_debt_ids"],
            "overdue_debt_ids": summary["overdue_debt_ids"],
            "findings": summary["findings"],
            "architecture_digest": architecture_binding["architecture_digest"],
            "applicable_base_sha": architecture_binding["architecture_base_sha"],
            "head_commit": architecture_binding["architecture_head_commit"],
            "head_kind": "worktree",
            "overall_status": summary["overall_status"],
            "tree_fingerprint": tree_fingerprint(root),
        }
        return {
            "governance_contract_version": 1,
            "governance_digest": summary["governance_digest"],
            "governance_evidence_digest": _canonical_digest(evidence_core),
            "governance_architecture_digest": architecture_binding[
                "architecture_digest"
            ],
            "governance_applicable_base_sha": architecture_binding[
                "architecture_base_sha"
            ],
            "governance_applicable_head_sha": architecture_binding[
                "architecture_head_commit"
            ],
        }
    except (GovernanceError, OSError, TypeError, ValueError) as exc:
        raise RuntimeError(f"governance validation failed: {exc}") from exc


def receipt_dir(root: Path, route_id: str) -> Path:
    path = runtime_dir(root) / 'receipts' / route_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _active_spec_binding(root: Path, route: dict[str, Any], kind: str) -> dict[str, Any] | None:
    active = get_active_change(root) or {}
    rel = active.get('path')
    if not rel:
        return None
    path = root / str(rel) / 'change-spec.yaml'
    if not path.is_file():
        return None
    spec = load_spec(path, allow_legacy=False)
    errors = validate_spec(root, path, gate=False, route=route)
    if errors:
        raise RuntimeError('active change spec is invalid: ' + '; '.join(errors))
    criterion_ids = sorted({
        str(item.get('id'))
        for item in spec.get('acceptance_criteria') or []
        if any(isinstance(ref, dict) and ref.get('receipt') == kind for ref in item.get('evidence') or [])
    })
    return {
        'criterion_ids': criterion_ids,
        'spec_digest': canonical_spec_digest(spec),
        'spec_fingerprint': spec_fingerprint(root, path, spec, route),
    }


def _write_receipt_bytes(handle, content: str) -> None:
    handle.write(content)
    handle.flush()
    os.fsync(handle.fileno())


def _publish_receipt(path: Path, data: dict[str, Any], interrupt_check: Callable[[], None] | None) -> None:
    """Publish complete bytes, fsync the file and directory, invalidate on failure."""
    temporary = None
    directory = None
    try:
        content = json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True) + '\n'
        if len(content.encode('utf-8')) > MAX_RECEIPT_BYTES:
            raise ValueError('receipt exceeds the byte limit')
        descriptor, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as handle:
            _write_receipt_bytes(handle, content)
        if interrupt_check:
            interrupt_check()
        os.replace(temporary, path)
        if not fsx.WINDOWS:  # Windows cannot open or fsync a directory; the rename is the durability point.
            directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            os.fsync(directory)
        if interrupt_check:
            interrupt_check()
    except BaseException:
        # A prior pass, or a rename whose directory durability failed, cannot qualify.
        try:
            path.unlink(missing_ok=True)
            if not fsx.WINDOWS:
                if directory is None:
                    directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                os.fsync(directory)
        except OSError:
            pass
        raise
    finally:
        if directory is not None:
            os.close(directory)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _verification_architecture_options(root: Path, route: dict[str, Any], kind: str, details: Any) -> dict[str, Any]:
    if kind != 'verification' or not isinstance(details, dict) or 'mode' not in details:
        return {}
    from .verification import _git_range_selection, _RANGE_MODES
    if type(details['mode']) is not str or details['mode'] not in {'fast', *_RANGE_MODES}:
        raise RuntimeError('verification invocation mode is unavailable')
    return {'_trusted_ranges': _git_range_selection(root, route, details['mode'])}


@serialized_task
def write_receipt(
    root: Path,
    kind: str,
    status: str,
    report: str | None = None,
    details: dict[str, Any] | None = None,
    *,
    criterion_ids: list[str] | tuple[str, ...] | None = None,
    spec_digest: str | None = None,
    spec_fingerprint: str | None = None,
    expected_tree_fingerprint: str | None = None,
    interrupt_check: Callable[[], None] | None = None,
    reviewed_commit: str | None = None,
    reviewed_context: str | None = None,
    expected_context: dict[str, Any] | None = None,
) -> Path:
    route = get_active_route(root)
    if not route:
        raise RuntimeError('no active route')
    from .continuity import context_binding, legacy_evidence_allowed, scope_gaps
    require_route_owner(root, route)
    modern = not legacy_evidence_allowed(route)
    if modern and kind == 'verification' and status == 'pass' and expected_context is None:
        raise ValueError('verification PASS requires the task context observed before work')
    review_source = review_source_binding(root, reviewed_commit, report, reviewed_context=reviewed_context) if kind != 'verification' and status == 'pass' else None
    observed = expected_context
    if modern and review_source is not None:
        observed = context_binding(root, route)
    if observed is not None and observed != context_binding(root, route):
        raise ValueError('observed task context changed before receipt publication')
    if modern and status == 'pass':
        gaps = scope_gaps(root, route)
        if gaps:
            raise ValueError('; '.join(gaps))

    def assert_context() -> None:
        current_route = get_active_route(root)
        if not current_route or current_route.get('route_id') != route['route_id']:
            raise ValueError('task context changed during receipt publication')
        require_route_owner(root, current_route)
        if observed is not None and context_binding(root, current_route) != observed:
            raise ValueError('task context changed during receipt publication')
        if observed is None and status == 'pass' and not legacy_evidence_allowed(current_route):
            raise ValueError('legacy evidence cannot qualify a changed task context')
        if modern and status == 'pass' and scope_gaps(root, current_route):
            raise ValueError('scope changed during receipt publication')
    before_tree = tree_fingerprint(root)
    before_head = _exact_head(root)
    plan_digest = (route.get('review_plan') or {}).get('digest')
    if plan_digest:
        from .review_plan import validate_review_plan
        plan_errors = validate_review_plan(root, route)
        if plan_errors:
            raise RuntimeError('; '.join(plan_errors))
    if (
        expected_tree_fingerprint is not None
        and before_tree != expected_tree_fingerprint
    ):
        raise RuntimeError("repository changed after verification checks")
    current = _active_spec_binding(root, route, kind)
    architecture_options = _verification_architecture_options(root, route, kind, details)
    current_architecture = active_architecture_binding(root, route, **architecture_options)
    current_governance = active_governance_binding(
        root, route, current_architecture, **architecture_options
    )
    explicit = {
        'criterion_ids': sorted({str(item) for item in (criterion_ids or [])}),
        'spec_digest': spec_digest,
        'spec_fingerprint': spec_fingerprint,
    }
    if current is not None:
        for field in ('criterion_ids', 'spec_digest', 'spec_fingerprint'):
            supplied = explicit[field]
            if supplied not in (None, []) and supplied != current[field]:
                raise ValueError(f'explicit {field} does not match active spec')
        binding = current
    else:
        binding = explicit
    data = {
        'schema_version': 1,
        'route_id': route['route_id'],
        'kind': kind,
        'status': status,
        'created_at': now_utc(),
        'tree_fingerprint': before_tree,
        'git_head': before_head,
        **({'review_plan_digest': plan_digest} if plan_digest else {}),
        'report': report,
        'details': details or {},
        **({'review_source': review_source} if review_source is not None else {}),
        **({'continuity': observed} if observed is not None else {}),
        **binding,
        **(current_architecture or {}),
        **(current_governance or {}),
    }
    after_tree = tree_fingerprint(root)
    after_binding = _active_spec_binding(root, route, kind)
    after_architecture = active_architecture_binding(root, route, **architecture_options)
    after_governance = active_governance_binding(root, route, after_architecture, **architecture_options)
    if (
        (review_source is not None and review_source_binding(root, reviewed_commit, report, reviewed_context=reviewed_context) != review_source)
        or after_tree != before_tree
        or _exact_head(root) != before_head
        or after_binding != current
        or after_architecture != current_architecture
        or after_governance != current_governance
    ):
        raise RuntimeError('repository, spec, architecture, or governance changed while receipt was written')
    path = receipt_dir(root, route['route_id']) / f'{kind}.json'
    spill = kind == 'verification'
    publication = None
    receipt_publication_started = False
    try:
        assert_context()
        # Classification can fail to serialize; that must retire an older pass too.
        spill = spill and len((json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True) + '\n').encode('utf-8')) > MAX_RECEIPT_BYTES
        if spill:
            publication = _publish_verification_report(root, route['route_id'], data, interrupt_check)
            assert_context()
            report_architecture = active_architecture_binding(root, route, **architecture_options)
            if (tree_fingerprint(root) != before_tree or _exact_head(root) != before_head
                    or _active_spec_binding(root, route, kind) != current
                    or report_architecture != current_architecture
                    or active_governance_binding(root, route, report_architecture, **architecture_options) != current_governance):
                raise RuntimeError('repository or authority changed while verification report was written')
            data['details'] = {'_verification_report': publication.reference}
        assert_context()
        receipt_publication_started = True
        _publish_receipt(path, data, interrupt_check)
        assert_context()
    except BaseException:
        if spill or receipt_publication_started:
            directory_fd = None
            try:
                directory_fd = _open_receipt_directory(root, route['route_id'])
                fsx.unlink_at(directory_fd, f'{kind}.json')
                fsx.fsync_dir(directory_fd)
            except OSError:
                pass
            finally:
                if directory_fd is not None:
                    fsx.close_dir(directory_fd)
        if publication is not None:
            _cleanup_verification_report(publication)
        raise
    finally:
        if publication is not None:
            publication.close()
    from .route_metrics import record_receipt
    from .metrics_journal import digest
    record_receipt(root, route.get('route_id'), kind, status, identity=digest(data))
    return path


def get_receipt(root: Path, route_id: str, kind: str) -> dict[str, Any] | None:
    return _read_receipt(root, route_id, kind)


def _receipt_storage_identity(root: Path, route_id: str) -> tuple | None:
    """Observe the bounded envelope and immutable artifact through pinned readers."""
    observation: list = []
    data = _read_receipt(root, route_id, 'verification', _observation=observation)
    return tuple(observation) if data is not None else None


def _read_receipt(root: Path, route_id: str, kind: str, *, _observation: list | None = None) -> dict[str, Any] | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", route_id) or kind not in RECEIPT_KINDS:
        raise RuntimeError("receipt route or kind is outside the closed set")
    directory_fd: fsx.DirHandle | None = None
    try:
        directory_fd = _open_receipt_directory(root, route_id)
        data, _ = _read_bounded_json(directory_fd, f'{kind}.json', MAX_RECEIPT_BYTES,
                                    'receipt', _observation=_observation)
        if kind == 'verification':
            _hydrate_verification_report(directory_fd, route_id, data, _observation=_observation)
        return data
    except FileNotFoundError:
        return None
    except RuntimeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise RuntimeError(f"receipt cannot be read safely: {exc}") from exc
    finally:
        if directory_fd is not None:
            fsx.close_dir(directory_fd)


def validate_evidence(
    root: Path,
    route: dict[str, Any],
    *,
    current_fingerprint: str | None = None,
) -> list[str]:
    from .continuity import scope_gaps, receipt_context_current
    missing: list[str] = scope_gaps(root, route)
    if 'risk_assessment' in route:
        from .review_plan import validate_review_plan
        missing.extend(validate_review_plan(root, route))
    route_id = route.get('route_id')
    required = route.get('required_evidence')
    if (
        not isinstance(route_id, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", route_id)
        or not isinstance(required, list)
        or not required
        or len(required) > len(RECEIPT_KINDS)
        or any(not isinstance(kind, str) or kind not in RECEIPT_KINDS for kind in required)
        or len(set(required)) != len(required)
    ):
        return ["route: required_evidence is empty, duplicated, or outside the closed receipt set"]
    if current_fingerprint is not None and not re.fullmatch(r"[0-9a-f]{64}", current_fingerprint):
        return ["route: trusted current fingerprint is invalid"]
    current = current_fingerprint or tree_fingerprint(root)
    base_fields = {
        'schema_version',
        'route_id',
        'kind',
        'status',
        'created_at',
        'tree_fingerprint',
        'report',
        'details',
        'criterion_ids',
        'spec_digest',
        'spec_fingerprint',
    }
    escalated = _escalated_evidence(root, route_id, required, current)
    waived = _waived_evidence(root, route_id, required, current)
    for kind in [*[item for item in required if item not in waived], *escalated]:
        try:
            receipt = get_receipt(root, route_id, kind)
        except RuntimeError as exc:
            missing.append(f'{kind}: unsafe receipt: {exc}')
            continue
        if not receipt:
            missing.append(f'{kind}: missing receipt')
            continue
        if not receipt_context_current(root, route, receipt):
            missing.append(f'{kind}: task context binding stale or unavailable')
        if (
            not base_fields.issubset(receipt)
            or receipt.get('schema_version') != 1
            or receipt.get('route_id') != route_id
            or receipt.get('kind') != kind
            or receipt.get('status') not in {'pass', 'fail'}
            or not isinstance(receipt.get('created_at'), str)
            or not isinstance(receipt.get('details'), dict)
            or not isinstance(receipt.get('criterion_ids'), list)
        ):
            missing.append(f'{kind}: malformed receipt envelope')
        if receipt.get('status') != 'pass':
            missing.append(f'{kind}: status={receipt.get("status")}')
        if receipt.get('stale') is True:
            missing.append(f'{kind}: explicitly invalidated')
        if kind == 'verification' and receipt.get('status') == 'pass':
            from .verification_plan import report_gaps
            if report_gaps(root, receipt.get('details')):
                missing.append('verification: current required plan or individual evidence is unavailable or stale')
        plan_digest = (route.get('review_plan') or {}).get('digest')
        if plan_digest and receipt.get('review_plan_digest') != plan_digest:
            missing.append(f'{kind}: review plan binding stale')
        if receipt.get('tree_fingerprint') != current:
            missing.append(f'{kind}: stale after repository changes')
        if 'git_head' in receipt and receipt['git_head'] != _exact_head(root):
            missing.append(f'{kind}: stale after Git head changes')
        if kind != 'verification' and receipt.get('status') == 'pass':
            try:
                source = receipt.get('review_source')
                if not isinstance(source, dict) or review_source_binding(root, source.get('reviewed_commit'), receipt.get('report'), reviewed_context=source.get('reviewed_context')) != source:
                    raise RuntimeError('missing or forged reviewed source binding')
            except (RuntimeError, ValueError, OSError, UnicodeError) as exc:
                missing.append(f'{kind}: review source invalid: {exc}')
        try:
            binding = _active_spec_binding(root, route, kind)
        except (RuntimeError, ValueError) as exc:
            missing.append(f'{kind}: active spec invalid: {exc}')
            continue
        if binding is not None:
            if receipt.get('spec_digest') != binding['spec_digest'] or receipt.get('spec_fingerprint') != binding['spec_fingerprint']:
                missing.append(f'{kind}: spec binding stale')
            if receipt.get('criterion_ids') != binding['criterion_ids']:
                missing.append(f'{kind}: criterion binding stale')
        try:
            architecture_options = _verification_architecture_options(root, route, kind, receipt.get('details'))
            architecture = active_architecture_binding(root, route, **architecture_options)
        except (RuntimeError, ValueError) as exc:
            missing.append(f'{kind}: architecture binding stale: {exc}')
            continue
        if architecture is not None:
            if any(receipt.get(field) != value for field, value in architecture.items()):
                missing.append(f'{kind}: architecture binding stale')
        elif "architecture_digest" in receipt or "architecture_fingerprint" in receipt:
            missing.append(f'{kind}: architecture binding stale')
        try:
            governance = active_governance_binding(root, route, architecture, **architecture_options)
        except (RuntimeError, ValueError) as exc:
            missing.append(f'{kind}: governance binding stale: {exc}')
            continue
        if governance is not None:
            if any(receipt.get(field) != value for field, value in governance.items()):
                missing.append(f'{kind}: governance binding stale')
        elif "governance_digest" in receipt or "governance_evidence_digest" in receipt:
            missing.append(f'{kind}: governance binding stale')
    if escalated:
        missing = [f'{item} (required by exact-head diff risk)' if item.split(':', 1)[0] in escalated else item
                   for item in missing]
    return missing


def _escalated_evidence(root: Path, route_id: str, required: list[str], current: str) -> list[str]:
    """Evidence the current verification receipt added because the diff was riskier than the route."""
    if 'verification' not in required:
        return []
    try:
        receipt = get_receipt(root, route_id, 'verification')
    except RuntimeError:
        return []
    if not isinstance(receipt, dict) or receipt.get('tree_fingerprint') != current:
        return []
    from .continuity import receipt_context_current
    if not receipt_context_current(root, get_active_route(root) or {}, receipt):
        return []
    details = receipt.get('details') if isinstance(receipt.get('details'), dict) else {}
    diff = details.get('diff_risk') if isinstance(details.get('diff_risk'), dict) else {}
    added = diff.get('added_evidence') if isinstance(diff.get('added_evidence'), list) else []
    return [kind for kind in added if isinstance(kind, str) and kind in RECEIPT_KINDS and kind not in required]


def _waived_evidence(root: Path, route_id: str, required: list[str], current: str) -> list[str]:
    """Reviews a current, passing verification proved unnecessary (TRIVIAL_PROVEN_BY_DIFF); never verification."""
    if 'verification' not in required:
        return []
    try:
        receipt = get_receipt(root, route_id, 'verification')
    except RuntimeError:
        return []
    if not isinstance(receipt, dict) or receipt.get('status') != 'pass' or receipt.get('stale') is True \
            or receipt.get('tree_fingerprint') != current:
        return []
    from .continuity import receipt_context_current
    if not receipt_context_current(root, get_active_route(root) or {}, receipt):
        return []
    details = receipt.get('details') if isinstance(receipt.get('details'), dict) else {}
    diff = details.get('diff_risk') if isinstance(details.get('diff_risk'), dict) else {}
    if diff.get('profile_reason') != 'TRIVIAL_PROVEN_BY_DIFF' or diff.get('effective_risk') != 'low':
        return []
    raw = diff.get('waived_evidence') if isinstance(diff.get('waived_evidence'), list) else []
    waived = [kind for kind in raw if isinstance(kind, str) and kind in RECEIPT_KINDS and kind != 'verification']
    kept = [kind for kind in required if kind not in waived]
    if not any(kind.endswith('_review') for kind in kept):
        return []  # one independent review always stays
    return waived


def invalidate_receipts(root: Path, route_id: str, reason: str) -> None:
    path = receipt_dir(root, route_id)
    for receipt_path in path.glob('*.json'):
        receipt = load_json(receipt_path)
        if not isinstance(receipt, dict):
            continue
        receipt['stale'] = True
        receipt['stale_reason'] = reason
        receipt['stale_at'] = now_utc()
        dump_json(receipt_path, receipt)
