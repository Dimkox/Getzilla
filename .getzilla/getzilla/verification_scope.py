"""Bounded documentation/state change-scope classification for route verification.

The full PR suite exists to measure executed product statements, so it stays the only
admissible profile for any change that can alter executed behavior. A change confined to
prose, the dated state model, tracked release bytes, and the modules that bind those together
cannot move a product statement, so it does not owe a full-suite run.

Like the static-landing selector, this is a closed selector: a path is admitted only by an
explicit allowlist entry, so an unknown directory, an unknown root file, a deleted or
renamed path, an unresolved comparison base, or an absent route all keep the caller on the
full PR verifier. The decision grants no merge authority and never relaxes fingerprint
binding, receipt writing, or independent review.

Admission is decided by the *role the bytes play*, not by the directory a file happens to
sit in, because two prose-looking classes break the invariant this lane is built on: content
that is shipped and executed somewhere else (``docs/bitrix-local-AGENTS.md`` is installed
verbatim as ``local/AGENTS.md`` into every consumer Bitrix install, so it is agent-executed
instructions, not documentation), and content a test pins to literal bytes as declared
immutable evidence (``tests/test_history.py`` sha256-pins ``evidence/historical-*``). Both are
rejected here even though they live under a documentation path. What remains is admitted on one
of two grounds: a module this lane runs re-derives it (root identity, dated state and package
bytes by the lockstep trio; README's Workflow-sources table by ``tests/test_workflow_sources.py``;
a delivered change package's route record by ``tests/test_repo_router.py``), or nothing executes
it at all (per-change workflow records, ADRs, backlogs, reviews and runbooks), so there is no
binding for it to lose.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from .git_ranges import GitRangeSelection


SCHEMA_VERSION = 1
DOCS_STATE_PROFILE = 'docs-state-focused'
FULL_PROFILE = 'full-pr-suite'
FORCE_FULL_VARIABLE = 'GETZILLA_VERIFY_FORCE_FULL'

# Prose that carries no executed behavior. Membership is explicit: a new root-level file
# is not documentation until it is declared here, and tests/test_structure.py already
# rejects an unexpected canonical root entry.
DOCUMENT_ROOT_FILES = frozenset({
    'AGENTS.md',
    'CHANGELOG.md',
    'DARK_FACTORY_ROADMAP.md',
    'FACTORY_TZ_v1.5_ADDENDUM_QG-01.md',
    'GROK_BUILD_HANDOFF.md',
    'LICENSE',
    'QUICKSTART.md',
    'README.md',
    'START_HERE.md',
    'decisions.md',
    'mistakes.md',
})
# Named documentation files below the repository root. There is deliberately no ``docs/``
# prefix: a directory is not a content role, and ``docs/`` also holds shipped product (see
# ``SHIPPED_EXECUTED_FILES``). A documentation file added later is not admitted until it is
# declared here, so the lane stays closed without anyone having to re-narrow a prefix.
DOCUMENT_FILES = frozenset({
    'docs/INVESTOR_DEMO.md',
    'docs/package-status.md',
    'engineering/decisions.md',
    'engineering/mistakes.md',
})
# Directory-shaped prefixes only. A prefix that does not end in a separator admits sibling
# names by string collision (``engineering/decisions.md.bak``), which is why the two dated
# decision logs above are named exactly instead of sitting here.
DOCUMENT_PREFIXES = (
    'docs/superpowers/plans/',
    'docs/superpowers/specs/',
    'engineering/adr/',
    'engineering/backlog/',
    'engineering/changes/',
    'engineering/project-confirmations/',
    'engineering/reviews/',
    'engineering/runbooks/',
)
# Documentation in name only. These bytes are installed verbatim into a consumer product and
# executed by an agent there, so editing them is a product change that owes the executed
# suite: scripts/install_into.py installs ``docs/bitrix-local-AGENTS.md`` as
# ``local/AGENTS.md`` in every Bitrix install, and tests/test_installer.py proves it ships.
SHIPPED_EXECUTED_FILES = frozenset({'docs/bitrix-local-AGENTS.md'})
# Readable content-addressed blobs and manifests materialize code/instructions.
# Their .txt/.json representation never makes them documentation-only changes.
SHIPPED_EXECUTED_PREFIXES = ('.getzilla/templates/baseline/',)
# Declared-immutable evidence. ``tests/test_history.py`` pins these bytes to a literal
# sha256, so rewriting one is a contract change and a documentation lane must never carry it.
# Matched structurally (``<any>/evidence/historical-<name>``) rather than by package name, so
# a newly declared immutable bundle cannot slip past a hard-coded list.
IMMUTABLE_EVIDENCE_DIRECTORY = 'evidence'
IMMUTABLE_EVIDENCE_PREFIX = 'historical-'

# The dated state model and the release identity literal. Both are machine-checked by the
# lockstep trio below, which is what makes them admissible without the executed suite.
STATE_ROOT_FILES = frozenset({'PROJECT_STATE.json', 'VERSION'})

# Tracked release bytes. tests/test_manifest_package.py re-derives the manifest and the
# package digest from these files instead of trusting the prose that names them.
ARTIFACT_PREFIXES = ('packages/',)

# The test modules this lane runs: the lockstep trio that re-derives documentation identity,
# dated state, and package bytes, plus the cheap binding tests whose *subject* is an admitted
# path — README's Workflow-sources table (tests/test_workflow_sources.py) and a delivered
# change package's route record (tests/test_repo_router.py). Admission is by content role on
# both sides: a path rides this lane only when a module that runs on this lane re-derives it,
# so no admitted content is left bound to a check this profile does not run. Any other test
# change can silence a check without touching a single product statement, so it owes the full
# suite; editing a module listed here can only weaken that module's own binding, which is the
# accepted trade-off already stated in this file's opening docstring.
FOCUSED_TEST_TARGETS = (
    'tests/test_structure.py',
    'tests/test_project_state.py',
    'tests/test_manifest_package.py',
    'tests/test_workflow_sources.py',
    'tests/test_repo_router.py',
)

# Checks the focused profile does not run. Each is disclosed in the report so a reviewer
# reads what was not measured instead of inferring it from absence. ``python-unittest`` is the
# replaced full-discovery runner in this repository; where a consumer install's runner is
# pytest instead, ``_focused_python`` emits that runner's name as well.
FOCUSED_SKIPPED_CHECKS = ('python-unittest', 'coverage', 'factory-postgres-exit')

# Git statuses that cannot hide a moved or removed product path. Anything else (deleted,
# renamed, copied, unmerged) keeps the caller on the full PR verifier. ``??`` is reachable on
# purpose: the docs/state side channel collects ``ls-files --others --exclude-standard`` so the
# veto channel spans exactly the path domain of the inventory it guards.
SAFE_FILE_STATUSES = frozenset({'A', 'M', '??'})


def is_valid_inventory_path(value: object) -> bool:
    """Reject any inventory entry that is not a plain repository-relative POSIX path."""
    if not isinstance(value, str) or not value or '\x00' in value or '\\' in value:
        return False
    if any(ord(char) < 32 for char in value):
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {'', '.', '..'} for part in path.parts)
    )


def safe_inventory_value(value: object) -> str:
    """Render an inventory entry for a report without embedding control bytes."""
    if isinstance(value, str):
        return value if is_valid_inventory_path(value) else repr(value)[:200]
    return f'<{type(value).__name__}>'


def _moved_or_malformed_statuses(file_statuses: object) -> list[str]:
    """Return offending entries when a status side-channel cannot prove a pure addition/edit.

    ``None`` means the caller supplied no side-channel at all, which is not proof of a safe
    inventory; only an explicit trusted list of safe statuses admits the focused profile.
    """
    if file_statuses is None:
        return ['status-preserving Git inventory was not supplied']
    if not isinstance(file_statuses, list):
        return ['status-preserving Git inventory is not a list of records']
    offending: list[str] = []
    for raw in file_statuses:
        if not isinstance(raw, dict):
            offending.append(safe_inventory_value(raw))
            continue
        status, path, original = raw.get('status'), raw.get('path'), raw.get('original_path')
        label = safe_inventory_value(path) if isinstance(path, str) else safe_inventory_value(raw)
        if not isinstance(status, str) or not status or not is_valid_inventory_path(path):
            offending.append(label)
        elif status not in SAFE_FILE_STATUSES:
            offending.append(f'{label} ({status})')
        elif original is not None:
            offending.append(label)
    return offending


def is_immutable_historical_evidence(path: str) -> bool:
    """Return True when a path is a declared-immutable evidence bundle entry.

    ``<anything>/evidence/historical-<name>`` is matched by structure, not by package name,
    because the role (bytes a test pins literally) is what makes the path non-admissible.
    """
    parts = path.split('/')
    return (
        len(parts) >= 3
        and parts[-2] == IMMUTABLE_EVIDENCE_DIRECTORY
        and parts[-1].startswith(IMMUTABLE_EVIDENCE_PREFIX)
    )


def _is_normalized_relative(path: object) -> bool:
    """Return True only for a plain, already-normalized repository-relative POSIX path.

    The allowlist is matched with string prefixes, so it must never be handed a path whose
    textual form and normalized form disagree (``packages/../../etc/passwd``). Callers reach
    the classifier through ``is_valid_inventory_path`` today; matching in depth anyway keeps
    the closed allowlist closed if a future caller forgets that validator.
    """
    if not isinstance(path, str) or not path or path.startswith('/') or '\\' in path:
        return False
    if any(ord(char) < 32 for char in path):
        return False
    parts = path.split('/')
    return all(part not in {'', '.', '..'} for part in parts)


def _classify_path(path: str) -> str | None:
    """Return the blocking reason code when a path cannot sit inside the focused scope."""
    if not _is_normalized_relative(path):
        return 'unnormalized-path'
    if path in FOCUSED_TEST_TARGETS:
        return None
    # Every test module outside the admitted set: a test change can silence a check without
    # moving one product statement, so it owes the full suite and gets its own reason code
    # instead of the generic unallowlisted-path.
    if path.startswith('tests/'):
        return 'test-suite-change'
    if path in SHIPPED_EXECUTED_FILES or path.startswith(SHIPPED_EXECUTED_PREFIXES):
        return 'shipped-executed-content'
    if is_immutable_historical_evidence(path):
        return 'immutable-historical-evidence'
    if path in DOCUMENT_ROOT_FILES or path in STATE_ROOT_FILES:
        return None
    if path in DOCUMENT_FILES:
        return None
    if path.startswith(DOCUMENT_PREFIXES) or path.startswith(ARTIFACT_PREFIXES):
        return None
    return 'unallowlisted-path'


def select_docs_state_scope(
    mode: str,
    files: Iterable[object],
    *,
    range_findings: list[dict[str, str]] | None = None,
    range_base_count: int | None = None,
    file_statuses: object = None,
    status_inventory_trusted: bool | None = None,
    route_present: bool = True,
    available_test_targets: Iterable[str] = (),
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Classify a changed-path inventory for the focused documentation/state profile.

    The caller must use the existing full PR verifier for every ineligible result; this
    function never narrows a check on its own.
    """
    scope: dict[str, object] = {
        'eligible': False,
        'profile': FULL_PROFILE,
        'mode': mode,
        'reason': '',
        'reason_code': 'inventory-unclassified',
        'documentation_files': [],
        'state_files': [],
        'artifact_files': [],
        'changed_lockstep_tests': [],
        'focused_tests': [],
        'rejected_files': [],
        'skipped_checks': [],
        'changed_paths_digest': '',
        'evidence_kind': f'verification:{FULL_PROFILE}',
        'rejection': None,
    }

    def reject(code: str, reason: str, *, offending: list[str] | None = None) -> dict[str, object]:
        scope['reason_code'] = code
        scope['reason'] = reason
        scope['rejected_files'] = sorted(set(scope['rejected_files']) | set(offending or []))
        return scope

    paths: list[str] = []
    for raw in list(files or []):
        if isinstance(raw, str) and is_valid_inventory_path(raw):
            paths.append(raw)
        else:
            scope['rejected_files'].append(safe_inventory_value(raw))

    paths = sorted(set(paths))
    scope['changed_paths_digest'] = hashlib.sha256(
        json.dumps(paths, ensure_ascii=True).encode('utf-8')
    ).hexdigest()

    if mode not in {'pr', 'release'}:
        return reject('mode-not-gated', f'mode {mode!r} is not a gated PR/release run')

    env = dict(os.environ) if environment is None else dict(environment)
    if env.get(FORCE_FULL_VARIABLE, '').strip().lower() in {'1', 'true', 'yes', 'on'}:
        return reject('operator-override', f'{FORCE_FULL_VARIABLE} forces the full PR suite')

    if not route_present:
        return reject('route-unavailable', 'focused verification requires an active route')
    if scope['rejected_files']:
        return reject(
            'invalid-inventory-path',
            'changed-path inventory contains an unusable path',
        )
    if range_findings:
        return reject(
            'comparison-inventory-incomplete',
            'comparison inventory is incomplete or ambiguous',
            offending=[str(item.get('code', 'range-finding')) for item in range_findings if isinstance(item, dict)],
        )
    if range_base_count is not None and range_base_count < 1:
        return reject('comparison-inventory-untrusted', 'comparison inventory has no trusted base')
    if status_inventory_trusted is not True:
        return reject(
            'file-status-inventory-unavailable',
            'focused verification requires a positively trusted status-preserving Git inventory; '
            'an absent or unknown trust signal is not a confirmation',
        )
    moved = _moved_or_malformed_statuses(file_statuses)
    if moved:
        return reject(
            'unsafe-file-status',
            'focused verification rejects deleted, renamed, copied, ambiguous, or malformed Git file statuses',
            offending=moved,
        )
    if not paths:
        return reject('unresolved-diff', 'changed-file inventory is empty; the comparison base may be unresolvable')

    documentation: list[str] = []
    state: list[str] = []
    artifacts: list[str] = []
    changed_lockstep_tests: list[str] = []
    blockers: list[tuple[str, str]] = []
    for path in paths:
        code = _classify_path(path)
        if code is not None:
            blockers.append((code, path))
            continue
        if path in FOCUSED_TEST_TARGETS:
            changed_lockstep_tests.append(path)
        elif path in STATE_ROOT_FILES:
            state.append(path)
        elif path.startswith(ARTIFACT_PREFIXES):
            artifacts.append(path)
        else:
            documentation.append(path)

    scope['documentation_files'] = documentation
    scope['state_files'] = state
    scope['artifact_files'] = artifacts
    scope['changed_lockstep_tests'] = changed_lockstep_tests

    if blockers:
        codes = sorted({code for code, _ in blockers})
        return reject(
            codes[0] if len(codes) == 1 else 'out-of-scope-or-invalid-paths',
            'one or more changed paths cannot be verified by the focused documentation/state profile',
            offending=[path for _, path in blockers],
        )
    unavailable = sorted(set(FOCUSED_TEST_TARGETS) - set(available_test_targets or ()))
    if unavailable:
        return reject(
            'lockstep-target-unavailable',
            'the focused profile cannot run a lockstep test that is absent from this checkout',
            offending=unavailable,
        )

    scope['eligible'] = True
    scope['profile'] = DOCS_STATE_PROFILE
    scope['evidence_kind'] = f'verification:{DOCS_STATE_PROFILE}'
    scope['reason_code'] = 'eligible'
    scope['reason'] = 'documentation/dated-state/lockstep-test inventory only'
    scope['skipped_checks'] = list(FOCUSED_SKIPPED_CHECKS)
    scope['rejection'] = None
    scope['checked_files'] = paths
    # The admitted modules re-derive identity, dated state, package bytes and admitted prose
    # tables from the current tree, so they run whether or not this change edited them.
    scope['focused_tests'] = list(FOCUSED_TEST_TARGETS)
    return scope


def focused_command(test_targets: list[str]) -> list[str]:
    """Build the exact unittest invocation for the admitted module set."""
    return [
        sys.executable,
        '-m',
        'unittest',
        *test_targets,
    ]


# Shared source inventory and tool applicability. These selectors execute no checks.

_STATIC_LANDING_PREFIX = 'side-projects/seo-landings/'


_FOCUSED_LANDING_TEST_NAME = re.compile(
    r'^test_(?P<landing>[A-Za-z0-9][A-Za-z0-9_-]*?)_seo_landing(?:_[A-Za-z0-9_-]+)?\.py$'
)


_CHANGE_PACKAGE_PREFIX = re.compile(
    r'^(?:engineering|\.getzilla/runtime)/changes/[A-Za-z0-9][A-Za-z0-9._-]*$'
)


_SAFE_FOCUSED_FILE_STATUSES = {'A', 'M', '??'}


QUALITY_PY_PATHS = (
    '.getzilla/getzilla',
    '.getzilla/integrations',
    'scripts',
    'tests',
    '.getzilla/hooks',
    'user_prompt_submit.py',
    'pre_tool_use.py',
    'post_tool_use.py',
    'pre_compact.py',
    'session_start.py',
    'session_end.py',
    'stop_gate.py',
    'subagent_start.py',
    'subagent_stop.py',
    'factory/src/getzilla_factory',
)


_SEMGREP_CONFIGS = ('semgrep.yaml', '.semgrep.yml', '.semgrep.yaml')


_TRIVY_FILES = ('Dockerfile', 'dockerfile', 'Containerfile')


NODE_LOCKFILES = (('package-lock.json', 'npm'), ('npm-shrinkwrap.json', 'npm'), ('pnpm-lock.yaml', 'pnpm'),
                  ('yarn.lock', 'yarn'))


def _changed_file_inventory(
    root: Path,
    route: dict[str, object] | None,
    mode: str,
    selection: GitRangeSelection,
) -> tuple[list[str], dict[str, object]]:
    from .git_ranges import FOCUSED_STATIC_SEO_LANDING_MODE, _RANGE_MODES
    from .util import changed_files, changed_file_statuses
    if mode not in _RANGE_MODES:
        route_base = route.get('base_commit') if route else None
        files = changed_files(root, route_base if isinstance(route_base, str) else None)
        return files, {
            'mode': 'route-base',
            'bases': ([{
                'kind': 'route',
                'source': 'route.base_commit',
                'base': route_base,
                'target': route_base,
                'count': len(files),
            }] if isinstance(route_base, str) else []),
            'worktree_count': len(changed_files(root)),
            'union_count': len(files),
        }

    if mode == FOCUSED_STATIC_SEO_LANDING_MODE:
        worktree_files = set(changed_files(root))
        union = set(worktree_files)
        status_records = changed_file_statuses(root)
        status_inventory_trusted = status_records is not None
        status_findings: list[dict[str, str]] = []
        if status_records is None:
            status_findings.append({
                'severity': 'error',
                'code': 'file-status-inventory-unavailable',
                'path': 'git',
                'message': 'focused verification could not obtain a status-preserving Git inventory',
            })
            status_records = []
        for item in status_records:
            for key in ('path', 'original_path'):
                path = item.get(key)
                if isinstance(path, str):
                    union.add(path)

        bases: list[dict[str, object]] = []
        for selected in selection.bases:
            files = set(changed_files(root, selected.comparison_base_sha))
            union.update(files)
            ranged_statuses = changed_file_statuses(
                root,
                selected.comparison_base_sha,
                include_worktree=False,
                include_untracked=False,
            )
            if ranged_statuses is None:
                status_inventory_trusted = False
                status_findings.append({
                    'severity': 'error',
                    'code': 'file-status-inventory-unavailable',
                    'path': selected.source,
                    'message': 'focused verification could not obtain status for the selected Git range',
                })
            else:
                for item in ranged_statuses:
                    item['source'] = f'range:{selected.comparison_base_sha}'
                    status_records.append(item)
                    for key in ('path', 'original_path'):
                        path = item.get(key)
                        if isinstance(path, str):
                            union.add(path)
            bases.append({
                'kind': selected.kind,
                'source': selected.source,
                'base': selected.comparison_base_sha,
                'target': selected.target_sha,
                'count': len(files),
            })
        return sorted(union), {
            'mode': 'range-union',
            'bases': bases,
            'worktree_count': len(worktree_files),
            'union_count': len(union),
            'selection_findings': list(selection.findings),
            'status_records': status_records,
            'status_inventory_trusted': status_inventory_trusted,
            'status_findings': status_findings,
        }

    worktree_files = set(changed_files(root))
    union = set(worktree_files)
    bases: list[dict[str, object]] = []
    for selected in selection.bases:
        files = set(changed_files(root, selected.comparison_base_sha))
        union.update(files)
        bases.append({
            'kind': selected.kind,
            'source': selected.source,
            'base': selected.comparison_base_sha,
            'target': selected.target_sha,
            'count': len(files),
        })
    return sorted(union), {
        'mode': 'range-union',
        'bases': bases,
        'worktree_count': len(worktree_files),
        'union_count': len(union),
        'selection_findings': list(selection.findings),
    }


def _is_valid_inventory_path(value: object) -> bool:
    return is_valid_inventory_path(value)


def _is_focused_landing_test(path: str, change_package: str | None) -> bool:
    basename = PurePosixPath(path).name
    if _FOCUSED_LANDING_TEST_NAME.fullmatch(basename) is None:
        return False
    if path.startswith('tests/'):
        return True
    return (
        change_package is not None
        and path.startswith(f'{change_package}/evidence/')
        and path.startswith('engineering/changes/')
    )


def _normalize_landing_key(value: str) -> str:
    return re.sub(r'[-_]+', '_', value).strip('_').lower()


def _focused_test_landing_key(path: str) -> str | None:
    match = _FOCUSED_LANDING_TEST_NAME.fullmatch(PurePosixPath(path).name)
    if match is None:
        return None
    return _normalize_landing_key(match.group('landing'))


def _safe_inventory_value(value: object) -> str:
    try:
        rendered = repr(value)
    except Exception:
        rendered = f'<unrepresentable {type(value).__name__}>'
    if not isinstance(rendered, str):
        rendered = f'<unrepresentable {type(value).__name__}>'
    rendered = ''.join(
        character if ord(character) >= 32 else f'\\x{ord(character):02x}'
        for character in rendered
    )
    return rendered[:512]


def _focused_file_status_findings(
    file_statuses: object,
    status_inventory_trusted: bool | None,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """Validate the status side-channel used only by focused classification."""
    invalid: list[dict[str, str]] = []
    unsafe: list[dict[str, str]] = []
    if status_inventory_trusted is False:
        return invalid, unsafe, [{
            'severity': 'error',
            'code': 'file-status-inventory-unavailable',
            'path': 'git',
            'message': 'focused verification requires a trusted status-preserving Git inventory',
        }]
    if not isinstance(file_statuses, list):
        invalid.append({
            'severity': 'error',
            'code': 'file-status-ambiguous',
            'path': 'git',
            'message': 'status-preserving Git inventory is not a list of records',
        })
        return invalid, unsafe, []

    for raw in file_statuses:
        if not isinstance(raw, dict):
            invalid.append({
                'severity': 'error',
                'code': 'file-status-ambiguous',
                'path': _safe_inventory_value(raw),
                'message': 'Git status record is not an object',
            })
            continue
        status = raw.get('status')
        path = raw.get('path')
        original_path = raw.get('original_path')
        if (
            not isinstance(status, str)
            or not status
            or not isinstance(path, str)
            or not _is_valid_inventory_path(path)
            or (
                original_path is not None
                and (
                    not isinstance(original_path, str)
                    or not _is_valid_inventory_path(original_path)
                )
            )
        ):
            invalid.append({
                'severity': 'error',
                'code': 'file-status-ambiguous',
                'path': _safe_inventory_value(path),
                'message': 'Git status record has a missing or malformed path/status',
            })
            continue
        if status in _SAFE_FOCUSED_FILE_STATUSES and original_path is not None:
            invalid.append({
                'severity': 'error',
                'code': 'file-status-ambiguous',
                'path': path,
                'message': 'a safe Git status record unexpectedly has an original path',
            })
            continue
        if status not in _SAFE_FOCUSED_FILE_STATUSES:
            finding = {
                'severity': 'error',
                'code': 'unsafe-file-status',
                'status': status,
                'path': path,
                'message': 'focused verification rejects deleted, renamed, copied, or ambiguous Git statuses',
            }
            if isinstance(original_path, str):
                finding['original_path'] = original_path
            source = raw.get('source')
            if isinstance(source, str):
                finding['source'] = source
            unsafe.append(finding)
    return invalid, unsafe, []


def select_static_seo_landing_scope(
    files: list[object],
    *,
    change_package: str | None = None,
    range_findings: list[dict[str, str]] | None = None,
    range_base_count: int | None = None,
    file_statuses: object = None,
    status_inventory_trusted: bool | None = None,
) -> dict[str, object]:
    """Classify an inventory for the explicit static-landing verifier.

    This is intentionally a closed selector.  A focused run is eligible only when
    it has landing-source paths, exactly one explicitly named landing contract, and
    no unrecognized product path or unresolved comparison inventory.  The caller
    must use the existing PR verifier for every ``full-pr`` result.
    """
    scope: dict[str, object] = {
        'eligible': False,
        'profile': 'full-pr',
        'reason': '',
        'landing_files': [],
        'landing_directories': [],
        'selected_landing_directory': None,
        'focused_tests': [],
        'focused_test_landing': None,
        'ignored_files': [],
        'rejected_files': [],
        'reason_code': 'inventory-unclassified',
        'rejection': None,
        'status_inventory_trusted': status_inventory_trusted,
        'status_findings': [],
        'unsafe_file_statuses': [],
    }
    if not isinstance(files, list) or not files:
        scope['reason'] = 'changed-file inventory is missing or empty'
        return scope

    if change_package is not None and (
        not isinstance(change_package, str)
        or not _CHANGE_PACKAGE_PREFIX.fullmatch(change_package)
    ):
        scope['reason'] = 'active change-package path is invalid'
        return scope

    landing_files: list[str] = []
    focused_tests: list[str] = []
    ignored_files: list[str] = []
    rejected_files: list[str] = []
    normalized_files: list[str] = []
    for raw in files:
        if not isinstance(raw, str):
            rejected_files.append(_safe_inventory_value(raw))
            continue
        rel = str.__str__(raw)
        if not _is_valid_inventory_path(rel):
            rejected_files.append(_safe_inventory_value(raw))
            continue
        normalized_files.append(rel)

    for rel in sorted(set(normalized_files)):
        if rel.startswith(_STATIC_LANDING_PREFIX):
            landing_files.append(rel)
        elif _is_focused_landing_test(rel, change_package):
            focused_tests.append(rel)
        elif change_package and rel.startswith(f'{change_package}/'):
            # The active change package is workflow evidence, not product scope.
            ignored_files.append(rel)
        else:
            rejected_files.append(rel)

    scope['landing_files'] = landing_files
    scope['landing_directories'] = sorted({
        rel[len(_STATIC_LANDING_PREFIX):].split('/', 1)[0]
        for rel in landing_files
    })
    if len(scope['landing_directories']) == 1:
        scope['selected_landing_directory'] = scope['landing_directories'][0]
    scope['focused_tests'] = focused_tests
    if len(focused_tests) == 1:
        scope['focused_test_landing'] = _focused_test_landing_key(focused_tests[0])
    scope['ignored_files'] = ignored_files
    scope['rejected_files'] = rejected_files

    status_metadata_supplied = file_statuses is not None or status_inventory_trusted is not None
    if status_metadata_supplied:
        invalid_statuses, unsafe_statuses, status_findings = _focused_file_status_findings(
            file_statuses,
            status_inventory_trusted,
        )
        scope['status_findings'] = invalid_statuses + status_findings
        scope['unsafe_file_statuses'] = unsafe_statuses

    if scope['status_findings']:
        first = scope['status_findings'][0]
        scope['reason_code'] = str(first['code'])
        scope['reason'] = str(first['message'])
    elif scope['unsafe_file_statuses']:
        scope['reason_code'] = 'unsafe-file-status'
        scope['reason'] = 'deleted, renamed, copied, or ambiguous Git file status is present'
    elif range_findings:
        scope['reason_code'] = 'comparison-inventory-incomplete'
        scope['reason'] = 'comparison inventory is incomplete or ambiguous'
    elif range_base_count is not None and range_base_count < 1:
        scope['reason_code'] = 'comparison-inventory-untrusted'
        scope['reason'] = 'comparison inventory has no trusted base'
    elif rejected_files:
        scope['reason_code'] = 'out-of-scope-or-invalid-paths'
        scope['reason'] = 'out-of-scope or invalid changed paths are present'
    elif not landing_files:
        scope['reason_code'] = 'landing-source-missing'
        scope['reason'] = 'no static SEO landing source changed'
    elif len(scope['landing_directories']) != 1:
        scope['reason_code'] = 'landing-directory-ambiguous'
        scope['reason'] = 'multiple static SEO landing directories are ambiguous'
    elif not focused_tests:
        scope['reason_code'] = 'focused-test-missing'
        scope['reason'] = 'focused test is missing'
    elif len(focused_tests) != 1:
        scope['reason_code'] = 'focused-test-ambiguous'
        scope['reason'] = 'focused landing test path is ambiguous'
    elif scope['focused_test_landing'] != _normalize_landing_key(str(scope['selected_landing_directory'])):
        scope['reason_code'] = 'focused-test-landing-mismatch'
        scope['reason'] = 'focused test does not match the selected landing directory'
        scope['rejection'] = {
            'code': 'focused-test-landing-mismatch',
            'message': scope['reason'],
            'landing_directory': scope['selected_landing_directory'],
            'focused_test': focused_tests[0],
            'focused_test_landing': scope['focused_test_landing'],
        }
    else:
        scope['eligible'] = True
        scope['profile'] = 'static-seo-landing'
        scope['reason_code'] = 'eligible'
        scope['reason'] = 'landing-only inventory with one focused contract'
    scope['checked_files'] = sorted(landing_files + focused_tests)
    return scope


def composer_check_selection(root: Path) -> list[tuple[str, list[str]]]:
    """The exact existing installed Composer tools; no tool is installed or executed."""
    return [(name, args) for name, path, args in (
        ('phpunit', 'vendor/bin/phpunit', ['vendor/bin/phpunit']),
        ('phpstan', 'vendor/bin/phpstan', ['vendor/bin/phpstan', 'analyse', '--no-progress']),
        ('phpcs', 'vendor/bin/phpcs', ['vendor/bin/phpcs']),
        ('deptrac', 'vendor/bin/deptrac', ['vendor/bin/deptrac', 'analyse']),
    ) if (root / path).is_file()]


def _existing_quality_paths(root: Path) -> list[str]:
    """Getzilla's own Python paths plus every top-level tree that holds the project's tracked Python."""
    from .util import run
    paths = [rel for rel in QUALITY_PY_PATHS if (root / rel).exists()]
    proc = run(['git', 'ls-files', '-z', '--', '*.py'], cwd=root, timeout=60)
    if proc.returncode == 0:
        for rel in proc.stdout.split('\0'):
            # Dot directories hold generated hook mirrors and tool state, not product code.
            # A name that starts with '-' would read as an option of ruff or bandit.
            if not rel or rel.startswith(('.', '-')) or not (root / rel).is_file():
                continue
            top = rel.split('/', 1)[0]
            if top not in paths:
                paths.append(top)
    return [rel for rel in paths if not any(rel.startswith(other + '/') for other in paths)]


def _semgrep_config(root: Path) -> str | None:
    config: str | None = None
    for name in _SEMGREP_CONFIGS:
        if (root / name).is_file():
            config = name
            break
    if config is None:
        semgrep_dir = root / '.semgrep'
        if semgrep_dir.is_dir():
            try:
                next(semgrep_dir.iterdir())
            except StopIteration:
                pass
            else:
                config = '.semgrep'
    return config


def _trivy_config_present(root: Path) -> bool:
    return any((root / name).is_file() for name in _TRIVY_FILES) or bool(
        list(root.glob('docker-compose*.yml')) or list(root.glob('docker-compose*.yaml'))
    )


def node_check_selection(root: Path, mode: str) -> tuple[dict, str, str | None, list[str]]:
    """Declare the same manifest, lock and script IDs used below, without running tools."""
    scripts = json.loads((root / 'package.json').read_text(encoding='utf-8')).get('scripts', {})
    if not isinstance(scripts, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in scripts.items()):
        raise ValueError('invalid package scripts')
    manager, lockfile = node_lockfile(root)
    names = ['package-json', 'node-tooling']
    if mode in {'pr', 'release'}:
        names.append('node-lockfile')
        if lockfile is not None:
            names.append(manager + '-install')
    names.extend(manager + '-' + name for name in ('lint', 'typecheck', 'test', 'prettier', 'format',
                 *(['build'] if mode in {'pr', 'release'} else [])) if name in scripts)
    if 'typecheck' not in scripts and (root / 'tsconfig.json').is_file() and mode in {'pr', 'release'}:
        names.append('tsc')
    return scripts, manager, lockfile, names


def node_lockfile(root: Path) -> tuple[str, str | None]:
    """The package manager the lockfile implies, and the lockfile (None: not reproducible)."""
    for name, manager in NODE_LOCKFILES:
        if (root / name).is_file():
            return manager, name
    return 'npm', None


def python_check_selection(root: Path) -> tuple[bool, bool]:
    from .util import command_exists
    has_project = any((root / item).exists() for item in ('pyproject.toml', 'requirements.txt', 'setup.py'))
    tests_dir = root / 'tests'
    return (has_project and command_exists('pytest') and tests_dir.is_dir(),
            tests_dir.is_dir() and any(tests_dir.glob('test*.py')))


def _docs_state_status_inventory(
    root: Path,
    selection: GitRangeSelection,
) -> tuple[list[dict[str, object]], bool]:
    """Collect status records for the documentation/state decision only.

    This read deliberately disables rename and copy detection, while the landing selector's
    shared helper keeps them on. Git scores a freshly scaffolded change package as a copy of
    an older one (`C085` plus an `original_path`), so with copy detection every pull request
    that carries its own evidence would be pushed to the full suite and the focused profile
    would never fire at all. Under `--no-renames` a scaffolded package is what it actually
    is — additions — while any *removed* path still reports `D`, which is the one shape that
    could hide a source file behind a documentation name.

    The records come from the shared name-status helper in `util`, called with rename/copy
    detection off and with the same untracked collection the changed-file inventory performs,
    so this veto channel spans exactly the path domain it guards instead of a subset of it.
    The PR/release changed-file inventory itself stays byte-unchanged: this side channel
    feeds a scope decision and must not widen what the full suite already inspects.
    """
    from .util import changed_file_statuses
    records: list[dict[str, object]] = []
    trusted = True

    def merge(part: list[dict[str, str]] | None, source: str | None) -> None:
        nonlocal trusted
        if part is None:
            trusted = False
            return
        for item in part:
            if source is not None:
                item['source'] = source
            records.append(item)

    merge(changed_file_statuses(root, rename_detection=False), None)
    for selected in selection.bases:
        merge(
            changed_file_statuses(
                root,
                selected.comparison_base_sha,
                include_worktree=False,
                include_untracked=False,
                rename_detection=False,
            ),
            f'range:{selected.comparison_base_sha}',
        )
    return records, trusted
