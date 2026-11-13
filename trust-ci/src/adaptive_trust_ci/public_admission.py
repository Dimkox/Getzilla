"""Entry points validate their own explicit bytes; pure evaluation has no I/O.

The prototype's function shape is retained, not its old signed wire version.
No publisher, merger, operator identity or actual deployment is implemented.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
import hashlib
import importlib
import os
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
import zipfile

from . import security_bundle as bundle
from .github import GitHubError
from .github_observer import ObservationError, observe
from .models import canonical_json, require_repository


@dataclass(frozen=True)
class Selector:
    repository: str
    repository_id: int
    pr_number: int
    base_sha: str
    head_sha: str
    tree_sha: str
    run_id: int
    run_attempt: int

    def source(self):
        return bundle.source_from({'mode': 'github', 'target_ref': 'refs/heads/main', **self.__dict__})


@dataclass(frozen=True)
class Authority:
    repository: str
    repository_id: int
    runner_repository: str
    runner_repository_id: int
    runner_sha: str
    runner_tree_sha: str
    workflow_id: int
    workflow_path: str
    checker_sha: str
    checker_tree_sha: str
    workflow_blob_sha: str
    producer_app_id: int
    event: str
    branch: str
    public_key_pem: bytes
    policy_digest: str
    target_branch: str = 'main'
    required_jobs: tuple = ()
    security_core: object | None = None

    def as_policy(self):
        for name in ('repository', 'runner_repository'):
            if require_repository(getattr(self, name)) != getattr(self, name):
                raise bundle.BundleError('authority-unconfigured')
        for name in ('repository_id', 'runner_repository_id', 'workflow_id', 'producer_app_id'):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise bundle.BundleError('authority-unconfigured')
        if self.event not in ('workflow_dispatch', 'repository_dispatch'):
            raise bundle.BundleError('authority-unconfigured')
        values = {key: value for key, value in self.__dict__.items() if key not in ('security_core', 'public_key_pem')}
        values['public_key_sha256'] = hashlib.sha256(self.public_key_pem).hexdigest()
        return bundle.BundlePolicy(self.policy_digest, self.public_key_pem, bundle.digest(values), self.required_jobs)


@dataclass(frozen=True)
class Evidence:
    binding: dict
    report: dict
    integration: dict | None = None
    descriptors: dict | None = None


@dataclass(frozen=True)
class Decision:
    eligible: bool
    blockers: tuple
    provenance: str = 'protected-host-evaluation-unactivated'
    valid_until: datetime | None = None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                or before.st_size > maximum):
            raise bundle.BundleError('input-file-shape-or-size')
        blocks, size = [], 0
        while block := os.read(fd, min(65536, maximum - size + 1)):
            size += len(block)
            if size > maximum:
                raise bundle.BundleError('input-file-size')
            blocks.append(block)
        if _identity(before) != _identity(os.fstat(fd)) or _identity(before) != _identity(Path(path).lstat()):
            raise bundle.BundleError('input-file-changed')
        return b''.join(blocks)
    finally:
        os.close(fd)


def content_manifest(root, maximum=bundle.SOURCE_BYTES):
    root = Path(root).absolute()
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise bundle.BundleError('source-root-shape')
    rows, total = [], 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in dirs:
            if name == '.git' and Path(directory) == root:
                continue
            item = (Path(directory) / name).lstat()
            if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid():
                raise bundle.BundleError('source-directory-shape')
        if Path(directory) == root and '.git' in dirs:
            dirs.remove('.git')
        for name in files:
            if Path(directory) == root and name == '.git':
                continue
            path = Path(directory) / name
            data = read_file(path, maximum - total)
            total += len(data)
            if total > maximum or len(rows) >= 4096:
                raise bundle.BundleError('source-limit')
            item = path.lstat()
            rows.append({'path': path.relative_to(root).as_posix(), 'bytes': len(data),
                         'mode': 0o755 if item.st_mode & 0o111 else 0o644,
                         'sha256': hashlib.sha256(data).hexdigest()})
    if _identity(info) != _identity(root.lstat()):
        raise bundle.BundleError('source-root-changed')
    return rows


def _core():
    # This code's installation selects its validators, never the candidate root.
    policy_root = Path(__file__).resolve().parents[3]
    library = policy_root / '.getzilla'
    if not (library / 'getzilla').is_dir():
        raise bundle.BundleError('accepted-validator-unavailable')
    if str(library) not in sys.path:
        sys.path.insert(0, str(library))
    modules = {name: importlib.import_module('getzilla.' + module) for name, module in
               (('inventory', 'security_inventory'), ('security', 'expanded_security'),
                ('report', 'security_cli'), ('tools', 'security_tools'), ('git', 'architecture_diff'))}
    return SimpleNamespace(**modules, policy_root=policy_root)


def _snapshot_preflight(root):
    rows = content_manifest(root, bundle.SNAPSHOT_BYTES)
    expanded = members = 0
    for row in rows:
        data = read_file(Path(root) / row['path'], bundle.SNAPSHOT_BYTES)
        import io
        # Authoritative objects are hash-named; compatibility suffixes confer no role.
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                members += len(entries)
                if members > 10000:
                    raise bundle.BundleError('snapshot-member-limit')
                for member in entries:
                    expanded += member.file_size
                    if member.file_size > bundle.MEMBER_BYTES or expanded > bundle.SNAPSHOT_BYTES:
                        raise bundle.BundleError('snapshot-expanded-limit')
        else:
            expanded += len(data)
            if expanded > bundle.SNAPSHOT_BYTES:
                raise bundle.BundleError('snapshot-expanded-limit')
    return rows


def _source_binding(core, source, root):
    if source.mode == 'local' and source.git_head is None:
        return
    raw = core.git.run_git_bounded(root, ['rev-parse', 'HEAD', 'HEAD^{tree}'], limit=1024)
    expected = [source.head_sha, source.tree_sha] if source.mode == 'github' else [source.git_head, source.git_tree]
    if raw.decode().splitlines() != expected:
        raise bundle.BundleError('source-git-identity')
    if core.git.run_git_bounded(root, ['status', '--porcelain=v1', '--untracked-files=all'], limit=65536).strip():
        raise bundle.BundleError('source-git-dirty')


def _integration(core, source, value, root):
    if value is None:
        return None, False
    commit = core.git.run_git_bounded(root, ['cat-file', 'commit', value['merge_sha']], limit=131072)
    headers = commit.split(b'\n\n', 1)[0].splitlines()
    parents = [row[7:].decode('ascii') for row in headers if row.startswith(b'parent ')]
    merged = core.git.run_git_bounded(root, ['merge-tree', '--write-tree', source.base_sha, source.head_sha],
                                      allow_failure=True, limit=131072)
    valid = (parents == [source.base_sha, source.head_sha] and headers[0] == b'tree ' + value['tree_sha'].encode() and
             merged.strip() == value['tree_sha'].encode())
    return bundle.digest(value), valid


def _scanner_targets(inventory, tools):
    # Keep exact parity with security_tools.scan_source and its normalized markers.
    selected = [value for value in inventory['files'] if not value.startswith('.getzilla/sast/')
                and not tools._SAST_EXCLUDED.intersection(Path(value).parts)]
    paths = {'opengrep': [value for value in selected if Path(value).suffix in tools._SAST_SUFFIXES],
             'bandit': [value for value in selected if Path(value).suffix == '.py'],
             'trivy-config': [value for value in selected if Path(value).name.lower().startswith('dockerfile')
                              or Path(value).name.endswith('.Dockerfile') or Path(value).suffix == '.tf']}
    return {name: {value.replace('\\', '/').removeprefix('./') for value in values}
            for name, values in paths.items()}


def validate_local_inputs(policy, evidence, *, source_root, snapshot_root, descriptors, now, core=None):
    """Real boundary validation outside pure evaluation; JSON claims never set facts."""
    value = evidence.document()
    source = evidence.source
    def refused():
        return bundle.ValidationFacts(bundle.digest(value['source']), policy.policy_digest, bundle.digest(value['report']),
                                      value['report']['inventory_sha256'], (), (), ('input-validation-unavailable',), False)
    try:
        core = core or _core()
        before = content_manifest(source_root)
        inventory = core.inventory.collect_inventory(source_root)
        actual_policy = core.security._policy_digest(core.policy_root)
        if actual_policy != policy.policy_digest or inventory['complete'] is not True:
            return refused()
        if source.mode == 'local' and bundle.digest(before) != source.candidate_digest:
            return refused()
        _source_binding(core, source, source_root)
        if snapshot_root is not None:
            snapshots = _snapshot_preflight(snapshot_root)
            roots = {'GETZILLA_OSV_DB': str(Path(snapshot_root) / 'database'),
                     'GETZILLA_SECURITY_DB': str(Path(snapshot_root) / 'database'),
                     'GETZILLA_SECURITY_ARTIFACTS': str(Path(snapshot_root) / 'artifacts'),
                     'GETZILLA_SECURITY_TOOLS': str(Path(snapshot_root) / 'tools')}
        else:
            snapshots, roots = None, {}
        if descriptors is None:
            return refused()
        bundle.fields(descriptors, ('checks', 'source_descriptors'))
        if value['report'].get('evidence_sha256') != bundle.digest(descriptors):
            return refused()
        if snapshot_root is None:
            # Never fall back to a candidate/default runtime database/catalogue.
            return refused()
        paired = (source.mode == 'github' and callable(getattr(core.report, 'source_binding', None))
                  and callable(getattr(core.report, 'finalize_report', None)))
        source_before = (core.report.source_binding(source_root, core.policy_root, snapshot_root)
                         if paired else None)
        obligations = core.security.security_obligations(source_root, inventory, environ=roots,
                                                        now=now, policy_root=core.policy_root)
        required, validated, actual_descriptors = [], {}, {}
        for obligation in obligations:
            applies = obligation['applicability']
            if applies not in ('required', 'not_applicable'):
                return refused()
            if applies == 'required' and obligation['check_id'] not in ('security-inventory', 'known-vulnerabilities'):
                return refused()  # No invented non-OSV qualification.
            ids = []
            for descriptor in obligation['data_sources']:
                identifier = descriptor['source_id']
                core.security.validate_data_source(descriptor, root=source_root, now=now,
                                                  environ=roots, policy_root=core.policy_root)
                validated[identifier] = bundle.ValidatedSource(identifier, descriptor['content_sha256'],
                    descriptor['acquisition']['last_verified_sync_utc'], True)
                actual_descriptors[identifier] = descriptor
                ids.append(identifier)
            required.append(bundle.Requirement(obligation['check_id'], applies == 'required', tuple(ids), inventory['digest']))
        targets = _scanner_targets(inventory, core.tools)
        for name, applies in [('secret-scan', True), *[(name, bool(paths)) for name, paths in targets.items()]]:
            required.append(bundle.Requirement(name, applies, (), inventory['digest']))
        supplied = descriptors['checks']
        if type(supplied) is not list or len(supplied) != len(required):
            return refused()
        normalized = []
        for check in supplied:
            markers = [m for m in check.get('details', []) if isinstance(m, dict) and m.get('kind') == 'security-result']
            if len(markers) != 1:
                return refused()
            marker = markers[0]
            if check['name'] in targets:
                coverage = marker.get('coverage', {'expected': [], 'observed': []})
                if (type(coverage) is not dict or set(coverage) != {'expected', 'observed'}
                        or any(type(paths) is not list or any(type(path) is not str or not path for path in paths)
                               or len(paths) != len(set(paths)) or set(paths) != targets[check['name']]
                               for paths in coverage.values())):
                    return refused()
            if not core.report._detail_consistent(check['name'], marker, inventory['digest'], actual_policy, now):
                return refused()
            if any(item != actual_descriptors.get(item.get('source_id')) for item in marker['data_sources']):
                return refused()
            normalized.append({'name': check['name'], 'status': check['status'], 'outcome': marker['outcome'],
                'finding_count': len(marker['findings']), 'gap_count': len(marker['gaps']),
                'source_ids': [row['source_id'] for row in marker['data_sources']], 'coverage_sha256': inventory['digest']})
        if sorted(normalized, key=lambda row: row['name']) != sorted(value['report']['checks'], key=lambda row: row['name']):
            return refused()
        if descriptors['source_descriptors'] != sorted(validated):
            return refused()
        integration_digest, integrated = (None, False) if source.mode == 'local' else _integration(core, source, value['integration'], source_root)
        if content_manifest(source_root) != before or _snapshot_preflight(snapshot_root) != snapshots:
            return refused()
        _source_binding(core, source, source_root)
        valid_until, checker_source = None, None
        if paired:
            source_after = core.report.source_binding(source_root, core.policy_root, snapshot_root)
            if (type(source_before) is not dict or source_before != source_after
                    or source_after.get('head_sha') != source.head_sha
                    or source_after.get('tree_sha') != source.tree_sha):
                return refused()
            timed = core.report.finalize_report(source_before, source_after, supplied,
                                                inventory['digest'], actual_policy, now=now)
            if timed.get('status') != 'pass' or timed.get('valid_until_utc') is None:
                return refused()
            valid_until = timed['valid_until_utc']
            if bundle.parse_datetime(valid_until) < now:
                return refused()
            checker_source = (source_after['checker_sha'], source_after['checker_tree_sha'])
        return bundle.ValidationFacts(bundle.digest(value['source']), actual_policy, bundle.digest(value['report']),
            inventory['digest'], tuple(required), tuple(validated.values()), (), True, integration_digest, integrated,
            bundle.digest(before), bundle.digest(snapshots), valid_until, checker_source)
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, AttributeError, zipfile.BadZipFile):
        return refused()


def evaluate(client, authority, selector, evidence, *, now, snapshot_root=None, candidate_root=None):
    """Protected host owns observation and facts. No local-result argument exists."""
    if authority is None or authority.security_core is None or candidate_root is None or evidence is None:
        return Decision(False, ('authority-or-inputs-unconfigured',))
    try:
        started = time.monotonic()
        source = selector.source()
        if not isinstance(source, bundle.GithubSource):
            return Decision(False, ('github-source-required',))
        policy = authority.as_policy()
        parsed = bundle.parse_bundle(canonical_json({'version': 1, 'source': source.as_dict(), 'policy_sha256': policy.policy_digest,
            'report': evidence.report, 'binding': evidence.binding, 'integration': evidence.integration}))
        facts = validate_local_inputs(policy, parsed, source_root=candidate_root, snapshot_root=snapshot_root,
                                      descriptors=evidence.descriptors, now=now, core=authority.security_core)
        if facts.source_validated is not True or facts.blockers:
            return Decision(False, ('source-unvalidated',))
        observed = observe(client, authority, source)
        if facts.source_validated is not True or facts.content_digest != bundle.digest(content_manifest(candidate_root)):
            return Decision(False, ('source-changed-or-unvalidated',))
        if (snapshot_root is None or facts.snapshot_digest != bundle.digest(_snapshot_preflight(snapshot_root)) or
                authority.security_core.security._policy_digest(authority.security_core.policy_root) != policy.policy_digest):
            return Decision(False, ('snapshot-or-policy-changed',))
        _source_binding(authority.security_core, source, candidate_root)
        current = now + timedelta(seconds=max(0, time.monotonic() - started))
        decision = bundle.evaluate_bundle(policy, source, parsed, observed, facts, now=current)
        if facts.valid_until is not None and facts.checker_source != (authority.checker_sha, authority.checker_tree_sha):
            return Decision(False, ('checker-source-mismatch',))
        return Decision(decision.consistent, decision.reasons, valid_until=decision.valid_until)
    except (bundle.BundleError, OSError, ValueError, TypeError, AttributeError, GitHubError, ObservationError, zipfile.BadZipFile, NotImplementedError):
        return Decision(False, ('protected-observation-or-validation-refused',))
