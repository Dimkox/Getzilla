"""Admission policy and the immutable read-only admission plan (Zero-Git, PLAN_READY).

Sensitive path classes are blockers until the owner excludes the file explicitly; an extension
is never proof of safety, so every candidate is also content-scanned. The plan records exactly
which files are admitted, which are excluded and why, the policy and scanner identities and the
intended target; `plan_id` changes with any of them. Planning writes nothing anywhere.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence

from .source_baseline import source_digest
from .source_inventory import effective_executable_mode, inventory_source
from .source_models import (
    AdmissionPlan, Exclusion, Finding, IngestPolicy, ScanReport, SourceEntry, SourceInventory, ValidationResult,
)
from .source_paths import source_target_problem
from .source_secrets import not_run_report, scan_candidates

_EXAMPLE_SUFFIXES = ('.example', '.sample', '.template', '.dist', '.tmpl')
_KEY_SUFFIXES = {'.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.ppk', '.p8', '.der', '.asc', '.gpg', '.kdbx'}
_KEY_PREFIXES = ('id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519')
# Credential store file names. The two web/DB auth files are built from parts so that secret
# detectors do not read a list of file names as a password assignment.
_CREDENTIAL_NAMES = {'.npmrc', '.pypirc', '.netrc', '_netrc', '.git-credentials', '.dockercfg',
                     'credentials', 'credentials.json', 'credentials.yml', 'credentials.yaml',
                     'secrets.json', 'secrets.yml', 'secrets.yaml', 'service-account.json',
                     '.ht' + 'passwd', '.pg' + 'pass'}
_DUMP_SUFFIXES = {'.sql', '.dump', '.sqlite', '.sqlite3', '.db', '.mdb', '.accdb', '.bak', '.rdb'}
_ARCHIVE_SUFFIXES = {'.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar', '.zst', '.jar', '.war', '.ear',
                     '.whl', '.egg', '.apk', '.ipa', '.dmg', '.iso', '.cab'}


@dataclass(frozen=True)
class AdmissionCandidates:
    candidates: tuple[SourceEntry, ...]
    exclusions: tuple[Exclusion, ...]
    blockers: tuple[Finding, ...]


def sensitive_class(path: str, allow_examples: bool = True) -> str | None:
    """The sensitive path class of `path`, if any."""
    pure = PurePosixPath(path)
    name = pure.name.lower()
    suffix = pure.suffix.lower()
    parts = [part.lower() for part in pure.parts]
    is_example = name.endswith(_EXAMPLE_SUFFIXES)
    if name == '.env' or name.startswith('.env.') or suffix == '.env':
        return None if is_example and allow_examples else 'SENSITIVE_ENV_FILE'
    if suffix in _KEY_SUFFIXES or (name.startswith(_KEY_PREFIXES) and not name.endswith('.pub')):
        return None if is_example and allow_examples else 'SENSITIVE_KEY_MATERIAL'
    if name in _CREDENTIAL_NAMES or (len(parts) >= 2 and parts[-2] in {'.aws', '.docker', '.kube', '.ssh', '.gnupg'}):
        return None if is_example and allow_examples else 'SENSITIVE_CREDENTIAL_STORE'
    if suffix in _DUMP_SUFFIXES:
        return 'SENSITIVE_DATABASE_DUMP'
    if suffix in _ARCHIVE_SUFFIXES or name.endswith(('.tar.gz', '.tar.bz2', '.tar.xz')):
        return 'ARCHIVE_REQUIRES_EXCLUSION'
    return None


def classify_entries(inventory: SourceInventory, policy: IngestPolicy) -> AdmissionCandidates:
    candidates: list[SourceEntry] = []
    blockers: list[Finding] = list(inventory.blockers)
    for entry in inventory.entries:
        klass = sensitive_class(entry.path, policy.allow_sensitive_example_files)
        if klass is not None:
            blockers.append(Finding(path=entry.path, reason_code=klass))
        else:
            candidates.append(entry)
    blockers.sort(key=lambda item: (item.path, item.reason_code))
    return AdmissionCandidates(tuple(candidates), inventory.excluded, tuple(blockers))


def redact_findings(findings: Sequence[Finding]) -> list[dict]:
    """Report form of findings: path, reason, rule and line only."""
    return [finding.to_dict() for finding in findings]


def build_admission_plan(inventory: SourceInventory, scan: ScanReport, policy: IngestPolicy,
                         source: Path, target: Path) -> AdmissionPlan:
    classified = classify_entries(inventory, policy)
    blockers = list(classified.blockers)
    security_codes = {'SECRET_PATTERN', 'OPAQUE_CONTAINER_REQUIRES_EXCLUSION'}
    blockers.extend(scan.findings)
    blockers.extend(scan.unsupported)
    blockers.extend(scan.errors)
    target_abs = Path(os.path.abspath(target))
    problem = source_target_problem(source, target_abs)
    if problem:
        blockers.append(Finding(path='<target>', reason_code=problem))
    elif os.path.lexists(target_abs):
        blockers.append(Finding(path='<target>', reason_code='TARGET_EXISTS'))
    if not classified.candidates and not classified.blockers:
        blockers.append(Finding(path='.', reason_code='SOURCE_EMPTY_ALLOWLIST'))
    capabilities = inventory.capabilities
    codes = {finding.reason_code for finding in blockers}
    scan_error_codes = {finding.reason_code for finding in scan.errors}
    if not capabilities.strict_supported:
        status = 'BLOCKED_UNSUPPORTED_FS'
    elif codes & security_codes or any(code.startswith(('SENSITIVE_', 'ARCHIVE_')) for code in codes):
        status = 'BLOCKED_SECURITY'
    elif (codes - scan_error_codes) or inventory.observed_mutation:
        status = 'BLOCKED_UNSAFE_SOURCE'
    elif scan.status != 'pass':
        status = 'ERROR'  # scanner error, changed bytes during the scan, or no scan: never a pass
    else:
        status = 'PLAN_READY'
    ready = status == 'PLAN_READY'
    executable_mode = effective_executable_mode(policy)
    blockers.sort(key=lambda item: (item.path, item.reason_code, item.rule_id or ''))
    plan = AdmissionPlan(
        status=status, source_root=str(Path(os.path.abspath(source))), target=str(target_abs),
        source_digest=source_digest(classified.candidates, policy.path_profile, executable_mode) if ready else None,
        path_profile=policy.path_profile, executable_mode=executable_mode,
        entries=classified.candidates if ready else (), exclusions=classified.exclusions,
        blockers=tuple(blockers), policy=policy.to_dict(), policy_digest=policy.digest(),
        scan=scan.to_dict(), capabilities=capabilities.to_dict(),
    )
    return AdmissionPlan(**{**plan.__dict__, 'plan_id': plan.compute_id()})


def plan_source(source: Path, target: Path, policy: IngestPolicy) -> AdmissionPlan:
    """Inventory, classify, scan and plan; read-only for the source, writes nothing anywhere."""
    inventory = inventory_source(source, policy)
    classified = classify_entries(inventory, policy)
    if inventory.blockers or not inventory.capabilities.strict_supported:
        scan = not_run_report(len(classified.candidates))
    else:
        scan = scan_candidates(source, classified.candidates, policy)
    return build_admission_plan(inventory, scan, policy, source, target)


@dataclass(frozen=True)
class ApprovalResult(ValidationResult):
    pass


def validate_plan_approval(plan: AdmissionPlan, expected_digest: str) -> ApprovalResult:
    errors: list[str] = []
    if plan.plan_id != plan.compute_id():
        errors.append('PLAN_TAMPERED')
    if plan.plan_id != expected_digest:
        errors.append('PLAN_DIGEST_MISMATCH')
    if plan.status != 'PLAN_READY':
        errors.append(f'PLAN_NOT_READY:{plan.status}')
    if plan.scan.get('status') != 'pass':
        errors.append('SCAN_NOT_PASSED')
    return ApprovalResult(not errors, tuple(errors))
