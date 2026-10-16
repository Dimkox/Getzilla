"""Fail-closed content secret scanner for Zero-Git admission (built in, no download, no spool).

The scanner reads candidate bytes into memory through the same identity-checked open the
inventory uses, matches versioned rules and reports only the path, rule id and line. Matched
bytes, their hashes and file contents are never logged or returned. Compressed archives and
containers cannot be fully inspected and require an explicit exclusion. A pass means these
rules matched nothing in every admitted byte; it is not a proof that no secret exists.
"""
from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from . import fsx
from .source_inventory import read_regular_file
from .source_models import Finding, IngestPolicy, ScanReport, SourceEntry, domain_digest

SCANNER = 'getzilla-builtin-secret-rules'
SCANNER_VERSION = '1'

RULES: tuple[tuple[str, bytes], ...] = (
    ('private-key', rb'-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----'),
    ('aws-access-key-id', rb'\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b'),
    ('aws-secret-access-key', rb'(?i)aws_?secret_?access_?key["\']?\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}'),
    ('github-token', rb'\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})'),
    ('gitlab-token', rb'\bglpat-[A-Za-z0-9_\-]{20,}'),
    ('slack-token', rb'\bxox[abposr]-[A-Za-z0-9-]{10,}'),
    ('slack-webhook', rb'https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}'),
    ('stripe-live-key', rb'\b(?:sk|rk)_live_[A-Za-z0-9]{20,}'),
    ('google-api-key', rb'\bAIza[0-9A-Za-z_\-]{35}'),
    ('anthropic-api-key', rb'\bsk-ant-[A-Za-z0-9_\-]{32,}'),
    ('openai-api-key', rb'\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}'),
    ('jwt', rb'\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'),
    ('url-credentials', rb'\b[a-z][a-z0-9+.\-]{1,20}://[^/\s:@"\']{1,64}:[^/\s@"\']{6,128}@[^/\s"\']+'),
    ('generic-assignment', rb'(?i)\b(?:api[_-]?key|secret|passw(?:or)?d|token|auth[_-]?key|private[_-]?key|client[_-]?secret)\b["\']?\s*[:=]\s*["\'][^"\'\s]{12,}["\']'),
)
_COMPILED = tuple((rule_id, re.compile(pattern)) for rule_id, pattern in RULES)

# Containers whose content is compressed or encoded: the rules cannot see inside them.
_OPAQUE_MAGIC: tuple[tuple[int, bytes, str], ...] = (
    (0, b'PK\x03\x04', 'zip'), (0, b'PK\x05\x06', 'zip'), (0, b'\x1f\x8b', 'gzip'), (0, b'BZh', 'bzip2'),
    (0, b'\xfd7zXZ\x00', 'xz'), (0, b"7z\xbc\xaf'\x1c", '7z'), (0, b'Rar!\x1a\x07', 'rar'),
    (0, b'\x28\xb5\x2f\xfd', 'zstd'), (257, b'ustar', 'tar'), (0, b'MSCF', 'cab'),
)


def rules_digest() -> str:
    return domain_digest('getzilla-secret-rules-v1', {
        'scanner': SCANNER, 'version': SCANNER_VERSION,
        'rules': [[rule_id, pattern.decode('latin-1')] for rule_id, pattern in RULES],
        'opaque': [[offset, magic.hex(), kind] for offset, magic, kind in _OPAQUE_MAGIC],
    })


def opaque_kind(content: bytes) -> str | None:
    for offset, magic, kind in _OPAQUE_MAGIC:
        if content[offset:offset + len(magic)] == magic:
            return kind
    return None


def scan_bytes(path: str, content: bytes) -> tuple[list[Finding], Finding | None]:
    """Findings for one file's bytes, or an unsupported marker for an opaque container."""
    kind = opaque_kind(content)
    if kind is not None:
        return [], Finding(path=path, reason_code='OPAQUE_CONTAINER_REQUIRES_EXCLUSION', rule_id=f'container:{kind}')
    findings: list[Finding] = []
    for rule_id, pattern in _COMPILED:
        for match in pattern.finditer(content):
            line = content.count(b'\n', 0, match.start()) + 1
            findings.append(Finding(path=path, reason_code='SECRET_PATTERN', rule_id=rule_id, line=line))
            break  # one finding per rule and file is enough to block; no match bytes are kept
    return findings, None


def _excepted(finding: Finding, entry: SourceEntry, policy: IngestPolicy) -> bool:
    return any(item.path == entry.path and item.rule_id == finding.rule_id and item.sha256 == entry.sha256
               for item in policy.exceptions)


@dataclass
class _Totals:
    files: int = 0
    bytes: int = 0


def evaluate(entry: SourceEntry, content: bytes, policy: IngestPolicy) -> tuple[list[Finding], Finding | None]:
    findings, unsupported = scan_bytes(entry.path, content)
    return [item for item in findings if not _excepted(item, entry, policy)], unsupported


def _open_parent(root_handle: fsx.DirHandle, parts: Sequence[str]) -> list[fsx.DirHandle]:
    handles = [root_handle]
    for part in parts:
        handles.append(fsx.open_dir_at(handles[-1], part))
    return handles


def read_entry(root: Path, entry: SourceEntry, limit: int) -> tuple[bytes | None, str | None]:
    """Read one admitted file again, through no-follow directory handles, and confirm its digest."""
    parts = entry.path.split('/')
    try:
        root_handle = fsx.open_dir(root)
    except OSError:
        return None, 'SOURCE_ROOT_UNREADABLE_OR_LINK'
    handles = [root_handle]
    try:
        try:
            handles = _open_parent(root_handle, parts[:-1])
            info = fsx.lstat_at(handles[-1], parts[-1])
        except OSError:
            return None, 'SOURCE_CHANGED_DURING_READ'
        if fsx.is_link(info) or not stat.S_ISREG(info.st_mode):
            return None, 'SOURCE_CHANGED_DURING_READ'
        content, digest, size, problem = read_regular_file(handles[-1], parts[-1], info, limit)
        if problem:
            return None, problem
        if digest != entry.sha256 or size != entry.size:
            return None, 'SOURCE_CHANGED_SINCE_INVENTORY'
        return content, None
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def scan_candidates(root: Path, candidates: Iterable[SourceEntry], policy: IngestPolicy) -> ScanReport:
    """Scan every candidate's current bytes; any error, change or opaque input is not a pass."""
    candidates = list(candidates)
    findings: list[Finding] = []
    unsupported: list[Finding] = []
    errors: list[Finding] = []
    totals = _Totals()
    for entry in candidates:
        content, problem = read_entry(root, entry, policy.max_file_bytes)
        if problem or content is None:
            errors.append(Finding(path=entry.path, reason_code=problem or 'UNREADABLE'))
            continue
        found, opaque = evaluate(entry, content, policy)
        del content
        totals.files += 1
        totals.bytes += entry.size
        findings.extend(found)
        if opaque is not None:
            unsupported.append(opaque)
    if errors:
        status = 'error'
    elif findings or unsupported:
        status = 'fail'
    else:
        status = 'pass'
    return ScanReport(status=status, scanner=SCANNER, scanner_version=SCANNER_VERSION,
                      rules_digest=rules_digest(), files_scanned=totals.files, bytes_scanned=totals.bytes,
                      findings=tuple(findings), unsupported=tuple(unsupported), errors=tuple(errors),
                      candidates=len(candidates))


def not_run_report(candidates: int) -> ScanReport:
    return ScanReport(status='not_run', scanner=SCANNER, scanner_version=SCANNER_VERSION,
                      rules_digest=rules_digest(), files_scanned=0, bytes_scanned=0, candidates=candidates)


