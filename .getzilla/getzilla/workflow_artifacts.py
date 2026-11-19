from __future__ import annotations

import hashlib
import itertools
import json as json  # compatibility export: same JSON parser owner
import os
import re
import stat as stat  # compatibility module export
import ctypes as ctypes  # compatibility module export
import errno as errno  # compatibility module export
import threading as threading  # compatibility module export
import time as time  # compatibility module export
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

try:
    from .workflow_inputs import (  # noqa: F401 exact compatibility exports
        PLACEHOLDER, MAX_DEPTH, MAX_NODES, MAX_SOURCE_BYTES, MAX_STRING_LENGTH, WorkflowArtifactError, _bounded_walk, _open_root, _read_regular, _read_regular_windows, _stat_identity, _strict_json, _windows_confirm_directories, _windows_open_regular, canonical_json, fsx,
    )
    from .workflow_storage import change_directory, valid_package_path
except ImportError:  # loaded standalone by file path: bind sibling input/storage owners
    import importlib.util as _importlib_util
    _INPUT_SPEC = _importlib_util.spec_from_file_location(
        "_getzilla_workflow_inputs", Path(__file__).with_name("workflow_inputs.py"))
    assert _INPUT_SPEC is not None and _INPUT_SPEC.loader is not None
    _inputs = _importlib_util.module_from_spec(_INPUT_SPEC)
    _INPUT_SPEC.loader.exec_module(_inputs)
    PLACEHOLDER = _inputs.PLACEHOLDER
    MAX_DEPTH = _inputs.MAX_DEPTH
    MAX_NODES = _inputs.MAX_NODES
    MAX_SOURCE_BYTES = _inputs.MAX_SOURCE_BYTES
    MAX_STRING_LENGTH = _inputs.MAX_STRING_LENGTH
    WorkflowArtifactError = _inputs.WorkflowArtifactError
    _bounded_walk = _inputs._bounded_walk
    _open_root = _inputs._open_root
    _read_regular = _inputs._read_regular
    _read_regular_windows = _inputs._read_regular_windows
    _stat_identity = _inputs._stat_identity
    _strict_json = _inputs._strict_json
    _windows_confirm_directories = _inputs._windows_confirm_directories
    _windows_open_regular = _inputs._windows_open_regular
    canonical_json = _inputs.canonical_json
    fsx = _inputs.fsx
    _STORAGE_SPEC = _importlib_util.spec_from_file_location(
        "_getzilla_workflow_storage", Path(__file__).with_name("workflow_storage.py"))
    assert _STORAGE_SPEC is not None and _STORAGE_SPEC.loader is not None
    _storage = _importlib_util.module_from_spec(_STORAGE_SPEC)
    _STORAGE_SPEC.loader.exec_module(_storage)
    change_directory, valid_package_path = _storage.change_directory, _storage.valid_package_path


MAX_MANIFEST_BYTES = 262_144
MAX_SOURCES = 256
MAX_MARKDOWN_LINES = 20_000
MAX_MARKDOWN_LINE_LENGTH = 8_192
MAX_TASKS = 500
MAX_REVIEWERS = 20
MAX_COMMAND_ARGV = 32
MAX_TASK_REFERENCES = 20_000
MAX_RECEIPT_ERRORS = 100
MAX_AGENT_LENGTH = 128
MAX_TITLE_LENGTH = 256
MAX_PATH_LENGTH = 512
MAX_INTERFACE_LENGTH = 512
MAX_MATCHED_DOMAINS = 16
MAX_MATCHED_KEYWORDS = 32
MAX_KEYWORD_LENGTH = 64
# Keep byte-identical to receipts.RECEIPT_KINDS (parity-tested; this module
# stays standalone-importable, so the set cannot be a shared import here).
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
RUNTIME_ROUTE_KEYS = {
    "task_context_version", "logical_task_id", "origin_session_id", "authority_epoch",
    "state_revision", "workspace", "context", "handoff",
    "allowed_agents",
    "analysis_agents",
    "base_commit",
    "base_fingerprint",
    "change_id",
    "complexity",
    "created_at",
    "delivery_expected",
    "delivery_lane",
    "light_diff",
    "light_lane_candidate",
    "domains",
    "human_gates",
    "intent",
    "matched_keywords",
    "primary_skill",
    "quality_profiles",
    "rationale",
    "repo",
    "required_evidence",
    "review_agents",
    "risk",
    "risk_assessment",
    "review_plan",
    "explicit_review_agents",
    "route_id",
    "schema_version",
    "session_id",
    "status",
    "task",
    "task_domains",
    "updated_at",
    "workflow_skills",
    "write_agent",
}
_CAS_RECOVERY_SEQUENCE = itertools.count()

ROLE_MAP = {
    "spec-kit": {
        "constitution": "governance-candidate",
        "spec": "requirements-candidate",
        "plan": "architecture-candidate",
        "tasks": "task-candidate",
        "checklist": "convergence-hint",
    },
    "bmad": {
        "prd": "requirements-candidate",
        "spec": "requirements-candidate",
        "architecture": "architecture-candidate",
        "project-context": "governance-candidate",
        "epics": "task-candidate",
        "stories": "task-candidate",
        "sprint-status": "status-projection",
        "readiness": "convergence-hint",
    },
    "superpowers": {
        "spec": "requirements-candidate",
        "plan": "architecture-candidate",
        "sdd-evidence": "runtime-evidence",
    },
}
PATH_PREFIXES = {
    "spec-kit": (".specify/", "specs/"),
    "bmad": ("_bmad/", "_bmad-output/"),
    "superpowers": ("docs/superpowers/", ".superpowers/sdd/"),
}
# YAML authority syntax is rejected; Markdown emphasis that merely looks like
# an alias (italic "*word ... *" at line start) is legitimate upstream template
# text (spec-kit ships e.g. "*Example of marking unclear requirements:*" and
# "*GATE: Must pass before Phase 0 research. ...*") and must load. Anchors and
# aliases are matched only in YAML positions: document/sequence start "&name",
# mapping value ": &name", whole-value alias "*name" after ": " or "- ".
FORBIDDEN_SOURCE = re.compile(
    r"(?:^|\s)!!"
    r"|(?:^|\s)<<:"
    r"|^[ \t]*(?:-[ \t]+)?&[A-Za-z0-9_.-]+"
    r"|:[ \t]+&[A-Za-z0-9_.-]+"
    r"|^[ \t]*-[ \t]+\*[A-Za-z0-9_.-]+[ \t]*$"
    r"|:[ \t]+\*[A-Za-z0-9_.-]+[ \t]*$",
    re.M,
)
TASK_PATTERN = re.compile(r"^\s*<!--\s*AGB-TASK\s+(.+?)\s*-->\s*$")
CLAIM_PATTERN = re.compile(r"^\s*<!--\s*AGB-CLAIM\s+(.+?)\s*-->\s*$")
STATUS_PATTERN = re.compile(r"^\s*<!--\s*AGB-TASK-STATUS\s+(.+?)\s*-->\s*$")
TASK_KEYS = {
    "key",
    "title",
    "depends_on",
    "covers",
    "files",
    "interfaces",
    "red",
    "green",
    "status",
    "enrichment_required",
}
SOURCE_STATUS_VALUES = {"pending", "in_progress", "complete"}
# Conservative-superset BMAD story-status vocabulary around
# bmad-code-org/BMAD-METHOD v6.12.0 (template samples omit `ready-for-review`;
# build-spec front matter adds `in-review`): only terminal members may mark
# imported work advanced; everything else (including `blocked`) stays a
# non-terminal hint, advisory only.
BMAD_TERMINAL_STATUS = frozenset({"done", "complete", "completed", "ready-for-review", "in-review", "review"})
BMAD_NONTERMINAL_STATUS = frozenset(
    {"backlog", "draft", "ready-for-dev", "ready", "in-progress", "open", "optional", "blocked", "high-level"}
)
SPEC_TASK = re.compile(r"^\s*-\s*\[([ xX])\]\s+(T[0-9]{1,6})\s+(?:(\[P\])\s+)?(?:\[US[0-9]+\]\s+)?(.+?)\s*$")
BMAD_TASK = re.compile(r"^\s*-\s*\[([ xX])\]\s+(.+?)\s*$")
CRITERION_TOKEN = re.compile(r"\b(?:AC|INV|FORBID)-[0-9]{3,6}\b")
FILE_TOKEN = re.compile(r"(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+)")
NATIVE_STATUS = re.compile(r"^\s*-\s*\[([ xX])\]\s+(T[0-9]{1,6})\b")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SAFE_UNITTEST_TARGET = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?::[A-Za-z_][A-Za-z0-9_]*)?$")




class WorkflowSource:
    def __init__(self, identity: dict[str, Any], content: str) -> None:
        self.identity = identity
        self.content = content

    def to_dict(self) -> dict[str, Any]:
        return dict(self.identity)


class SourceBundle:
    def __init__(self, sources: tuple[WorkflowSource, ...], manifest_digest: str) -> None:
        self.sources = sources
        self.manifest_digest = manifest_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "manifest_digest": self.manifest_digest,
            "sources": [source.to_dict() for source in self.sources],
        }


def validate_workflow_source(identity: Any) -> dict[str, Any]:
    required = {"schema_version", "source_type", "source_version", "role", "path", "size", "sha256"}
    if not isinstance(identity, dict) or set(identity) != required or identity.get("schema_version") != 1:
        raise WorkflowArtifactError("workflow source has an invalid closed shape", code="source-schema")
    source_type = identity.get("source_type")
    role = identity.get("role")
    if source_type not in ROLE_MAP or role not in ROLE_MAP[source_type]:
        raise WorkflowArtifactError("workflow source type or role is invalid", code="source-schema")
    _bounded_text(identity.get("source_version"), "source_version", maximum=32)
    path = identity.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        raise WorkflowArtifactError("workflow source path is invalid", code="source-schema")
    _relative_path(Path("/repository"), path)
    size = identity.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_SOURCE_BYTES:
        raise WorkflowArtifactError("workflow source size is invalid", code="source-schema")
    if not isinstance(identity.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", identity["sha256"]):
        raise WorkflowArtifactError("workflow source digest is invalid", code="source-schema")
    return identity








def _relative_path(root: Path, path: Path | str) -> str:
    # Text is untrusted repository-relative input: a backslash is a filename character on POSIX
    # and a separator on Windows, so it is refused. A Path was built by this platform and keeps
    # its native separators (every absolute Windows path has backslashes).
    raw = path.as_posix() if isinstance(path, Path) else os.fspath(path)
    if not isinstance(raw, str) or "\\" in raw or CONTROL.search(raw):
        raise WorkflowArtifactError("path contains a control character or backslash", code="path")
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            candidate = candidate.relative_to(root)
        except ValueError:
            # The root is canonical; an absolute path may still name it through a system symlink
            # (macOS /var -> /private/var). No other link is followed here.
            try:
                candidate = Path(fsx.system_canonical(candidate)).relative_to(root)
            except ValueError as exc:
                raise WorkflowArtifactError("path escapes repository", code="path") from exc
    pure = PurePosixPath(candidate.as_posix())
    # Windows does not call '/etc/passwd' absolute (no drive), and 'C:x' names another drive:
    # joined to the root, both leave the repository.
    if pure.is_absolute() or PureWindowsPath(pure.as_posix()).anchor:
        raise WorkflowArtifactError("path escapes repository", code="path")
    if not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise WorkflowArtifactError("invalid repository-relative path", code="path")
    value = pure.as_posix()
    if len(value) > MAX_PATH_LENGTH or unicodedata.normalize("NFC", value) != value:
        raise WorkflowArtifactError("path is unbounded or non-NFC", code="path")
    return value


def _bounded_text(value: Any, name: str, *, minimum: int = 1, maximum: int = MAX_STRING_LENGTH) -> str:
    if (
        not isinstance(value, str)
        or len(value) < minimum
        or len(value) > maximum
        or unicodedata.normalize("NFC", value) != value
        or CONTROL.search(value)
    ):
        raise WorkflowArtifactError(f"{name} is empty, unbounded, non-NFC, or contains controls", code="schema")
    return value


def _bounded_markdown(content: str, path: str) -> None:
    if "\x00" in content or unicodedata.normalize("NFC", content) != content:
        raise WorkflowArtifactError(f"source content is unsafe: {path}", code="content")
    lines = content.splitlines()
    if len(lines) > MAX_MARKDOWN_LINES or any(len(line) > MAX_MARKDOWN_LINE_LENGTH for line in lines):
        raise WorkflowArtifactError(f"source text limits exceeded: {path}", code="limit")














def load_source_manifest(root: Path, manifest_path: Path) -> SourceBundle:
    canonical = root.resolve(strict=True)
    manifest_rel = _relative_path(canonical, manifest_path)
    manifest_raw = _read_regular(canonical, manifest_rel, limit=MAX_MANIFEST_BYTES)
    manifest = _strict_json(manifest_raw, limit=MAX_MANIFEST_BYTES)
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "sources"}
        or manifest.get("schema_version") != 1
    ):
        raise WorkflowArtifactError("manifest must be a closed schema_version 1 object", code="schema")
    entries = manifest.get("sources")
    if not isinstance(entries, list) or len(entries) > MAX_SOURCES:
        raise WorkflowArtifactError("manifest sources must be a bounded array", code="schema")
    seen: set[str] = set()
    seen_casefold: set[str] = set()
    sources: list[WorkflowSource] = []
    for entry in entries:
        required = {"source_type", "source_version", "role", "path"}
        if (
            not isinstance(entry, dict)
            or set(entry) != required
            or not all(isinstance(entry[key], str) for key in required)
        ):
            raise WorkflowArtifactError("manifest source entry is not closed", code="schema")
        source_type = entry["source_type"]
        role = entry["role"]
        source_version = _bounded_text(entry["source_version"], "source_version", maximum=32)
        _bounded_text(source_type, "source_type", maximum=32)
        _bounded_text(role, "role", maximum=32)
        if source_type not in ROLE_MAP or role not in ROLE_MAP[source_type]:
            raise WorkflowArtifactError("source type or role is not allowlisted", code="role")
        if Path(entry["path"]).is_absolute():
            raise WorkflowArtifactError("source path must be repository-relative", code="path")
        path = _relative_path(canonical, entry["path"])
        folded_path = path.casefold()
        if path in seen or folded_path in seen_casefold or not path.startswith(PATH_PREFIXES[source_type]):
            raise WorkflowArtifactError("source path is duplicate or outside framework allowlist", code="path")
        if source_type == "superpowers" and role == "sdd-evidence" and not path.startswith(".superpowers/sdd/"):
            raise WorkflowArtifactError("Superpowers runtime evidence must stay under .superpowers/sdd", code="path")
        if source_type == "superpowers" and role != "sdd-evidence" and not path.startswith("docs/superpowers/"):
            raise WorkflowArtifactError("Superpowers tracked sources must stay under docs/superpowers", code="path")
        seen.add(path)
        seen_casefold.add(folded_path)
        raw = _read_regular(canonical, path, limit=MAX_SOURCE_BYTES)
        try:
            content = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise WorkflowArtifactError(f"source is not UTF-8: {path}", code="unicode") from exc
        _bounded_markdown(content, path)
        if FORBIDDEN_SOURCE.search(content):
            raise WorkflowArtifactError(
                f"source contains non-NFC or forbidden YAML authority syntax: {path}", code="content"
            )
        identity = {
            "schema_version": 1,
            "source_type": source_type,
            "source_version": source_version,
            "role": role,
            "path": path,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        validate_workflow_source(identity)
        sources.append(WorkflowSource(identity, content))
    sources.sort(key=lambda item: (item.identity["source_type"], item.identity["path"], item.identity["role"]))
    normalized_manifest = {"schema_version": 1, "sources": [source.to_dict() for source in sources]}
    return SourceBundle(tuple(sources), hashlib.sha256(canonical_json(normalized_manifest)).hexdigest())


def load_runtime_authority(root: Path, kind: str) -> dict[str, Any]:
    """Read the two CLI authority pointers through the bounded descriptor loader."""
    relative = {
        "route": ".getzilla/runtime/active-route.json",
        "change": ".getzilla/runtime/active-change.json",
    }.get(kind)
    if relative is None:
        raise WorkflowArtifactError("runtime authority kind is invalid", code="route")
    if kind == 'route':
        from .state import get_active_route, _route_document
        from .continuity import has_task_context, validate_route
        selected = get_active_route(root)
        if selected is not None and has_task_context(selected):
            data = selected
            validate_route(root, data)
        else:
            data = _route_document(root, root / relative, limit=1_048_576)
            if has_task_context(data):
                raise WorkflowArtifactError('canonical owned route is unavailable', code='route')
    else:
        from .native_state_snapshot import decode
        data = _strict_json(decode(_read_regular(root, relative, limit=4096),limit=4096), limit=MAX_MANIFEST_BYTES)
    if not isinstance(data, dict):
        raise WorkflowArtifactError(f"active {kind} must be an object", code=kind)
    if kind == "route":
        required = {"route_id", "write_agent", "review_agents", "required_evidence"}
        if set(data) - RUNTIME_ROUTE_KEYS or not required.issubset(data):
            raise WorkflowArtifactError("active route has an invalid closed shape", code="route")
        if "schema_version" in data and data["schema_version"] != 1:
            raise WorkflowArtifactError("active route schema version is invalid", code="route")
        if not isinstance(data.get("route_id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", data["route_id"]):
            raise WorkflowArtifactError("active route id is invalid", code="route")
        _validate_route(data)
        if "matched_keywords" in data:
            matches = data["matched_keywords"]
            if not isinstance(matches, dict) or len(matches) > MAX_MATCHED_DOMAINS:
                raise WorkflowArtifactError("active route keyword evidence is not a bounded map", code="route")
            for domain, keywords in matches.items():
                if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", domain):
                    raise WorkflowArtifactError("active route keyword domain is invalid", code="route")
                _string_list(
                    keywords,
                    "matched_keywords",
                    allow_empty=False,
                    maximum_items=MAX_MATCHED_KEYWORDS,
                    maximum_length=MAX_KEYWORD_LENGTH,
                )
    elif (
        set(data) != {"change_id", "path"}
        or not isinstance(data.get("change_id"), str)
        or not re.fullmatch(r"[A-Za-z0-9._:-]{3,128}", data["change_id"])
        or not valid_package_path(data.get("path"), data["change_id"])
    ):
        raise WorkflowArtifactError("active change has an invalid closed shape", code="change")
    return data


def digest_without(value: dict[str, Any], field: str) -> str:
    return hashlib.sha256(canonical_json({key: item for key, item in value.items() if key != field})).hexdigest()


def adapt_sources(bundle: SourceBundle) -> list[dict[str, Any]]:
    candidates = []
    for source in bundle.sources:
        identity = source.identity
        role = str(identity["role"])
        source_type = str(identity["source_type"])
        candidate = {
            "schema_version": 1,
            "source_type": source_type,
            "role": role,
            "path": identity["path"],
            "sha256": identity["sha256"],
            "candidate_kind": ROLE_MAP[source_type][role],
            "authority": False,
            "receipt_eligible": False,
        }
        candidates.append(candidate)
    return candidates


def _load_native_spec(root: Path, change_id: str) -> dict[str, Any]:
    relative = (change_directory(root, change_id) / "change-spec.yaml").relative_to(root).as_posix()
    data = _strict_json(_read_regular(root, relative, limit=MAX_SOURCE_BYTES), limit=MAX_SOURCE_BYTES)
    if not isinstance(data, dict) or data.get("change_id") != change_id:
        raise WorkflowArtifactError("native change specification is missing or mismatched", code="native")
    return data


def _string_list(
    value: Any,
    name: str,
    *,
    allow_empty: bool = True,
    maximum_items: int,
    maximum_length: int = 512,
) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value) or len(value) > maximum_items:
        raise WorkflowArtifactError(f"task {name} must be a bounded array", code="task")
    result = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > maximum_length
            or unicodedata.normalize("NFC", item) != item
            or CONTROL.search(item)
        ):
            raise WorkflowArtifactError(f"task {name} item is invalid", code="task")
        result.append(item)
    if len({item.casefold() for item in result}) != len(result):
        raise WorkflowArtifactError(f"task {name} contains duplicates", code="task")
    return result


def _verification_command(value: Any, name: str) -> list[str]:
    command = _string_list(
        value,
        name,
        allow_empty=False,
        maximum_items=MAX_COMMAND_ARGV,
        maximum_length=512,
    )
    if any("http://" in item.casefold() or "https://" in item.casefold() for item in command):
        raise WorkflowArtifactError(f"task {name} command contains a network locator", code="command")
    if command[:3] == ["python3", "-m", "unittest"]:
        if not all(SAFE_UNITTEST_TARGET.fullmatch(item) for item in command[3:]):
            raise WorkflowArtifactError(f"task {name} unittest command is outside the allowlist", code="command")
        return command
    if command in (
        ["python3", "scripts/getzilla_verify.py", "--mode", "fast"],
        ["python3", "scripts/getzilla_verify.py", "--mode", "pr"],
        ["python3", "scripts/getzilla_verify.py", "--mode", "focused-static-seo-landing"],
    ):
        return command
    raise WorkflowArtifactError(f"task {name} is not an allowlisted read-only verification command", code="command")


def _validate_route(route: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    writer = route.get("write_agent")
    reviewers = route.get("review_agents")
    required = route.get("required_evidence")
    if not isinstance(writer, str):
        raise WorkflowArtifactError("active route has no valid writer", code="route")
    writer = _bounded_text(writer, "write_agent", maximum=MAX_AGENT_LENGTH)
    if (
        not isinstance(reviewers, list)
        or len(reviewers) > MAX_REVIEWERS
        or not all(isinstance(item, str) for item in reviewers)
    ):
        raise WorkflowArtifactError("active route reviewers are invalid", code="route")
    normalized_reviewers = [_bounded_text(item, "review_agent", maximum=MAX_AGENT_LENGTH) for item in reviewers]
    if len({item.casefold() for item in normalized_reviewers}) != len(normalized_reviewers):
        raise WorkflowArtifactError("active route reviewers collide", code="route")
    if (
        not isinstance(required, list)
        or not required
        or len(required) > len(RECEIPT_KINDS)
        or any(not isinstance(item, str) or item not in RECEIPT_KINDS for item in required)
        or len(set(required)) != len(required)
    ):
        raise WorkflowArtifactError("active route required_evidence is empty or outside the closed set", code="route")
    return writer, normalized_reviewers, list(required)


def _task_metadata(bundle: SourceBundle) -> list[tuple[WorkflowSource, dict[str, Any]]]:
    result: list[tuple[WorkflowSource, dict[str, Any]]] = []
    for source in bundle.sources:
        if ROLE_MAP[str(source.identity["source_type"])][str(source.identity["role"])] != "task-candidate":
            continue
        if len(result) > MAX_TASKS:
            raise WorkflowArtifactError("task graph exceeds the task limit", code="limit")
        annotated_keys: set[str] = set()
        for line in source.content.splitlines():
            match = TASK_PATTERN.fullmatch(line)
            if not match:
                continue
            value = _strict_json(match.group(1).encode("utf-8"), limit=65_536)
            if (
                not isinstance(value, dict)
                or set(value) - TASK_KEYS
                or not TASK_KEYS.difference({"enrichment_required"}).issubset(value)
            ):
                raise WorkflowArtifactError("AGB task metadata has unsupported or missing fields", code="task")
            annotated_keys.add(str(value["key"]))
            result.append((source, value))
        native = _native_framework_tasks(source)
        result.extend((source, value) for value in native if value["key"] not in annotated_keys)
    return result


def _generated_task(key: str, title: str, depends_on: list[str], *, checked: bool) -> dict[str, Any]:
    covers = sorted(set(CRITERION_TOKEN.findall(title)))
    parsed_files = sorted(set(FILE_TOKEN.findall(title)))
    files = parsed_files or [f"workflow/imports/{key}.md"]
    command = ["python3", "scripts/getzilla_verify.py", "--mode", "pr"]
    enrichment = ["green", "interfaces", "red"] + ([] if parsed_files else ["files"])
    return {
        "key": key,
        "title": title[:256],
        "depends_on": depends_on,
        "covers": covers,
        "files": files,
        "interfaces": [f"imported-task:{key}"],
        "red": command,
        "green": command,
        "status": "complete" if checked else "pending",
        "enrichment_required": sorted(enrichment),
    }


def _native_framework_tasks(source: WorkflowSource) -> list[dict[str, Any]]:
    source_type = str(source.identity["source_type"])
    role = str(source.identity["role"])
    if source_type == "spec-kit" and role == "tasks":
        result: list[dict[str, Any]] = []
        previous_phase: list[str] = []
        current_phase: list[str] = []
        saw_phase = False
        for line in source.content.splitlines():
            if re.match(r"^#{2,6}\s+Phase\b", line, re.I):
                if saw_phase:
                    previous_phase = list(current_phase)
                current_phase = []
                saw_phase = True
                continue
            match = SPEC_TASK.fullmatch(line)
            if not match:
                continue
            key = match.group(2).lower()
            parallel = bool(match.group(3))
            title = match.group(4)
            dependencies = list(previous_phase)
            if not parallel and current_phase:
                dependencies.append(current_phase[-1])
            result.append(_generated_task(key, title, sorted(set(dependencies)), checked=match.group(1).lower() == "x"))
            current_phase.append(key)
        return result
    if source_type == "bmad" and role in {"stories", "epics"}:
        result: list[dict[str, Any]] = []
        section_kind = "epic" if role == "epics" else "story"
        section = "unscoped"
        previous: str | None = None
        ordinal = 0
        for line in source.content.splitlines():
            heading = re.match(
                r"^#{1,4}\s+(Story|Epic)\s+([0-9]+(?:\.[0-9]+)*[a-z]?|[A-Za-z0-9][A-Za-z0-9.-]*)", line, re.I
            )
            if heading:
                section_kind = heading.group(1).lower()
                section = re.sub(r"[^a-z0-9]+", "-", heading.group(2).lower()).strip("-") or "unscoped"
                previous = None
                ordinal = 0
                continue
            match = BMAD_TASK.fullmatch(line)
            if not match:
                continue
            ordinal += 1
            key = f"{section_kind}-{section}-{ordinal:03d}"
            title = match.group(2)
            dependencies = [previous] if previous is not None else []
            result.append(_generated_task(key, title, dependencies, checked=match.group(1).lower() == "x"))
            previous = key
        return result
    return []


def _source_status_is_terminal(source: "WorkflowSource", lines: list[str]) -> bool:
    """First-wins status extraction for native framework story/spec documents.

    Accepts the leading ``---`` front-matter ``status:`` key (BMAD v6.12 build
    spec), the annotated ``## Status`` heading followed by its value line, and
    the upstream story-template bare line form ``Status: <value>``. Unknown
    tokens are non-terminal by design; only BMAD_TERMINAL_STATUS advances
    imported work, and never native verification.
    """
    if source.identity["source_type"] != "bmad":
        return False
    if lines and lines[0] == "---":
        for line in lines[1:]:
            if line == "---":
                break
            match = re.fullmatch(r"status:\s*['\"]?([^'\"\s#]+)['\"]?", line, re.I)
            if match:
                return match.group(1).lower().replace(" ", "-") in BMAD_TERMINAL_STATUS
    for index, line in enumerate(lines):
        if re.fullmatch(r"#{2,6}\s+Status", line, re.I):
            status = next((item for item in lines[index + 1 :] if item and not item.startswith("#")), "")
            return status.lower().replace(" ", "-") in BMAD_TERMINAL_STATUS
        match = re.fullmatch(r"Status:\s*(.+)", line, re.I)
        if match:
            return match.group(1).strip("'\"").lower().replace(" ", "-") in BMAD_TERMINAL_STATUS
    return False


def _advanced_status_hints(bundle: SourceBundle | None) -> set[str]:
    if bundle is None:
        return set()
    hints: set[str] = set()
    all_task_keys = {task["key"] for source in bundle.sources for task in _native_framework_tasks(source)}
    for source in bundle.sources:
        native = _native_framework_tasks(source)
        checked_lines = [line for line in source.content.splitlines() if re.match(r"^\s*-\s*\[[xX]\]", line)]
        if checked_lines:
            checked_titles = {BMAD_TASK.fullmatch(line).group(2) for line in checked_lines if BMAD_TASK.fullmatch(line)}
            hints.update(
                task["key"]
                for task in native
                if task["title"] in checked_titles
                or str(source.identity["source_type"]) == "spec-kit"
                and any(task["key"].upper() in line for line in checked_lines)
            )
        lines = [line.strip() for line in source.content.splitlines()]
        if source.identity["source_type"] == "bmad" and source.identity["role"] == "sprint-status":
            for line in lines:
                match = re.fullmatch(
                    r"([a-z0-9][a-z0-9-]{0,127}):\s*(done|complete|completed|ready-for-review|in-review|review)",
                    line,
                    re.I,
                )
                if not match:
                    continue
                parts = match.group(1).lower().split("-")
                numeric = [part for part in parts if part.isdigit()]
                prefix = "story-" + "-".join(numeric[:2]) + "-" if numeric else "story-" + match.group(1).lower() + "-"
                hints.update(key for key in all_task_keys if key.startswith(prefix))
        if native and _source_status_is_terminal(source, lines):
            hints.update(task["key"] for task in native)
    return hints


def _validate_repo_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_PATH_LENGTH
        or "\\" in value
        or CONTROL.search(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        raise WorkflowArtifactError("task file path is unsafe", code="path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise WorkflowArtifactError("task file path is unsafe", code="path")
    return pure.as_posix()


def _has_path(graph: dict[str, set[str]], start: str, target: str) -> bool:
    pending = list(graph.get(start, ()))
    seen: set[str] = set()
    while pending:
        item = pending.pop()
        if item == target:
            return True
        if item not in seen:
            seen.add(item)
            pending.extend(graph.get(item, ()))
    return False


def compile_task_graph(root: Path, change_id: str, bundle: SourceBundle, route: dict[str, Any]) -> dict[str, Any]:
    writer, reviewers, _required_evidence = _validate_route(route)
    native = _load_native_spec(root, change_id)
    required_ids = sorted(
        str(item["id"])
        for group in ("acceptance_criteria", "invariants", "forbidden_outcomes")
        for item in native.get(group, [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    raw_tasks = _task_metadata(bundle)
    if len(raw_tasks) > MAX_TASKS:
        raise WorkflowArtifactError("task graph exceeds the task limit", code="limit")
    keys: set[str] = set()
    interim: list[dict[str, Any]] = []
    for source, raw in raw_tasks:
        key, title = raw["key"], raw["title"]
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key)
            or key in keys
            or not isinstance(title, str)
            or not title
            or len(title) > MAX_TITLE_LENGTH
            or unicodedata.normalize("NFC", title) != title
            or CONTROL.search(title)
        ):
            raise WorkflowArtifactError("task key/title is invalid or duplicate", code="task")
        keys.add(key)
        dependencies = _string_list(raw["depends_on"], "depends_on", maximum_items=100)
        covers = _string_list(raw["covers"], "covers", maximum_items=500)
        if any(CRITERION_TOKEN.fullmatch(item) is None for item in covers):
            raise WorkflowArtifactError("task criterion id is invalid", code="coverage")
        files = [
            _validate_repo_path(item)
            for item in _string_list(raw["files"], "files", allow_empty=False, maximum_items=200)
        ]
        interfaces = _string_list(
            raw["interfaces"], "interfaces", allow_empty=False, maximum_items=100, maximum_length=MAX_INTERFACE_LENGTH
        )
        red = _verification_command(raw["red"], "red")
        green = _verification_command(raw["green"], "green")
        status_value = raw["status"]
        enrichment = _string_list(
            raw.get("enrichment_required", []), "enrichment_required", maximum_items=5, maximum_length=32
        )
        if any(item not in {"files", "interfaces", "red", "green", "covers"} for item in enrichment):
            raise WorkflowArtifactError("task enrichment marker is invalid", code="task")
        if status_value not in SOURCE_STATUS_VALUES:
            raise WorkflowArtifactError("task source status is invalid", code="task")
        stable_core = {
            "key": key,
            "title": title,
            "covers": sorted(covers),
            "files": sorted(files),
            "interfaces": sorted(interfaces),
            "enrichment_required": sorted(enrichment),
            "source_sha256": source.identity["sha256"],
        }
        task_id = "TASK-" + hashlib.sha256(canonical_json(stable_core)).hexdigest()[:12]
        interim.append(
            {
                "task_id": task_id,
                "key": key,
                "title": title,
                "depends_on_keys": dependencies,
                "covers": sorted(covers),
                "files": sorted(files),
                "interfaces": sorted(interfaces),
                "red": red,
                "green": green,
                "source_status": status_value,
                "enrichment_required": sorted(enrichment),
                "source_sha256": source.identity["sha256"],
            }
        )
    aggregate_references = sum(
        len(task["depends_on_keys"]) + len(task["covers"]) + len(task["files"]) + len(task["interfaces"])
        for task in interim
    )
    if aggregate_references > MAX_TASK_REFERENCES:
        raise WorkflowArtifactError("task graph aggregate reference limit exceeded", code="limit")
    id_by_key = {task["key"]: task["task_id"] for task in interim}
    dependencies: dict[str, set[str]] = {}
    for task in interim:
        missing = set(task.pop("depends_on_keys")) - set(id_by_key)
        if missing:
            raise WorkflowArtifactError(f"task has missing dependencies: {sorted(missing)}", code="dependency")
        task["depends_on"] = sorted(id_by_key[key] for key in raw_tasks_by_key(interim, task["key"], raw_tasks))
        if task["task_id"] in task["depends_on"]:
            raise WorkflowArtifactError("task depends on itself", code="self-dependency")
        dependencies[task["task_id"]] = set(task["depends_on"])
    pending = {task_id: len(values) for task_id, values in dependencies.items()}
    dependents: dict[str, set[str]] = {task_id: set() for task_id in dependencies}
    for task_id, values in dependencies.items():
        for dependency in values:
            dependents[dependency].add(task_id)
    ready = sorted(task_id for task_id, count in pending.items() if count == 0)
    order: list[str] = []
    while ready:
        task_id = ready.pop(0)
        order.append(task_id)
        for dependent in sorted(dependents[task_id]):
            pending[dependent] -= 1
            if pending[dependent] == 0:
                ready.append(dependent)
                ready.sort()
    if len(order) != len(dependencies):
        raise WorkflowArtifactError("task dependency graph contains a cycle", code="cycle")
    ancestors: dict[str, set[str]] = {}
    for task_id in order:
        ancestors[task_id] = set(dependencies[task_id])
        for dependency in dependencies[task_id]:
            ancestors[task_id].update(ancestors[dependency])
    file_owners: dict[str, list[str]] = {}
    for task in interim:
        for path in task["files"]:
            file_owners.setdefault(path.casefold(), []).append(task["task_id"])
    for owners in file_owners.values():
        for index, left in enumerate(owners):
            for right in owners[index + 1 :]:
                if left not in ancestors[right] and right not in ancestors[left]:
                    raise WorkflowArtifactError("unordered tasks declare a write conflict", code="write-conflict")
    covered = {criterion for task in interim for criterion in task["covers"]}
    unknown = covered - set(required_ids)
    missing = set(required_ids) - covered
    if unknown or missing:
        raise WorkflowArtifactError(
            f"task criterion coverage mismatch: unknown={sorted(unknown)} missing={sorted(missing)}", code="coverage"
        )
    graph: dict[str, Any] = {
        "schema_version": 1,
        "change_id": change_id,
        "source_manifest_digest": bundle.manifest_digest,
        "write_agent": writer,
        "review_agents": sorted(set(reviewers)),
        "tasks": sorted(interim, key=lambda item: item["task_id"]),
    }
    graph["graph_digest"] = digest_without(graph, "graph_digest")
    validate_task_graph(graph)
    return graph


def raw_tasks_by_key(
    interim: list[dict[str, Any]], key: str, raw_tasks: list[tuple[WorkflowSource, dict[str, Any]]]
) -> list[str]:
    del interim
    for _source, raw in raw_tasks:
        if raw["key"] == key:
            return list(raw["depends_on"])
    raise WorkflowArtifactError("task dependency source disappeared", code="task")


def validate_task_graph(graph: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "change_id",
        "source_manifest_digest",
        "write_agent",
        "review_agents",
        "tasks",
        "graph_digest",
    }
    if not isinstance(graph, dict) or set(graph) != required or graph.get("schema_version") != 1:
        raise WorkflowArtifactError("task graph has an invalid closed shape", code="graph-schema")
    _bounded_text(graph.get("change_id"), "change_id", minimum=3, maximum=128)
    _bounded_text(graph.get("write_agent"), "write_agent", maximum=MAX_AGENT_LENGTH)
    for field in ("source_manifest_digest", "graph_digest"):
        if not isinstance(graph.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", graph[field]):
            raise WorkflowArtifactError(f"task graph {field} is invalid", code="graph-schema")
    reviewers = graph.get("review_agents")
    if (
        not isinstance(reviewers, list)
        or len(reviewers) > MAX_REVIEWERS
        or any(not isinstance(item, str) for item in reviewers)
    ):
        raise WorkflowArtifactError("task graph reviewers are invalid", code="graph-schema")
    normalized_reviewers = [_bounded_text(item, "review_agent", maximum=MAX_AGENT_LENGTH) for item in reviewers]
    if len({item.casefold() for item in normalized_reviewers}) != len(normalized_reviewers):
        raise WorkflowArtifactError("task graph reviewers collide", code="graph-schema")
    tasks = graph.get("tasks")
    if not isinstance(tasks, list) or len(tasks) > MAX_TASKS:
        raise WorkflowArtifactError("task graph task limit exceeded", code="graph-schema")
    expected_task_keys = {
        "task_id",
        "key",
        "title",
        "depends_on",
        "covers",
        "files",
        "interfaces",
        "red",
        "green",
        "source_status",
        "enrichment_required",
        "source_sha256",
    }
    task_ids: set[str] = set()
    task_keys: set[str] = set()
    aggregate = 0
    for task in tasks:
        if not isinstance(task, dict) or set(task) != expected_task_keys:
            raise WorkflowArtifactError("task record has an invalid closed shape", code="graph-schema")
        task_id = task.get("task_id")
        key = task.get("key")
        if (
            not isinstance(task_id, str)
            or not re.fullmatch(r"TASK-[0-9a-f]{12}", task_id)
            or task_id in task_ids
            or not isinstance(key, str)
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key)
            or key.casefold() in task_keys
        ):
            raise WorkflowArtifactError("task identity is invalid or duplicate", code="graph-schema")
        task_ids.add(task_id)
        task_keys.add(key.casefold())
        _bounded_text(task.get("title"), "task title", maximum=MAX_TITLE_LENGTH)
        dependencies = _string_list(task.get("depends_on"), "depends_on", maximum_items=100)
        covers = _string_list(task.get("covers"), "covers", maximum_items=500)
        if any(CRITERION_TOKEN.fullmatch(item) is None for item in covers):
            raise WorkflowArtifactError("task criterion id is invalid", code="graph-schema")
        files = _string_list(task.get("files"), "files", allow_empty=False, maximum_items=200)
        for path in files:
            _validate_repo_path(path)
        interfaces = _string_list(
            task.get("interfaces"),
            "interfaces",
            allow_empty=False,
            maximum_items=100,
            maximum_length=MAX_INTERFACE_LENGTH,
        )
        _verification_command(task.get("red"), "red")
        _verification_command(task.get("green"), "green")
        enrichment = _string_list(
            task.get("enrichment_required"), "enrichment_required", maximum_items=5, maximum_length=32
        )
        if any(item not in {"files", "interfaces", "red", "green", "covers"} for item in enrichment):
            raise WorkflowArtifactError("task enrichment marker is invalid", code="graph-schema")
        if task.get("source_status") not in SOURCE_STATUS_VALUES:
            raise WorkflowArtifactError("task source status is invalid", code="graph-schema")
        if not isinstance(task.get("source_sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", task["source_sha256"]):
            raise WorkflowArtifactError("task source digest is invalid", code="graph-schema")
        aggregate += len(dependencies) + len(covers) + len(files) + len(interfaces)
    if aggregate > MAX_TASK_REFERENCES:
        raise WorkflowArtifactError("task graph aggregate reference limit exceeded", code="graph-schema")
    if any(dependency not in task_ids for task in tasks for dependency in task["depends_on"]):
        raise WorkflowArtifactError("task graph dependency is missing", code="graph-schema")
    return graph


def validate_convergence_report(report: Any) -> dict[str, Any]:
    required = {
        "schema_version",
        "change_id",
        "graph_digest",
        "source_manifest_digest",
        "status",
        "coverage",
        "findings",
        "report_digest",
    }
    if not isinstance(report, dict) or set(report) != required or report.get("schema_version") != 1:
        raise WorkflowArtifactError("convergence report has an invalid closed shape", code="report-schema")
    _bounded_text(report.get("change_id"), "change_id", minimum=3, maximum=128)
    for field in ("graph_digest", "source_manifest_digest", "report_digest"):
        if not isinstance(report.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", report[field]):
            raise WorkflowArtifactError(f"convergence report {field} is invalid", code="report-schema")
    if report.get("status") not in {"pass", "block"}:
        raise WorkflowArtifactError("convergence report status is invalid", code="report-schema")
    coverage = report.get("coverage")
    if not isinstance(coverage, dict) or set(coverage) != {"required", "covered", "missing"}:
        raise WorkflowArtifactError("convergence report coverage is invalid", code="report-schema")
    for field in ("required", "covered", "missing"):
        _string_list(coverage[field], f"coverage.{field}", maximum_items=2_000, maximum_length=32)
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > 2_000:
        raise WorkflowArtifactError("convergence report findings are invalid", code="report-schema")
    finding_keys = {"finding_id", "code", "path", "message", "disposition", "blocking"}
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != finding_keys:
            raise WorkflowArtifactError("convergence finding has an invalid closed shape", code="report-schema")
        finding_id = finding.get("finding_id")
        if (
            not isinstance(finding_id, str)
            or not re.fullmatch(r"FIND-[0-9a-f]{12}", finding_id)
            or finding_id in finding_ids
        ):
            raise WorkflowArtifactError("convergence finding identity is invalid", code="report-schema")
        finding_ids.add(finding_id)
        code = _bounded_text(finding.get("code"), "finding code", maximum=64)
        if not re.fullmatch(r"[a-z0-9-]+", code):
            raise WorkflowArtifactError("convergence finding code is invalid", code="report-schema")
        _bounded_text(finding.get("path"), "finding path", maximum=MAX_PATH_LENGTH)
        _bounded_text(finding.get("message"), "finding message", maximum=2_048)
        if (
            finding.get("disposition")
            not in {
                "accept-native",
                "revise-import",
                "refresh-evidence",
                "resolve-conflict",
            }
            or finding.get("blocking") is not True
        ):
            raise WorkflowArtifactError("convergence finding disposition is invalid", code="report-schema")
    return report


def _finding(code: str, path: str, message: str, disposition: str) -> dict[str, Any]:
    core = {"code": code, "path": path, "message": message, "disposition": disposition, "blocking": True}
    return {"finding_id": "FIND-" + hashlib.sha256(canonical_json(core)).hexdigest()[:12], **core}


def _explicit_claims(bundle: SourceBundle | None) -> list[dict[str, str]]:
    if bundle is None:
        return []
    claims: list[dict[str, str]] = []
    for source in bundle.sources:
        for line in source.content.splitlines():
            match = CLAIM_PATTERN.fullmatch(line)
            if not match:
                continue
            value = _strict_json(match.group(1).encode("utf-8"), limit=65_536)
            if (
                not isinstance(value, dict)
                or set(value) != {"kind", "id", "statement"}
                or value.get("kind") not in {"objective", "criterion", "architecture"}
                or not all(isinstance(value.get(key), str) and value[key] for key in ("id", "statement"))
            ):
                raise WorkflowArtifactError("AGB claim metadata is invalid", code="claim")
            claims.append(
                {
                    "kind": value["kind"],
                    "id": value["id"],
                    "statement": value["statement"],
                    "path": str(source.identity["path"]),
                }
            )
    return sorted(claims, key=lambda item: (item["kind"], item["id"], item["path"], item["statement"]))


def _native_task_statuses(root: Path, change_id: str) -> dict[str, str]:
    relative = (change_directory(root, change_id) / "tasks.md").relative_to(root).as_posix()
    try:
        raw = _read_regular(root, relative, limit=MAX_SOURCE_BYTES)
    except WorkflowArtifactError as exc:
        if exc.code == "io":
            return {}
        raise
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise WorkflowArtifactError("native tasks projection is not UTF-8", code="unicode") from exc
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        native_match = NATIVE_STATUS.match(line)
        if native_match:
            key = native_match.group(2).lower()
            status = "complete" if native_match.group(1).lower() == "x" else "pending"
            if key in statuses and statuses[key] != status:
                raise WorkflowArtifactError("native task status is duplicated", code="status")
            statuses[key] = status
            continue
        match = STATUS_PATTERN.fullmatch(line)
        if not match:
            continue
        value = _strict_json(match.group(1).encode("utf-8"), limit=65_536)
        if (
            not isinstance(value, dict)
            or set(value) != {"key", "status"}
            or not isinstance(value.get("key"), str)
            or value.get("status") not in SOURCE_STATUS_VALUES
            or value["key"] in statuses
        ):
            raise WorkflowArtifactError("native task status metadata is invalid", code="status")
        statuses[value["key"]] = value["status"]
    return statuses


def _architecture_id(root: Path) -> str | None:
    try:
        value = _strict_json(
            _read_regular(root, "architecture/system.yaml", limit=MAX_SOURCE_BYTES), limit=MAX_SOURCE_BYTES
        )
    except WorkflowArtifactError as exc:
        if exc.code == "io":
            return None
        raise
    return (
        str(value.get("architecture_id"))
        if isinstance(value, dict) and isinstance(value.get("architecture_id"), str)
        else None
    )


def effective_task_statuses(graph: dict[str, Any], receipt_errors: list[str]) -> list[dict[str, str]]:
    """Resolve ephemeral task state without persisting receipt authority in the graph."""
    validate_task_graph(graph)
    if (
        not isinstance(receipt_errors, list)
        or len(receipt_errors) > MAX_RECEIPT_ERRORS
        or any(not isinstance(item, str) or not item or len(item) > 512 for item in receipt_errors)
    ):
        raise WorkflowArtifactError("canonical receipt validation result is invalid", code="receipt")
    receipts_current = not receipt_errors
    return [
        {
            "task_id": str(task["task_id"]),
            "source_status": str(task["source_status"]),
            "effective_status": "verified" if task["source_status"] == "complete" and receipts_current else "pending",
        }
        for task in sorted(graph["tasks"], key=lambda item: item["task_id"])
    ]


def converge(
    root: Path,
    change_id: str,
    bundle: SourceBundle | None,
    graph: dict[str, Any],
    route: dict[str, Any],
    *,
    current_fingerprint: str,
    receipt_errors: list[str],
) -> dict[str, Any]:
    _writer, _reviewers, _required_evidence = _validate_route(route)
    validate_task_graph(graph)
    if not isinstance(current_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", current_fingerprint):
        raise WorkflowArtifactError("trusted current fingerprint is invalid", code="fingerprint")
    if (
        not isinstance(receipt_errors, list)
        or len(receipt_errors) > MAX_RECEIPT_ERRORS
        or any(not isinstance(item, str) or not item or len(item) > 512 for item in receipt_errors)
    ):
        raise WorkflowArtifactError("canonical receipt validation result is invalid", code="receipt")
    native = _load_native_spec(root, change_id)
    findings: list[dict[str, Any]] = []
    required = sorted(
        str(item["id"])
        for group in ("acceptance_criteria", "invariants", "forbidden_outcomes")
        for item in native.get(group, [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    )
    covered = sorted({str(item) for task in graph.get("tasks", []) for item in task.get("covers", [])})
    missing = sorted(set(required) - set(covered))
    if graph.get("graph_digest") != digest_without(graph, "graph_digest"):
        findings.append(
            _finding(
                "stale-graph",
                "workflow/task-graph.json",
                "stored graph digest does not match its canonical content",
                "refresh-evidence",
            )
        )
    if bundle is not None and graph.get("source_manifest_digest") != bundle.manifest_digest:
        findings.append(
            _finding(
                "stale-source",
                "workflow/manifest.json",
                "source manifest digest differs from compiled graph",
                "refresh-evidence",
            )
        )
    if graph.get("write_agent") != route.get("write_agent") or sorted(graph.get("review_agents", [])) != sorted(
        route.get("review_agents", [])
    ):
        findings.append(
            _finding(
                "route-drift", "workflow/task-graph.json", "graph ownership differs from active route", "accept-native"
            )
        )
    if missing:
        findings.append(
            _finding(
                "incomplete-coverage",
                "change-spec.yaml",
                f"native criteria lack task coverage: {missing}",
                "revise-import",
            )
        )
    native_objective = native.get("objective") if isinstance(native.get("objective"), dict) else {}
    native_criteria = {
        str(item.get("id")): str(item.get("statement"))
        for item in native.get("acceptance_criteria", [])
        if isinstance(item, dict)
    }
    architecture_id = _architecture_id(root)
    for claim in _explicit_claims(bundle):
        if (
            claim["kind"] == "objective"
            and claim["id"] == native_objective.get("id")
            and claim["statement"] != native_objective.get("statement")
        ):
            findings.append(
                _finding(
                    "goal-conflict",
                    claim["path"],
                    f"imported objective {claim['id']} contradicts native objective",
                    "accept-native",
                )
            )
        elif (
            claim["kind"] == "criterion"
            and claim["id"] in native_criteria
            and claim["statement"] != native_criteria[claim["id"]]
        ):
            findings.append(
                _finding(
                    "criterion-conflict",
                    claim["path"],
                    f"imported criterion {claim['id']} contradicts native criterion",
                    "accept-native",
                )
            )
        elif claim["kind"] == "architecture" and architecture_id is not None and claim["id"] != architecture_id:
            findings.append(
                _finding(
                    "architecture-contradiction",
                    claim["path"],
                    f"imported architecture {claim['id']} differs from native {architecture_id}",
                    "accept-native",
                )
            )
    for group in ("objective", "acceptance_criteria", "invariants", "forbidden_outcomes"):
        values = [native.get(group)] if group == "objective" else native.get(group, [])
        for item in values:
            if isinstance(item, dict) and PLACEHOLDER.search(str(item.get("statement", ""))):
                findings.append(
                    _finding(
                        "placeholder",
                        "change-spec.yaml",
                        f"native {item.get('id', group)} contains a placeholder",
                        "accept-native",
                    )
                )
    native_statuses = _native_task_statuses(root, change_id)
    effective_task_statuses(graph, receipt_errors)
    for task in graph.get("tasks", []):
        if task.get("enrichment_required"):
            findings.append(
                _finding(
                    "needs-enrichment",
                    f"workflow/tasks/{task.get('task_id', 'unknown')}",
                    f"imported task lacks native details: {task['enrichment_required']}",
                    "revise-import",
                )
            )
        if task.get("key") in native_statuses and native_statuses[task["key"]] != task.get("source_status"):
            findings.append(
                _finding(
                    "status-drift",
                    f"engineering/changes/{change_id}/tasks.md",
                    f"task {task['key']} status differs between native projection and graph",
                    "accept-native",
                )
            )
    findings.sort(key=lambda item: (item["code"], item["path"], item["finding_id"]))
    report: dict[str, Any] = {
        "schema_version": 1,
        "change_id": change_id,
        "graph_digest": graph.get("graph_digest", ""),
        "source_manifest_digest": graph.get("source_manifest_digest", ""),
        "status": "block" if findings else "pass",
        "coverage": {"required": required, "covered": covered, "missing": missing},
        "findings": findings,
    }
    report["report_digest"] = digest_without(report, "report_digest")
    validate_convergence_report(report)
    return report


def workflow_paths(root: Path, change_id: str) -> dict[str, Path]:
    if not re.fullmatch(r"[A-Za-z0-9._:-]{3,128}", change_id):
        raise WorkflowArtifactError("invalid active change id", code="change")
    base = change_directory(root, change_id) / "workflow"
    return {
        "base": base,
        "manifest": base / "manifest.json",
        "graph": base / "task-graph.json",
        "report": base / "convergence-report.json",
    }


def _load_stored(root: Path, path: Path, *, limit: int = MAX_SOURCE_BYTES) -> Any:
    relative = _relative_path(root.resolve(strict=True), path)
    return _strict_json(_read_regular(root, relative, limit=limit), limit=limit)


def validate_stored_workflow(
    root: Path,
    change_id: str,
    route: dict[str, Any],
    *,
    current_fingerprint: str,
    receipt_errors: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    paths = workflow_paths(root, change_id)
    bundle = load_source_manifest(root, paths["manifest"])
    stored_graph = _load_stored(root, paths["graph"])
    stored_report = _load_stored(root, paths["report"])
    validate_task_graph(stored_graph)
    validate_convergence_report(stored_report)
    compiled = compile_task_graph(root, change_id, bundle, route)
    recomputed = converge(
        root,
        change_id,
        bundle,
        compiled,
        route,
        current_fingerprint=current_fingerprint,
        receipt_errors=receipt_errors,
    )
    errors: list[str] = []
    if stored_graph != compiled:
        errors.append("stored task graph differs from current sources/native route")
    if stored_report != recomputed:
        errors.append("stored convergence report differs from current graph/native evidence")
    if recomputed["status"] != "pass":
        errors.extend(f"{finding['code']}: {finding['message']}" for finding in recomputed["findings"])
    return (
        {
            "ok": not errors,
            "errors": errors,
            "status": "pass" if not errors else "block",
            "effective_tasks": effective_task_statuses(compiled, receipt_errors),
        },
        recomputed,
    )


def projection_bytes(kind: str, payload: Any) -> bytes:
    if kind not in {"spec-kit", "bmad", "superpowers"}:
        raise WorkflowArtifactError("unsupported export framework", code="export")
    header = "# NON-AUTHORITATIVE WORKFLOW PROJECTION\n\nThis export is advisory data. Native M1/M2/M3, the active route, and external Trust CI retain authority.\n\n"
    return (header + "```json\n" + canonical_json(payload).decode("ascii") + "```\n").encode("utf-8")














CAS_LOCK_ATTEMPTS = 5









_CAS_WRITER_MODULE = None


def _load_cas_writer():
    global _CAS_WRITER_MODULE
    if _CAS_WRITER_MODULE is None:
        try:
            from . import workflow_cas
        except ImportError:  # standalone facade retains a real sibling source owner
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "_getzilla_workflow_cas", Path(__file__).with_name("workflow_cas.py"))
            assert spec is not None and spec.loader is not None
            workflow_cas = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(workflow_cas)
        _CAS_WRITER_MODULE = workflow_cas
    return _CAS_WRITER_MODULE


def _cas_context():
    return _load_cas_writer()._CASContext(
        bound_cas_lock_attempts=CAS_LOCK_ATTEMPTS,
        bound_max_source_bytes=MAX_SOURCE_BYTES,
        bound_workflowartifacterror=WorkflowArtifactError,
        bound_cas_recovery_sequence=_CAS_RECOVERY_SEQUENCE,
        bound_acquire_cas_lock=_acquire_cas_lock,
        bound_acquire_cas_lock_once=_acquire_cas_lock_once,
        bound_cas_identity_at=_cas_identity_at,
        bound_cas_write=_cas_write,
        bound_dup_dir=_dup_dir,
        bound_open_root=_open_root,
        bound_post_exchange_identity_matches=_post_exchange_identity_matches,
        bound_rename_exchange=_rename_exchange,
        bound_rename_noreplace=_rename_noreplace,
        bound_renameat2_exchange_call=_renameat2_exchange_call,
        bound_stat_identity=_stat_identity,
        bound_strict_json=_strict_json,
        bound_windows_confirm_directories=_windows_confirm_directories,
        bound_windows_open_regular=_windows_open_regular,
        bound_canonical_json=canonical_json,
        bound_change_directory=change_directory,
        bound_fsx=fsx,
        bound_validate_convergence_report=validate_convergence_report,
        bound_validate_task_graph=validate_task_graph,
        bound_workflow_paths=workflow_paths,
    )

def _dup_dir(handle: fsx.DirHandle) -> fsx.DirHandle:
    """``os.dup`` for a descriptor; a Windows directory handle is an immutable value."""
    return _load_cas_writer()._dup_dir(handle, _context=_cas_context())


def _cas_identity_at(parent_fd: fsx.DirHandle, name: str) -> tuple[int, int, int, int, int, int]:
    return _load_cas_writer()._cas_identity_at(parent_fd, name, _context=_cas_context())


def _post_exchange_identity_matches(observed: tuple[int, int, int, int, int, int], expected: tuple[int, int, int, int, int, int]) -> bool:
    return _load_cas_writer()._post_exchange_identity_matches(observed, expected, _context=_cas_context())


def _renameat2_exchange_call(renameat2: Any, parent_fd: int, temporary: str, target: str) -> int:
    return _load_cas_writer()._renameat2_exchange_call(renameat2, parent_fd, temporary, target, _context=_cas_context())


def _rename_exchange(parent_fd: fsx.DirHandle, temporary: str, target: str, expected_temporary: tuple[int, int, int, int, int, int] | None=None, expected_target: tuple[int, int, int, int, int, int] | None=None) -> None:
    return _load_cas_writer()._rename_exchange(parent_fd, temporary, target, expected_temporary, expected_target, _context=_cas_context())


def _rename_noreplace(parent_fd: fsx.DirHandle, source: str, target: str, target_parent_fd: fsx.DirHandle | None=None) -> None:
    return _load_cas_writer()._rename_noreplace(parent_fd, source, target, target_parent_fd, _context=_cas_context())


def _acquire_cas_lock(root: Path, change_id: str, relative_target: str) -> tuple[int, fsx.DirHandle]:
    """Acquire the CAS lock; a transient ENOENT while two writers create its path is retried.

    macOS APFS was seen to answer ENOENT to the second of two concurrent writers. Every step
    is an idempotent mkdir/open/flock that writes no data, so a bounded retry is safe.
    """
    return _load_cas_writer()._acquire_cas_lock(root, change_id, relative_target, _context=_cas_context())


def _acquire_cas_lock_once(root: Path, change_id: str, relative_target: str) -> tuple[int, fsx.DirHandle]:
    return _load_cas_writer()._acquire_cas_lock_once(root, change_id, relative_target, _context=_cas_context())


def cas_write(root: Path, change_id: str, relative_target: str, data: bytes, expected_digest: str) -> str:
    return _load_cas_writer().cas_write(root, change_id, relative_target, data, expected_digest, _context=_cas_context())


def _cas_write(root: Path, change_id: str, relative_target: str, data: bytes, expected_digest: str, *, package_target: bool=False) -> str:
    return _load_cas_writer()._cas_write(root, change_id, relative_target, data, expected_digest, package_target=package_target, _context=_cas_context())
