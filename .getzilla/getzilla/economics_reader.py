"""Fixed native-local protected economics reader over existing canonical state.

The OS-owned actual CWD, current route owner and existing Read policy qualify
this local profile. A result is not enterprise ACL, acceptance or private egress
permission. Public DTOs and caller callbacks cannot construct this reader.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import hashlib
import os
from pathlib import Path
import threading
import time

from . import native_access as access, state, policy
from .economics_snapshot import freeze, SnapshotError
from .metrics_journal import digest, MAX_BYTES
from .trace_storage import native_root

_LIVE = {}
_SEAL = object()
PURPOSES = frozenset({"economics-local-report", "review-experiment"})


class _Handle:
    def __new__(cls, *args, **kwargs):
        raise TypeError("native economics reader required")

    def __reduce__(self):
        raise TypeError("native economics reader cannot be serialized")


class ProtectedReport:
    __slots__ = ("_canonical", "_owner", "_seal")

    def __init__(self, seal, owner, report, snapshot):
        if seal is not _SEAL:
            raise TypeError("protected report required")
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_seal", seal)
        object.__setattr__(
            self,
            "_canonical",
            json.dumps(
                {
                    "definition_version": "protected-local-economics-v1",
                    "qualification": "native_local_protected_read",
                    "private_egress_authorized": False,
                    "purpose": owner.purpose,
                    "source_snapshot": snapshot["identity"],
                    "source_coverage": snapshot["coverage"],
                    "report": report.as_dict(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        if len(self._canonical.encode("utf-8")) > 1_048_576:
            raise SnapshotError("input_limit")

    def __setattr__(self, name, value):
        raise AttributeError("immutable protected report")

    def as_dict(self):
        return json.loads(self._canonical)

    @property
    def canonical(self):
        return self._canonical


class _Reader:
    def __init__(self, root, anchor, purpose):
        self.root, self.anchor, self.purpose = root, anchor, purpose
        self.pid, self.thread = os.getpid(), threading.get_ident()
        self.expires = time.monotonic() + 15
        self.deadline = min(self.expires, time.monotonic() + 2)
        self.requests = 0
        self.owner = state.require_route_owner(root, anchor=anchor)
        if not state.current_session() or self.owner.get("workspace") != str(root):
            raise SnapshotError("protected_read_unavailable")
        from .continuity import context_binding

        self.context = context_binding(root, self.owner, anchor=anchor)
        self.policy = anchor.read(".getzilla/config/policy.json", 65536, source=True)
        self.source = anchor.git_source()
        self.results = {}
        self.active = True

    def check(self):
        from .continuity import context_binding

        self.anchor.check_cwd()
        if (
            not self.active
            or os.getcwd() != str(self.root)
            or os.path.realpath(self.root) != str(self.root)
            or self.pid != os.getpid()
            or self.thread != threading.get_ident()
            or time.monotonic() >= self.deadline
            or time.monotonic() >= self.expires
            or state.require_route_owner(self.root, anchor=self.anchor) != self.owner
            or context_binding(self.root, self.owner, anchor=self.anchor) != self.context
            or self.anchor.git_source() != self.source
            or self.anchor.read(".getzilla/config/policy.json", 65536, source=True) != self.policy
        ):
            raise SnapshotError("snapshot_unavailable")
        event = {"tool_name": "Read", "tool_input": {"file_path": str(self.root / ".getzilla/runtime/metrics.jsonl")}}
        if not policy.evaluate_pre_tool(self.root, event, execution_cwd=self.root)[0]:
            raise SnapshotError("protected_read_unavailable")

    def source_fingerprint(self, path):
        # Preserve each existing named source's bound. The generic metadata
        # stat helper defaults to1MiB and cannot qualify an8MiB journal.
        limit = MAX_BYTES if path == ".getzilla/runtime/metrics.jsonl" else 1_048_576
        if path == ".getzilla/runtime/executions/registry.json":
            from .execution_store import MAX_REGISTRY_BYTES

            limit = MAX_REGISTRY_BYTES
        if path.startswith(".getzilla/config/"):
            limit = 65536
        with self.anchor.file(path, source=path.startswith(".getzilla/config/"), limit=limit) as (descriptor, _):
            return _fingerprint(os.fstat(descriptor))

    def capture(self, query):
        self.check()
        snapshot = freeze(self.root, self.anchor, query, self.deadline)
        snapshot["fingerprints"] = {path: self.source_fingerprint(path) for path in snapshot["documents"]}
        context_bytes = json.dumps(self.context, sort_keys=True, separators=(",", ":")).encode()
        snapshot["documents"]["native-authority-context"] = context_bytes
        if sum(map(len, snapshot["documents"].values())) > 8_388_608:
            raise SnapshotError("input_limit")
        snapshot["identity"] = digest({"sources": snapshot["identity"], "authority_context": self.context})
        snapshot["cut"]["source_cut_digest"] = snapshot["identity"]
        return snapshot

    def unchanged(self, snapshot):
        self.check()
        for path, expected in snapshot["fingerprints"].items():
            if self.source_fingerprint(path) != expected:
                raise SnapshotError("snapshot_unavailable")

    def read(self, request):
        from .route_metrics import _unavailable_economics

        self.requests += 1
        if self.requests > 8 or not self.active:
            return _unavailable_economics()
        self.deadline = min(self.expires, time.monotonic() + 2)
        host = None
        try:
            self.check()
            host = _Host(self, request)
            broker = access.NativeAccessBroker._compose(host)
            handle = broker.bind_native_request(host.request, host.workflow)
            q = access.RegisteredQuery(
                "core.task-economics/v1", tuple(request.as_dict()["scope_ids"]), request.as_dict()
            )
            cut = broker.load_authorized_cut(handle, q, absolute_deadline=self.deadline)
            prepared = broker.prepare_owned_response(
                handle, "task-economics/v1", cut, self.purpose, absolute_deadline=self.deadline
            )
            disposition = broker.admit_response(handle, prepared)
            if disposition.status == "issued" and host.result is not None:
                return host.result
        except (OSError, ValueError, TimeoutError) as error:
            reason = "input_limit" if time.monotonic() >= self.deadline else "input_unavailable"
            if isinstance(error, SnapshotError) and str(error) in {
                "input_limit",
                "snapshot_unavailable",
                "protected_read_unavailable",
            }:
                reason = str(error)
            if host is not None and host.failure_reason is not None:
                reason = host.failure_reason
            return _unavailable_economics(reason)
        return _unavailable_economics("input_unavailable")


def _fingerprint(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


class _Host(access.NativeAccessHost):
    def __init__(self, owner, query):
        self.owner, self.query = owner, query
        self.request, self.workflow, self.binding, self.reference = object(), object(), object(), object()
        self.snapshot, self.report, self.result = None, None, None
        self.failure_reason = None

    def bind_native_request(self, request, workflow, deadline):
        if request is not self.request or workflow is not self.workflow:
            raise access.NativeAccessError("native_access_denied")
        self.owner.check()
        return self.binding

    def check_current(self, binding, deadline):
        if binding is not self.binding:
            raise access.NativeAccessError("native_access_denied")
        if self.snapshot is not None:
            self.owner.unchanged(self.snapshot)
        else:
            self.owner.check()
        return access.AuthorityStamp(1, digest(self.owner.policy.hex()), digest(self.owner.owner))

    def load_authorized_cut(self, binding, query, deadline):
        self.check_current(binding, deadline)
        if query.reader_id != "core.task-economics/v1" or query.parameters != self.query.as_dict():
            raise access.NativeAccessError("native_access_denied")
        try:
            self.snapshot = self.owner.capture(query.parameters)
        except SnapshotError as error:
            if str(error) in {"input_limit", "input_unavailable", "snapshot_unavailable", "protected_read_unavailable"}:
                self.failure_reason = str(error)
            raise
        project = self.snapshot["binding"]["repository_digest"]
        if query.scope_ids != (project,):
            raise access.NativeAccessError("native_access_denied")
        cohort = query.parameters["cohort"]
        if cohort["kind"] == "verified_pr_ids" and cohort["repository_digest"] != project:
            raise access.NativeAccessError("native_access_denied")
        if cohort["kind"] == "task_ids" and any(
            task["project_digest"] != project or task not in self.snapshot["cut"]["census"] for task in cohort["tasks"]
        ):
            raise access.NativeAccessError("native_access_denied")
        documents = tuple(
            access.SourceDocument(
                access.SourceDependency(
                    ("os-" + str(os.getuid()), project, "native-local", "economics", digest(path)),
                    hashlib.sha256(raw).hexdigest(),
                    hashlib.sha256(raw).hexdigest(),
                    hashlib.sha256(raw).hexdigest(),
                    "native-canonical-v1",
                ),
                raw,
            )
            for path, raw in self.snapshot["documents"].items()
        )
        return access.CapturedRead(documents, self.snapshot)

    def prepare_owned_response(self, binding, captured, computation, response, deadline):
        self.check_current(binding, deadline)
        if (
            captured.native_ref is not self.snapshot
            or computation != "task-economics/v1"
            or response != self.owner.purpose
        ):
            raise access.NativeAccessError("native_access_denied")
        from .route_metrics import compute_economics

        self.report = compute_economics(self.snapshot["cut"], self.query)
        if self.report.as_dict()["status"] not in {"ok", "partial"}:
            self.failure_reason = self.report.as_dict().get("reason", "input_unavailable")
            raise access.NativeAccessError()
        return access.PreparedReadResponse(
            self.reference, tuple(doc.dependency for doc in captured.documents), digest(self.report.canonical)
        )

    def admit_response(self, binding, prepared, deadline):
        self.check_current(binding, deadline)
        if prepared.native_ref is not self.reference or prepared.payload_sha256 != digest(self.report.canonical):
            raise access.NativeAccessError("native_access_denied")
        fresh = self.owner.capture(self.query.as_dict())
        if fresh["identity"] != self.snapshot["identity"]:
            raise access.NativeAccessError("native_access_stale")
        self.result = ProtectedReport(_SEAL, self.owner, self.report, self.snapshot)
        self.owner.results[id(self.result)] = (self.result, self.snapshot, self.query)
        return access.ExistingOperationDisposition("issued", None)


@contextmanager
def local_report_reader(root, *, purpose="economics-local-report"):
    if purpose not in PURPOSES:
        raise SnapshotError("protected_read_unavailable")
    root = Path(root)
    with native_root(root) as anchor:
        owner = _Reader(root, anchor, purpose)
        handle = object.__new__(_Handle)
        _LIVE[handle] = owner
        try:
            yield handle
        finally:
            owner.active = False
            owner.results.clear()
            _LIVE.pop(handle, None)


def read_protected(request, handle):
    from .route_metrics import _unavailable_economics

    owner = _LIVE.get(handle) if type(handle) is _Handle else None
    return owner.read(request) if owner is not None else _unavailable_economics()


def is_protected_report(result, *, handle=None, purpose=None):
    owner = _LIVE.get(handle) if type(handle) is _Handle else None
    if (
        owner is None
        or purpose is not None
        and owner.purpose != purpose
        or type(result) is not ProtectedReport
        or result._seal is not _SEAL
        or result._owner is not owner
        or id(result) not in owner.results
    ):
        return False
    try:
        # This is a fresh current-authority recheck, not a cached permission.
        # Its own bounded stage does not extend the completed broker request.
        owner.deadline = min(owner.expires, time.monotonic() + 2)
        owner.unchanged(owner.results[id(result)][1])
        return True
    except (OSError, ValueError):
        return False


def emit_report(result, *, handle, as_json=True):
    owner = _LIVE.get(handle) if type(handle) is _Handle else None
    if owner is None or owner.purpose != "economics-local-report":
        raise SnapshotError("protected_read_unavailable")
    owner.deadline = min(owner.expires, time.monotonic() + 2)
    if not is_protected_report(result, handle=handle):
        raise SnapshotError("snapshot_unavailable")
    owner = _LIVE[handle]
    _, snapshot, query = owner.results[id(result)]
    if owner.capture(query.as_dict())["identity"] != snapshot["identity"]:
        raise SnapshotError("snapshot_unavailable")
    if as_json:
        text = result.canonical + "\n"
    else:
        from .route_metrics import render_report_text

        report = owner.results[id(result)][0].as_dict()["report"]
        from .route_metrics import ReportResult, _economic_json

        gaps = ", ".join(snapshot["coverage"]["gaps"]) or "none observed"
        text = (
            "Protected native-local economics; private egress not authorized.\n"
            + "Source coverage gaps: "
            + gaps
            + "\n"
            + render_report_text(ReportResult(_economic_json(report)))
        )
    import sys

    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except OSError:
        raise SnapshotError("disclosure_outcome_unknown") from None
