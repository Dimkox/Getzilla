"""Concrete native-local composition of the existing source/access broker.

Only an actual held-CWD root and owned current route reach this profile. Local
stdout and an explicitly enabled installed hook are concrete local sinks; no
cloud/model/private-egress permission follows from their successful delivery.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
from functools import wraps
import os
from pathlib import Path
import sys
import time

from .. import native_access as access
from .. import state
from ..code_graph.models import GraphConfig, make_graph_input
from ..code_graph.store import GraphStore
from ..component_state import MANIFEST
from ..optional_modules import admit_module
from ..trace_storage import native_root
from .budget import Budget, RetrievalError
from .contracts import digest, sha
from .extract import build_generation
from .graph_packet import current_graph, prepare_graph_packet
from .native_source import NativeSource
from . import observation
from .policy_inputs import BASE_INPUTS, CONTINUATION, input_paths


CONTEXT_REASONS = frozenset({'source_file_limit', 'source_inventory_exceeded', 'source_bytes_exceeded',
    'source_file_exceeded', 'source_or_authority_changed', 'mandatory_budget_exceeded',
    'deadline_exceeded', 'context_bytes_exceeded', 'current_graph_unavailable', 'current_index_unavailable',
    'native_context_unavailable', 'unsupported_sink', 'context_disabled', 'actual_backend_proof_required',
    'backend_profile_unavailable', 'policy_unavailable', 'unsafe_context_index', 'stale_citation'})


def _diagnostic_stage(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except BaseException as error:
            self.failure_outcome = observation._outcome(error)
            if (isinstance(error, RetrievalError) and error.args
                    and type(error.args[0]) is str and error.args[0] in CONTEXT_REASONS):
                self.failure_reason = error.args[0]
            raise
    return guarded


class _LocalHost(access.NativeAccessHost):
    def __init__(self, root, anchor, resources, query, mandatory, consumer, sink, token_budget):
        self.root, self.anchor, self.resources = root, anchor, resources
        self.query, self.mandatory, self.consumer, self.sink = query, mandatory, consumer, sink
        self.token_budget = token_budget
        self.request, self.workflow, self.binding, self.reference = object(), object(), object(), object()
        self.budget = Budget()
        self.failure_reason = None
        self.failure_outcome = None
        self.reader = None
        self.packet = None
        self.route = state.require_route_owner(root, anchor=anchor)
        from ..router import route_context
        canonical = route_context(self.route, root)
        if canonical not in self.mandatory:
            self.mandatory = canonical + '\n\n' + self.mandatory
        self.policy = anchor.read('.getzilla/config/policy.json', source=True)
        self.manifest = anchor.read(MANIFEST, source=True)
        self.continuation = self._continuation_bytes()
        managed = json.loads(self.manifest)
        self.module_metadata = [path for path in input_paths(managed, sink, self.continuation is not None)
                                if path not in BASE_INPUTS and path != CONTINUATION]
        if not admit_module(root, 'context-retrieval').get('allowed'):
            raise RetrievalError('context_disabled')
        if sink.startswith('native-hook-'):
            harness = sink.removeprefix('native-hook-')
            managed = json.loads(self.manifest)
            if (harness not in managed.get('agents', []) or not admit_module(
                    root, 'context-hook-' + harness, permission='context.hook.' + harness).get('allowed')):
                raise RetrievalError('unsupported_sink')
            self._check_backend_profile()
        elif sink != 'native-local-stdout':
            raise RetrievalError('unsupported_sink')

    def _continuation_bytes(self):
        path = '.getzilla/config/model-continuation.json'
        return self.anchor.read(path, source=True) if self.anchor.exists(path, source=True) else None

    def _check_backend_profile(self):
        if self.continuation is None:
            return
        # The existing continuation profile owns these restrictions. Project
        # activation cannot waive actual free/local/closed-network admission.
        from ..model_continuation import _parse
        try:
            profile = _parse(self.continuation)
        except (ValueError, TypeError, KeyError):
            raise RetrievalError('backend_profile_unavailable') from None
        if profile.admission is not None:
            raise RetrievalError('actual_backend_proof_required')

    def bind_native_request(self, request, workflow, deadline):
        if request is not self.request or workflow is not self.workflow:
            raise access.NativeAccessError('native_access_denied')
        return self.binding

    @_diagnostic_stage
    def check_current(self, binding, deadline):
        if binding is not self.binding or time.monotonic() >= deadline:
            raise access.NativeAccessError('native_access_denied')
        self._check_configuration()
        if self.reader is not None:
            self.reader.recheck()
        return access.AuthorityStamp(1, digest([sha(self.policy), sha(self.manifest),
                                               sha(self.continuation or b'')]), digest(self.route))

    def _check_configuration(self):
        self.anchor.check_cwd()
        if (state.require_route_owner(self.root, anchor=self.anchor) != self.route
                or self.anchor.read('.getzilla/config/policy.json', source=True) != self.policy
                or self.anchor.read(MANIFEST, source=True) != self.manifest
                or self._continuation_bytes() != self.continuation
                or not admit_module(self.root, 'context-retrieval').get('allowed')):
            raise access.NativeAccessError('native_access_stale')
        if self.sink.startswith('native-hook-'):
            harness = self.sink.removeprefix('native-hook-')
            if not admit_module(self.root, 'context-hook-' + harness,
                                permission='context.hook.' + harness).get('allowed'):
                raise access.NativeAccessError('native_access_stale')
            self._check_backend_profile()

    def observation_current(self, budget):
        """Check current access and held identities without restarting expired work."""
        budget.check()
        self._check_configuration()
        if self.reader is not None:
            if self.reader._paths(budget=budget) != self.reader.paths:
                raise access.NativeAccessError('native_access_stale')
            for path, descriptor, parent, expected, _ in self.reader.held:
                budget.check()
                self.reader._held_unchanged(path, descriptor, parent, expected)

    @_diagnostic_stage
    def load_authorized_cut(self, binding, query, deadline):
        if query.parameters != {'query_sha256': sha(self.query.encode())}:
            raise access.NativeAccessError('native_access_denied')
        with observation.stage('access_check'):
            self.reader = NativeSource(self.root, self.anchor, self.resources, self.budget,
                extra_metadata=tuple(self.module_metadata) + (
                    ('.getzilla/config/model-continuation.json',) if self.continuation is not None else ()),
                read_profile=self.sink)
        accepted = {document.path: document.original for document in self.reader.source.documents}
        documents = []
        # Include governing metadata and every scanned source in complete lineage.
        # Excluded source content is represented by empty bytes, never disclosed.
        for path, descriptor, _, _, original_hash in self.reader.held:
            content = accepted.get(path, self.reader.metadata.get(path, b''))
            dependency = access.SourceDependency(('os-' + str(os.getuid()),
                self.anchor.binding['repository_digest'], 'native-local', 'local', sha(path.encode())),
                'sha256:' + original_hash, original_hash, sha(content), 'identity-or-excluded-v1')
            documents.append(access.SourceDocument(dependency, content))
        route_bytes = json.dumps(self.route, sort_keys=True, separators=(',', ':')).encode()
        route_sha = sha(route_bytes)
        documents.append(access.SourceDocument(access.SourceDependency(('os-' + str(os.getuid()),
            self.anchor.binding['repository_digest'], 'native-local', 'local', 'route-context'),
            'sha256:' + route_sha, route_sha, route_sha, 'identity-v1'), route_bytes))
        if len(documents) > 128:
            raise RetrievalError('source_file_limit')
        return access.CapturedRead(tuple(documents), self.reader)

    @_diagnostic_stage
    def prepare_owned_response(self, binding, captured, computation, response, deadline):
        if captured.native_ref is not self.reader or computation != 'shared-context/v1' or response != self.sink:
            raise access.NativeAccessError('native_access_denied')
        source = self.reader.source
        baseline = {'source_kind': 'folder', 'source_digest': source.source_digest}
        if self.reader.git is not None:
            baseline = {'source_kind': 'local_git', 'source_digest': source.source_digest,
                        'git': {'commit_oid': self.reader.git['head'], 'tree_oid': self.reader.git['tree']}}
        graph_input = make_graph_input(baseline, {d.path: d.original for d in source.documents}, GraphConfig())
        cache = '.getzilla/index/graph.sqlite'
        with self.anchor.parent(cache, create=True) as (parent, _):
            self.anchor.check_parent(parent)
            store = GraphStore(self.root / cache, private_parent=parent)
            try:
                graph, counters = current_graph(graph_input, store)
                rebuilt = store.rebuilt_reason
            finally:
                store.close()
            self.anchor.check_parent(parent)
        generation = build_generation(source, budget=self.budget)
        if self.observation is not None:
            self.observation.metadata_from(source.source_identity, graph.generation_id,
                {'graph_input': graph_input.identity, 'retrieval_generation': generation.identity,
                 'query_sha256': sha(self.query.encode()), 'mandatory_sha256': sha(self.mandatory.encode()),
                 'token_budget': self.token_budget, 'sink': self.sink})
        self.packet = prepare_graph_packet(source, generation, graph, self.query,
            mandatory=self.mandatory, token_budget=self.token_budget, budget=self.budget)
        self.packet['coverage_gaps'] = sorted(set(self.packet['coverage_gaps']) | self.reader.gaps)
        self.packet.update(sink=self.sink, private_egress_authorized=False,
                           qualification='native_local_source_context', index_counters=counters,
                           cache_rebuilt_reason=rebuilt)
        self.reader.recheck()
        return access.PreparedReadResponse(self.reference, tuple(d.dependency for d in captured.documents),
                                           sha(self.packet['text'].encode()))

    def admit_response(self, binding, prepared, deadline):
        if prepared.native_ref is not self.reference or prepared.payload_sha256 != sha(self.packet['text'].encode()):
            raise access.NativeAccessError('native_access_denied')
        self.check_current(binding, deadline)
        self.packet['native_counters'] = {**self.reader.counters,
            'context_output_bytes': len(self.packet['text'].encode()), 'model_calls': 0,
            'retrieval_ast_files': len(self.reader.source.documents)}
        if self.observation is not None:
            self.packet['trace_operation_id'] = self.observation.operation_id
            self.packet['trace_observation_status'] = 'pending_delivery'
        elif 'observation_publication' in self.route:
            self.packet['trace_observation_status'] = 'capture_unavailable'
        # The fixed native emitter executes while held resources remain live.
        self.consumer(self.packet)
        return access.ExistingOperationDisposition('issued', None)


def _deliver(root, query, mandatory, consumer, *, sink, token_budget=8192):
    if (os.name != 'posix' or not Path('/proc/self/fd').is_dir() or type(query) is not str
            or not query.strip() or len(query.encode()) > 4096 or type(mandatory) is not str
            or not callable(consumer)):
        raise RetrievalError('native_context_unavailable')
    root = Path(root)
    with ExitStack() as resources:
        anchor = resources.enter_context(native_root(root))
        host = _LocalHost(root, anchor, resources, query, mandatory, consumer, sink, token_budget)
        host.observation = observation.capture(root, host.route, anchor, host.sink)
        broker = access.NativeAccessBroker._compose(host)
        outcome = 'unknown'
        observation_delivered = False
        try:
            with observation.observing(host.observation):
                handle = broker.bind_native_request(host.request, host.workflow)
                registered = access.RegisteredQuery('local-source-context/v1', ('current-project',),
                                                    {'query_sha256': sha(query.encode())})
                cut = broker.load_authorized_cut(handle, registered, absolute_deadline=host.budget.deadline)
                prepared = broker.prepare_owned_response(handle, 'shared-context/v1', cut, sink,
                                                        absolute_deadline=host.budget.deadline)
                result = broker.admit_response(handle, prepared)
                outcome = 'succeeded' if result.status == 'issued' else 'unknown'
        except BaseException as error:
            outcome = host.failure_outcome or observation._outcome(error)
            if isinstance(error, access.NativeAccessError) and host.failure_reason is not None:
                outcome = 'timeout' if host.failure_reason == 'deadline_exceeded' else 'failed'
                raise RetrievalError(host.failure_reason) from None
            raise
        finally:
            if host.observation is not None:
                try:
                    host.observation.finish(outcome)
                    observation_delivered = observation.publish(root, host.observation, host)
                except Exception as error:
                    if observation._outcome(error) == 'cancelled':
                        raise
                    # Observation loss never repeats or changes an original read.
                    pass
        return {'schema': 'getzilla-context-delivery-v1', 'status': result.status,
                'sink': sink, 'private_egress_authorized': False, 'model_calls': 0,
                **({'trace_operation_id': host.observation.operation_id,
                    'trace_observation_delivered': observation_delivered}
                   if host.observation is not None else {})}


def _write_stdout(value):
    raw = (value + '\n').encode('utf-8')
    stream = getattr(sys.stdout, 'buffer', None)
    if stream is None:
        sys.stdout.write(raw.decode('utf-8'))
        sys.stdout.flush()
    else:
        sys.stdout.flush()
        stream.write(raw)
        stream.flush()


def deliver_local_context(root, query, mandatory='', *, token_budget=8192, output_format='json'):
    if output_format not in {'json', 'text'}:
        raise RetrievalError('unsupported_sink')
    def emit(packet):
        _write_stdout(packet['text'] if output_format == 'text' else json.dumps(packet, sort_keys=True))
    return _deliver(root, query, mandatory, emit, sink='native-local-stdout', token_budget=token_budget)


def deliver_hook_context(context, harness, query, mandatory):
    # RootContext is issued by the actual native ingress helper. It is advisory
    # without the additional held-CWD, current owner and source checks above.
    if (type(context).__name__ != 'RootContext' or not context.sensitive_safe
            or context.resolution_status != 'session-root' or context.execution_cwd != context.effective_root
            or context.session_root != context.effective_root or harness not in
            {'grok', 'claude', 'codex', 'copilot', 'gemini', 'qwen'}):
        raise RetrievalError('unsupported_sink')
    def emit(packet):
        _write_stdout(json.dumps({'hookSpecificOutput': {'hookEventName': 'UserPromptSubmit',
                                                       'additionalContext': packet['text']}}, ensure_ascii=False))
    return _deliver(context.effective_root, query, mandatory, emit, sink='native-hook-' + harness)
