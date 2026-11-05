"""Optional Core bridge for trusted parent composition, never an auth/role parser.

Import this module only in a parent which already includes Core and Factory.
Ordinary Factory and Core startup do not import it. This does not qualify a
trusted host/OS transport,151 transform or162/200 consumer by construction.
"""
from __future__ import annotations

from dataclasses import dataclass

from getzilla.native_access import (
    AuthorityStamp, CapturedRead, ExistingOperationDisposition, NativeAccessError,
    NativeAccessHost, PreparedReadResponse, SourceDependency, SourceDocument,
)

from .access_authority import AccessSession, source_key
from .access_release import AccessReleaseService, _CapturedSources, _remaining_bounds
from .contracts import canonical_digest
from .models import LeaseGrant


def factory_source_scope(key):
    """An opaque locator for the complete existing SourceKey, not a permission."""
    return 'factory-source:' + canonical_digest(list(source_key(key)))


@dataclass(frozen=True, repr=False)
class FactoryTaskBinding:
    grant: LeaseGrant
    execution_packet_digest: str


@dataclass(repr=False)
class _Binding:
    issuer: object
    session: AccessSession
    workflow: FactoryTaskBinding
    captured: _CapturedSources | None = None


@dataclass(frozen=True, repr=False)
class _PreparedBinding:
    binding: _Binding
    identifier: str


class FactoryNativeAccessHost(NativeAccessHost):
    """Reuse the actual authority, registered source producer and existing outbox.

    Source/response registration is the existing server-owned composition only.
    This fixed initial profile does not accept arbitrary computations or sinks.
    """
    def __init__(self, service):
        if type(service) is not AccessReleaseService:
            raise NativeAccessError()
        self._service, self._issuer = service, object()
        self._authority, self._source_adapter = service._authority, service._sources
        self._sources = dict(service._sources._sources)
        self._destinations = dict(service._destinations)
        self._scopes = {factory_source_scope(dict(zip(
            ('tenant', 'project', 'provider', 'site', 'resource'), key))): key for key in self._sources}

    def _binding(self, binding):
        if (type(binding) is not _Binding or binding.issuer is not self._issuer
                or self._service._authority is not self._authority
                or self._service._sources is not self._source_adapter
                or self._source_adapter._sources != self._sources
                or self._service._destinations != self._destinations):
            raise NativeAccessError('native_access_stale')
        return binding

    def bind_native_request(self, native_request, workflow_resource, deadline):
        if (type(native_request) is not AccessSession or type(workflow_resource) is not FactoryTaskBinding
                or type(workflow_resource.grant) is not LeaseGrant
                or type(workflow_resource.execution_packet_digest) is not str
                or len(workflow_resource.execution_packet_digest) != 64
                or any(c not in '0123456789abcdef' for c in workflow_resource.execution_packet_digest)):
            raise NativeAccessError('native_access_denied')
        _remaining_bounds(deadline)
        return _Binding(self._issuer, native_request, workflow_resource)

    def check_current(self, binding, deadline):
        binding = self._binding(binding)
        actor = self._authority.actor(binding.session)
        grant = binding.workflow.grant
        if (actor.kind != 'worker' or actor.actor_id != grant.owner
                or not {'task:execute', 'source:read'} <= actor.scopes):
            raise NativeAccessError('native_access_denied')
        with self._service._store._transaction(**_remaining_bounds(deadline)) as cursor:
            context, attempt = self._service._context(cursor, grant, binding.workflow.execution_packet_digest)
        if '*' not in actor.repositories and context.repository_id not in actor.repositories:
            raise NativeAccessError('native_access_denied')
        if binding.captured is not None:
            # Reuse the SAME actual registered source reader and current task context.
            # Hash, version, ownership/mode/link/FD custody changes cannot hide behind
            # an unchanged operator permission revision, including cached broker paths.
            self._service._revalidate_native_sources(binding.captured, context, attempt, deadline)
        self._authority._live()
        self._authority._credential_live(binding.session)
        with self._authority._source:
            snapshot, _actor, _principal = self._authority._current(binding.session)
            revision, permission = snapshot.revision, snapshot.permission_digest
        workflow = canonical_digest({'task': context.task_id, 'run': context.run_id,
            'owner': context.owner, 'fence': context.fence, 'packet': context.packet_digest,
            'repository': context.repository_id, 'workspace': context.workspace_handle,
            'paths': list(context.allowed_paths), 'tools': list(context.allowed_tools),
            'artifact_classes': list(context.allowed_artifact_classes),
            'limits': [context.max_note_bytes, context.max_artifact_bytes, context.max_output_bytes,
                       context.max_cost_usd_micros, context.max_token_units],
            'capabilities': list(context.declared_capabilities), 'attempt': attempt,
            'profile': list(self._service._native_profile())})
        return AuthorityStamp(revision, permission, workflow)

    def load_authorized_cut(self, binding, query, deadline):
        self.check_current(binding, deadline)
        if (query.reader_id != 'factory.source-text/v1' or query.parameters != {}
                or any(scope not in self._scopes for scope in query.scope_ids)):
            raise NativeAccessError('native_access_denied')
        sources = [dict(zip(('tenant', 'project', 'provider', 'site', 'resource'), self._scopes[scope]))
                   for scope in query.scope_ids]
        captured = self._service._capture_native_sources(binding.session, binding.workflow.grant,
            binding.workflow.execution_packet_digest, sources, deadline)
        documents = tuple(SourceDocument(SourceDependency(key, version, digest, digest, 'identity/v1'), raw)
            for raw, (key, version, digest) in zip(captured.chunks, captured.lineage, strict=True))
        binding.captured = captured
        return CapturedRead(documents, captured)

    def prepare_owned_response(self, binding, captured, computation, response, deadline):
        self.check_current(binding, deadline)
        if (computation != 'factory.source-text/v1' or response not in self._destinations
                or type(captured.native_ref) is not _CapturedSources
                or captured.native_ref is not binding.captured):
            raise NativeAccessError()
        result = self._service._prepare_native_sources(binding.captured, response, deadline, native_revalidate=True)
        identifier = result['prepared_id']
        with self._service._lock:
            prepared = self._service._prepared[identifier]
        return PreparedReadResponse(_PreparedBinding(binding, identifier),
            tuple(document.dependency for document in captured.documents), prepared.envelope.sanitized_payload_digest)

    def admit_response(self, binding, prepared, deadline):
        self.check_current(binding, deadline)
        reference = prepared.native_ref
        if type(reference) is not _PreparedBinding or reference.binding is not binding:
            raise NativeAccessError('native_access_denied')
        _remaining_bounds(deadline)
        # release() owns final task/stop/SOURCE/pending-commit/outbox admission;
        # its dispatcher repeats current admission before the actual registered UDS.
        result = self._service.release(binding.session, reference.identifier)
        return ExistingOperationDisposition(result['status'], result['operation_id'])
