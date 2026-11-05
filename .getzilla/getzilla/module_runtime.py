"""Generic opt-in runtime admission. Trusted ports are supplied by the native host.

This module does not import an addon, start a client or create external authority.
No project configuration can supply a trusted port. Missing ports stay unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import time
from typing import Protocol
import uuid

from .component_state import MANIFEST, BoundRoot, component_transaction, encode_manifest, matches_owned, read_state

FEATURES = frozenset({'owned-runtime-v1', 'trusted-transport-v1', 'owned-native-fragment-v1'})
STATES = frozenset({'installed-disabled', 'enabling', 'enabled', 'quiescing', 'disabled-conflict', 'recovery-required'})


def _need(ok, reason):
    from .optional_modules import ModuleError
    if not ok:
        raise ModuleError(reason)


def _id(value):
    return type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value) is not None


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def runtime_descriptor(raw, module, version):
    """Read owned declarative bytes only. Unknown active features fail closed."""
    from .optional_modules import _json
    value = _json(raw)
    _need(type(value) is dict and set(value) == {'schema_version', 'module', 'version', 'required_features', 'native_profiles'}, 'runtime_descriptor_schema')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and value['module'] == module and value['version'] == version, 'runtime_descriptor_identity')
    features = value['required_features']
    _need(type(features) is list and 1 <= len(features) <= 8 and all(type(v) is str for v in features)
          and len(set(features)) == len(features), 'runtime_descriptor_features')
    _need(set(features) <= FEATURES and {'owned-runtime-v1', 'trusted-transport-v1'} <= set(features), 'runtime_feature_unsupported')
    profiles = value['native_profiles']
    _need(type(profiles) is list and 1 <= len(profiles) <= 8 and all(_id(v) for v in profiles)
          and len(set(profiles)) == len(profiles), 'runtime_descriptor_profiles')
    return value


def installed_runtime(binding, name, record):
    path = f'.getzilla/modules/{name}/runtime.v1.json'
    current = binding.read(path)
    if current is None:
        _need(record['module']['schema_version'] == 1, 'runtime_descriptor_missing')
        return None
    _need(matches_owned(current, record.get('owned', {}).get(path)), 'runtime_descriptor_modified')
    value = runtime_descriptor(current.content, name, record['module']['version'])
    _need(record['module']['schema_version'] == 2 and record['module']['runtime']['descriptor_sha256'] == current.sha256,
          'runtime_ledger_descriptor_mismatch')
    return value


def disabled_runtime(descriptor_sha256):
    return {'schema_version': 1, 'state': 'installed-disabled', 'descriptor_sha256': descriptor_sha256,
            'generation': None, 'owner_handle': None, 'request_digest': None, 'native_fragments': []}


@dataclass(frozen=True)
class ActivationRequestV1:
    project: str
    module: str
    version: str
    manifest_sha256: str
    task_id: str
    run_id: str
    owner_id: str
    authority_epoch: int
    context_digest: str
    native_profile: str
    scope_digest: str
    operations: tuple[str, ...]

    def digest(self):
        from .optional_modules import _digest
        _need(type(self.project) is str and 1 <= len(self.project.encode()) <= 4096, 'activation_project')
        _need(all(_id(v) for v in (self.module, self.task_id, self.run_id, self.owner_id, self.native_profile)), 'activation_identity')
        _need(type(self.version) is str and re.fullmatch(r'[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}', self.version), 'activation_version')
        _need(all(_sha(v) for v in (self.manifest_sha256, self.context_digest, self.scope_digest)), 'activation_digest')
        _need(type(self.authority_epoch) is int and self.authority_epoch >= 0, 'activation_epoch')
        _need(type(self.operations) is tuple and 1 <= len(self.operations) <= 32
              and all(_id(v) for v in self.operations) and len(set(self.operations)) == len(self.operations), 'activation_operations')
        return _digest(self.__dict__)


@dataclass(frozen=True)
class ActivationPlanV1:
    request: ActivationRequestV1
    ledger_sha256: str
    descriptor_sha256: str
    generation: str


@dataclass(frozen=True)
class OwnedRuntimeV1:
    """Opaque resource-service handle; not a PID or a caller supplied allow flag."""
    owner_handle: str
    generation: str


@dataclass(frozen=True)
class NativeProfileProofV1:
    request_digest: str
    generation: str
    owner_handle: str
    # TaskB adds owned fragment plans. TaskA permits only a no-registration profile.
    registration_required: bool = False


@dataclass(frozen=True)
class QuiescenceProofV1:
    owner_handle: str
    generation: str
    remaining: int


@dataclass(frozen=True)
class LifecycleOutcomeV1:
    state: str
    module: str
    generation: str | None
    workers: int | None
    reason: str | None = None


class TaskAuthorityPort(Protocol):
    def authorize_activation(self, request: ActivationRequestV1) -> object: ...
    def validate_activation(self, request: ActivationRequestV1, handle: object) -> None: ...


class ModuleRuntimePort(Protocol):
    # prepare reserves an owned identity only. It MUST NOT start workers/sessions.
    def prepare(self, request: ActivationRequestV1, generation: str, handle: object) -> OwnedRuntimeV1: ...
    def quiesce(self, owner: OwnedRuntimeV1, deadline: float) -> QuiescenceProofV1: ...


class NativeRegistrationPort(Protocol):
    # Proves the actual trusted transport checks every call; a project hook is insufficient.
    def inspect_owned(self, request: ActivationRequestV1, owner: OwnedRuntimeV1, handle: object) -> NativeProfileProofV1: ...


def _ports(native, runtime, authority):
    _need(all(v is not None for v in (native, runtime, authority)), 'runtime_adapter_unavailable')
    _need(all(callable(getattr(obj, name, None)) for obj, names in (
        (native, ('inspect_owned',)), (runtime, ('prepare', 'quiesce')),
        (authority, ('authorize_activation', 'validate_activation'))) for name in names), 'runtime_adapter_unavailable')


def _activation(binding, root, name, request, entitlement=None):
    from .optional_modules import PENDING, _validate_installed, _entitled
    _need(type(request) is ActivationRequestV1, 'activation_request_schema')
    request.digest()
    _need(request.module == name and request.project == str(root.absolute()), 'activation_project_module_mismatch')
    _need(binding.read(PENDING) is None, 'module_recovery_required')
    observed = binding.read(MANIFEST)
    state = read_state(root, binding=binding)
    state.require_selection()
    record = state.manifest['components'].get('module:' + name)
    _need(record is not None, 'module_not_installed')
    _validate_installed(binding, name, record)
    metadata = record['module']
    _entitled(root, name, metadata, entitlement)
    descriptor = installed_runtime(binding, name, record)
    _need(descriptor is not None, 'runtime_descriptor_required')
    _need(metadata['version'] == request.version and metadata['manifest_sha256'] == request.manifest_sha256, 'activation_artifact_changed')
    _need(not metadata['enabled'] and metadata['runtime']['state'] == 'installed-disabled', 'runtime_quiescence_required')
    _need(request.native_profile in descriptor['native_profiles'], 'native_profile_unsupported')
    _need(set(request.operations) == set(metadata['permissions']), 'explicit_scoped_grants_required')
    for dependency, version in metadata['dependencies'].items():
        from .optional_modules import admit_module
        admitted = admit_module(root, dependency, entitlement=entitlement)
        _need(admitted['allowed'] and admitted['version'] == version, 'module_dependency_invalid')
    return observed, state.manifest, record


def plan_activation(root, module_id, request, *, native=None, runtime=None, authority=None, entitlement=None):
    _ports(native, runtime, authority)
    with BoundRoot(root) as binding:
        observed, _manifest, record = _activation(binding, root, module_id, request, entitlement)
        # Planning does not reserve owners, authenticate or publish config.
        return ActivationPlanV1(request, observed.sha256, record['module']['runtime']['descriptor_sha256'], uuid.uuid4().hex)


def _metadata_plan(binding, before, manifest, name, transaction_id, *, revoke=False):
    from .optional_modules import Plan, HISTORY, LAST, MAX_HISTORY, _pointer
    from .component_state import read_keep_contract, validate_manifest_publication
    encoded = encode_manifest(manifest)
    kept, digests = read_keep_contract(binding)
    validate_manifest_publication(before, encoded, kept, digests)
    _pointer(binding.read(LAST))
    available = len(binding.files(HISTORY)) < MAX_HISTORY
    _need(available or revoke, 'module_history_limit')
    return Plan({'operation': 'runtime', 'status': 'planned', 'rollback_available': available,
                 'workers': None, 'external_authority': False}, before, encoded, [], [name])


def commit_activation(root, plan, *, native=None, runtime=None, authority=None, entitlement=None):
    from .optional_modules import _publish_plan
    _ports(native, runtime, authority)
    _need(type(plan) is ActivationPlanV1 and type(plan.request) is ActivationRequestV1
          and type(plan.generation) is str and re.fullmatch('[0-9a-f]{32}', plan.generation)
          and _sha(plan.ledger_sha256) and _sha(plan.descriptor_sha256), 'activation_plan_schema')
    request = plan.request
    with component_transaction(root) as transaction:
        before, manifest, record = _activation(transaction, root, request.module, request, entitlement)
        _need(before.sha256 == plan.ledger_sha256 and record['module']['runtime']['descriptor_sha256'] == plan.descriptor_sha256, 'activation_plan_stale')
        descriptor = installed_runtime(transaction, request.module, record)
        _need('owned-native-fragment-v1' not in descriptor['required_features'], 'native_fragment_adapter_required')
        handle = authority.authorize_activation(request)
        _need(handle is not None and not isinstance(handle, (dict, bool, str, int)), 'runtime_authority_unavailable')
        owner = runtime.prepare(request, plan.generation, handle)
        _need(type(owner) is OwnedRuntimeV1 and _id(owner.owner_handle) and owner.generation == plan.generation, 'runtime_owner_unavailable')
        proof = native.inspect_owned(request, owner, handle)
        _need(type(proof) is NativeProfileProofV1 and proof.request_digest == request.digest()
              and proof.generation == owner.generation and proof.owner_handle == owner.owner_handle, 'native_profile_unavailable')
        _need(proof.registration_required is False, 'native_fragment_adapter_required')
        authority.validate_activation(request, handle)
        transaction_id = uuid.uuid4().hex
        metadata = record['module']
        metadata['enabled'], metadata['grants'], metadata['transaction'] = True, list(request.operations), transaction_id
        metadata['runtime'].update(state='enabled', generation=owner.generation, owner_handle=owner.owner_handle, request_digest=request.digest())
        _publish_plan(transaction, _metadata_plan(transaction, before, manifest, request.module, transaction_id), transaction_id)
    return LifecycleOutcomeV1('enabled', request.module, owner.generation, None)


def quiesce_module(root, module_id, *, native=None, runtime=None, authority=None, deadline=None):
    """Deny durably before checking optional ports; missing ownership never means zero."""
    from .optional_modules import PENDING, _publish_plan
    deadline = time.monotonic() + 30 if deadline is None else deadline
    _need(type(deadline) in (int, float) and time.monotonic() < deadline <= time.monotonic() + 300, 'quiescence_deadline')
    with component_transaction(root) as transaction:
        _need(transaction.read(PENDING) is None, 'module_recovery_required')
        before = transaction.read(MANIFEST)
        manifest = read_state(root, binding=transaction).manifest
        record = manifest['components'].get('module:' + module_id)
        _need(record is not None and record['module']['schema_version'] == 2, 'runtime_module_required')
        metadata = record['module']
        current = metadata['runtime']
        if current['state'] == 'installed-disabled':
            return LifecycleOutcomeV1('installed-disabled', module_id, None, None)
        owner = OwnedRuntimeV1(current['owner_handle'], current['generation'])
        if current['state'] != 'quiescing' or metadata['enabled']:
            metadata['enabled'], metadata['grants'] = False, []
            current['state'] = 'quiescing'
            transaction_id = uuid.uuid4().hex
            metadata['transaction'] = transaction_id
            _publish_plan(transaction, _metadata_plan(transaction, before, manifest, module_id, transaction_id, revoke=True), transaction_id)
        if runtime is None or not callable(getattr(runtime, 'quiesce', None)):
            return LifecycleOutcomeV1('quiescing', module_id, owner.generation, None, 'runtime_adapter_unavailable')
        _need(not current['native_fragments'], 'native_fragment_adapter_required')
        proof = runtime.quiesce(owner, deadline)
        _need(time.monotonic() <= deadline and type(proof) is QuiescenceProofV1
              and proof.owner_handle == owner.owner_handle and proof.generation == owner.generation
              and type(proof.remaining) is int and proof.remaining == 0, 'runtime_quiescence_unproven')
        before = transaction.read(MANIFEST)
        manifest = read_state(root, binding=transaction).manifest
        metadata = manifest['components']['module:' + module_id]['module']
        _need(metadata['runtime']['state'] == 'quiescing' and metadata['runtime']['generation'] == owner.generation, 'runtime_state_changed')
        metadata['runtime'] = disabled_runtime(metadata['runtime']['descriptor_sha256'])
        transaction_id = uuid.uuid4().hex
        metadata['transaction'] = transaction_id
        _publish_plan(transaction, _metadata_plan(transaction, before, manifest, module_id, transaction_id, revoke=True), transaction_id)
        return LifecycleOutcomeV1('installed-disabled', module_id, None, 0)


def quiesce_journal_owners(journal, runtime, *, deadline):
    """The existing pending record is the durable deny; restore no live owner."""
    from .optional_modules import _unpack
    from .component_state import decode_manifest
    owners = set()
    for key in ('before_manifest', 'after_manifest'):
        manifest = decode_manifest(_unpack(journal[key])[0])
        for name in journal['affected']:
            record = manifest['components'].get('module:' + name)
            if record is not None and record['module']['schema_version'] == 2:
                state = record['module']['runtime']
                _need(not state['native_fragments'], 'native_fragment_adapter_required')
                if state['owner_handle'] is not None:
                    owners.add((state['owner_handle'], state['generation']))
    if owners:
        _need(runtime is not None and callable(getattr(runtime, 'quiesce', None)), 'runtime_adapter_unavailable')
    for handle, generation in sorted(owners):
        _need(time.monotonic() < deadline, 'runtime_quiescence_unproven')
        proof = runtime.quiesce(OwnedRuntimeV1(handle, generation), deadline)
        _need(time.monotonic() <= deadline and type(proof) is QuiescenceProofV1
              and proof.owner_handle == handle and proof.generation == generation
              and type(proof.remaining) is int and proof.remaining == 0, 'runtime_quiescence_unproven')
    return frozenset(owners)
