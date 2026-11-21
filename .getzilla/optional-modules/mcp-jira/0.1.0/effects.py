"""One optional effect projection keyed to canonical execution/operation IDs.

This is an effect journal, never an execution queue or an authority source.
Only a trusted provider port with qualified intent/read-back semantics may emit.
"""
import hashlib
import json
import re
from getzilla import execution, state
from getzilla.component_state import BoundRoot

BASE = '.getzilla/runtime/mcp-jira/effects'


def digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 65536:
        raise ValueError('effect_scope_limit')
    return hashlib.sha256(raw).hexdigest()


class Effects:
    def __init__(self, root, *, caller, access, provider, runtime):
        self.root, self.caller, self.access, self.provider = root, caller, access, provider
        self.runtime = runtime

    def _record(self, execution_id, operation_id):
        if not self.runtime.current():
            raise ValueError('module_disabled')
        if 'jira.write' not in self.runtime.request.operations:
            raise ValueError('module_write_not_granted')
        if not re.fullmatch('[0-9a-f]{32}', execution_id) or not re.fullmatch('[A-Za-z0-9._:-]{1,128}', operation_id):
            raise ValueError('effect_identity')
        record = execution.get(self.root, self.caller, execution_id)
        if record['operation_id'] != operation_id:
            raise ValueError('effect_execution_mismatch')
        return record

    def _path(self, execution_id):
        return f'{BASE}/{execution_id}.json'

    def intent(self, execution_id, operation_id, *, target, operation, arguments, baseline):
        self._record(execution_id, operation_id)
        self.access.authorize(target, operation)
        release = getattr(self.access, 'authorize_release', None)
        if not callable(release):
            raise ValueError('effect_release_profile_unqualified')
        release(target, operation, arguments)
        if getattr(self.provider, 'intent_reconciliation_qualified', False) is not True:
            raise ValueError('effect_provider_unqualified')
        identity = dict(execution_id=execution_id, operation_id=operation_id, target=target,
                        operation=operation, arguments_digest=digest(arguments), baseline=baseline)
        identity_digest = digest(identity)
        with state.task_transition(self.root), BoundRoot(self.root) as binding:
            old = binding.read(self._path(execution_id))
            if old:
                value = json.loads(old.content)
                if value['identity_digest'] != identity_digest:
                    raise ValueError('effect_identity_conflict')
                return value
            files = binding.files(BASE)
            if len(files) >= 128:
                raise ValueError('resource_busy')
            for path in files:
                prior = json.loads(binding.read(path).content)
                if prior['operation_id'] == operation_id:
                    self._record(prior['execution_id'], operation_id)
                    if any(prior[field] != identity[field] for field in ('target', 'operation', 'arguments_digest', 'baseline')):
                        raise ValueError('effect_identity_conflict')
                    return prior
                if prior['target'] == target and prior['status'] in {'inflight', 'unknown'}:
                    raise ValueError('effect_conflicting_unknown')
            value = dict(identity, schema_version=1, identity_digest=identity_digest, status='prepared',
                         outcome='unknown', remote_receipt=None)
            binding.write(self._path(execution_id), json.dumps(value, sort_keys=True).encode(), 0o600,
                          expected=None, before_publish=lambda: self._record(execution_id, operation_id))
            return value

    def _update(self, execution_id, operation_id, change):
        with state.task_transition(self.root), BoundRoot(self.root) as binding:
            old = binding.read(self._path(execution_id))
            if old is None:
                raise ValueError('effect_intent_missing')
            value = json.loads(old.content)
            self._record(execution_id, operation_id)
            self.access.authorize(value['target'], value['operation'])
            change(value)
            binding.write(self._path(execution_id), json.dumps(value, sort_keys=True).encode(), 0o600,
                          expected=old, before_publish=lambda: self._record(execution_id, operation_id))
            return value

    def apply(self, execution_id, operation_id, *, arguments):
        emit = []
        def reserve(value):
            if value['arguments_digest'] != digest(arguments):
                raise ValueError('effect_arguments_changed')
            if value['status'] == 'prepared':
                current = self._record(execution_id, operation_id)
                if current['execution_status'] != 'running' or current.get('deadline_elapsed') is not False:
                    raise ValueError('effect_execution_not_running')
                with BoundRoot(self.root) as binding:
                    for path in binding.files(BASE):
                        prior = json.loads(binding.read(path).content)
                        if prior['execution_id'] != execution_id and prior['target'] == value['target'] and prior['status'] in {'inflight', 'unknown'}:
                            raise ValueError('effect_conflicting_unknown')
                value['status'] = 'inflight'
                emit.append(dict(value))
        value = self._update(execution_id, operation_id, reserve)
        if not emit:
            return value  # Includes unknown: never blindly repeat a mutation.
        try:
            self.access.authorize_release(emit[0]['target'], emit[0]['operation'], arguments)
            receipt = self.provider.emit(emit[0], arguments)
            if not isinstance(receipt, dict) or receipt.get('operation_id') != operation_id or receipt.get('applied') is not True:
                raise ValueError('effect_unconfirmed')
        except Exception:
            # Revocation may deny even this projection update. Its durable
            # inflight value still means unknown and prevents a second send.
            try:
                return self._update(execution_id, operation_id, lambda v: v.update(status='unknown', outcome='unknown'))
            except ValueError:
                return dict(value, status='inflight', outcome='unknown')
        return self._update(execution_id, operation_id,
                            lambda v: v.update(status='confirmed', outcome='confirmed_applied', remote_receipt=receipt))

    def reconcile(self, execution_id, operation_id):
        observation = []
        def inspect(value):
            if value['status'] in {'inflight', 'unknown'}:
                observation.append(dict(value))
        value = self._update(execution_id, operation_id, inspect)
        if not observation:
            return value
        current = self.provider.observe(observation[0])  # Read only, current permission required.
        def resolve(value):
            if current.get('operation_id') == operation_id and current.get('applied') is True:
                value.update(status='confirmed', outcome='confirmed_applied', remote_receipt=current)
            else:
                value.update(status='unknown', outcome='unknown')
                if current.get('revision') != value['baseline']:
                    value['conflict'] = 'intervening_human_change'
        return self._update(execution_id, operation_id, resolve)
