"""Limits and infrastructure breaker derived from the canonical attempt store."""
from datetime import datetime, timedelta, timezone
import hashlib
import json


def scope_key(*, endpoint, project, credential_scope, configuration):
    # Display aliases are deliberately absent. This is a nonsecret credential
    # scope identifier, never credential contents or an incoming connector token.
    raw = json.dumps([endpoint, project, credential_scope, configuration], separators=(',', ':'), sort_keys=True).encode()
    return 'mcp-' + hashlib.sha256(raw).hexdigest()


def gate(registry, label, *, now=None, read_only=True):
    now = now or datetime.now(timezone.utc)
    records = [record for record in registry['records'].values()
               if record['input']['display']['label'].startswith('mcp-')]
    active = [record for record in records if record['execution_status'] in {'running', 'cancel_requested'}
              or record['cleanup_status'] in {'pending', 'failed', 'unconfirmed'}
              or record.get('local_supervisor_consuming') is True]
    scoped = [record for record in records if record['input']['display']['label'] == label]
    owned = [record for record in active if record['input']['display']['label'] == label]
    unresolved = [record for record in records if record.get('operation_outcome') == 'unknown']
    if len(unresolved) >= 32:
        return 'unresolved_budget_busy'
    if len(active) >= 8 or len(owned) >= 2:
        return 'resource_busy'
    outcomes = []
    for record in scoped:
        try:
            finished = datetime.fromisoformat(record['retention_until']) - timedelta(days=1)
        except (ValueError, TypeError):
            continue
        outcomes.append((finished, record['terminal_reason']))
    failures = []
    opened = None
    for finished, reason in sorted(outcomes):
        if reason in {'mcp_success', 'mcp_domain'}:
            failures = []
            opened = None
        elif reason and reason.startswith('mcp_infra_'):
            if opened is not None:
                # A failed half-open probe starts a new full cooldown. Ignore
                # domain/cancel/policy outcomes instead of charging or healing.
                opened = finished
            else:
                failures = [at for at in failures if (finished - at).total_seconds() <= 60]
                failures.append(finished)
                if len(failures) >= 3:
                    opened = finished
    if opened is not None:
        if (now - opened).total_seconds() < 60:
            return 'breaker_open'
        if not read_only:
            return 'breaker_safe_probe_required'
        if owned:
            return 'breaker_probe_busy'
    return None


class HostBudget:
    """Trusted native-host inventory of canonical stores, never project settings."""
    def __init__(self, coordinator_root, project_roots):
        from pathlib import Path
        self.coordinator = Path(coordinator_root).resolve(strict=True)
        self.roots = tuple(Path(root).resolve(strict=True) for root in project_roots)
        if not self.roots or len(set(self.roots)) != len(self.roots) or len(self.roots) > 64:
            raise ValueError('mcp_host_inventory_unavailable')

    def allocation_lock(self):
        from contextlib import contextmanager
        from getzilla import state, execution
        # Non-queueing bounded admission. This lock ends before dispatch starts.
        @contextmanager
        def bounded():
            try:
                with state.runtime_lock(self.coordinator, 'mcp-host-budget', timeout=.01):
                    yield
            except TimeoutError as error:
                raise execution.ExecutionError('resource_busy') from error
        return bounded()

    def snapshot(self, project_root, current_registry):
        from getzilla import execution_store
        from pathlib import Path
        root = Path(project_root).resolve()
        if root not in self.roots:
            raise ValueError('mcp_host_inventory_unavailable')
        records = {}
        for project in self.roots:
            try:
                registry = current_registry if project == root else execution_store.load_registry(project)
            except execution_store.RegistryError as error:
                if error.code == 'registry_not_found':
                    continue
                raise ValueError('mcp_host_inventory_unavailable') from error
            for key, value in registry['records'].items():
                label = value['input']['display']['label']
                if label.startswith('mcp-'):
                    records[str(project) + ':' + key] = {name: value.get(name) for name in
                        ('execution_status', 'cleanup_status', 'terminal_reason', 'retention_until', 'remote_task_id', 'operation_outcome')}
                    records[str(project) + ':' + key]['input'] = {'display': {'label': label}}
                    records[str(project) + ':' + key]['local_supervisor_consuming'] = local_supervisor_consuming(value)
        return {'records': records}


def local_supervisor_consuming(record):
    """A flushed protocol body is not a stopped supervisor. Unknown stays charged."""
    identity = record.get('supervisor')
    if identity is None:
        return False
    from getzilla import supervised_execution
    supervised_execution.reap()
    try:
        return supervised_execution._host_identity(identity['host_pid']) == identity['start_ticks']
    except FileNotFoundError:
        return False
    except (OSError, ValueError, KeyError, TypeError):
        # Includes unreaped zombies and unavailable host observations.
        return True
