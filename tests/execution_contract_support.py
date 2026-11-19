"""Shared public EX02 contract fixtures; these provide no production backend."""
from datetime import datetime, timedelta, timezone
import threading
from pathlib import Path

from getzilla import execution, execution_store as store, state
from getzilla.router import build_route

class FakeClock:
    def __init__(self):
        self.seconds = 100.0
        self.now = datetime(2026, 11, 4, tzinfo=timezone.utc)
        self.sleeps = []

    def monotonic(self):
        return self.seconds

    def utcnow(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.seconds += seconds
        self.now += timedelta(seconds=seconds)

class CountingBackend:
    kind = 'contract-test'
    external_mutations = False
    cooperative_admission = True

    def __init__(self, complete=True):
        self.calls = 0
        self.cancels = 0
        self.complete = complete
        self.admissions = []
        self.lock = threading.Lock()

    def dispatch(self, root, admission, request):
        admission.consume(root, request)
        persisted = store.load_registry(root)['records'][admission.execution_id]
        assert persisted['backend']['claim'] == 'committed'
        with self.lock:
            self.calls += 1
            self.admissions.append(admission)
        return {'execution_status': 'succeeded', 'terminal_reason': 'exit_zero'} if self.complete else None

    def cancel(self, root, admission):
        admission.consume(root)
        self.cancels += 1
        return True

def owned_route(root, session='owner', task='Fix a README typo.', *, provision=True):
    state.bind_session(session)
    route = build_route(root, task, session).to_dict()
    state.set_active_route(root, route)
    if provision:
        execution.provision(root, execution.trusted_caller(root))
    return state.get_active_route(root)

def observe_saved_attempt(path, execution_id, result):
    root = Path(path)
    state.bind_session('owner')
    from getzilla.execution_output import read_output
    caller = execution.trusted_caller(root, execution_id=execution_id)
    view = execution.get(root, caller, execution_id)
    output = read_output(root, caller, execution_id)
    result.put({'execution_id': view['execution_id'], 'route_id': view['owner']['route_id'],
                'authority': view['evidence_authority'], 'live_continuity': view['live_continuity'],
                'observation_status': view['observation_status'], 'output_status': output['status']})
