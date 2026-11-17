"""NEW guarded service-dispatch controls; no App, kernel, DB or HTTP calls."""

import contextlib
import importlib.util
import json
import struct
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from adaptive_trust_ci import public_http as http
from adaptive_trust_ci.github import GitHubClient

if importlib.util.find_spec("adaptive_trust_ci.public_dispatch"):
    from adaptive_trust_ci import public_dispatch as dispatch
else:
    dispatch = None
ACTIVE = False


def guard(event, args):
    if ACTIVE and (event == "open" or event.startswith(("os.", "socket.", "subprocess.", "ctypes.", "shutil."))):
        raise AssertionError("new fixture denies outside/native/network I/O")


sys.addaudithook(guard)


@contextlib.contextmanager
def guarded():
    global ACTIVE
    ACTIVE = True
    try:
        yield
    finally:
        ACTIVE = False


class DispatcherControls(unittest.TestCase):
    def config(self):
        return SimpleNamespace(producer={"dispatch": {"enabled": True}})

    def context(self):
        role = http.WorkflowDispatchConfig("owned/runner", 8, 81, 91, 9, "main", Path("/UNREAD-key"))
        return SimpleNamespace(key="a" * 64, active=False, budget=SimpleNamespace(deadline=3.0), role=role)

    def test_default_off_never_reads_configuration_or_dispatches(self):
        self.assertIsNotNone(dispatch, "missing automatic service dispatcher")
        with patch.object(dispatch, "_context", side_effect=AssertionError("disabled path must not observe")):
            with guarded():
                result = dispatch.request_producer(
                    SimpleNamespace(producer={"dispatch": {"enabled": False}}), 5, object()
                )
        self.assertEqual(result.state, "blocked")

    def test_pending_is_recorded_before_one_fixed_dispatch(self):
        self.assertIsNotNone(dispatch, "missing automatic service dispatcher")
        events = []
        journal = SimpleNamespace(
            reserve_dispatch=lambda key, pr: events.append("pending") or True,
            finish_dispatch=lambda key, state: events.append(state),
        )

        class Port:
            def open(self, client, method, path, body, **kwargs):
                events.append("POST")
                self_body = body
                if self_body != {"ref": "main", "inputs": {"pull_request": "5"}}:
                    raise AssertionError("wrong request")
                return SimpleNamespace(status=204, read=lambda count: b"", close=lambda: None)

        with (
            patch.object(dispatch, "_context", return_value=self.context()),
            patch.object(dispatch, "issue_scoped_token", return_value="owned-token"),
            patch.object(dispatch, "WorkflowDispatchPort", return_value=Port()),
        ):
            with guarded():
                result = dispatch.request_producer(self.config(), 5, journal)
        self.assertEqual(events, ["pending", "POST", "requested"])
        self.assertEqual(result.reason, "producer-run-requested")

    def test_prior_dispatch_never_reposts(self):
        self.assertIsNotNone(dispatch, "missing automatic service dispatcher")
        journal = SimpleNamespace(reserve_dispatch=lambda key, pr: False)
        with (
            patch.object(dispatch, "_context", return_value=self.context()),
            patch.object(
                dispatch, "issue_scoped_token", side_effect=AssertionError("no new credentials after prior intent")
            ),
        ):
            with guarded():
                result = dispatch.request_producer(self.config(), 5, journal)
        self.assertEqual(result.reason, "producer-generation-already-requested")

    def test_unknown_dispatch_outcome_is_retained_and_not_success(self):
        self.assertIsNotNone(dispatch, "missing automatic service dispatcher")
        events = []
        journal = SimpleNamespace(
            reserve_dispatch=lambda key, pr: True, finish_dispatch=lambda key, state: events.append(state)
        )
        with (
            patch.object(dispatch, "_context", return_value=self.context()),
            patch.object(dispatch, "issue_scoped_token", return_value="owned-token"),
            patch.object(
                dispatch,
                "WorkflowDispatchPort",
                return_value=SimpleNamespace(open=lambda *a, **k: (_ for _ in ()).throw(ValueError("owned refusal"))),
            ),
        ):
            with guarded():
                result = dispatch.request_producer(self.config(), 5, journal)
        self.assertEqual(result.state, "unknown")
        self.assertEqual(events, ["unknown"])

    def test_dispatch_port_cannot_write_checks_or_choose_another_workflow(self):
        role = http.WorkflowDispatchConfig("owned/runner", 8, 81, 91, 9, "main", Path("/UNREAD-key"))
        port = http.WorkflowDispatchPort(role, clock=lambda: 1.0)
        client = GitHubClient(token="owned-token")
        with patch.object(http, "_run_owned", side_effect=AssertionError("foreign effect reached child")):
            for path in ("/repos/owned/runner/check-runs", "/repos/owned/runner/actions/workflows/10/dispatches"):
                with self.subTest(path=path), guarded(), self.assertRaises(ValueError):
                    port.open(
                        client, "POST", path, {"ref": "main", "inputs": {"pull_request": "5"}}, deadline=3.0, maximum=64
                    )
        self.assertEqual(
            role.token_request(), {"repository_ids": [8], "permissions": {"actions": "write", "contents": "read"}}
        )

    def test_actual_service_failure_path_calls_dispatcher_after_durable_fence(self):
        self.assertIsNotNone(dispatch)
        from adaptive_trust_ci import public_runtime as runtime

        events = []
        queue = SimpleNamespace(require_refresh_safe=lambda current: events.append("fence"))
        worker = runtime.PublicWorker(SimpleNamespace(producer={"dispatch": {"enabled": False}}), queue)
        with (
            patch.object(worker, "_prepare_publication", side_effect=ValueError("owned unavailable")),
            patch.object(
                dispatch,
                "request_producer",
                side_effect=lambda *args, **kwargs: (
                    events.append("dispatch") or SimpleNamespace(state="blocked", reason="disabled")
                ),
            ),
        ):
            with guarded():
                result = worker.publish_for_pr(5)
        self.assertEqual(events, ["fence", "dispatch"])
        self.assertEqual(result.state, "blocked")

    def test_actual_dispatch_port_uses_fixed_profile_and_preserves_empty_204(self):
        role = http.WorkflowDispatchConfig("owned/runner", 8, 81, 91, 9, "main", Path("/UNREAD"))
        port = http.WorkflowDispatchPort(role, clock=lambda: 1.0)
        with patch.object(http, "_run_owned", return_value=struct.pack("!II", 204, 0)) as owned:
            with guarded():
                response = port.open(
                    GitHubClient(token="-".join(("owned", "fixture", "token"))),
                    "POST",
                    "/repos/owned/runner/actions/workflows/9/dispatches",
                    {"ref": "main", "inputs": {"pull_request": "5"}},
                    deadline=3.0,
                    maximum=64,
                )
                self.assertEqual(response.status, 204)
                self.assertEqual(response.read(64), b"")
                response.close()
        wire = json.loads(owned.call_args.args[1])
        self.assertEqual(wire["action"], "dispatch-http")
        self.assertEqual(wire["dispatch"], {"workflow_id": 9, "branch": "main"})
        self.assertNotIn("checks", role.token_request()["permissions"])

    def test_global_stop_prevents_observation_and_actions_write(self):
        def stopped():
            raise ValueError("global-kill-switch-active")

        with patch.object(dispatch, "_context", side_effect=AssertionError("stop must prevent observation")):
            with guarded(), self.assertRaises(ValueError):
                dispatch.request_producer(self.config(), 5, object(), guard=stopped)


if __name__ == "__main__":
    unittest.main()
