"""Real bounded namespace-owned local jobs, without provider or network effects."""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from getzilla import execution, execution_store as store, state
from tests.execution_contract_support import owned_route

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "linux" and shutil.which("bwrap"), "Linux namespace profile required")
class SupervisedExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.session = "supervised-test-only"
        self.enterContext(patch.dict(os.environ, {"GETZILLA_SESSION_ID": self.session}))
        self.addCleanup(state.bind_session, None)
        cfg = self.root / ".getzilla/config"
        cfg.mkdir(parents=True)
        for p in (cfg, cfg.parent):
            p.chmod(0o755)
        (cfg / "policy.json").write_text('{"schema_version": 2}')
        (cfg / "policy.json").chmod(0o644)
        owned_route(self.root, session=self.session)
        self.ids = []
        self.addCleanup(self.cleanup)

    def configure(self, code):
        target = self.root / "bin/python3"
        target.parent.mkdir(mode=0o700, exist_ok=True)
        shutil.copyfile(Path("/usr/bin/python3").resolve(), target)
        target.chmod(0o755)
        script = self.root / "fixture_program.py"
        script.write_text(code)
        script.chmod(0o644)
        data = {
            "schema_version": 1,
            "tools": [
                {
                    "id": "fixture",
                    "commands": ["python3"],
                    "managed": {
                        "executable": str(target),
                        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                        "argv": ["-I", "-S", str(script)],
                    },
                }
            ],
        }
        config = self.root / ".getzilla/config/toolchain.json"
        config.write_text(json.dumps(data))
        config.chmod(0o644)

    def start(self, key="one", timeout=10):
        from getzilla.supervised_execution import start

        view = start(self.root, tool_id="fixture", intent_key=key, hard_timeout_seconds=timeout)
        self.ids.append(view["execution_id"])
        return view

    def observe(self, identity):
        return execution.get(self.root, execution.trusted_caller(self.root, execution_id=identity), identity)

    def finish(self, identity, timeout=12):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            view = self.observe(identity)
            if view["execution_status"] in store.TERMINAL:
                return view
            time.sleep(0.05)
        self.fail("owned execution did not terminate within bound")

    def cleanup(self):
        from getzilla.supervised_execution import cancel

        for identity in self.ids:
            try:
                cancel(self.root, identity)
                self.finish(identity, 3)
            except (ValueError, AssertionError):
                pass

    def test_start_replay_get_wait_survive_cli_exit_without_relaunch(self):
        self.configure("import time;print('public-output',flush=True);time.sleep(1)")
        first = self.start()
        again = self.start()
        self.assertEqual(first["execution_id"], again["execution_id"])
        waited = execution.wait(self.root, execution.trusted_caller(self.root), first["execution_id"], 0.05)
        self.assertEqual(waited["wait_status"], "wait_expired")
        execution._LIVE.clear()
        self.assertEqual(self.observe(first["execution_id"])["observation_status"], "ready")
        result = self.finish(first["execution_id"])
        self.assertEqual(result["execution_status"], "succeeded")
        self.assertEqual(result["cleanup_status"], "confirmed")
        self.assertIn("public-output", result["output"]["preview"])
        self.assertEqual(len(store.load_registry(self.root)["records"]), 1)

    def test_cancel_reaps_detached_descendant_before_confirming_cleanup(self):
        self.configure(
            "import os,time;pid=os.fork();\nif pid==0: os.setsid();time.sleep(20)\nelse: print('started',flush=True);time.sleep(20)"
        )
        view = self.start()
        time.sleep(0.25)
        from getzilla.supervised_execution import cancel

        cancel(self.root, view["execution_id"])
        result = self.finish(view["execution_id"])
        self.assertEqual(result["execution_status"], "cancelled")
        self.assertEqual(result["cleanup_status"], "confirmed")

    def test_deadline_and_output_are_bounded_and_network_is_isolated(self):
        self.configure(
            "import os,socket,time;print(os.readlink('/proc/self/ns/net'));print('x'*1000000,flush=True);time.sleep(20)"
        )
        view = self.start(timeout=2)
        result = self.finish(view["execution_id"])
        self.assertEqual(result["execution_status"], "timed_out")
        self.assertEqual(result["cleanup_status"], "confirmed")
        self.assertGreater(result["output"]["observed_bytes"], 100000)
        self.assertLessEqual(result["output"]["retained_bytes"], 4096)
        self.assertFalse(result["output"]["complete_output"])

    def test_policy_denial_never_allocates_or_dispatches(self):
        self.configure("print('must not run')")
        with patch("getzilla.managed_execution._policy", side_effect=execution.ExecutionError("managed_policy_denied")):
            with self.assertRaises(execution.ExecutionError):
                self.start()
        self.assertEqual(store.load_registry(self.root)["records"], {})

    def test_new_task_has_distinct_intent_but_original_owner_can_observe_old_attempt(self):
        self.configure("import time;time.sleep(.3)")
        view = self.start()
        self.finish(view["execution_id"])
        owned_route(self.root, session=self.session, task="A distinct fixture task")
        other = self.start()
        self.finish(other["execution_id"])
        self.assertNotEqual(view["execution_id"], other["execution_id"])
        self.assertEqual(self.observe(view["execution_id"])["execution_id"], view["execution_id"])

    def test_epoch_handoff_fences_old_caller(self):
        caller = execution.trusted_caller(self.root)
        route = state.get_active_route(self.root)
        route["authority_epoch"] += 1
        state.durable_json(self.root, self.root / ".getzilla/runtime/routes" / (route["route_id"] + ".json"), route)
        with self.assertRaises(execution.ExecutionError):
            execution._caller(self.root, caller)

    def test_native_cli_exit_leaves_job_owned_and_restart_observes_same_attempt(self):
        self.configure("import time;print('cli-owned',flush=True);time.sleep(.7)")
        command = [sys.executable, "-B", str(ROOT / "scripts/getzilla_execution.py")]
        first = subprocess.run(
            [*command, "start", "--tool", "fixture", "--intent", "cli-test", "--timeout", "5"],
            cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True,
            timeout=4,
        )
        self.assertEqual(first.returncode, 0, first.stderr.decode())
        identity = json.loads(first.stdout)["execution_id"]
        self.ids.append(identity)
        second = subprocess.run([*command, "get", identity], cwd=self.root, capture_output=True, timeout=3)
        self.assertEqual(second.returncode, 0, second.stderr.decode())
        self.assertEqual(json.loads(second.stdout)["execution_id"], identity)
        self.assertEqual(self.finish(identity)["execution_status"], "succeeded")

    def test_supervisor_death_cannot_relaunch_unknown_attempt(self):
        from getzilla import supervised_execution as backend

        self.configure(
            "import os,time;pid=os.fork();\nif pid==0: os.setsid();time.sleep(20)\nelse: print('owned-alive',flush=True);time.sleep(20)"
        )
        view = self.start(timeout=3)
        end = time.monotonic() + 1.5
        while time.monotonic() < end:
            current = self.observe(view["execution_id"])
            if "owned-alive" in current["output"]["preview"]:
                break
            time.sleep(0.03)
        self.assertIn("owned-alive", current["output"]["preview"])
        # Observe only the actual owned launch tree's public PID metadata.
        pending, identities = [current["launch"]["process_id"]], []
        while pending and len(identities) < 16:
            pid = pending.pop()
            try:
                identities.append(
                    {"profile": backend.PROFILE, "host_pid": pid, "start_ticks": backend._host_identity(pid)}
                )
                pending.extend(int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split())
            except (OSError, ValueError):
                pass
        self.assertGreaterEqual(len(identities), 3)
        os.kill(view["supervisor"]["host_pid"], signal.SIGKILL)
        end = time.monotonic() + 2
        while time.monotonic() < end and any(backend.is_live(item) for item in identities):
            time.sleep(0.02)
        self.assertFalse(any(backend.is_live(item) for item in identities))
        time.sleep(0.15)
        execution._LIVE.clear()
        observed = self.observe(view["execution_id"])
        self.assertFalse(observed["live_continuity"])
        self.assertEqual(observed["observation_status"], "recovery_unknown")
        replay = self.start(timeout=3)
        self.assertEqual(replay["execution_id"], view["execution_id"])
        report = execution.restore(self.root)
        self.assertEqual(report["orphaned"], 1)
        self.assertEqual(self.observe(view["execution_id"])["cleanup_status"], "unconfirmed")

    def test_network_namespace_differs_and_has_no_external_route(self):
        self.configure(
            "import os,socket;print(os.readlink('/proc/self/ns/net'));s=socket.socket();s.settimeout(.1);print(s.connect_ex(('203.0.113.1',9)))"
        )
        result = self.finish(self.start()["execution_id"])
        self.assertEqual(result["execution_status"], "succeeded")
        self.assertNotIn(os.readlink("/proc/self/ns/net"), result["output"]["preview"])
        self.assertNotEqual(result["output"]["preview"].strip().splitlines()[-1], "0")

    def test_two_active_slots_refuse_without_queue_and_release_after_cleanup(self):
        self.configure("import time;time.sleep(2)")
        first = self.start(key="capacity-one")
        second = self.start(key="capacity-two")
        with self.assertRaises(execution.ExecutionError) as error:
            self.start(key="capacity-three")
        self.assertEqual(error.exception.code, "backend_saturated")
        self.assertEqual(len(store.load_registry(self.root)["records"]), 2)
        from getzilla.supervised_execution import cancel

        for item in (first, second):
            cancel(self.root, item["execution_id"])
            self.assertEqual(self.finish(item["execution_id"])["cleanup_status"], "confirmed")
        third = self.start(key="capacity-three")
        self.assertEqual(self.finish(third["execution_id"])["execution_status"], "succeeded")

    def test_live_preview_is_bounded_and_does_not_claim_complete_output(self):
        self.configure("import time;print('preview-now',flush=True);time.sleep(1.5)")
        view = self.start()
        time.sleep(0.5)
        observed = self.observe(view["execution_id"])
        self.assertIn("preview-now", observed["output"]["preview"])
        self.assertFalse(observed["output"]["complete_output"])
        self.assertFalse(observed["output"]["evidence_authority"])
        self.assertEqual(self.finish(view["execution_id"])["execution_status"], "succeeded")

    def test_installed_file_and_archive_payloads_run_the_native_supervisor(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("supervised_installer_test", ROOT / "scripts/install_into.py")
        install = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = install
        spec.loader.exec_module(install)
        original = self.root
        try:
            for archive in (False, True):
                with self.subTest(archive=archive):
                    target = original / ("archive-consumer" if archive else "file-consumer")
                    install.materialize_new(
                        ROOT, target, selection=install.PayloadSelection(("codex",), engine_archive=archive)
                    )
                    self.root = target
                    self.configure("print('installed-native-public')")
                    # The installed payload already approaches the closed16MiB
                    # source bound. Pin the existing system ELF outside it.
                    config_path = target / ".getzilla/config/toolchain.json"
                    config = json.loads(config_path.read_text())
                    executable = Path("/usr/bin/python3").resolve()
                    config["tools"][0]["commands"] = [executable.name]
                    config["tools"][0]["managed"]["executable"] = str(executable)
                    config["tools"][0]["managed"]["sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
                    config_path.write_text(json.dumps(config))
                    (target / "bin/python3").unlink()
                    owned_route(self.root, session=self.session)
                    command = [sys.executable, "-B", str(target / "scripts/getzilla_execution.py")]
                    result = subprocess.run(
                        [*command, "start", "--tool", "fixture", "--intent", "installed-native", "--timeout", "30"],
                        cwd=target,
                        capture_output=True,
                        timeout=8,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
                    identity = json.loads(result.stdout)["execution_id"]
                    self.ids.append(identity)
                    observed = self.finish(identity, 30)
                    self.assertEqual(observed["execution_status"], "succeeded")
                    self.assertEqual(observed["cleanup_status"], "confirmed")
                    self.assertIn("installed-native-public", observed["output"]["preview"])
                    self.ids.remove(identity)
        finally:
            self.root = original

    def test_managed_par_uses_the_same_registry_and_stable_intent(self):
        self.configure("print('managed-par-public')")
        command = [
            sys.executable,
            "-B",
            str(ROOT / "scripts/getzilla_par.py"),
            "--managed-tool",
            "fixture",
            "--intent",
            "par-fixture",
            "--timeout",
            "5",
            "--wait-seconds",
            "2",
        ]
        for _ in range(2):
            result = subprocess.run(command, cwd=self.root, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stdout.decode() + result.stderr.decode())
            parsed = json.loads(result.stdout)
            item = parsed["attempts"][0]["execution"]
            self.assertEqual(item["execution_status"], "succeeded")
            self.assertIn("managed-par-public", item["output"]["preview"])
        self.assertEqual(len(store.load_registry(self.root)["records"]), 1)

    def test_published_schema_accepts_the_real_supervisor_and_rejects_extra_authority(self):
        import copy
        import jsonschema

        self.configure("pass")
        self.assertEqual(self.finish(self.start()["execution_id"])["execution_status"], "succeeded")
        schema = json.loads((ROOT / "schemas/execution-registry.v2.schema.json").read_text())
        ledger = store.load_registry(self.root)
        jsonschema.validate(ledger, schema)
        invalid = copy.deepcopy(ledger)
        next(iter(invalid["records"].values()))["supervisor"]["authority"] = "caller-controlled"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(invalid, schema)
        with self.assertRaises(store.RegistryError):
            store._validate(invalid)
