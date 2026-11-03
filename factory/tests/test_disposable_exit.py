from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from factory.tests import run_disposable_exit as runner
from getzilla.disposable_resources import CleanupUnconfirmed


CONTAINER_ID = "a" * 64
PASS_LINE = (
    "PASS: disposable PostgreSQL + API + effective roles + actual "
    "restart/reconciliation"
)
# Deliberately public test payload; terminal diagnostics must omit it.
DIAGNOSTIC_SENTINEL = "test-only-diagnostic-payload"


class DisposableExitTests(unittest.TestCase):
    @contextmanager
    def harness(self, *, primary=None, venv_error=None, container_error=None):
        events = []
        commands = []
        stdout = io.StringIO()
        stderr = io.StringIO()

        class Environment:
            name = "/inert/disposable-venv"

            def __enter__(self):
                return self.name

            def __exit__(self, *_args):
                self.cleanup()

            def cleanup(self):
                events.append("venv-cleanup")
                if venv_error is not None:
                    raise venv_error

        def docker(command, **_kwargs):
            if command == ["docker", "port", CONTAINER_ID, "5432/tcp"]:
                return subprocess.CompletedProcess(command, 0, "127.0.0.1:6543\n")
            self.fail(f"unexpected subprocess: {command[:2]}")

        def execute(command, **kwargs):
            commands.append((command, dict(kwargs, environment=dict(kwargs.get("environment", {})))))
            phase = ("suite" if "factory/tests/run_live_suite.py" in command
                     else "preflight" if "--preflight-only" in command else "restart")
            events.append(phase)
            if phase == "suite" and primary is not None:
                raise primary

        def remove():
            events.append("container-cleanup")
            if container_error is not None:
                raise container_error

        owner = SimpleNamespace(namespace="gz-fixture", nonce="b" * 32,
                                manifest=Path("/inert/factory-resources.json"),
                                network=lambda _suffix: {}, cleanup=remove)
        def create(_owner, suffix, _password, _network):
            events.append("create" if suffix == "db" else "fresh-create")
            identifier = CONTAINER_ID if suffix == "db" else "c" * 64
            return {"id": identifier, "name": "gz-fixture-" + suffix}, "postgresql://factory_exit:synthetic@127.0.0.1:5432/factory_exit"

        with (
            patch.object(runner.subprocess, "run", side_effect=docker),
            patch.object(runner, "_binding_matches", return_value=True),
            patch.object(runner, "_final_postgres_ready", return_value=True),
            patch.object(runner, "_run", side_effect=execute),
            patch.object(runner, "_new_owner", return_value=owner),
            patch.object(runner, "_postgres", side_effect=create),
            patch.object(runner.tempfile, "TemporaryDirectory", return_value=Environment()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            yield SimpleNamespace(events=events, commands=commands, owner=owner, stdout=stdout, stderr=stderr)

    def test_pass_is_emitted_only_after_both_finalizers_succeed(self):
        with self.harness() as run:
            with patch("builtins.print") as printed:
                printed.side_effect = lambda *_args, **_kwargs: run.events.append("printed")
                self.assertEqual(runner.main(), 0)
            printed.assert_called_once_with(PASS_LINE)
        self.assertEqual(
            run.events,
            ["create", "preflight", "fresh-create", "preflight", "suite", "restart", "venv-cleanup", "container-cleanup", "printed"],
        )

    def test_success_with_failed_cleanup_never_prints_pass(self):
        for venv_error, container_error in (
            (None, RuntimeError(DIAGNOSTIC_SENTINEL)),
            (PermissionError(DIAGNOSTIC_SENTINEL), None),
            (PermissionError(DIAGNOSTIC_SENTINEL), subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 30)),
        ):
            with self.subTest(venv=type(venv_error), container=type(container_error)):
                with self.harness(venv_error=venv_error, container_error=container_error) as run:
                    with self.assertRaises(Exception):
                        runner.main()
                self.assertNotIn(PASS_LINE, run.stdout.getvalue())
                self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
                self.assertIn("primary=passed", run.stderr.getvalue())
                self.assertIn("venv=", run.stderr.getvalue())
                self.assertIn("container=", run.stderr.getvalue())
                self.assertNotIn(DIAGNOSTIC_SENTINEL, run.stderr.getvalue())

    def test_real_container_removal_is_checked_bounded_and_controls_result(self):
        for remove_exit in (0, 17):
            with self.subTest(remove_exit=remove_exit):
                calls = []
                def docker(command, **kwargs):
                    calls.append((command, kwargs))
                    if command[:2] == ["docker", "inspect"]:
                        metadata = "\t".join((CONTAINER_ID, "/gz-fixture-db", runner.POSTGRES["reference"],
                                               "false", "b" * 32, runner.POSTGRES["image_id"]))
                        return subprocess.CompletedProcess(command, 0, metadata)
                    if command[:2] == ["docker", "rm"] and remove_exit:
                        raise subprocess.CalledProcessError(remove_exit, command)
                    return subprocess.CompletedProcess(command, 0, "")
                with patch.object(runner.subprocess, "run", side_effect=docker):
                    if remove_exit:
                        with self.assertRaises(subprocess.CalledProcessError):
                            runner._remove_bound_container(CONTAINER_ID, "gz-fixture-db", "b" * 32)
                    else:
                        runner._remove_bound_container(CONTAINER_ID, "gz-fixture-db", "b" * 32)
                removals = [(command, kwargs) for command, kwargs in calls if command[:2] == ["docker", "rm"]]
                self.assertEqual(len(removals), 1)
                self.assertEqual(removals[0][0], ["docker", "rm", "-f", CONTAINER_ID])
                self.assertIs(removals[0][1]["check"], True)
                self.assertEqual(removals[0][1]["timeout"], 30)
                if not remove_exit:
                    self.assertEqual(calls[-1][0][:3], ["docker", "container", "ls"])

    def test_cleanup_only_failure_retains_both_original_exception_objects(self):
        venv_error = PermissionError(DIAGNOSTIC_SENTINEL)
        container_error = subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 30)
        with self.harness(venv_error=venv_error, container_error=container_error) as run:
            with self.assertRaises(runner._CleanupError) as raised:
                runner.main()
        self.assertEqual(tuple(name for name, _error in raised.exception.failures), ("venv", "container"))
        self.assertIs(raised.exception.failures[0][1], venv_error)
        self.assertIs(raised.exception.failures[1][1], container_error)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertNotIn(DIAGNOSTIC_SENTINEL, run.stderr.getvalue())

    def test_original_primary_survives_both_cleanup_failures(self):
        for primary in (
            ValueError(DIAGNOSTIC_SENTINEL),
            subprocess.CalledProcessError(23, [DIAGNOSTIC_SENTINEL]),
            subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 720),
            KeyboardInterrupt(DIAGNOSTIC_SENTINEL),
            SystemExit(0),
        ):
            with self.subTest(primary=type(primary).__name__):
                with self.harness(
                    primary=primary,
                    venv_error=PermissionError(DIAGNOSTIC_SENTINEL),
                    container_error=subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 30),
                ) as run:
                    with self.assertRaises(BaseException) as raised:
                        runner.main()
                self.assertIs(raised.exception, primary)
                self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
                self.assertEqual(run.events.count("venv-cleanup"), 1)
                self.assertEqual(run.events.count("container-cleanup"), 1)
                self.assertNotIn(PASS_LINE, run.stdout.getvalue())
                report = run.stderr.getvalue()
                self.assertIn("phase=suite", report)
                self.assertIn("venv=failed", report)
                self.assertIn("error=PermissionError", report)
                self.assertIn("container=unconfirmed", report)
                self.assertIn("error=TimeoutExpired", report)
                self.assertIn(f"container_id={CONTAINER_ID}", report)
                self.assertNotIn(DIAGNOSTIC_SENTINEL, report)
                notes = "\n".join(getattr(primary, "__notes__", ()))
                self.assertIn("venv=failed", notes)
                self.assertIn("container=unconfirmed", notes)
                self.assertNotIn(DIAGNOSTIC_SENTINEL, notes)

    def test_primary_survives_successful_cleanup(self):
        primary = ValueError(DIAGNOSTIC_SENTINEL)
        with self.harness(primary=primary) as run:
            with self.assertRaises(ValueError) as raised:
                runner.main()
        self.assertIs(raised.exception, primary)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("venv=removed", run.stderr.getvalue())
        self.assertIn("container=removed", run.stderr.getvalue())

    def test_unwritable_diagnostics_preserve_primary_and_all_cleanup_notes(self):
        primary = ValueError(DIAGNOSTIC_SENTINEL)
        with self.harness(
            primary=primary,
            venv_error=PermissionError(DIAGNOSTIC_SENTINEL),
            container_error=RuntimeError(DIAGNOSTIC_SENTINEL),
        ) as run:
            with patch("builtins.print", side_effect=BrokenPipeError(DIAGNOSTIC_SENTINEL)):
                with self.assertRaises(ValueError) as raised:
                    runner.main()
        self.assertIs(raised.exception, primary)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        notes = "\n".join(primary.__notes__)
        self.assertIn("venv=failed", notes)
        self.assertIn("container=unconfirmed", notes)

    def test_cli_preserves_primary_exit_precedence_and_hides_exception_payloads(self):
        for primary, expected in (
            (ValueError(DIAGNOSTIC_SENTINEL), 1),
            (subprocess.CalledProcessError(23, [DIAGNOSTIC_SENTINEL], output=DIAGNOSTIC_SENTINEL, stderr=DIAGNOSTIC_SENTINEL), 1),
            (subprocess.CalledProcessError(-9, [DIAGNOSTIC_SENTINEL]), 1),
            (subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 720, output=DIAGNOSTIC_SENTINEL, stderr=DIAGNOSTIC_SENTINEL), 124),
            (KeyboardInterrupt(DIAGNOSTIC_SENTINEL), 130),
            (SystemExit(0), 1),
        ):
            with self.subTest(primary=type(primary).__name__, expected=expected):
                with self.harness(
                    primary=primary,
                    venv_error=PermissionError(DIAGNOSTIC_SENTINEL),
                    container_error=subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 30),
                ) as run:
                    self.assertEqual(runner._cli(), expected)
                self.assertNotIn(PASS_LINE, run.stdout.getvalue())
                report = run.stderr.getvalue()
                self.assertNotIn(DIAGNOSTIC_SENTINEL, report)
                self.assertNotIn("Traceback", report)
                self.assertIn("phase=suite", report)
                self.assertIn(f"error={type(primary).__name__}", report)
                if isinstance(primary, subprocess.CalledProcessError):
                    field = "signal=9" if primary.returncode < 0 else "exit=23"
                    self.assertIn(field, report)
                if isinstance(primary, subprocess.TimeoutExpired):
                    self.assertIn("timeout_seconds=720", report)
                if isinstance(primary, KeyboardInterrupt):
                    self.assertIn("signal=2", report)

    def test_cleanup_timeout_is_not_reported_as_a_primary_timeout(self):
        with self.harness(container_error=subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 30)) as run:
            self.assertEqual(runner._cli(), 1)
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("primary=passed", run.stderr.getvalue())
        self.assertIn("container=unconfirmed", run.stderr.getvalue())
        self.assertIn("timeout_seconds=30", run.stderr.getvalue())

    def test_interrupt_in_venv_cleanup_still_attempts_container_cleanup(self):
        interrupt = KeyboardInterrupt(DIAGNOSTIC_SENTINEL)
        with self.harness(venv_error=interrupt) as run:
            with self.assertRaises(KeyboardInterrupt) as raised:
                runner.main()
        self.assertIs(raised.exception, interrupt)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())

    def test_cli_reports_uncertain_creation_without_secret_argv_or_name_cleanup(self):
        for failure, expected in ((subprocess.CalledProcessError(125, [DIAGNOSTIC_SENTINEL]), 1),
                                  (subprocess.TimeoutExpired([DIAGNOSTIC_SENTINEL], 60), 124)):
            with self.subTest(failure=type(failure).__name__), self.harness() as run:
                with patch.object(runner, "_postgres", side_effect=failure):
                    self.assertEqual(runner._cli(), expected)
                self.assertEqual(run.events, ["container-cleanup"])
                self.assertNotIn(PASS_LINE, run.stdout.getvalue())
                report = run.stderr.getvalue()
                self.assertIn("phase=container-create", report)
                self.assertIn("venv=not_created", report)
                self.assertIn("container=removed", report)
                self.assertNotIn(DIAGNOSTIC_SENTINEL, report)

    def test_cli_does_not_echo_unvalidated_container_output(self):
        with self.harness() as run:
            with patch.object(runner, "_postgres", side_effect=ValueError(DIAGNOSTIC_SENTINEL)):
                self.assertEqual(runner._cli(), 1)
            self.assertIn("container_id=unknown", run.stderr.getvalue())
            self.assertNotIn(DIAGNOSTIC_SENTINEL, run.stderr.getvalue())
            self.assertNotIn(PASS_LINE, run.stdout.getvalue())

    def test_changed_binding_at_cleanup_is_unconfirmed_and_never_removed(self):
        # The real live identity/absence decisions are exercised by IsolatedResourceTests.
        with self.harness(container_error=CleanupUnconfirmed("changed")) as run:
            self.assertEqual(runner._cli(), 1)
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("primary=passed", run.stderr.getvalue())
        self.assertIn("container=unconfirmed", run.stderr.getvalue())

    def test_changed_or_unobservable_identity_never_authorizes_removal(self):
        name, nonce = "adaptive-factory-exit-owner", "b" * 32
        valid = [CONTAINER_ID, f"/{name}", runner.POSTGRES["reference"], "false", nonce, runner.POSTGRES["image_id"]]
        invalid = []
        for index, value in ((0, "c" * 64), (1, "/foreign"), (2, "postgres:18-alpine"), (3, "unknown"), (4, "d" * 32), (5, "sha256:" + "0" * 64)):
            fields = list(valid)
            fields[index] = value
            invalid.append(subprocess.CompletedProcess([], 0, "\t".join(fields)))
        invalid.extend((
            subprocess.CompletedProcess([], 1, ""),
            subprocess.CompletedProcess([], 0, "malformed"),
            subprocess.TimeoutExpired(["docker", "inspect", CONTAINER_ID], 10),
            OSError(DIAGNOSTIC_SENTINEL),
        ))
        for result in invalid:
            with self.subTest(result=type(result).__name__):
                with patch.object(runner.subprocess, "run", side_effect=[result]) as called:
                    with self.assertRaises(Exception):
                        runner._remove_bound_container(CONTAINER_ID, name, nonce)
                self.assertEqual(called.call_count, 1)
                self.assertEqual(called.call_args.args[0][:2], ["docker", "inspect"])
                self.assertEqual(called.call_args.args[0][-1], CONTAINER_ID)
                self.assertEqual(called.call_args.kwargs["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
