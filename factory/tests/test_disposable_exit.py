from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from factory.tests import run_disposable_exit as runner


CONTAINER_ID = "a" * 64
PASS_LINE = (
    "PASS: disposable PostgreSQL + API + effective roles + actual "
    "restart/reconciliation"
)
SECRET = "terminal-secret-sentinel"


class DisposableExitTests(unittest.TestCase):
    @contextmanager
    def harness(self, *, primary=None, venv_error=None, container_error=None):
        events = []
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
            if command[:2] == ["docker", "run"]:
                events.append("create")
                return subprocess.CompletedProcess(command, 0, CONTAINER_ID)
            if command == ["docker", "port", CONTAINER_ID, "5432/tcp"]:
                return subprocess.CompletedProcess(command, 0, "127.0.0.1:5432\n")
            self.fail(f"unexpected subprocess: {command[:2]}")

        def execute(command, **_kwargs):
            phase = (
                "suite" if "unittest" in command
                else "preflight" if "--preflight-only" in command
                else "restart"
            )
            events.append(phase)
            if phase == "suite" and primary is not None:
                raise primary

        def remove(container_id, _name, _nonce):
            self.assertEqual(container_id, CONTAINER_ID)
            events.append("container-cleanup")
            if container_error is not None:
                raise container_error

        with (
            patch.object(runner.subprocess, "run", side_effect=docker),
            patch.object(runner, "_binding_matches", return_value=True),
            patch.object(runner, "_final_postgres_ready", return_value=True),
            patch.object(runner, "_run", side_effect=execute),
            patch.object(runner, "_remove_bound_container", side_effect=remove),
            patch.object(runner.tempfile, "TemporaryDirectory", return_value=Environment()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            yield SimpleNamespace(events=events, stdout=stdout, stderr=stderr)

    def test_pass_is_emitted_only_after_both_finalizers_succeed(self):
        with self.harness() as run:
            with patch("builtins.print") as printed:
                printed.side_effect = lambda *_args, **_kwargs: run.events.append("printed")
                self.assertEqual(runner.main(), 0)
            printed.assert_called_once_with(PASS_LINE)
        self.assertEqual(
            run.events,
            ["create", "preflight", "suite", "restart", "venv-cleanup", "container-cleanup", "printed"],
        )

    def test_success_with_failed_cleanup_never_prints_pass(self):
        for venv_error, container_error in (
            (None, RuntimeError(SECRET)),
            (PermissionError(SECRET), None),
            (PermissionError(SECRET), subprocess.TimeoutExpired([SECRET], 30)),
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
                self.assertNotIn(SECRET, run.stderr.getvalue())

    def test_original_primary_survives_both_cleanup_failures(self):
        for primary in (
            ValueError(SECRET),
            subprocess.CalledProcessError(23, [SECRET]),
            subprocess.TimeoutExpired([SECRET], 720),
            KeyboardInterrupt(SECRET),
            SystemExit(0),
        ):
            with self.subTest(primary=type(primary).__name__):
                with self.harness(
                    primary=primary,
                    venv_error=PermissionError(SECRET),
                    container_error=subprocess.TimeoutExpired([SECRET], 30),
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
                self.assertNotIn(SECRET, report)
                notes = "\n".join(getattr(primary, "__notes__", ()))
                self.assertIn("venv=failed", notes)
                self.assertIn("container=unconfirmed", notes)
                self.assertNotIn(SECRET, notes)

    def test_primary_survives_successful_cleanup(self):
        primary = ValueError(SECRET)
        with self.harness(primary=primary) as run:
            with self.assertRaises(ValueError) as raised:
                runner.main()
        self.assertIs(raised.exception, primary)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("venv=removed", run.stderr.getvalue())
        self.assertIn("container=removed", run.stderr.getvalue())

    def test_unwritable_diagnostics_preserve_primary_and_all_cleanup_notes(self):
        primary = ValueError(SECRET)
        with self.harness(
            primary=primary,
            venv_error=PermissionError(SECRET),
            container_error=RuntimeError(SECRET),
        ) as run:
            with patch("builtins.print", side_effect=BrokenPipeError(SECRET)):
                with self.assertRaises(ValueError) as raised:
                    runner.main()
        self.assertIs(raised.exception, primary)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        notes = "\n".join(primary.__notes__)
        self.assertIn("venv=failed", notes)
        self.assertIn("container=unconfirmed", notes)

    def test_cli_preserves_primary_exit_precedence_and_hides_exception_payloads(self):
        for primary, expected in (
            (ValueError(SECRET), 1),
            (subprocess.CalledProcessError(23, [SECRET], output=SECRET, stderr=SECRET), 1),
            (subprocess.CalledProcessError(-9, [SECRET]), 1),
            (subprocess.TimeoutExpired([SECRET], 720, output=SECRET, stderr=SECRET), 124),
            (KeyboardInterrupt(SECRET), 130),
            (SystemExit(0), 1),
        ):
            with self.subTest(primary=type(primary).__name__, expected=expected):
                with self.harness(
                    primary=primary,
                    venv_error=PermissionError(SECRET),
                    container_error=subprocess.TimeoutExpired([SECRET], 30),
                ) as run:
                    self.assertEqual(runner._cli(), expected)
                self.assertNotIn(PASS_LINE, run.stdout.getvalue())
                report = run.stderr.getvalue()
                self.assertNotIn(SECRET, report)
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
        with self.harness(container_error=subprocess.TimeoutExpired([SECRET], 30)) as run:
            self.assertEqual(runner._cli(), 1)
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("primary=passed", run.stderr.getvalue())
        self.assertIn("container=unconfirmed", run.stderr.getvalue())
        self.assertIn("timeout_seconds=30", run.stderr.getvalue())

    def test_interrupt_in_venv_cleanup_still_attempts_container_cleanup(self):
        interrupt = KeyboardInterrupt(SECRET)
        with self.harness(venv_error=interrupt) as run:
            with self.assertRaises(KeyboardInterrupt) as raised:
                runner.main()
        self.assertIs(raised.exception, interrupt)
        self.assertEqual(run.events[-2:], ["venv-cleanup", "container-cleanup"])
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())

    def test_cli_reports_uncertain_creation_without_secret_argv_or_name_cleanup(self):
        for failure_kind, expected in (("exit", 1), ("timeout", 124)):
            calls = []

            def failed_create(command, **_kwargs):
                calls.append(command)
                self.assertEqual(command[:2], ["docker", "run"])
                if failure_kind == "timeout":
                    raise subprocess.TimeoutExpired(command, 60, output=SECRET, stderr=SECRET)
                raise subprocess.CalledProcessError(125, command, output=SECRET, stderr=SECRET)

            stdout, stderr = io.StringIO(), io.StringIO()
            with (
                self.subTest(failure=failure_kind),
                patch.object(runner.subprocess, "run", side_effect=failed_create),
                patch.object(runner.uuid, "uuid4", return_value=SimpleNamespace(hex="e" * 32)),
                redirect_stdout(stdout), redirect_stderr(stderr),
            ):
                self.assertEqual(runner._cli(), expected)
            self.assertEqual(len(calls), 1)
            self.assertNotIn(PASS_LINE, stdout.getvalue())
            report = stderr.getvalue()
            self.assertIn("phase=container-create", report)
            self.assertIn("venv=not_created", report)
            self.assertIn("container=unbound", report)
            for private in (SECRET, "POSTGRES_PASSWORD", "local-" + "e" * 32, "postgresql://"):
                self.assertNotIn(private, report)

    def test_cli_does_not_echo_unvalidated_container_output(self):
        result = subprocess.CompletedProcess(["docker", "run"], 0, SECRET)
        stderr = io.StringIO()
        with (
            patch.object(runner.subprocess, "run", return_value=result) as called,
            patch.object(runner, "_remove_bound_container") as remove,
            redirect_stderr(stderr),
        ):
            self.assertEqual(runner._cli(), 1)
        self.assertEqual(called.call_count, 1)
        remove.assert_not_called()
        self.assertIn("container=unbound", stderr.getvalue())
        self.assertIn("container_id=unknown", stderr.getvalue())
        self.assertNotIn(SECRET, stderr.getvalue())

    def test_changed_binding_at_cleanup_is_unconfirmed_and_never_removed(self):
        remove = runner._remove_bound_container
        with self.harness() as run:
            with (
                patch.object(runner, "_remove_bound_container", new=remove),
                patch.object(runner, "_binding_matches", side_effect=[True, True, False]),
                patch.object(runner.subprocess, "run", wraps=runner.subprocess.run) as called,
            ):
                self.assertEqual(runner._cli(), 1)
        self.assertEqual(
            [call.args[0][:2] for call in called.call_args_list],
            [["docker", "run"], ["docker", "port"], ["docker", "port"]],
        )
        self.assertNotIn(PASS_LINE, run.stdout.getvalue())
        self.assertIn("primary=passed", run.stderr.getvalue())
        self.assertIn("container=unconfirmed", run.stderr.getvalue())
        self.assertIn("error=RuntimeError", run.stderr.getvalue())

    def test_changed_or_unobservable_identity_never_authorizes_removal(self):
        name, nonce = "adaptive-factory-exit-owner", "b" * 32
        valid = [CONTAINER_ID, f"/{name}", "postgres:17-alpine", "false", nonce]
        invalid = []
        for index, value in ((0, "c" * 64), (1, "/foreign"), (2, "postgres:18-alpine"), (3, "unknown"), (4, "d" * 32)):
            fields = list(valid)
            fields[index] = value
            invalid.append(subprocess.CompletedProcess([], 0, "\t".join(fields)))
        invalid.extend((
            subprocess.CompletedProcess([], 1, ""),
            subprocess.CompletedProcess([], 0, "malformed"),
            subprocess.TimeoutExpired(["docker", "inspect", CONTAINER_ID], 10),
            OSError(SECRET),
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
