"""Owned data/ordinary-file controls; native/kernel/process/network effects denied."""

from contextlib import ExitStack
import hashlib
import os
import shutil
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_image_authority as image_authority
from getzilla import security_image_backend as backend, security_image_producer as producer
from getzilla.security_build_inputs import _instructions


class BuildLifetimeControls(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for port in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen", "subprocess.run"):
            effects.enter_context(mock.patch(port, side_effect=AssertionError("outside effects denied")))

    def builder(self, guard):
        value = object.__new__(backend.BuildKit)
        value.guard, value.client, value.address = guard, Path("/owned/buildctl"), "unix:///owned/socket"
        value.deadline, value._in_build = time.monotonic() + 3, False
        value.env = {"PATH": os.defpath}
        return value

    def test_fixed_prune_uses_only_live_idle_owned_daemon_and_remaining_deadline(self):
        self.assertTrue(callable(getattr(backend.BuildKit, "prune", None)))
        guard = object()
        builder = self.builder(guard)
        with (
            mock.patch.object(image_authority, "_GUARD", guard),
            mock.patch.object(backend.BuildKit, "_daemon_alive", return_value=True),
            mock.patch.object(backend.BuildKit, "_volume_usage", return_value={}),
            mock.patch("getzilla.architecture_diff._run_capped", return_value=(0, b"", b"")) as port,
        ):
            builder.prune()
            arguments, options = port.call_args
            self.assertEqual(arguments[0], [builder.client, "--addr", builder.address, "prune", "--all"])
            self.assertGreater(options["timeout"], 0)
            self.assertLessEqual(options["timeout"], 3)
            for change in ("busy", "expired", "foreign"):
                with self.subTest(change=change):
                    builder._in_build = change == "busy"
                    builder.deadline = time.monotonic() - 1 if change == "expired" else time.monotonic() + 3
                    with mock.patch.object(image_authority, "_GUARD", object() if change == "foreign" else guard):
                        before = port.call_count
                        with self.assertRaises(backend.BackendUnavailable):
                            builder.prune()
                        self.assertEqual(port.call_count, before)
            builder._in_build, builder.deadline = False, time.monotonic() + 3
            with mock.patch.object(backend.BuildKit, "_daemon_alive", return_value=False):
                before = port.call_count
                with self.assertRaises(backend.BackendUnavailable):
                    builder.prune()
                self.assertEqual(port.call_count, before)
            port.return_value = (1, b"", b"owned prune refusal")
            with self.assertRaises(backend.BackendUnavailable):
                builder.prune()
            self.assertEqual(port.call_count, 2, "failure must not retry")

    def test_build_fault_keeps_actual_ci_counters_in_existing_artifact(self):
        guard = object()
        builder = self.builder(guard)
        before = dict(capacity_bytes=8589934592, used_bytes=8000000000, free_bytes=589934592)
        failed = dict(capacity_bytes=8589934592, used_bytes=8589934592, free_bytes=0)
        builder.last_prune_usage = dict(before)
        recipe = dict(dockerfile="/owned/Dockerfile", context="/owned", platform="linux/amd64", arguments={})
        with (
            mock.patch.object(image_authority, "_GUARD", guard),
            mock.patch.object(backend.BuildKit, "_daemon_alive", return_value=True),
            mock.patch.object(backend.BuildKit, "_volume_usage", side_effect=[before, failed]),
            mock.patch("getzilla.architecture_diff._run_capped", return_value=(1, b"", b"owned ENOSPC")),
            self.assertRaises(backend.BackendUnavailable) as caught,
        ):
            builder.build(recipe, Path("/owned"), Path("/owned/export"))
        self.assertFalse(builder._in_build)
        self.assertEqual(caught.exception.detail["volume_before_build"], before)
        self.assertEqual(caught.exception.detail["volume_at_failure"], failed)
        self.assertEqual(caught.exception.detail["volume_after_previous_prune"], before)
        with mock.patch.object(producer.os, "write") as write:
            producer._fault(caught.exception)
        import json

        self.assertEqual(json.loads(write.call_args.args[1])["fault"]["volume_at_failure"], failed)

    def test_volume_counters_use_only_fresh_held_ci_descriptor(self):
        self.assertTrue(callable(getattr(backend.BuildKit, "_volume_usage", None)))
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as raw:
            fd = os.open(raw, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            self.addCleanup(os.close, fd)
            identity = os.fstat(fd)
            proof = dict(ci_corpus=True, volume_fd=fd, volume_identity=(identity.st_dev, identity.st_ino))
            guard = (Path(raw), object(), [], proof)
            builder = self.builder(guard)
            info = SimpleNamespace(f_blocks=2097152, f_frsize=4096, f_bfree=3, f_bavail=2)
            with (
                mock.patch.object(image_authority, "_GUARD", guard),
                mock.patch.object(image_authority, "measured_ci_profile", return_value=True),
                mock.patch.object(os, "fstatvfs", return_value=info) as port,
            ):
                self.assertEqual(
                    builder._volume_usage(), dict(capacity_bytes=8589934592, used_bytes=8589922304, free_bytes=8192)
                )
                port.assert_called_once_with(fd)
                proof["volume_identity"] = (identity.st_dev, identity.st_ino + 1)
                with self.assertRaises(backend.BackendUnavailable):
                    builder._volume_usage()
                self.assertEqual(port.call_count, 1)
                proof["volume_identity"] = (identity.st_dev, identity.st_ino)
                with mock.patch.object(image_authority, "measured_ci_profile", return_value=False):
                    with self.assertRaises(backend.BackendUnavailable):
                        builder._volume_usage()
                self.assertEqual(port.call_count, 1)

    def test_completed_export_is_retained_before_prune_and_context_is_retired(self):
        self.assertTrue(callable(getattr(producer, "_build_recipe", None)))
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as raw:
            root = Path(raw)
            volume = root / "volume"
            volume.mkdir()
            layout = volume / "oci"
            layout.mkdir()
            (root / "src").mkdir()
            payload = b"owned context bytes"
            (root / "src/input").write_bytes(payload)
            recipe = dict(
                context="src",
                context_files=[
                    dict(path="src/input", bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(), mode=0o644)
                ],
            )
            events = []
            builder = SimpleNamespace()

            def build(selected, context, archive):
                self.assertEqual((context / "input").read_bytes(), payload)
                events.append(("build", context))
                archive.write_bytes(b"owned export model")
                return backend._ACTIVE

            def copied(archive, destination):
                self.assertEqual(archive.read_bytes(), b"owned export model")
                (destination / "retained").write_bytes(b"owned copied graph model")
                events.append(("copied", archive))
                return {"digest": "owned-descriptor"}

            def prune():
                self.assertTrue((layout / "retained").is_file())
                self.assertTrue(events[0][1].is_dir())
                self.assertTrue(events[1][1].is_file())
                events.append(("prune", None))

            builder.build, builder.prune = build, mock.Mock(side_effect=prune)
            with mock.patch.object(producer, "_unpack_export", side_effect=copied):
                self.assertEqual(
                    producer._build_recipe(root, recipe, volume, layout, builder), {"digest": "owned-descriptor"}
                )
            self.assertEqual([x[0] for x in events], ["build", "copied", "prune"])
            self.assertEqual(len(list(volume.glob('context-*'))), 1)
            for bad_export in (True, False):
                with self.subTest(bad_export=bad_export):
                    builder.prune.reset_mock()
                    builder.build = build if bad_export else mock.Mock(return_value=object())
                    with mock.patch.object(
                        producer, "_unpack_export", side_effect=backend.BackendUnavailable("owned hash failure")
                    ):
                        with self.assertRaises(backend.BackendUnavailable):
                            producer._build_recipe(root, recipe, volume, layout, builder)
                    builder.prune.assert_not_called()
                    self.assertTrue(events[0][1].is_dir())

    def test_context_name_replacement_refuses_foreign_cleanup(self):
        self.assertTrue(callable(getattr(producer, "_build_recipe", None)))
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as raw:
            volume = Path(raw)
            layout = volume / "oci"
            layout.mkdir()

            def replace(_recipe, context, _archive):
                scope = context.parent
                scope.rename(volume / "retired-owned")
                scope.mkdir()
                (scope / "foreign-marker").write_bytes(b"preserve")
                raise backend.BackendUnavailable("owned replacement model")

            builder = SimpleNamespace(build=replace, prune=mock.Mock())
            with mock.patch.object(producer, "_copy_context", side_effect=lambda _r, _s, path: path.mkdir()):
                with self.assertRaises(backend.BackendUnavailable):
                    producer._build_recipe(volume, {}, volume, layout, builder)
            self.assertEqual(len(list(volume.glob("*/foreign-marker"))), 1)
            builder.prune.assert_not_called()

    def test_late_cleanup_boundary_cannot_delete_a_replacement_recipe_root(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as raw:
            volume = Path(raw)
            layout = volume / 'oci'
            layout.mkdir()
            foreign = volume / 'foreign-canary'
            foreign.mkdir()
            marker = foreign / 'marker'
            marker.write_bytes(b'foreign inert canary')
            identity = foreign.stat()
            contexts = []
            def build(_recipe, context, archive):
                contexts.append(context)
                archive.write_bytes(b'owned model export')
                return backend._ACTIVE
            recursive = shutil.rmtree
            def swap_at_recursive_call(name, **kwargs):
                scope = volume / name
                scope.rename(volume / 'original-held-root')
                foreign.rename(scope)
                return recursive(name, **kwargs)
            builder = SimpleNamespace(build=build, prune=mock.Mock())
            with mock.patch.object(producer, '_copy_context', side_effect=lambda _r, _s, path: path.mkdir()), \
                    mock.patch.object(producer, '_unpack_export', return_value={'digest': 'owned'}), \
                    mock.patch.object(shutil, 'rmtree', side_effect=swap_at_recursive_call) as deletion, \
                    mock.patch.object(Path, 'unlink', side_effect=AssertionError('early path deletion denied')):
                self.assertEqual(producer._build_recipe(volume, {}, volume, layout, builder), {'digest': 'owned'})
                deletion.assert_not_called()
            self.assertEqual(marker.read_bytes(), b'foreign inert canary')
            self.assertEqual((foreign.stat().st_dev, foreign.stat().st_ino), (identity.st_dev, identity.st_ino))
            self.assertTrue(contexts[0].is_dir(), 'original context stays until whole-job teardown')
            self.assertEqual((contexts[0].parent / 'export.tar').read_bytes(), b'owned model export')
            builder.prune.assert_called_once_with()

    def test_all_four_recipes_pin_wheel_backend_before_local_project_build(self):
        profiles = {'Dockerfile.api': 'runtime', 'Dockerfile.worker': 'runtime',
                    'Dockerfile.test': 'test', 'runner.Dockerfile': 'runner'}
        directory = ROOT / 'trust-ci'
        for recipe, profile in profiles.items():
            with self.subTest(recipe=recipe):
                text = (directory / recipe).read_text()
                install = f'--only-binary=:all: --require-hashes --no-deps -r requirements-{profile}.txt'
                self.assertLess(text.index('python lock_profiles.py --check'), text.index(install))
                self.assertLess(text.index(install), text.index('--no-deps --no-build-isolation .'))
                self.assertNotIn('coverage==7.15.4', text)
                lock = (directory / f'requirements-{profile}.txt').read_text()
                self.assertRegex(lock, r'(?m)^setuptools==84\.1\.0 [^\n]*\n(?:    --hash=[^\n]*\n)*?'
                                       r'    --hash=sha256:5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9')
        runner = (directory / 'requirements-runner.txt').read_text()
        for pin in ('coverage==7.15.4', 'pytest==9.1.1', 'pytest-xdist==3.8.0',
                    'pytest-cov==7.1.0', 'ruff==0.16.3', 'bandit==1.9.4', 'tomli==2.5.0'):
            self.assertIn(pin, runner)

    def test_runner_installs_after_exact_inputs_and_preserves_final_runtime(self):
        statements = [value for _, value in _instructions((ROOT / "trust-ci/runner.Dockerfile").read_text())]
        copy = [value for value in statements if value.startswith("COPY ")]
        self.assertEqual(copy, ["COPY pyproject.toml README.md uv.lock lock_profiles.py lock_profile_validation.py lock-profiles.json requirements-*.txt ./", "COPY src ./src"])
        run = [value for value in statements if value.startswith("RUN ")]
        self.assertEqual(len(run), 1, "avoid native full-rootfs copies between heavy install steps")
        self.assertLess(statements.index(copy[1]), statements.index(run[0]))
        self.assertLess(statements.index("WORKDIR /opt/adaptive-trust-ci"), statements.index(copy[0]))
        self.assertLess(run[0].index("apt-get update"), run[0].index("pip install --no-cache-dir --only-binary=:all: --require-hashes"))
        self.assertLess(
            run[0].index("pip install --no-cache-dir --only-binary=:all: --require-hashes"), run[0].index("urllib.request.urlretrieve")
        )
        self.assertIn("sha256sum -c -", run[0])
        self.assertIn("opengrep --version", run[0])
        self.assertEqual(statements[-3:], ["USER 10001:10001", "WORKDIR /workspace", 'CMD ["python3", "--version"]'])
