"""Owned resource-bound fixtures only; no native allocation/network/build."""

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import public_security_context
from getzilla import security_image_authority as image_authority
from getzilla import security_image_backend as backend, security_image_job as job, security_oci as oci
from getzilla import security_cli as cli, security_tools as tools, security_image_registry as registry
from getzilla import security_image_producer as producer

GIB = 1024**3


@unittest.skipUnless(sys.platform == "linux", "Linux resource admission contract")
class CapacityControls(unittest.TestCase):
    def setUp(self):
        self.effects = ExitStack()
        self.addCleanup(self.effects.close)
        for name in ("socket.socket", "socket.getaddrinfo", "subprocess.Popen"):
            self.effects.enter_context(mock.patch(name, side_effect=AssertionError("outside fixture effect denied")))

    @contextmanager
    def physical_model(self):
        """Real held fixture FDs; all kernel observations are explicitly mocked."""
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory, ExitStack() as stack:
            volume = Path(directory)
            group = volume / "group"
            group.mkdir()
            for name, value in {
                "memory.max": str(12 * GIB),
                "memory.swap.max": "0",
                "pids.max": "256",
                "cpu.max": "200000 100000",
                "cgroup.procs": str(os.getpid()),
            }.items():
                (group / name).write_text(value)
            vfd = os.open(volume, os.O_RDONLY | os.O_DIRECTORY)
            cfd = os.open(group, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, vfd)
            stack.callback(os.close, cfd)
            controls = backend._open_ci_controls(cfd)
            stack.callback(backend._close_ci_controls, controls)
            vi, gi = os.fstat(vfd), os.fstat(cfd)
            guard = (
                volume,
                object(),
                [],
                dict(
                    ci_corpus=True,
                    volume_fd=vfd,
                    cgroup_fd=cfd,
                    volume_identity=(vi.st_dev, vi.st_ino),
                    cgroup_root_device=gi.st_dev,
                    cgroup_root_inode=gi.st_ino,
                    controls=controls,
                ),
            )
            stack.enter_context(mock.patch.object(image_authority, "_GUARD", guard))
            real_stat = os.stat
            stack.enter_context(
                mock.patch.object(
                    os,
                    "stat",
                    side_effect=lambda path, **kw: gi if str(path) == "/sys/fs/cgroup" else real_stat(path, **kw),
                )
            )
            stack.enter_context(
                mock.patch.object(image_authority, "_filesystem",
                    side_effect=lambda path: 0x63677270 if str(path) == "/sys/fs/cgroup" else 0x01021994,
                )
            )
            capacity = SimpleNamespace(f_blocks=8 * GIB // 4096, f_frsize=4096, f_flag=os.ST_NOSUID | os.ST_NODEV)
            stack.enter_context(mock.patch.object(os, "fstatvfs", return_value=capacity))
            stack.enter_context(mock.patch.object(os, "sched_getaffinity", return_value={24, 25}))
            yield volume, group, capacity

    def test_forged_large_json_and_environment_cannot_raise_default(self):
        profile = dict(oci.LIMITS, images=["owned@sha256:" + "1" * 64], platform="linux/amd64")
        profile.update(max_storage_bytes=8 * GIB, max_compressed_bytes=8 * GIB, max_unpacked_bytes=8 * GIB)
        with (
            mock.patch.dict(os.environ, GETZILLA_CI_IMAGE_BYTES=str(8 * GIB)),
            mock.patch.object(image_authority, "_GUARD", None),
        ):
            with self.assertRaises(oci.OCIError):
                oci._profile(profile)
            self.assertTrue(callable(getattr(oci, "active_limits", None)), "need one live-bound profile derivation")
            self.assertEqual(oci.active_limits()["max_storage_bytes"], GIB // 2)

    def test_memory_admission_observes_ancestor_remaining_and_reserve(self):
        self.assertTrue(callable(getattr(job, "_memory_admission", None)), "need pre-effect physical memory admission")
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory:
            mount = Path(directory)
            parent = mount / "system.slice"
            parent.mkdir()
            (parent / "memory.max").write_text(str(16 * GIB))
            (parent / "memory.current").write_text(str(2 * GIB))
            mountinfo = f"1 0 0:1 / {mount} rw - cgroup2 cgroup rw\n"
            real_read = job._memory_read

            def read(path, limit):
                if path == Path("/proc/meminfo"):
                    return memory[0]
                if path == Path("/proc/self/cgroup"):
                    return "0::/caller\n"
                if path == Path("/proc/self/mountinfo"):
                    return mountinfo
                raise AssertionError("outside fixture metadata read denied")

            memory = ["MemTotal: 999999999 kB\nMemAvailable: 14680064 kB\n"]
            with (
                mock.patch.object(job, "_memory_read", read),
                mock.patch.object(image_authority, "_filesystem", return_value=0x63677270),
            ):
                admitted = job._memory_admission(parent)
                self.assertEqual(admitted["remaining_bytes"], 14 * GIB)
                self.assertEqual(admitted["reserve_bytes"], 2 * GIB)
                (mount / "memory.max").write_text(str(13 * GIB))
                (mount / "memory.current").write_text("0")
                with self.assertRaises(backend.BackendUnavailable):
                    job._memory_admission(parent)
                (mount / "memory.max").unlink()
                (mount / "memory.current").unlink()
                memory[0] = "MemAvailable: 14680063 kB\n"
                with self.assertRaises(backend.BackendUnavailable):
                    job._memory_admission(parent)
                memory[0] = "MemAvailable: unknown kB\n"
                with self.assertRaises(backend.BackendUnavailable):
                    job._memory_admission(parent)
                memory[0] = "MemAvailable: 14680064 kB\n"
                child = parent / "ci.slice"
                child.mkdir()
                (child / "memory.max").write_text("max")
                (child / "memory.current").write_text("0")
                self.assertEqual(job._memory_admission(child)["remaining_bytes"], 14 * GIB)
                (parent / "memory.current").write_text(str(2 * GIB + 1))
                with self.assertRaises(backend.BackendUnavailable):
                    job._memory_admission(child)
                (parent / "memory.max").unlink()
                with self.assertRaises(backend.BackendUnavailable):
                    job._memory_admission(parent)
            self.assertTrue(callable(real_read))

    def test_large_profile_needs_held_physical_proof_not_guard_dictionary(self):
        self.assertTrue(callable(getattr(oci, "active_limits", None)), "need measured active limits")
        with mock.patch.object(image_authority, "_GUARD", (Path("/not-a-volume"), object(), [], {"ci_corpus": True})):
            with self.assertRaises(backend.BackendUnavailable):
                oci.active_limits()

    def test_measured_model_preserves_bounds_and_refuses_changed_kernel_or_lifetime(self):
        with self.physical_model() as (_volume, group, capacity):
            large = dict(oci.active_limits(), images=["owned@sha256:" + "1" * 64], platform="linux/amd64")
            self.assertEqual(large["max_storage_bytes"], 8 * GIB)
            self.assertEqual(large["max_layers"], 10000)
            budget = oci._Budget(large)
            budget.charge("storage", 8 * GIB)
            with self.assertRaises(oci.OCIError):
                budget.charge("storage", 1)
            capacity.f_blocks -= 1
            with self.assertRaises(backend.BackendUnavailable):
                oci._profile(large)
            capacity.f_blocks += 1
            with mock.patch.dict(image_authority._GUARD[3], volume_fd=-1):
                with self.assertRaises(backend.BackendUnavailable):
                    oci._profile(large)
            (group / "memory.max").write_text(str(2 * GIB))
            with self.assertRaises(backend.BackendUnavailable):
                oci._profile(large)
            (group / "memory.max").write_text(str(12 * GIB))
            with mock.patch.object(image_authority, "_GUARD", None):
                with self.assertRaises(oci.OCIError):
                    budget.tick()

    def test_same_live_profile_for_declaration_preparation_and_evaluation_rejects_replay(self):
        now = datetime.now(timezone.utc)
        inventory = dict(
            complete=True,
            gaps=[],
            digest="1" * 64,
            dependencies=[],
            tools=[],
            images=[dict(reference="owned@sha256:" + "2" * 64, platform="linux/amd64")],
        )
        with (
            self.physical_model() as (volume, _group, _capacity),
            mock.patch.object(public_security_context, "validate_selection_authority"),
            mock.patch.object(public_security_context, "current_context", return_value=None),
        ):
            roots = {name: str(volume / name) for name in ("database", "artifacts", "tools")}
            args = ({}, inventory, roots, {}, "3" * 64)
            declared = cli.input_profile(*args, now=now)
            self.assertEqual(declared["image_profile"]["max_storage_bytes"], 8 * GIB)
            for _stage in ("prepare", "evaluate"):
                self.assertEqual(cli.validate_input_profile(declared, *args, now=now), declared)
                self.assertEqual(
                    tools.image_acquisition_profile(inventory, declared["image_profile"]), declared["image_profile"]
                )
            collector = registry.Registry(
                transport=SimpleNamespace(get=mock.Mock(side_effect=AssertionError("network denied")))
            )
            self.assertEqual(collector.limits["max_storage_bytes"], 8 * GIB)
            with mock.patch.object(image_authority, "_GUARD", None):
                with self.assertRaises(cli.SecurityDataError):
                    cli.validate_input_profile(declared, *args, now=now)
                with self.assertRaises(tools.SecurityDataError):
                    tools.image_acquisition_profile(inventory, declared["image_profile"])
                with self.assertRaises(registry.RegistryError):
                    collector._get("library/owned", "manifests", "tag", 100)

    def test_ci_memory_refusal_precedes_process_and_admitted_command_is_finite(self):
        with tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as directory, ExitStack() as stack:
            stack.enter_context(mock.patch.object(os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.dict(os.environ, SUDO_UID=str(os.getuid()), SUDO_GID=str(os.getgid())))
            stack.enter_context(mock.patch.object(Path, "read_text", return_value="cpu memory pids"))
            stack.enter_context(mock.patch.object(Path, "exists", return_value=False))
            stack.enter_context(mock.patch.object(backend, "_retain_fault"))
            stack.enter_context(mock.patch.object(job, "_retain_fault"))
            stack.enter_context(
                mock.patch("getzilla.startup_cpu.cgroup_bounds", return_value={"effective_cpuset": "24-25"})
            )
            stack.enter_context(
                mock.patch(
                    "getzilla.startup_cpu.measure", return_value={"chosen_capacity": 2, "verified_cpus": "24-25"}
                )
            )
            stack.enter_context(mock.patch.object(os, "sched_getaffinity", return_value={24, 25}))
            stack.enter_context(mock.patch.object(os, "fchown"))
            stack.enter_context(mock.patch.object(job, "_reap_children"))
            native = stack.enter_context(mock.patch.object(job.ctypes, "CDLL"))
            native.return_value.prctl.return_value = 0
            port = stack.enter_context(
                mock.patch("getzilla.architecture_diff._run_capped", return_value=(0, b'{"result":{}}', b""))
            )
            memory = stack.enter_context(
                mock.patch.object(job, "_memory_admission", side_effect=backend.BackendUnavailable("owned unknown"))
            )
            with self.assertRaises(backend.BackendUnavailable):
                job.run_job(b'{"kind":"pipeline"}', Path(directory), slice_name="system.slice", ci_corpus=True)
            port.assert_not_called()
            memory.side_effect = None
            memory.return_value = {"remaining_bytes": 14 * GIB, "reserve_bytes": 2 * GIB}
            job.run_job(b'{"kind":"pipeline"}', Path(directory), slice_name="system.slice", ci_corpus=True)
            command = port.call_args.args[0]
            self.assertIn("--property=MemoryMax=" + str(12 * GIB), command)
            self.assertIn("--property=TasksMax=256", command)
            self.assertIn("--property=MemorySwapMax=0", command)
            self.assertIn("--property=CPUQuota=200%", command)
            self.assertEqual(command[-1], "ci-corpus")
            self.assertEqual(memory.call_count, 3)

    def test_large_import_stages_inside_held_volume_despite_external_workspace(self):
        reference = "owned@sha256:" + "5" * 64
        inventory = dict(
            complete=True, gaps=[], digest="4" * 64, images=[dict(reference=reference, platform="linux/amd64")]
        )
        catalog = dict(
            schema_version=1,
            inventory_sha256=inventory["digest"],
            records=[dict(reference=reference, platform="linux/amd64", layout="/never-read-model")],
        )
        with (
            self.physical_model() as (volume, _group, _capacity),
            tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as outside,
        ):
            stages = []

            def imported(record, profile, stage, budget):
                stages.append(stage)
                return SimpleNamespace(reference=record["reference"], config_digest="6" * 64, _proof=object())

            profile = dict(oci.active_limits(), images=[reference], platform="linux/amd64")
            with (
                mock.patch.object(oci, "_import_one", side_effect=imported),
                oci.import_layouts(catalog, inventory, profile, Path(outside)),
            ):
                self.assertEqual(len(stages), 1)
                self.assertTrue(stages[0].is_relative_to(volume), "large OCI bytes cannot spill to caller workspace")

    def test_ci_tools_use_same_owned_volume_and_leave_requested_path_untouched(self):
        self.assertTrue(callable(getattr(producer, "_pipeline_tools", None)), "need contained effective tools root")
        requested = Path("/never-created-requested-tools")
        with self.physical_model() as (volume, _group, _capacity):
            self.assertEqual(producer._pipeline_tools({"tools": str(requested)}, volume), volume / "tools")
            with self.assertRaises(backend.BackendUnavailable):
                producer._pipeline_tools({"tools": str(requested)}, volume / "foreign")
            with mock.patch.object(image_authority, "_GUARD", None):
                self.assertEqual(producer._pipeline_tools({"tools": str(requested)}, volume), requested)

    def test_ci_image_writer_refuses_external_root_and_parent_link_without_spill(self):
        with (
            self.physical_model() as (volume, _group, _capacity),
            tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime") as outside,
        ):
            external = Path(outside)
            producer._write(volume, "owned/data", b"owned image bytes")
            self.assertEqual((volume / "owned/data").read_bytes(), b"owned image bytes")
            with self.assertRaises(backend.BackendUnavailable):
                producer._write(external, "no-write", b"outside forbidden")
            self.assertFalse((external / "no-write").exists())
            (volume / "linked").symlink_to(external, target_is_directory=True)
            with self.assertRaises(OSError):
                producer._write(volume, "linked/escaped", b"outside forbidden")
            self.assertFalse((external / "escaped").exists())
