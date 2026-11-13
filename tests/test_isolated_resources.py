"""Exercise ownership and cleanup decisions against a stateful Docker boundary double."""
from __future__ import annotations
import importlib
import importlib.util
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))
from getzilla.python_test_runner import ProcessResult
PIN = "postgres@sha256:" + "1" * 64
IMAGE_ID = "sha256:" + "2" * 64
ROOT = Path(__file__).resolve().parents[1]


def setUpModule():
    global child_guard
    child_guard = patch.object(subprocess, "Popen", side_effect=AssertionError("unmocked child forbidden in ownership controls"))
    child_guard.start()


def tearDownModule():
    child_guard.stop()


@unittest.skipUnless(sys.platform == "linux", "Linux UID/procfs/private-FD ownership contract")
class ResourceHardeningTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module("getzilla.disposable_resources")
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        identity = {"pid": os.getpid(), "start": "unit-start", "boot": "unit-boot"}
        process = patch.object(self.module, "_process_identity", return_value=identity)
        process.start()
        self.addCleanup(process.stop)
        original = Path.read_text
        boot = patch.object(Path, "read_text", lambda path,*a,**k: "unit-boot" if str(path)=="/proc/sys/kernel/random/boot_id" else original(path,*a,**k))
        boot.start()
        self.addCleanup(boot.stop)

    def test_config_size_and_link_are_refused(self):
        path = self.root / ".getzilla/config/ci-images.json"
        path.parent.mkdir(parents=True)
        raw = (ROOT / ".getzilla/config/ci-images.json").read_bytes()
        path.write_bytes(raw)
        self.assertEqual(self.module.image_pins(self.root)["platform"], "linux/amd64")
        path.write_bytes(raw + b" " * (1048577-len(raw)))
        with self.assertRaises(ValueError):
            self.module.image_pins(self.root)
        path.unlink()
        target=self.root/"pins.json"
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises((OSError,ValueError)):
            self.module.image_pins(self.root)

    def test_held_directory_cleanup_refuses_linked_payload(self):
        owner = self.module.OwnedDocker(self.root / 'owner.json', 'gz-unit')
        directory = owner.directory('data')
        target = self.root / 'unowned'
        target.write_text('retained')
        (directory / 'payload').symlink_to(target)
        with self.assertRaises(self.module.CleanupUnconfirmed):
            owner.cleanup()
        self.assertEqual(target.read_text(), 'retained')
        self.assertTrue(directory.is_dir())
        (directory / 'payload').unlink()
        (directory / 'payload').write_text('owned')
        owner.cleanup()
        self.assertFalse(directory.exists())

    def test_serialized_journal_bound_preserves_previous_bytes(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-unit")
        before = owner.manifest.read_bytes()
        owner.resources = [{"kind":"volume","name":"gz-unit-v","status":"bound","identity":{
            "Name":"gz-unit-v","Labels":owner.labels,"Driver":"local","Options":{"note":"x"*1048576},
            "CreatedAt":"owned","Mountpoint":"/owned"}}]
        with self.assertRaises(ValueError):
            owner._save()
        self.assertEqual(owner.manifest.read_bytes(),before)

    def test_recovery_rejects_incomplete_resource_before_any_command(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-unit")
        value=json.loads(owner.manifest.read_text())
        value["resources"]=[{"kind":"container","name":"gz-unit-c","status":"bound"}]
        owner.manifest.write_text(json.dumps(value))
        with patch.object(self.module,"_process_identity",return_value={**owner.owner_process,"start":"changed"}), \
                patch.object(self.module,"_docker",side_effect=AssertionError("unexpected command")) as command:
            with self.assertRaises(ValueError):
                self.module.OwnedDocker.recover(owner.manifest)
        command.assert_not_called()

    def test_native_result_uncertainty_is_not_command_success(self):
        from getzilla.python_test_runner import ProcessResult
        for state,error in (("timeout",""),("cancelled",""),("completed","unknown cleanup")):
            with self.subTest(state=state), patch.object(self.module,"_execute",return_value=ProcessResult(["docker"],0,terminal_state=state,cleanup_error=error)):
                with self.assertRaises(self.module.CleanupUnconfirmed):
                    self.module._docker("volume","ls")

    def test_readonly_mount_change_cannot_authorize_removal(self):
        owner=self.module.OwnedDocker(self.root/"owner.json","gz-unit")
        docker=DockerDouble()
        with patch.object(self.module,"_execute",side_effect=docker):
            item=owner.container("c",PIN,bind={self.root:"/owned"})
            docker.items["container"][item["id"]]["Mounts"][0]["RW"]=True
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertEqual(docker.removed,[])

    def test_returned_container_id_must_equal_inspected_id(self):
        owner=self.module.OwnedDocker(self.root/"owner.json","gz-unit")
        docker=DockerDouble()
        def changed(command,*_args,**kwargs):
            result=docker(command,**kwargs)
            if command[1:3]==["container","inspect"]:
                value=json.loads(result.stdout)
                value[0]["Id"]="f"*64
                return ProcessResult(command,0,json.dumps(value),"")
            return result
        with patch.object(self.module,"_execute",side_effect=changed):
            with self.assertRaises(ValueError):
                owner.container("c",PIN)


@unittest.skipUnless(sys.platform == "linux", "Linux UID/procfs/private-FD ownership contract")
class ResourceRepairTests(unittest.TestCase):
    def setUp(self):
        self.native_identity = importlib.import_module("getzilla.disposable_resources")._process_identity
        ResourceHardeningTests.setUp(self)

    def test_directory_deadline_precedes_destructive_steps(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-repair")
        path = owner.directory("data")
        (path / "payload").write_text("retained")
        with self.assertRaises(self.module.CleanupUnconfirmed):
            owner.cleanup(deadline=time.monotonic() - 1)
        self.assertEqual((path / "payload").read_text(), "retained")
        self.assertEqual(owner.resources[0]["status"], "unconfirmed")
        owner.cleanup()
        self.assertFalse(path.exists())

    def test_pending_network_and_container_bind_full_identity_without_reallocation(self):
        for kind in ("network", "container"):
            with self.subTest(kind=kind):
                owner = self.module.OwnedDocker(self.root / (kind + ".json"), "gz-repair")
                docker = DockerDouble()
                interrupted = [False]
                def boundary(command, *args, **kwargs):
                    if command[1:3] == [kind, "inspect"] and not interrupted[0]:
                        interrupted[0] = True
                        return ProcessResult(command, 0, terminal_state="timeout")
                    return docker(command, *args, **kwargs)
                with patch.object(self.module, "_execute", side_effect=boundary):
                    with self.assertRaises(self.module.CleanupUnconfirmed):
                        owner.network("net") if kind == "network" else owner.container("app", PIN)
                    self.assertEqual(owner.resources[0]["status"], "pending")
                    try:
                        owner.cleanup()
                    except self.module.CleanupUnconfirmed:
                        self.fail("complete owned pending identity must recover")
                self.assertEqual(docker.items[kind], {})
                self.assertEqual(owner.resources[0]["status"], "removed")
                self.assertRegex(docker.removed[0][1], r"^[0-9a-f]{64}$")
                self.assertEqual(sum(c[1] == "run" or c[1:3] == ["network", "create"] for c in docker.commands), 1)

    def test_volume_required_values_refuse_partial_live_and_recovered_identity(self):
        for field in ("CreatedAt", "Mountpoint"):
            for bad in (None, ""):
                with self.subTest(field=field, value=bad):
                    stem = field + ("null" if bad is None else "empty")
                    owner = self.module.OwnedDocker(self.root / (stem + ".json"), "gz-repair")
                    docker = DockerDouble()
                    def partial(command, *args, **kwargs):
                        result = docker(command, *args, **kwargs)
                        if command[1:3] == ["volume", "inspect"]:
                            value = json.loads(result.stdout)
                            value[0][field] = bad
                            return ProcessResult(command, 0, json.dumps(value))
                        return result
                    with patch.object(self.module, "_execute", side_effect=partial):
                        with self.assertRaises(ValueError):
                            owner.volume("disk")
                    self.assertEqual(docker.removed, [])
        owner = self.module.OwnedDocker(self.root / "complete.json", "gz-repair")
        docker = DockerDouble()
        with patch.object(self.module, "_execute", side_effect=docker):
            owner.volume("disk")
            complete = json.loads(owner.manifest.read_text())
            for field in ("CreatedAt", "Mountpoint"):
                malformed = copy.deepcopy(complete)
                malformed["resources"][0]["identity"][field] = None
                owner.manifest.write_text(json.dumps(malformed))
                with patch.object(self.module, "_process_identity", return_value={**owner.owner_process, "start": "changed"}):
                    with self.assertRaises(ValueError):
                        self.module.OwnedDocker.recover(owner.manifest)
            owner.manifest.write_text(json.dumps(complete))
            owner._journal_identity = self.module._read(owner.manifest).identity
            owner.cleanup()
        self.assertEqual(docker.items["volume"], {})

    def test_recovery_requires_namespace_before_exact_target_absence(self):
        with patch.object(self.module, "_process_identity", return_value={"pid": 424242, "start": "unit-start", "boot": "unit-boot"}):
            owner = self.module.OwnedDocker(self.root / "owner.json", "gz-repair")
        native_read = Path.read_text
        mode = ["self"]
        def proc(path, *args, **kwargs):
            value = str(path)
            if value == "/proc/sys/kernel/random/boot_id":
                if mode[0] == "boot":
                    raise FileNotFoundError("owned boot unavailable")
                return "unit-boot"
            if value == "/proc/self/stat":
                if mode[0] == "self":
                    raise FileNotFoundError("owned self unavailable")
                return f"{os.getpid()} (owned) " + " ".join(["R", *(["0"] * 18), "unit-start"])
            if value == "/proc/424242/stat":
                raise FileNotFoundError("owned target absent")
            if value.startswith("/proc/"):
                raise AssertionError("unadmitted procfs observation")
            return native_read(path, *args, **kwargs)
        with patch.object(Path, "read_text", proc), patch.object(self.module, "_process_identity", self.native_identity):
            for missing in ("self", "boot"):
                with self.subTest(missing=missing):
                    mode[0] = missing
                    try:
                        outcome = self.module.OwnedDocker.recover(owner.manifest)
                    except (OSError, self.module.CleanupUnconfirmed) as error:
                        outcome = type(error)
                    self.assertIs(outcome, self.module.CleanupUnconfirmed)
            mode[0] = "target"
            self.assertEqual(self.module.OwnedDocker.recover(owner.manifest).nonce, owner.nonce)

    def test_initial_marker_cannot_be_replaced_by_later_baseline(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-repair")
        path = owner.directory("data")
        (path / "payload").write_text("retained")
        read = self.module.fsx.ReadOnlyBoundRoot.read
        calls = []
        def changed(root, relative, **kwargs):
            if root.path == path and relative == ".owner":
                calls.append(relative)
                if len(calls) == 2:
                    (path / ".owner").write_text("f" * 32)
            return read(root, relative, **kwargs)
        with patch.object(self.module.fsx.ReadOnlyBoundRoot, "read", changed):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertTrue((path / "payload").is_file())
        self.assertEqual((path / "payload").read_text(), "retained")
        (path / ".owner").write_text(owner.nonce)
        owner.cleanup()
        self.assertFalse(path.exists())


@unittest.skipUnless(sys.platform == "linux", "Linux UID/procfs/private-FD ownership contract")
class ResourceTransitionTests(unittest.TestCase):
    setUp = ResourceRepairTests.setUp

    def test_mount_fields_follow_kind_and_full_bind_cleanup(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-transition")
        for kind in ("bind", "volume"):
            with self.subTest(kind=kind):
                mount = {"Type": kind, "Source": "/owned", "Destination": "/data", "RW": False}
                if kind == "volume":
                    mount["Name"] = "gz-transition-vol"
                value = {"Id": "1" * 64, "Name": "/gz-transition-app", "Image": IMAGE_ID,
                         "Config": {"Image": PIN, "Labels": owner.labels}, "Mounts": [mount]}
                try:
                    identity = self.module._identity("container", value)
                except ValueError:
                    self.fail("complete type-specific mount must be admitted")
                self.assertEqual(identity["mounts"][0]["Name"], mount.get("Name"))
                for field in ("Source", "Destination", "RW", *( ("Name",) if kind == "volume" else () )):
                    broken = copy.deepcopy(value)
                    del broken["Mounts"][0][field]
                    with self.assertRaises(ValueError):
                        self.module._identity("container", broken)
        docker = DockerDouble()
        def inspect(command, *args, **kwargs):
            result = docker(command, *args, **kwargs)
            if command[1:3] == ["container", "inspect"]:
                values = json.loads(result.stdout)
                for mount in values[0]["Mounts"]:
                    if mount["Type"] == "bind" and mount.get("Name") is None:
                        mount.pop("Name", None)
                return ProcessResult(command, 0, json.dumps(values))
            return result
        with patch.object(self.module, "_execute", side_effect=inspect):
            try:
                owner.container("app", PIN, bind={self.root: "/src"})
                owner.cleanup()
            except ValueError:
                self.fail("omitted volume-only Name must not strand a bind container")
        self.assertEqual(docker.items["container"], {})

    def test_marker_unlink_transition_is_recoverable_and_bound(self):
        for ordinal, after in enumerate(("payload", ".owner")):
            with self.subTest(after=after):
                owner = self.module.OwnedDocker(self.root / f"owner{ordinal}.json", "gz-transition")
                path = owner.directory("data" + str(ordinal))
                (path / "payload").write_text("owned")
                now = [0.0]
                unlink, move = self.module.fsx.unlink_at, self.module.fsx.replace_at
                def interrupted(parent, name):
                    result = unlink(parent, name)
                    if name == after:
                        now[0] = 61.0
                    return result
                def moved(parent, name, target, target_name):
                    result = move(parent, name, target, target_name)
                    if name == after:
                        now[0] = 61.0
                    return result
                with patch.object(self.module.time, "monotonic", side_effect=lambda: now[0]), \
                        patch.object(self.module.fsx, "unlink_at", side_effect=interrupted), \
                        patch.object(self.module.fsx, "replace_at", side_effect=moved):
                    with self.assertRaises(self.module.CleanupUnconfirmed):
                        owner.cleanup()
                self.assertTrue(path.is_dir())
                if after == ".owner":
                    foreign = self.root / "original"
                    path.rename(foreign)
                    path.mkdir(mode=0o700)
                    with self.assertRaises(self.module.CleanupUnconfirmed):
                        owner.cleanup()
                    self.assertTrue(path.is_dir())
                    path.rmdir()
                    foreign.rename(path)
                with patch.object(self.module, "_process_identity", return_value={**owner.owner_process, "start": "changed"}):
                    recovered = self.module.OwnedDocker.recover(owner.manifest)
                try:
                    recovered.cleanup()
                except self.module.CleanupUnconfirmed:
                    self.fail("durably owned cleanup transition must recover")
                recovered.cleanup()
                self.assertFalse(path.exists())
        owner = self.module.OwnedDocker(self.root / "pending.json", "gz-transition")
        path = owner.directory("pending")
        (path / ".owner").unlink()
        with self.assertRaises(self.module.CleanupUnconfirmed):
            owner.cleanup()
        self.assertTrue(path.is_dir())
        (path / ".owner").write_text(owner.nonce)
        (path / ".owner").chmod(0o600)
        with patch.object(owner, "_save", side_effect=OSError("owned publication unavailable")):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertTrue((path / ".owner").is_file())
        owner.cleanup()
        self.assertFalse(path.exists())

    def test_second_boot_is_bound_before_live_reused_or_absent_target(self):
        with patch.object(self.module, "_process_identity", return_value={"pid": 424242, "start": "unit-start", "boot": "unit-boot"}):
            owner = self.module.OwnedDocker(self.root / "owner.json", "gz-transition")
        original = Path.read_text
        for second in ("", "changed", "unit-boot"):
            for target in ("live", "reused", "absent"):
                with self.subTest(second=second, target=target):
                    boots = []
                    def proc(path, *args, **kwargs):
                        name = str(path)
                        if name == "/proc/sys/kernel/random/boot_id":
                            boots.append(name)
                            return "unit-boot" if len(boots) == 1 else second
                        if name == "/proc/self/stat":
                            return f"{os.getpid()} (owned) " + " ".join(["R", *(["0"] * 18), "observer"])
                        if name == "/proc/424242/stat":
                            if target == "absent":
                                raise FileNotFoundError("owned absent target")
                            birth = "unit-start" if target == "live" else "changed"
                            return "424242 (owned) " + " ".join(["R", *(["0"] * 18), birth])
                        if name.startswith("/proc/"):
                            raise AssertionError("unadmitted procfs observation")
                        return original(path, *args, **kwargs)
                    with patch.object(Path, "read_text", proc), patch.object(self.module, "_process_identity", self.native_identity):
                        if second == "unit-boot" and target != "live":
                            self.assertEqual(self.module.OwnedDocker.recover(owner.manifest).nonce, owner.nonce)
                        else:
                            with self.assertRaises(self.module.CleanupUnconfirmed):
                                self.module.OwnedDocker.recover(owner.manifest)


@unittest.skipUnless(sys.platform == "linux", "Linux UID/procfs/private-FD ownership contract")
class LiveAnchorTests(unittest.TestCase):
    setUp = ResourceRepairTests.setUp

    def witness_fault(self, *, detached=True, slot="marker", stage="read", missing=False):
        number = getattr(self, "witness_number", 0) + 1
        self.witness_number = number
        owner = self.module.OwnedDocker(self.root / f"journal{number}.json", f"gz-witness-{number}")
        path = self.detached(owner) if detached else owner.directory("owned")
        key = self.module.hashlib.sha256(("directory:" + path.name).encode()).hexdigest()
        target = owner._anchor_path() / ("owner" if slot == "header" else key + "." + slot)
        aside = self.root / f"original-{number}"
        seen, changed = [], []
        private = self.module.OwnedDocker._private
        check = self.module.fsx.ReadOnlyBoundRoot.check
        move, remove, unlink = self.module.fsx.replace_at, self.module.fsx.rmdir_at, self.module.fsx.unlink_at
        def change():
            if not changed:
                raw = target.read_bytes()
                target.rename(aside)
                if not missing:
                    target.write_bytes(raw)
                    target.chmod(0o600)
                changed.append(raw)
        def read(root, name, limit=2048):
            value = private(root, name, limit)
            if stage == "owner-read" and root.path == owner._anchor_path() and name == "owner":
                change()
            if stage == "anchor-read" and root.path == owner._anchor_path() and name == key + ".record":
                change()
            if root.path == path and name == ".owner":
                seen.append(True)
                if stage == "read":
                    change()
            return value
        def checked(root):
            check(root)
            if stage == "check" and root.path == path and seen:
                change()
        def moved(parent, name, destination, destination_name):
            result = move(parent, name, destination, destination_name)
            if stage == "move" and name == ".owner":
                change()
            return result
        def removed(parent, name):
            result = remove(parent, name)
            if stage == "rmdir":
                change()
            return result
        def unlinked(parent, name):
            result = unlink(parent, name)
            if stage == "marker-unlink" and name.endswith(".marker"):
                change()
            return result
        actor = self.recovered(owner) if detached else owner
        with ExitStack() as patches:
            patches.enter_context(patch.object(self.module.OwnedDocker, "_private", staticmethod(read)))
            patches.enter_context(patch.object(self.module.fsx.ReadOnlyBoundRoot, "check", checked))
            patches.enter_context(patch.object(self.module.fsx, "replace_at", moved))
            patches.enter_context(patch.object(self.module.fsx, "rmdir_at", removed))
            patches.enter_context(patch.object(self.module.fsx, "unlink_at", unlinked))
            try:
                actor.cleanup()
                outcome = "removed"
            except self.module.CleanupUnconfirmed:
                outcome = "refused"
        self.assertTrue(changed, "the real filesystem boundary must be reached")
        self.assertEqual(aside.read_bytes(), changed[0])
        return owner, path, target, aside, outcome

    def test_recovered_witness_mutation_before_rmdir_refuses(self):
        for stage in ("read", "check"):
            for missing in (False, True):
                with self.subTest(stage=stage, missing=missing):
                    _, path, marker, _, outcome = self.witness_fault(stage=stage, missing=missing)
                    self.assertEqual(outcome, "refused")
                    self.assertTrue(path.is_dir(), "changed witness cannot authorize rmdir")
                    self.assertEqual(marker.exists(), not missing)

    def test_newly_moved_witness_mutation_before_rmdir_refuses(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                _, path, marker, _, outcome = self.witness_fault(detached=False, stage="move", missing=missing)
                self.assertEqual(outcome, "refused")
                self.assertTrue(path.is_dir(), "MOVE must retain the original marker identity")
                self.assertEqual(marker.exists(), not missing)

    def test_header_and_record_identity_changes_revoke_removal(self):
        for detached in (True, False):
            stage = "read" if detached else "move"
            for slot, boundary in (("header", "owner-read"), ("header", "anchor-read"), ("header", stage), ("record", stage)):
                with self.subTest(detached=detached, slot=slot, boundary=boundary):
                    _, path, target, _, outcome = self.witness_fault(detached=detached, slot=slot, stage=boundary)
                    self.assertEqual(outcome, "refused")
                    self.assertTrue(path.is_dir())
                    self.assertTrue(target.exists())

    def test_finalization_never_adopts_replacement_authority(self):
        for detached in (True, False):
            for slot, stage in (("marker", "rmdir"), ("record", "rmdir"), ("header", "rmdir"), ("record", "marker-unlink")):
                with self.subTest(detached=detached, slot=slot, stage=stage):
                    _, path, target, _, outcome = self.witness_fault(detached=detached, slot=slot, stage=stage)
                    self.assertEqual(outcome, "refused")
                    self.assertFalse(path.exists(), "resource removal precedes this injected change")
                    self.assertTrue(target.exists(), "finalization must preserve the replacement")

    def test_live_witness_restore_and_partial_finalization_retry(self):
        owner, path, marker, original, outcome = self.witness_fault(missing=True)
        self.assertEqual(outcome, "refused")
        self.assertTrue(path.exists())
        original.rename(marker)
        now = [0.0]
        unlink = self.module.fsx.unlink_at
        def expire(parent, name):
            result = unlink(parent, name)
            if name.endswith(".marker"):
                now[0] = 61.0
            return result
        with patch.object(self.module.time, "monotonic", lambda: now[0]), patch.object(self.module.fsx, "unlink_at", expire):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                self.recovered(owner).cleanup()
        self.assertFalse(path.exists())
        self.assertFalse(marker.exists())
        recovered = self.recovered(owner)
        recovered.cleanup()
        recovered.cleanup()
        self.assertEqual([p.name for p in owner._anchor_path().iterdir()], ["owner"])
        self.assertEqual(recovered.cleanup_status, "removed")

    def recovered(self, owner):
        with patch.object(self.module, "_process_identity", return_value={**owner.owner_process, "start": "reused"}):
            return self.module.OwnedDocker.recover(owner.manifest)

    def detached(self, owner):
        path = owner.directory("owned")
        now = [0.0]
        unlink, move = self.module.fsx.unlink_at, self.module.fsx.replace_at
        def cut(parent, name):
            result = unlink(parent, name)
            if name == ".owner":
                now[0] = 61.0
            return result
        def cut_move(parent, name, target, target_name):
            result = move(parent, name, target, target_name)
            if name == ".owner":
                now[0] = 61.0
            return result
        with patch.object(self.module.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(self.module.fsx, "unlink_at", side_effect=cut), \
                patch.object(self.module.fsx, "replace_at", side_effect=cut_move):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertTrue(path.is_dir())
        self.assertFalse((path / ".owner").exists())
        return path

    def test_invented_journal_transition_cannot_adopt_never_marked_directory(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        foreign = self.root / "gz-anchor-never"
        foreign.mkdir(mode=0o700)
        info = foreign.stat()
        value = json.loads(owner.manifest.read_text())
        value["resources"] = [{"kind": "directory", "name": foreign.name, "status": "bound",
            "identity": {"device": info.st_dev, "inode": info.st_ino},
            "directory_removal": {"nonce": owner.nonce, "marker": [1, 2, 32768, 32, 3, 4, 1, 384]}}]
        owner.manifest.write_text(json.dumps(value))
        recovered = self.recovered(owner)
        with self.assertRaises(self.module.CleanupUnconfirmed):
            recovered.cleanup()
        self.assertTrue(foreign.is_dir())

    def test_live_transition_cannot_be_redirected_by_journal(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        owned = self.detached(owner)
        foreign = self.root / "gz-anchor-foreign"
        foreign.mkdir(mode=0o700)
        value = json.loads(owner.manifest.read_text())
        info = foreign.stat()
        value["resources"][0].update(name=foreign.name, identity={"device": info.st_dev, "inode": info.st_ino})
        owner.manifest.write_text(json.dumps(value))
        with self.assertRaises(self.module.CleanupUnconfirmed):
            self.recovered(owner).cleanup()
        self.assertTrue(foreign.is_dir())
        self.assertTrue(owned.is_dir())

    def test_pending_journal_cannot_claim_detached_transition(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = self.detached(owner)
        value = json.loads(owner.manifest.read_text())
        value["resources"][0]["status"] = "pending"
        owner.manifest.write_text(json.dumps(value))
        try:
            self.recovered(owner).cleanup()
        except (ValueError, self.module.CleanupUnconfirmed):
            pass
        self.assertTrue(path.is_dir(), "pending record must not authorize directory removal")

    def test_live_witness_cannot_be_copied(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = self.detached(owner)
        key = self.module.hashlib.sha256(("directory:" + path.name).encode()).hexdigest()
        marker = owner._anchor_path() / (key + ".marker")
        retained = self.root / "original-marker"
        raw = marker.read_bytes()
        marker.rename(retained)
        marker.write_bytes(raw)
        marker.chmod(0o600)
        with self.assertRaises(self.module.CleanupUnconfirmed):
            self.recovered(owner).cleanup()
        self.assertTrue(path.exists())
        self.assertEqual(retained.read_bytes(), raw)

    def test_anchor_binds_same_name_directory_identity_independently(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = self.detached(owner)
        original = self.root / "original-directory"
        path.rename(original)
        path.mkdir(mode=0o700)
        info = path.stat()
        value = json.loads(owner.manifest.read_text())
        value["resources"][0]["identity"] = {"device": info.st_dev, "inode": info.st_ino}
        owner.manifest.write_text(json.dumps(value))
        with self.assertRaises(self.module.CleanupUnconfirmed):
            self.recovered(owner).cleanup()
        self.assertTrue(path.is_dir())
        self.assertTrue(original.is_dir())

    def test_atomic_metadata_peak_counts_live_anchors(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = owner.directory("owned")
        for index in range(100):
            record = owner._anchor_path() / (f"{index:064x}.record")
            record.write_bytes(b"{}" + b" " * 2046)
            record.chmod(0o600)
        owner.resources.append({"kind": "volume", "name": "gz-anchor-v", "status": "bound", "identity": {
            "Name": "gz-anchor-v", "Labels": owner.labels, "Driver": "local", "Options": {"note": "x" * 500000},
            "CreatedAt": "owned", "Mountpoint": "/owned"}})
        owner._save()
        before = owner.manifest.read_bytes()
        with self.assertRaises(ValueError):
            owner._save()
        self.assertEqual(owner.manifest.read_bytes(), before)
        self.assertEqual((path / ".owner").read_text(), owner.nonce)

    def test_publication_expiry_keeps_original_and_resumes_complete_temporary(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = owner.directory("owned")
        now = [0.0]
        sync = self.module.os.fsync
        def expire(fd):
            result = sync(fd)
            now[0] = 61.0
            return result
        with patch.object(self.module.time, "monotonic", side_effect=lambda: now[0]), patch.object(self.module.os, "fsync", side_effect=expire):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertEqual((path / ".owner").read_text(), owner.nonce)
        self.recovered(owner).cleanup()
        self.assertFalse(path.exists())

    def test_final_witness_cleanup_resumes_after_resource_absence(self):
        owner = self.module.OwnedDocker(self.root / "owner.json", "gz-anchor")
        path = owner.directory("owned")
        now = [0.0]
        remove = self.module.fsx.rmdir_at
        def expired(parent, name):
            result = remove(parent, name)
            now[0] = 61.0
            return result
        with patch.object(self.module.time, "monotonic", side_effect=lambda: now[0]), patch.object(self.module.fsx, "rmdir_at", side_effect=expired):
            with self.assertRaises(self.module.CleanupUnconfirmed):
                owner.cleanup()
        self.assertFalse(path.exists())
        recovered = self.recovered(owner)
        recovered.cleanup()
        recovered.cleanup()
        self.assertEqual([p.name for p in owner._anchor_path().iterdir()], ["owner"])
        self.assertEqual(recovered.cleanup_status, "removed")


class ProcessIdentityTests(unittest.TestCase):
    def test_mismatched_process_namespace_cannot_supply_any_birth_identity(self):
        module = importlib.import_module("getzilla.disposable_resources")

        def proc_text(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return "unit-boot"
            pid = 9001 if str(path) == "/proc/self/stat" else int(path.parent.name)
            return f"{pid} (unit process) " + " ".join(["R", *(["0"] * 18), "1234"])

        with patch.object(module.os, "getpid", return_value=7001), patch.object(Path, "read_text", proc_text):
            for pid in (7001, 8001):
                with self.subTest(pid=pid), self.assertRaises(module.CleanupUnconfirmed):
                    module._process_identity(pid)

    def test_matching_process_namespace_preserves_birth_identity(self):
        module = importlib.import_module("getzilla.disposable_resources")

        def proc_text(path, *args, **kwargs):
            if str(path) == "/proc/sys/kernel/random/boot_id":
                return "unit-boot\n"
            pid = 7001 if str(path) == "/proc/self/stat" else int(path.parent.name)
            return f"{pid} (unit process) " + " ".join(["R", *(["0"] * 18), "1234"])

        with patch.object(module.os, "getpid", return_value=7001), patch.object(Path, "read_text", proc_text):
            self.assertEqual(module._process_identity(8001), {"pid": 8001, "start": "1234", "boot": "unit-boot"})


class DockerDouble:
    def __init__(self):
        self.items = {"container": {}, "volume": {}, "network": {}}
        self.removed = []
        self.lie_about_removal = False
        self.unavailable_listing = False
        self.next_id = 3
        self.commands = []

    def __call__(self, command, *_args, **kwargs):
        self.assert_bounded(kwargs)
        self.commands.append(list(command))
        args = command[1:]
        if args[:2] == ["image", "inspect"]:
            value = [{"Id": IMAGE_ID, "RepoDigests": [PIN]}]
        elif args[:2] == ["volume", "create"] or args[:2] == ["network", "create"]:
            kind = args[0]
            name = args[-1]
            labels = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--label")
            value = {"Name": name, "Labels": labels, "Driver": "local" if kind == "volume" else "bridge",
                     "CreatedAt": "2026-11-03T00:00:00Z", "Options": {},
                     "Mountpoint": "/var/lib/docker/volumes/" + name, "Containers": {}}
            if kind == "network":
                value["Id"] = f"{self.next_id:064x}"
                value.update(Internal="--internal" in args, Scope="local", Ingress=False,
                             IPAM={"Config": [{"Subnet": "172.28.0.0/16", "Gateway": "172.28.0.1"}]})
                self.next_id += 1
            self.items[kind][name] = value
            return ProcessResult(command, 0, value.get("Id", name), "")
        elif args[:1] == ["run"]:
            name = args[args.index("--name") + 1]
            labels = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--label")
            identifier = f"{self.next_id:064x}"
            self.next_id += 1
            mounts = []
            for index, arg in enumerate(args):
                if arg != "--mount":
                    continue
                parts = dict(x.split("=", 1) if "=" in x else (x, "true")
                             for x in args[index + 1].split(","))
                mounts.append({"Type": parts["type"], "Name": parts["source"] if parts["type"] == "volume" else None,
                               "Source": parts["source"], "Destination": parts["target"],
                               "RW": "readonly" not in parts})
            value = {"Id": identifier, "Name": "/" + name, "Image": IMAGE_ID,
                     "Config": {"Image": PIN, "Labels": labels}, "Mounts": mounts,
                     "State": {"Running": True}, "NetworkSettings": {"Networks": {}, "Ports": {}},
                     "HostConfig": {"NetworkMode": "default", "PortBindings": {}, "AutoRemove": False}}
            if "--network" in args:
                network_name = args[args.index("--network") + 1]
                network = self.items["network"][network_name]
                endpoint_id = f"{self.next_id + 1000:064x}"
                address = f"172.28.0.{len(network['Containers']) + 2}"
                value["HostConfig"]["NetworkMode"] = network_name
                value["NetworkSettings"]["Networks"][network_name] = {
                    "NetworkID": network["Id"], "EndpointID": endpoint_id,
                    "IPAddress": address, "IPPrefixLen": 16, "Gateway": "",
                }
                network["Containers"][identifier] = {
                    "Name": name, "EndpointID": endpoint_id, "IPv4Address": address + "/16",
                }
            if "--publish" in args:
                value["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]}
            self.items["container"][identifier] = value
            return ProcessResult(command, 0, identifier, "")
        elif args[:1] == ["port"]:
            # Actual internal bridges have no usable published mapping. The
            # allocator may still retain the requested HostConfig binding.
            raise subprocess.CalledProcessError(1, command, stderr="No public port")
        elif args[:2] in (["container", "inspect"], ["volume", "inspect"], ["network", "inspect"]):
            selected = self.items[args[0]].get(args[-1])
            if selected is None:
                selected = next(x for x in self.items[args[0]].values()
                                if x.get("Id") == args[-1] or x.get("Name", "").removeprefix("/") == args[-1])
            value = [selected]
            if args[0] == "container":
                value = copy.deepcopy(value)
                for mount in value[0]["Mounts"]:
                    if mount["Type"] == "bind" and mount.get("Name") is None:
                        mount.pop("Name", None)
        elif len(args) > 1 and args[1] == "ls":
            if self.unavailable_listing:
                raise subprocess.CalledProcessError(1, command)
            if args[0] == "container" and args[-1] == "{{.Names}}":
                return ProcessResult(command, 0, "\n".join(v["Name"].removeprefix("/") for v in self.items["container"].values()), "")
            return ProcessResult(command, 0, "\n".join(self.items[args[0]]), "")
        elif len(args) > 1 and args[1] == "rm":
            kind, key = args[0], args[-1]
            self.removed.append((kind, key))
            if not self.lie_about_removal:
                named = next((name for name, value in self.items[kind].items()
                              if name == key or value.get("Id") == key), key)
                self.items[kind].pop(named, None)
            return ProcessResult(command, 0, key, "")
        else:
            raise AssertionError(f"unexpected docker boundary {args[:3]}")
        return ProcessResult(command, 0, json.dumps(value), "")

    @staticmethod
    def assert_bounded(kwargs):
        if not 0 < kwargs.get("timeout", 0) <= 60:
            raise AssertionError("Docker operation must have a bounded timeout")


@unittest.skipUnless(sys.platform == "linux", "Disposable CI allocator uses Linux birth identities")
class IsolatedResourceTests(unittest.TestCase):
    def setUp(self):
        # These controls exercise the Docker decision boundary, not the host's
        # procfs capability. ProcessIdentityTests separately enforce that boundary.
        module = self.module()
        identity = {"pid": os.getpid(), "start": "unit-start", "boot": "unit-boot"}
        patcher = patch.object(module, "_process_identity", return_value=identity)
        patcher.start()
        self.addCleanup(patcher.stop)
        original_read = Path.read_text

        def proc_boot(path, *args, **kwargs):
            return "unit-boot" if str(path) == "/proc/sys/kernel/random/boot_id" else original_read(path, *args, **kwargs)

        boot_patcher = patch.object(Path, "read_text", proc_boot)
        boot_patcher.start()
        self.addCleanup(boot_patcher.stop)

    def test_expired_cleanup_budget_does_not_start_more_docker_operations(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                owner.container("db", PIN)
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup(deadline=time.monotonic() - 1)
            self.assertEqual(docker.removed, [])

    def module(self):
        self.assertIsNotNone(importlib.util.find_spec("getzilla.disposable_resources"),
                             "owned Docker resource lifecycle is not implemented")
        return importlib.import_module("getzilla.disposable_resources")

    def test_mutable_image_is_refused_before_creation(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                with self.assertRaises(ValueError):
                    owner.container("db", "postgres:17", publish_postgres=True)
            self.assertEqual(docker.items["container"], {})

    def test_dotted_readonly_destination_is_allocated_without_relaxing_mount_structure(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                try:
                    item = owner.container("db", PIN, bind={Path(raw): "/docker-entrypoint-initdb.d"})
                except ValueError as error:
                    self.fail(f"legitimate readonly init-script destination was refused: {error}")
            mounted = docker.items["container"][item["id"]]["Mounts"]
            self.assertEqual(mounted, [{"Type": "bind", "Name": None, "Source": str(Path(raw).resolve()),
                                       "Destination": "/docker-entrypoint-initdb.d", "RW": False}])

    def test_noncanonical_or_option_like_container_paths_never_allocate(self):
        module = self.module()
        invalid = ("", "/", "relative", "--privileged", "/a/../b", "/a/./b", "/a//b", "/a/", "/a,b",
                   "/a:rw", "/a=other", "/a\\b", "/a\nb", "/a b", "/a\x00b", "/a;$HOME", "/%2e%2e/x")
        for destination in invalid:
            with self.subTest(destination=repr(destination)), tempfile.TemporaryDirectory() as raw:
                owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
                docker = DockerDouble()
                with patch.object(module, "_execute", side_effect=docker):
                    with self.assertRaises(ValueError):
                        owner.container("db", PIN, bind={Path(raw): destination})
                self.assertEqual(docker.items["container"], {})

    def _endpoint_fixture(self, raw, module, docker):
        owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
        network = owner.network("db-network")
        item = owner.container("db", PIN, network=network)
        arguments = {"container_id": item["id"], "container_name": item["name"],
                     "image": PIN, "image_id": IMAGE_ID, "nonce": owner.nonce,
                     "namespace": owner.namespace, "network_id": network["identity"]["Id"]}
        return arguments, docker.items["container"][item["id"]], docker.items["network"][network["name"]]

    def test_real_endpoint_reader_accepts_only_matching_owned_inspections(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "internal_postgres_endpoint", None)), "bound endpoint reader missing")
        with tempfile.TemporaryDirectory() as raw:
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                arguments, _, _ = self._endpoint_fixture(raw, module, docker)
                self.assertEqual(module.internal_postgres_endpoint(**arguments), ("172.28.0.2", 5432))

    def test_internal_endpoint_has_no_default_gateway_even_when_ipam_has_a_bridge_address(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                arguments, container, network = self._endpoint_fixture(raw, module, docker)
                endpoint = container["NetworkSettings"]["Networks"][network["Name"]]
                endpoint["Gateway"] = ""
                self.assertEqual(module.internal_postgres_endpoint(**arguments), ("172.28.0.2", 5432))
                endpoint["Gateway"] = "172.28.0.99"
                with self.assertRaises(ValueError):
                    module.internal_postgres_endpoint(**arguments)

    def test_endpoint_refuses_wrong_network_ip_container_and_external_connectivity(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "internal_postgres_endpoint", None)), "bound endpoint reader missing")
        cases = ("network-id", "network-label", "network-external", "container-id", "container-image",
                 "container-nonce", "wrong-ip", "multiple-networks", "published-port", "endpoint-id")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                docker = DockerDouble()
                with patch.object(module, "_execute", side_effect=docker):
                    arguments, container, network = self._endpoint_fixture(raw, module, docker)
                    endpoint = container["NetworkSettings"]["Networks"][network["Name"]]
                    if case == "network-id":
                        endpoint["NetworkID"] = "e" * 64
                    elif case == "network-label":
                        network["Labels"]["getzilla.ci.nonce"] = "e" * 32
                    elif case == "network-external":
                        network["Internal"] = False
                    elif case == "container-id":
                        container["Id"] = "e" * 64
                    elif case == "container-image":
                        container["Image"] = "sha256:" + "e" * 64
                    elif case == "container-nonce":
                        container["Config"]["Labels"]["getzilla.ci.nonce"] = "e" * 32
                    elif case == "wrong-ip":
                        endpoint["IPAddress"] = "172.28.0.99"
                    elif case == "multiple-networks":
                        container["NetworkSettings"]["Networks"]["bridge"] = copy.deepcopy(endpoint)
                    elif case == "published-port":
                        container["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}
                    else:
                        endpoint["EndpointID"] = "e" * 64
                    with self.assertRaises((ValueError, RuntimeError)):
                        module.internal_postgres_endpoint(**arguments)

    def test_endpoint_reader_detects_identity_change_during_observation(self):
        module = self.module()
        self.assertTrue(callable(getattr(module, "internal_postgres_endpoint", None)), "bound endpoint reader missing")
        with tempfile.TemporaryDirectory() as raw:
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                arguments, container, _ = self._endpoint_fixture(raw, module, docker)
            reads = []
            def boundary(command, *_args, **kwargs):
                if command[1:3] == ["container", "inspect"]:
                    reads.append(command)
                    if len(reads) == 2:
                        container["Config"]["Labels"]["getzilla.ci.nonce"] = "e" * 32
                return docker(command, **kwargs)
            with patch.object(module, "_execute", side_effect=boundary), self.assertRaises((ValueError, RuntimeError)):
                module.internal_postgres_endpoint(**arguments)

    def test_removal_success_without_absence_is_failure(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                owner.container("db", PIN)
                docker.lie_about_removal = True
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            report = json.loads((Path(raw) / "owner.json").read_text())
            self.assertEqual(report["cleanup_status"], "unconfirmed")
            self.assertEqual(len(docker.items["container"]), 1)

    def test_changed_binding_does_not_delete_foreign_resource(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                resource = owner.container("db", PIN)
                docker.items["container"][resource["id"]]["Config"]["Labels"]["getzilla.ci.nonce"] = "foreign"
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            self.assertEqual(docker.removed, [])

    def test_reordered_identical_mounts_keep_ownership_and_allow_confirmed_cleanup(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                volume = owner.volume("deps")
                item = owner.container("provision", PIN, volume=volume, volume_target="/deps",
                                       bind={Path(raw): "/src"})
                docker.items["container"][item["id"]]["Mounts"].reverse()
                try:
                    owner.cleanup()
                except module.CleanupUnconfirmed as error:
                    self.fail(f"the same mount set lost ownership solely through ordering: {error}")
            self.assertEqual(owner.cleanup_status, "removed")
            self.assertEqual(docker.items["container"], {})
            self.assertEqual(docker.items["volume"], {})

    def test_changed_mount_fields_and_duplicates_still_deny_removal_with_safe_diagnostics(self):
        module = self.module()
        sentinel = "private-mount-source-must-not-be-reported"
        for field in ("Type", "Name", "Source", "Destination", "duplicate"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as raw:
                owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
                docker = DockerDouble()
                with patch.object(module, "_execute", side_effect=docker):
                    item = owner.container("provision", PIN, bind={Path(raw): "/src"})
                    mounts = docker.items["container"][item["id"]]["Mounts"]
                    if field == "duplicate":
                        mounts.append(copy.deepcopy(mounts[0]))
                    else:
                        mounts[0][field] = sentinel
                    with self.assertRaises(module.CleanupUnconfirmed):
                        owner.cleanup()
                self.assertNotIn(("container", item["id"]), docker.removed)
                self.assertEqual(item.get("cleanup_mismatch_fields"), ["mounts"])
                self.assertNotIn(sentinel, (Path(raw) / "owner.json").read_text(encoding="utf-8"))

    def test_legacy_journal_mount_order_is_compared_without_mutating_its_binding(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                volume = owner.volume("deps")
                item = owner.container("provision", PIN, volume=volume, volume_target="/deps",
                                       bind={Path(raw): "/src"})
                item["identity"]["mounts"].reverse()
                stored = copy.deepcopy(item["identity"])
                try:
                    owner.cleanup()
                except module.CleanupUnconfirmed as error:
                    self.fail(f"legacy journal ordering was treated as a changed mount: {error}")
                self.assertEqual(item["identity"], stored)
            self.assertEqual(owner.cleanup_status, "removed")

    def test_owned_container_volume_network_cleanup_is_idempotent_and_scoped(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            docker.items["volume"]["unrelated"] = {"Name": "unrelated", "Labels": {}}
            with patch.object(module, "_execute", side_effect=docker):
                volume = owner.volume("data")
                network = owner.network("db")
                owner.container("db", PIN, volume=volume, network=network)
                owner.cleanup()
                owner.cleanup()
            self.assertEqual(docker.items["container"], {})
            self.assertEqual(docker.items["network"], {})
            self.assertEqual(set(docker.items["volume"]), {"unrelated"})
            self.assertEqual(json.loads((Path(raw) / "owner.json").read_text())["cleanup_status"], "removed")

    def test_unavailable_listing_never_proves_absence(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                owner.container("db", PIN)
                docker.unavailable_listing = True
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            self.assertEqual(docker.removed, [])

    def test_recovery_does_not_race_a_still_live_allocator(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            journal = Path(raw) / "owner.json"
            module.OwnedDocker(journal, "gz-live")
            with self.assertRaises(module.CleanupUnconfirmed):
                module.OwnedDocker.recover(journal)

    def test_a_changed_journal_cannot_replace_live_ownership_labels(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module, "_execute", side_effect=docker):
                item = owner.container("db", PIN)
                docker.items["container"][item["id"]]["Config"]["Labels"]["getzilla.ci.nonce"] = "foreign"
                item["identity"]["labels"]["getzilla.ci.nonce"] = "foreign"
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            self.assertEqual(docker.removed, [])


if __name__ == "__main__":
    unittest.main()
