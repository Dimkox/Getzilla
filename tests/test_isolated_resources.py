"""Exercise ownership and cleanup decisions against a stateful Docker boundary double."""
from __future__ import annotations
import importlib
import importlib.util
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
PIN = "postgres@sha256:" + "1" * 64
IMAGE_ID = "sha256:" + "2" * 64


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

    def __call__(self, command, **kwargs):
        self.assert_bounded(kwargs)
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
                self.next_id += 1
            self.items[kind][name] = value
            return subprocess.CompletedProcess(command, 0, value.get("Id", name), "")
        elif args[:1] == ["run"]:
            name = args[args.index("--name") + 1]
            labels = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--label")
            identifier = f"{self.next_id:064x}"
            self.next_id += 1
            mounts = []
            if "--mount" in args:
                parts = dict(x.split("=", 1) for x in args[args.index("--mount")+1].split(","))
                mounts.append({"Type": "volume", "Name": parts["source"], "Destination": parts["target"]})
            value = {"Id": identifier, "Name": "/" + name, "Image": IMAGE_ID,
                     "Config": {"Image": PIN, "Labels": labels}, "Mounts": mounts,
                     "State": {"Running": True}, "NetworkSettings": {"Networks": {}}}
            self.items["container"][identifier] = value
            return subprocess.CompletedProcess(command, 0, identifier, "")
        elif args[:2] in (["container", "inspect"], ["volume", "inspect"], ["network", "inspect"]):
            value = [self.items[args[0]][args[-1]]]
        elif len(args) > 1 and args[1] == "ls":
            if self.unavailable_listing:
                raise subprocess.CalledProcessError(1, command)
            return subprocess.CompletedProcess(command, 0, "\n".join(self.items[args[0]]), "")
        elif len(args) > 1 and args[1] == "rm":
            kind, key = args[0], args[-1]
            self.removed.append((kind, key))
            if not self.lie_about_removal:
                self.items[kind].pop(key, None)
            return subprocess.CompletedProcess(command, 0, key, "")
        else:
            raise AssertionError(f"unexpected docker boundary {args[:3]}")
        return subprocess.CompletedProcess(command, 0, json.dumps(value), "")

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
            with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
                with self.assertRaises(ValueError):
                    owner.container("db", "postgres:17", publish_postgres=True)
            self.assertEqual(docker.items["container"], {})

    def test_removal_success_without_absence_is_failure(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
                resource = owner.container("db", PIN)
                docker.items["container"][resource["id"]]["Config"]["Labels"]["getzilla.ci.nonce"] = "foreign"
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            self.assertEqual(docker.removed, [])

    def test_owned_container_volume_network_cleanup_is_idempotent_and_scoped(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            docker.items["volume"]["unrelated"] = {"Name": "unrelated", "Labels": {}}
            with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
                item = owner.container("db", PIN)
                docker.items["container"][item["id"]]["Config"]["Labels"]["getzilla.ci.nonce"] = "foreign"
                item["identity"]["labels"]["getzilla.ci.nonce"] = "foreign"
                with self.assertRaises(module.CleanupUnconfirmed):
                    owner.cleanup()
            self.assertEqual(docker.removed, [])


if __name__ == "__main__":
    unittest.main()

