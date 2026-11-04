"""Exercise ownership and cleanup decisions against a stateful Docker boundary double."""
from __future__ import annotations
import importlib
import importlib.util
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

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
        self.commands = []

    def __call__(self, command, **kwargs):
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
            return subprocess.CompletedProcess(command, 0, value.get("Id", name), "")
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
            return subprocess.CompletedProcess(command, 0, identifier, "")
        elif args[:1] == ["port"]:
            # Actual internal bridges have no usable published mapping. The
            # allocator may still retain the requested HostConfig binding.
            raise subprocess.CalledProcessError(1, command, stderr="No public port")
        elif args[:2] in (["container", "inspect"], ["volume", "inspect"], ["network", "inspect"]):
            selected = self.items[args[0]].get(args[-1])
            if selected is None:
                selected = next(x for x in self.items[args[0]].values() if x.get("Id") == args[-1])
            value = [selected]
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

    def test_dotted_readonly_destination_is_allocated_without_relaxing_mount_structure(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker):
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
                with patch.object(module.subprocess, "run", side_effect=docker):
                    with self.assertRaises(ValueError):
                        owner.container("db", PIN, bind={Path(raw): destination})
                self.assertEqual(docker.items["container"], {})

    def test_factory_uses_the_owned_internal_endpoint_without_publishing_a_host_port(self):
        from factory.tests import run_disposable_exit as runner
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker), \
                    patch.object(runner, "POSTGRES", {"reference": PIN, "image_id": IMAGE_ID}), \
                    patch.object(runner, "_final_postgres_ready", return_value=True):
                network = owner.network("db-network")
                try:
                    item, url = runner._postgres(owner, "db", "test-only-pw", network)
                except subprocess.CalledProcessError:
                    self.fail("the real runner queried a nonexistent published port on its internal bridge")
            self.assertEqual(url, "postgresql://factory_exit:test-only-pw@172.28.0.2:5432/factory_exit")
            self.assertEqual(docker.items["container"][item["id"]]["HostConfig"]["PortBindings"], {})
            self.assertFalse(any(command[:2] == ["docker", "port"] for command in docker.commands))

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
            with patch.object(module.subprocess, "run", side_effect=docker):
                arguments, _, _ = self._endpoint_fixture(raw, module, docker)
                self.assertEqual(module.internal_postgres_endpoint(**arguments), ("172.28.0.2", 5432))

    def test_internal_endpoint_has_no_default_gateway_even_when_ipam_has_a_bridge_address(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker):
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
                with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
                arguments, container, _ = self._endpoint_fixture(raw, module, docker)
            reads = []
            def boundary(command, **kwargs):
                if command[1:3] == ["container", "inspect"]:
                    reads.append(command)
                    if len(reads) == 2:
                        container["Config"]["Labels"]["getzilla.ci.nonce"] = "e" * 32
                return docker(command, **kwargs)
            with patch.object(module.subprocess, "run", side_effect=boundary), self.assertRaises((ValueError, RuntimeError)):
                module.internal_postgres_endpoint(**arguments)

    def test_real_preflight_accepts_the_exact_internal_endpoint_and_cluster(self):
        self._preflight_case("172.28.0.2", 5432, expect_pass=True)

    def test_real_preflight_rejects_a_different_private_ip_or_port_before_database_access(self):
        for host, port in (("172.28.0.99", 5432), ("172.28.0.2", 5433), ("127.0.0.1", 5432)):
            with self.subTest(host=host, port=port):
                self._preflight_case(host, port, expect_pass=False)

    def test_result_dispatch_live_case_uses_the_real_bound_reader_before_mutation(self):
        import inspect
        from factory.tests import postgres_restart_probe as probe
        from factory.tests import test_postgres_integration as live_case
        module = self.module()

        class BeforeMutation(RuntimeError):
            pass

        for valid_network in (True, False):
            with self.subTest(valid_network=valid_network), tempfile.TemporaryDirectory() as raw:
                docker = DockerDouble()
                with patch.object(module.subprocess, "run", side_effect=docker):
                    arguments, container, network = self._endpoint_fixture(raw, module, docker)
                if not valid_network:
                    container["NetworkSettings"]["Networks"][network["Name"]]["NetworkID"] = "e" * 64

                def boundary(command, **kwargs):
                    if command[:2] == ["docker", "inspect"]:
                        if "--format" in command:
                            value = "\t".join((container["Id"], container["Name"], PIN, "true", arguments["nonce"], IMAGE_ID))
                        else:
                            value = json.dumps([container])
                        return subprocess.CompletedProcess(command, 0, value, "")
                    if command[:2] == ["docker", "exec"]:
                        return subprocess.CompletedProcess(command, 0, "bound-cluster" if "psql" in command else "", "")
                    return docker(command, **kwargs)

                case = live_case.PostgresFactoryTests("test_result_dispatch_process_and_postgres_restart_observes_without_second_post")
                case.submit = MagicMock(side_effect=BeforeMutation())
                # This unit control executes only the actual live fixture's
                # preflight; stop before submission, never bypass a live gate.
                method = inspect.unwrap(type(case).test_result_dispatch_process_and_postgres_restart_observes_without_second_post)
                environment = {"FACTORY_TEST_POSTGRES_CONTAINER_ID": arguments["container_id"],
                               "FACTORY_TEST_POSTGRES_NONCE": arguments["nonce"],
                               "FACTORY_TEST_POSTGRES_NETWORK_ID": arguments["network_id"],
                               "FACTORY_TEST_POSTGRES_NAMESPACE": arguments["namespace"]}
                connection = MagicMock()
                connection.execute.return_value.fetchone.return_value = ("factory_exit", "factory_exit", 170_006, "bound-cluster")
                with patch.object(module.subprocess, "run", side_effect=boundary), \
                        patch.object(probe, "POSTGRES", {"reference": PIN, "image_id": IMAGE_ID}), \
                        patch.dict(os.environ, environment), \
                        patch.object(live_case, "POSTGRES_CONTAINER", arguments["container_name"]), \
                        patch.object(live_case, "DATABASE_URL", "postgresql://factory_exit:test-only@172.28.0.2:5432/factory_exit"), \
                        patch("psycopg.connect") as connect:
                    connect.return_value.__enter__.return_value = connection
                    with self.assertRaises(BeforeMutation if valid_network else ValueError):
                        method(case)
                    if valid_network:
                        case.submit.assert_called_once()
                        connect.assert_called_once()
                    else:
                        case.submit.assert_not_called()
                        connect.assert_not_called()

    def test_restart_rechecks_live_network_and_container_before_waiting_for_database(self):
        from factory.tests import postgres_restart_probe as probe
        module = self.module()
        for case in ("network", "ip", "container"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                docker = DockerDouble()
                with patch.object(module.subprocess, "run", side_effect=docker):
                    arguments, container, network = self._endpoint_fixture(raw, module, docker)
                restarts = []

                def boundary(command, **kwargs):
                    if command[:2] == ["docker", "restart"]:
                        self.assertEqual(command[2:], [arguments["container_id"]])
                        restarts.append(command)
                        endpoint = container["NetworkSettings"]["Networks"][network["Name"]]
                        if case == "network":
                            endpoint["NetworkID"] = "e" * 64
                        elif case == "ip":
                            endpoint["IPAddress"] = "172.28.0.99"
                        else:
                            container["Id"] = "e" * 64
                        return subprocess.CompletedProcess(command, 0)
                    return docker(command, **kwargs)

                environment = {"FACTORY_TEST_POSTGRES_NETWORK_ID": arguments["network_id"],
                               "FACTORY_TEST_POSTGRES_NAMESPACE": arguments["namespace"]}
                owner_url = "postgresql://factory_exit:test-only-pw@172.28.0.2:5432/factory_exit"
                with patch.object(module.subprocess, "run", side_effect=boundary), \
                        patch.object(probe, "POSTGRES", {"reference": PIN, "image_id": IMAGE_ID}), \
                        patch.dict(os.environ, environment), \
                        patch.object(probe, "_assert_disposable_target") as initial_preflight, \
                        patch.object(probe, "_postmaster_started_at", return_value=1), \
                        patch.object(probe, "_wait_for_database") as wait:
                    with self.assertRaises((ValueError, RuntimeError)):
                        probe._restart_database(arguments["container_name"], arguments["container_id"],
                                                arguments["nonce"], owner_url, owner_url, owner_url)
                    initial_preflight.assert_called_once()
                    wait.assert_not_called()
                self.assertEqual(len(restarts), 1)

    def _preflight_case(self, host, port, *, expect_pass):
        from factory.tests import postgres_restart_probe as probe
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker):
                arguments, container, _ = self._endpoint_fixture(raw, module, docker)
            def boundary(command, **kwargs):
                if command[:2] == ["docker", "inspect"]:
                    value = "\t".join((container["Id"], container["Name"], PIN, "true", arguments["nonce"], IMAGE_ID))
                    return subprocess.CompletedProcess(command, 0, value, "")
                if command[:2] == ["docker", "exec"]:
                    value = "cluster-bound" if "psql" in command else ""
                    return subprocess.CompletedProcess(command, 0, value, "")
                return docker(command, **kwargs)
            connection = MagicMock()
            connection.execute.return_value.fetchone.return_value = ("factory_exit", "factory_exit", 170_006, "cluster-bound")
            environment = {"FACTORY_TEST_POSTGRES_NETWORK_ID": arguments["network_id"],
                           "FACTORY_TEST_POSTGRES_NAMESPACE": arguments["namespace"]}
            url = f"postgresql://factory_exit:test-only-pw@{host}:{port}/factory_exit"
            with patch.object(module.subprocess, "run", side_effect=boundary), \
                    patch.object(probe, "POSTGRES", {"reference": PIN, "image_id": IMAGE_ID}), \
                    patch.dict(os.environ, environment), patch("psycopg.connect") as connect:
                connect.return_value.__enter__.return_value = connection
                if expect_pass:
                    try:
                        probe._assert_disposable_target(url, arguments["container_name"], arguments["container_id"], arguments["nonce"])
                    except (RuntimeError, subprocess.SubprocessError) as error:
                        self.fail(f"valid owned endpoint was refused before real preflight checks: {type(error).__name__}")
                    self.assertEqual(connect.call_args.args, (url,))
                    self.assertIn("pg_control_system", connection.execute.call_args.args[0])
                else:
                    with self.assertRaises((RuntimeError, ValueError, subprocess.SubprocessError)):
                        probe._assert_disposable_target(url, arguments["container_name"], arguments["container_id"], arguments["nonce"])
                    self.assertFalse(connect.called)

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

    def test_reordered_identical_mounts_keep_ownership_and_allow_confirmed_cleanup(self):
        module = self.module()
        with tempfile.TemporaryDirectory() as raw:
            owner = module.OwnedDocker(Path(raw) / "owner.json", "gz-test")
            docker = DockerDouble()
            with patch.object(module.subprocess, "run", side_effect=docker):
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
                with patch.object(module.subprocess, "run", side_effect=docker):
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
            with patch.object(module.subprocess, "run", side_effect=docker):
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

