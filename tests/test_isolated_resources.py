"""Public synthetic Docker metadata and process-boundary controls for issue320."""

from __future__ import annotations
import copy
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import hashlib
import io
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
PIN = "postgres@sha256:" + "1" * 64
IMAGE_ID = "sha256:" + "2" * 64


class ClosedImageProfiles(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec("getzilla.disposable_resources"))
        self.module = importlib.import_module("getzilla.disposable_resources")
        self.module._VERIFIED_IMAGES.clear()

    def metadata(self, *, wrong_platform=False, wrong_join=False):
        config = json.dumps({"os": "windows" if wrong_platform else "linux", "architecture": "amd64"}).encode()
        configuration = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = json.dumps(
            {"config": {"digest": "sha256:" + "0" * 64 if wrong_join else configuration, "size": len(config)}}
        ).encode()
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        return "postgres@" + digest, digest, configuration, manifest, config

    def export(self, metadata, *, missing=False, duplicate=False, delay=0):
        reference, digest, configuration, manifest, config = metadata
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "public-image.tar"
        with tarfile.open(path, "w") as archive:
            items = [(digest, manifest)] + ([] if missing else [(configuration, config)])
            if duplicate:
                items.append((configuration, config))
            for key, content in items:
                member = tarfile.TarInfo("blobs/sha256/" + key.split(":")[1])
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        popen = subprocess.Popen

        def launch(command, **kwargs):
            self.assertEqual(command, ["docker", "image", "save", reference])
            return popen(
                [
                    sys.executable,
                    "-c",
                    "import pathlib,sys,time;time.sleep(float(sys.argv[2]));"
                    "sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes())",
                    str(path),
                    str(delay),
                ],
                **kwargs,
            )

        return launch

    def image(self, metadata, *, classic=False):
        reference, digest, configuration, _manifest, _config = metadata
        return {
            "Id": configuration if classic else digest,
            "RepoDigests": [reference],
            "Os": "linux",
            "Architecture": "amd64",
            "Descriptor": {"digest": digest, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
        }

    def test_classic_requires_the_exact_configuration_without_export(self):
        metadata = self.metadata()
        with (
            patch.object(self.module, "_docker", return_value=json.dumps([self.image(metadata, classic=True)])),
            patch.object(self.module, "_verify_oci_export") as export,
        ):
            self.assertEqual(self.module.verified_image_id(metadata[0], metadata[2]), metadata[2])
            export.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "real bounded public export process")
    def test_oci_raw_hash_join_and_same_context_cache(self):
        metadata = self.metadata()
        with (
            patch.object(self.module, "_docker", return_value=json.dumps([self.image(metadata)])),
            patch.object(self.module, "_daemon_context", return_value=("public-daemon", "public-context")),
            patch.object(self.module.subprocess, "Popen", side_effect=self.export(metadata)) as child,
        ):
            self.assertEqual(self.module.verified_image_id(metadata[0], metadata[2]), metadata[1])
            self.assertEqual(self.module.verified_image_id(metadata[0], metadata[2]), metadata[1])
            self.assertEqual(child.call_count, 1)
        self.assertEqual(len(self.module._VERIFIED_IMAGES), 1)

    @unittest.skipUnless(sys.platform == "linux", "real bounded public export process")
    def test_missing_duplicate_wrong_join_or_platform_refuses(self):
        for case in ("missing", "duplicate", "join", "platform"):
            metadata = self.metadata(wrong_join=case == "join", wrong_platform=case == "platform")
            with (
                self.subTest(case=case),
                patch.object(
                    self.module.subprocess,
                    "Popen",
                    side_effect=self.export(metadata, missing=case == "missing", duplicate=case == "duplicate"),
                ),
                self.assertRaises(ValueError),
            ):
                self.module._verify_oci_export(metadata[0], metadata[1], metadata[2])

    @unittest.skipUnless(sys.platform == "linux", "real bounded public export process")
    def test_stream_census_and_metadata_caps_refuse(self):
        metadata = self.metadata()
        for limit, value in (("_EXPORT_BYTES", 4096), ("_EXPORT_MEMBERS", 1), ("_METADATA_BYTES", 4)):
            with (
                self.subTest(limit=limit),
                patch.object(self.module, limit, value),
                patch.object(self.module.subprocess, "Popen", side_effect=self.export(metadata)),
                self.assertRaises(ValueError),
            ):
                self.module._verify_oci_export(metadata[0], metadata[1], metadata[2])

    @unittest.skipUnless(sys.platform == "linux", "real bounded public export process")
    def test_export_deadline_refuses_and_reaps_the_own_child(self):
        metadata = self.metadata()
        processes = []
        launch = self.export(metadata, delay=0.3)

        def capture(*args, **kwargs):
            process = launch(*args, **kwargs)
            processes.append(process)
            return process

        with (
            patch.object(self.module, "_EXPORT_SECONDS", 0.05, create=True),
            patch.object(self.module.subprocess, "Popen", side_effect=capture),
            self.assertRaises(TimeoutError),
        ):
            self.module._verify_oci_export(metadata[0], metadata[1], metadata[2])
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].returncode)

    def test_changed_or_unrelated_inspect_identity_never_uses_a_cached_alias(self):
        metadata = self.metadata()
        image = self.image(metadata)
        for field in ("Id", "RepoDigests", "Os", "Architecture", "Descriptor"):
            changed = copy.deepcopy(image)
            changed[field] = {
                "Id": "sha256:" + "f" * 64,
                "RepoDigests": [],
                "Os": "windows",
                "Architecture": "arm64",
                "Descriptor": {},
            }[field]
            with (
                self.subTest(field=field),
                patch.object(self.module, "_docker", return_value=json.dumps([changed])),
                patch.object(self.module, "_verify_oci_export") as export,
                self.assertRaises(ValueError),
            ):
                self.module.verified_image_id(metadata[0], metadata[2])
            export.assert_not_called()


class OwnedPostgresControls(unittest.TestCase):
    def module(self):
        self.assertIsNotNone(
            importlib.util.find_spec("getzilla.disposable_resources"),
            "exact owned PostgreSQL resource implementation must exist",
        )
        return importlib.import_module("getzilla.disposable_resources")

    def fixture(self):
        module = self.module()
        identity = patch.object(
            module,
            "_process_identity",
            return_value={"pid": os.getpid(), "start": "public-start", "boot": "public-boot"},
        )
        identity.start()
        self.addCleanup(identity.stop)
        affinity = patch.object(module.os, "sched_getaffinity", return_value={0, 1}, create=True)
        affinity.start()
        self.addCleanup(affinity.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        engine = DockerDouble()
        patched = patch.object(module.subprocess, "run", side_effect=engine)
        patched.start()
        self.addCleanup(patched.stop)
        return module, module.OwnedDocker(Path(temporary.name) / "owner.json", "gz-public"), engine

    def test_dotted_mount_is_readonly_and_allocation_is_exact(self):
        _module, owner, engine = self.fixture()
        with tempfile.TemporaryDirectory() as raw:
            owner.container("db", PIN, configuration_digest=IMAGE_ID, bind={Path(raw): "/docker-entrypoint-initdb.d"})
        commands = [c for c in engine.commands if c[1] == "run"]
        self.assertEqual(len(commands), 1)
        self.assertIn("target=/docker-entrypoint-initdb.d,readonly", commands[0][commands[0].index("--mount") + 1])

    def test_noncanonical_mounts_never_allocate(self):
        _module, owner, engine = self.fixture()
        for target in ("relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a,readonly", "//a", "/"):
            with tempfile.TemporaryDirectory() as raw, self.subTest(target=target), self.assertRaises(ValueError):
                owner.container(
                    "bad" + str(len(owner.resources)), PIN, configuration_digest=IMAGE_ID, bind={Path(raw): target}
                )
        self.assertFalse(any(c[1] == "run" for c in engine.commands))

    def test_manifest_and_image_configuration_must_match(self):
        module, owner, engine = self.fixture()
        with self.assertRaises(ValueError):
            owner.container("mutable", "postgres:17-alpine", configuration_digest=IMAGE_ID)
        self.assertFalse(any(c[1] == "run" for c in engine.commands))
        with patch.object(module, "_docker", return_value=json.dumps([{"Id": IMAGE_ID, "RepoDigests": []}])):
            with self.assertRaises(ValueError):
                owner.container("wrong", PIN, configuration_digest=IMAGE_ID)

    def test_container_explicitly_keeps_the_controller_cpuset(self):
        _module, owner, engine = self.fixture()
        owner.container("db", PIN, configuration_digest=IMAGE_ID)
        command = next(c for c in engine.commands if c[1] == "run")
        self.assertIn("--cpuset-cpus", command)
        cpus = {int(v) for v in command[command.index("--cpuset-cpus") + 1].split(",")}
        self.assertEqual(cpus, os.sched_getaffinity(0))

    def endpoint_fixture(self):
        module, owner, engine = self.fixture()
        network = owner.network("internal")
        item = owner.container("db", PIN, configuration_digest=IMAGE_ID, network=network)
        args = dict(
            container_id=item["id"],
            container_name=item["name"],
            image=PIN,
            image_id=IMAGE_ID,
            nonce=owner.nonce,
            namespace=owner.namespace,
            network_id=network["identity"]["Id"],
        )
        return module, owner, engine, network, item, args

    def test_exact_owned_internal_endpoint_has_no_published_port(self):
        module, _owner, engine, _network, _item, args = self.endpoint_fixture()
        self.assertEqual(module.internal_postgres_endpoint(**args), ("172.28.0.2", 5432))
        self.assertFalse(any("--publish" in c for c in engine.commands))

    def test_endpoint_refuses_wrong_owner_and_published_connectivity(self):
        for field in ("nonce", "published", "network", "ip"):
            with self.subTest(field=field):
                module, _owner, engine, network, item, args = self.endpoint_fixture()
                container = engine.items["container"][item["id"]]
                if field == "nonce":
                    container["Config"]["Labels"]["getzilla.ci.nonce"] = "f" * 32
                elif field == "published":
                    container["HostConfig"]["PortBindings"] = {"5432/tcp": [{"HostIp": "0.0.0.0", "HostPort": "5432"}]}
                elif field == "network":
                    engine.items["network"][network["name"]]["Internal"] = False
                else:
                    container["NetworkSettings"]["Networks"][network["name"]]["IPAddress"] = "172.28.9.9"
                with self.assertRaises(ValueError):
                    module.internal_postgres_endpoint(**args)

    def test_cleanup_requires_independent_absence_and_never_deletes_changed_owner(self):
        module, owner, engine = self.fixture()
        item = owner.container("db", PIN, configuration_digest=IMAGE_ID)
        engine.lie_about_removal = True
        with self.assertRaises(module.CleanupUnconfirmed):
            owner.cleanup()
        self.assertNotEqual(owner.cleanup_status, "removed")
        engine.lie_about_removal = False
        engine.items["container"][item["id"]]["Config"]["Labels"]["getzilla.ci.nonce"] = "f" * 32
        removed = list(engine.removed)
        with self.assertRaises(module.CleanupUnconfirmed):
            owner.cleanup()
        self.assertEqual(engine.removed, removed)

    def test_cleanup_of_exact_owned_closure_is_idempotent(self):
        _module, owner, engine = self.fixture()
        network = owner.network("internal")
        volume = owner.volume("data")
        owner.container("db", PIN, configuration_digest=IMAGE_ID, network=network, volume=volume)
        owner.cleanup()
        owner.cleanup()
        self.assertEqual(owner.cleanup_status, "removed")
        self.assertTrue(all(not v for v in engine.items.values()))


class SafePhaseDiagnostics(unittest.TestCase):
    def test_allowed_docker_operation_does_not_export_secret_arguments_or_output(self):
        path = ROOT / "factory/tests/run_disposable_exit.py"
        spec = importlib.util.spec_from_file_location("public_factory_runner", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        error = subprocess.CalledProcessError(
            17,
            ["docker", "network", "create", "public-sentinel-password"],
            output="public-sentinel-output",
            stderr="public-sentinel-error",
        )
        detail = module._error_detail(error)
        self.assertIn("operation=docker.network.create", detail)
        self.assertIn("exit=17", detail)
        self.assertNotIn("sentinel", detail)


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
        if args[:2] == ["info", "--format"]:
            return subprocess.CompletedProcess(command, 0, "public-unit-daemon", "")
        if args[:2] == ["image", "inspect"]:
            value = [{"Id": IMAGE_ID, "RepoDigests": [PIN], "Os": "linux", "Architecture": "amd64"}]
        elif args[:2] == ["volume", "create"] or args[:2] == ["network", "create"]:
            kind = args[0]
            name = args[-1]
            labels = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "--label")
            value = {
                "Name": name,
                "Labels": labels,
                "Driver": "local" if kind == "volume" else "bridge",
                "CreatedAt": "2026-11-03T00:00:00Z",
                "Options": {},
                "Mountpoint": "/var/lib/docker/volumes/" + name,
                "Containers": {},
            }
            if kind == "network":
                value["Id"] = f"{self.next_id:064x}"
                value.update(
                    Internal="--internal" in args,
                    Scope="local",
                    Ingress=False,
                    IPAM={"Config": [{"Subnet": "172.28.0.0/16", "Gateway": "172.28.0.1"}]},
                )
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
                parts = dict(x.split("=", 1) if "=" in x else (x, "true") for x in args[index + 1].split(","))
                mounts.append(
                    {
                        "Type": parts["type"],
                        "Name": parts["source"] if parts["type"] == "volume" else None,
                        "Source": parts["source"],
                        "Destination": parts["target"],
                        "RW": "readonly" not in parts,
                    }
                )
            value = {
                "Id": identifier,
                "Name": "/" + name,
                "Image": IMAGE_ID,
                "Config": {"Image": PIN, "Labels": labels},
                "Mounts": mounts,
                "State": {"Running": True},
                "NetworkSettings": {"Networks": {}, "Ports": {}},
                "HostConfig": {"NetworkMode": "default", "PortBindings": {}, "AutoRemove": False},
            }
            if "--network" in args:
                network_name = args[args.index("--network") + 1]
                network = self.items["network"][network_name]
                endpoint_id = f"{self.next_id + 1000:064x}"
                address = f"172.28.0.{len(network['Containers']) + 2}"
                value["HostConfig"]["NetworkMode"] = network_name
                value["NetworkSettings"]["Networks"][network_name] = {
                    "NetworkID": network["Id"],
                    "EndpointID": endpoint_id,
                    "IPAddress": address,
                    "IPPrefixLen": 16,
                    "Gateway": "",
                }
                network["Containers"][identifier] = {
                    "Name": name,
                    "EndpointID": endpoint_id,
                    "IPv4Address": address + "/16",
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

class RawArchiveCensusTests(unittest.TestCase):
    def module(self):
        return importlib.import_module('getzilla.disposable_resources')

    def record(self, name, content=b'', kind=tarfile.REGTYPE):
        item = tarfile.TarInfo(name)
        item.type, item.size = kind, len(content)
        return item.tobuf(format=tarfile.USTAR_FORMAT) + content + b'\0' * (-len(content) % 512)

    def archive(self, raw_count=4, kind=tarfile.XHDTYPE):
        config = json.dumps({'os': 'linux', 'architecture': 'amd64'}).encode()
        config_id = 'sha256:' + hashlib.sha256(config).hexdigest()
        manifest = json.dumps({'config': {'digest': config_id, 'size': len(config)}}).encode()
        manifest_id = 'sha256:' + hashlib.sha256(manifest).hexdigest()
        body = 'comment=public\n'
        length = len(body) + 2
        while length != len(str(length)) + 1 + len(body):
            length = len(str(length)) + 1 + len(body)
        pax = (str(length) + ' ' + body).encode()
        extension = self.record('PaxHeaders/public', pax, kind)
        if kind == tarfile.GNUTYPE_LONGNAME:
            extension = self.record('././@LongLink', b'public-name\0', kind)
        groups = min(100, max(1, (raw_count - 2) // 2))
        extra, remainder = divmod(raw_count - 2 - groups, groups)
        content = b''.join(extension * (extra + (index < remainder)) + self.record('public-' + str(index))
                           for index in range(groups))
        content += self.record('blobs/sha256/' + manifest_id[7:], manifest)
        content += self.record('blobs/sha256/' + config_id[7:], config)
        return content + b'\0' * 1024, manifest_id, config_id

    def verify(self, archive):
        module = self.module()
        data, manifest, config = archive
        source = io.BytesIO(data)
        class Output(io.BytesIO):
            def fileno(self):
                return 73
        class Child:
            pid = 123
            stdout = Output()
            def poll(self):
                return 0
            def wait(self, timeout=None):
                return 0
        class Selector:
            def register(self, *args):
                pass
            def select(self, timeout):
                return [(None, None)]
            def close(self):
                pass
        child = Child()
        try:
            with patch.object(module.subprocess, 'Popen', return_value=child), \
                    patch.object(module.selectors, 'DefaultSelector', return_value=Selector()), \
                    patch.object(module.os, 'read', side_effect=lambda _fd, size: source.read(size)):
                module._verify_oci_export('public@' + manifest, manifest, config)
        finally:
            self.last_stream_read = source.tell()
            self.assertTrue(child.stdout.closed)
        return source.tell()

    def test_raw_pax_boundary_and_normal_pax_positive(self):
        self.verify(self.archive(4))
        self.verify(self.archive(4096))
        with self.assertRaises(ValueError):
            self.verify(self.archive(4097))
        with self.assertRaises(ValueError):
            self.verify(self.archive(5102))

    def test_5102_raw_headers_cannot_hide_behind_102_members(self):
        with self.assertRaises(ValueError):
            self.verify(self.archive(5102))

    def test_hidden_global_pax_and_gnu_longname_are_counted(self):
        for kind in (tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind):
                self.verify(self.archive(4, kind))
                with self.assertRaises(ValueError):
                    self.verify(self.archive(4097, kind))

    def test_extension_body_limit_and_sparse_refuse_before_delegation(self):
        good, manifest, config = self.archive(4)
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME):
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    self.verify((self.record('extension', b'\0' * (1024 * 1024 + 1), kind) + good, manifest, config))
                self.assertLessEqual(self.last_stream_read, 10240)
        with self.assertRaises(ValueError):
            self.verify((self.record('public-sparse', kind=tarfile.GNUTYPE_SPARSE) + good, manifest, config))
        for fields in ({"GNU.sparse.map": "0,0"}, {"GNU.sparse.size": "0"},
                       {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}):
            header = tarfile.TarInfo("public-sparse")
            header.pax_headers = fields
            archive = header.tobuf(format=tarfile.PAX_FORMAT) + good
            with self.subTest(format=tuple(fields)), self.assertRaisesRegex(ValueError, "sparse archive format"):
                self.verify((archive, manifest, config))
            self.assertLessEqual(self.last_stream_read, 10240)
