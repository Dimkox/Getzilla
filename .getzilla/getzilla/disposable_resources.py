"""Bounded, identity-bound Docker resources for disposable CI acceptance only.

The journal is an observation, never authority by itself. Every deletion checks
the live object, and a successful independent list must confirm its absence.
"""
from __future__ import annotations

import json
import ipaddress
import hashlib
from contextvars import ContextVar
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import subprocess
import tarfile
import time
import uuid

_PIN = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,100}\Z")
_ID = re.compile(r"[0-9a-f]{64}\Z")
_DEADLINE = ContextVar("disposable_cleanup_deadline", default=None)
_VERIFIED_IMAGES = set()
_EXPORT_BYTES = 1024 * 1024 * 1024
_METADATA_BYTES = 1024 * 1024
_EXPORT_MEMBERS = 4096
_EXPORT_SECONDS = 90


def _daemon_context():
    identity = _docker("info", "--format", "{{.ID}}")
    if not re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", identity):
        raise ValueError("Docker daemon identity is unavailable")
    context = tuple(os.environ.get(key, "") for key in (
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"))
    return identity, hashlib.sha256(repr(context).encode()).hexdigest()


def _verify_oci_export(reference, manifest_digest, configuration_digest):
    """Verify raw local metadata; never extract archive paths or retain layers."""
    deadline = time.monotonic() + _EXPORT_SECONDS
    process = subprocess.Popen(["docker", "image", "save", reference], stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)

    class Reader:
        total = 0

        def read(self, size):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise TimeoutError("Public image metadata verification deadline")
            data = os.read(process.stdout.fileno(), min(size, 65536))
            self.total += len(data)
            if self.total > _EXPORT_BYTES:
                raise ValueError("Public image metadata export exceeds byte bound")
            return data

    class CountedTarInfo(tarfile.TarInfo):
        # CPython dispatches each raw header here, including recursive
        # PAX/GNU extension reads hidden from TarFile iteration. Count before
        # the parser consumes their bodies; a yielded-member census is not raw.
        raw_headers = 0

        def _proc_member(self, archive):
            type(self).raw_headers += 1
            if type(self).raw_headers > _EXPORT_MEMBERS:
                raise ValueError("Public image archive exceeds raw header bound")
            if self.type == tarfile.GNUTYPE_SPARSE:
                raise ValueError("Public image sparse archive format is unsupported")
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                             tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                if self.size > _METADATA_BYTES:
                    raise ValueError("Public image extension metadata exceeds byte bound")
            return super()._proc_member(archive)

        def _unsupported_sparse(self, *args, **kwargs):
            raise ValueError("Public image sparse archive format is unsupported")

        # PAX sparse maps have separate continuation/body rules. Refuse before
        # those processors consume blocks that are not counted tar headers.
        _proc_gnusparse_00 = _unsupported_sparse
        _proc_gnusparse_01 = _unsupported_sparse
        _proc_gnusparse_10 = _unsupported_sparse

    wanted = {"blobs/sha256/" + digest.split(":")[1]: digest
              for digest in (manifest_digest, configuration_digest)}
    metadata = {}
    try:
        with tarfile.open(fileobj=Reader(), mode="r|", tarinfo=CountedTarInfo) as archive:
            for count, member in enumerate(archive, 1):
                parts = PurePosixPath(member.name).parts
                if (count > _EXPORT_MEMBERS or not parts or member.name.startswith("/")
                        or ".." in parts or "\\" in member.name
                        or not (member.isfile() or member.isdir())
                        or member.size > _EXPORT_BYTES):
                    raise ValueError("Public image archive structure is unsupported")
                digest = wanted.get(member.name)
                if digest is None:
                    continue
                if digest in metadata or not member.isfile() or member.size > _METADATA_BYTES:
                    raise ValueError("Public image metadata is missing or ambiguous")
                content = archive.extractfile(member).read()
                if "sha256:" + hashlib.sha256(content).hexdigest() != digest:
                    raise ValueError("Public image metadata digest mismatch")
                metadata[digest] = content
        if process.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise ValueError("Public image metadata export failed")
        if set(metadata) != {manifest_digest, configuration_digest}:
            raise ValueError("Public image metadata closure is incomplete")
        manifest = json.loads(metadata[manifest_digest])
        config = json.loads(metadata[configuration_digest])
        if (manifest["config"]["digest"] != configuration_digest
                or manifest["config"]["size"] != len(metadata[configuration_digest])
                or config["os"] != "linux" or config["architecture"] != "amd64"):
            raise ValueError("Public image manifest/configuration/platform mismatch")
    except (KeyError, TypeError, tarfile.TarError, json.JSONDecodeError) as error:
        raise ValueError("Public image metadata closure is malformed") from error
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)


def verified_image_id(reference, configuration_digest):
    """Join immutable manifest/config pins to this engine's observed identity."""
    if not _PIN.fullmatch(reference) or not re.fullmatch(r"sha256:[0-9a-f]{64}", configuration_digest):
        raise ValueError("Immutable image manifest/configuration pins are required")
    images = json.loads(_docker("image", "inspect", reference))
    if len(images) != 1:
        raise ValueError("Image observation is ambiguous")
    image = images[0]
    if (reference not in (image.get("RepoDigests") or [])
            or image.get("Os") != "linux" or image.get("Architecture") != "amd64"):
        raise ValueError("Pinned image reference or platform mismatch")
    identifier = image["Id"]
    manifest_digest = reference.split("@")[1]
    if identifier == configuration_digest:
        return identifier
    descriptor = image.get("Descriptor") or {}
    if (identifier != manifest_digest or descriptor.get("digest") != manifest_digest
            or descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"):
        raise ValueError("Image configuration identity mismatch")
    context = _daemon_context()
    key = (context, reference, configuration_digest, identifier)
    if key not in _VERIFIED_IMAGES:
        _verify_oci_export(reference, manifest_digest, configuration_digest)
        # The daemon, context and image must still match after export.
        if _daemon_context() != context or json.loads(_docker("image", "inspect", reference)) != images:
            raise ValueError("Image identity changed during raw verification")
        _VERIFIED_IMAGES.add(key)
    return identifier


def process_error_detail(error: BaseException | None) -> str:
    """Describe control flow without exposing exception text, argv or output."""
    if error is None:
        return "error=none"
    kind = type(error).__name__
    if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", kind) is None:
        kind = "BaseException"
    detail = f"error={kind}"
    if isinstance(error, subprocess.CalledProcessError) and type(error.returncode) is int:
        code = error.returncode
        detail += f" signal={-code}" if code < 0 else f" exit={code}"
    elif isinstance(error, subprocess.TimeoutExpired):
        if type(error.timeout) in (int, float) and 0 <= error.timeout < float("inf"):
            detail += f" timeout_seconds={error.timeout}"
    elif isinstance(error, KeyboardInterrupt):
        detail += " signal=2"
    elif isinstance(error, SystemExit) and type(error.code) is int:
        detail += f" exit={error.code}"
    command = getattr(error, "cmd", None)
    if isinstance(command, (list, tuple)) and len(command) >= 2 and command[0] == "docker":
        operation = None
        if command[1] in {"run", "exec", "port", "inspect", "restart", "rm"}:
            operation = command[1]
        elif (len(command) >= 3 and command[1] in {"image", "container", "network", "volume"}
                and command[2] in {"inspect", "create", "ls", "rm"}):
            operation = command[1] + "." + command[2]
        if operation is not None:
            detail += " operation=docker." + operation
    return detail


def _process_identity(pid: int) -> dict:
    current = Path("/proc/self/stat").read_text(encoding="utf-8")
    if int(current.split(" ", 1)[0]) != os.getpid():
        raise CleanupUnconfirmed("Process and procfs namespaces disagree; resource ownership cannot be established")
    value = current if pid == os.getpid() else Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = value[value.rfind(")") + 2:].split()
    return {"pid": pid, "start": fields[19], "boot": Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()}


class CleanupUnconfirmed(RuntimeError):
    """A resource remains, changed identity, or could not be observed."""


def image_pins(root: Path) -> dict:
    data = json.loads((root / ".getzilla/config/ci-images.json").read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or data.get("platform") != "linux/amd64":
        raise ValueError("Unknown CI image configuration")
    for key in ("postgres", "python"):
        if not _PIN.fullmatch(data[key]["reference"]) or not re.fullmatch(r"sha256:[0-9a-f]{64}", data[key]["image_id"]):
            raise ValueError("CI image must bind both manifest and configuration digest")
    return data


def ensure_images(root: Path, names=("postgres", "python")) -> None:
    pins = image_pins(root)
    for name in names:
        pin = pins[name]
        try:
            _docker("image", "inspect", pin["reference"])
        except subprocess.CalledProcessError:
            subprocess.run(["docker", "pull", "--platform", "linux/amd64", pin["reference"]],
                           check=True, timeout=120)
        verified_image_id(pin["reference"], pin["image_id"])


def _docker(*args: str, timeout: int = 30) -> str:
    deadline = _DEADLINE.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CleanupUnconfirmed("Cleanup deadline exhausted; no additional Docker operation authorized")
        timeout = min(timeout, remaining)
    return subprocess.run(["docker", *args], check=True, capture_output=True,
                          text=True, encoding="utf-8", timeout=timeout).stdout.strip()


def _inspect(kind: str, key: str) -> dict:
    items = json.loads(_docker(kind, "inspect", key))
    if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
        raise ValueError("Docker inspect did not identify one object")
    return items[0]


def _canonical_mounts(mounts):
    """Mount ordering is not identity; every entry and field remains significant."""
    if not isinstance(mounts, list) or any(not isinstance(item, dict) for item in mounts):
        raise ValueError("Invalid container mount identity")
    return sorted(mounts, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))


def _identity(kind: str, value: dict) -> dict:
    if kind == "container":
        return {"id": value["Id"], "name": value["Name"].removeprefix("/"),
                "image_id": value["Image"], "image": value["Config"]["Image"],
                "labels": value["Config"].get("Labels") or {},
                "mounts": _canonical_mounts([
                    {key: item.get(key) for key in ("Type", "Name", "Source", "Destination")}
                    for item in value.get("Mounts", [])])}
    result = {key: value.get(key) for key in ("Name", "Labels", "Driver", "Options")}
    if kind == "volume":
        result.update({key: value.get(key) for key in ("CreatedAt", "Mountpoint")})
    else:
        result["Id"] = value["Id"]
    return result


def _absolute_posix_path(value: str) -> bool:
    """Validate the raw mount value without normalizing traversal or CSV syntax."""
    return (isinstance(value, str) and value.startswith("/") and len(value) <= 4096
            and all(part not in ("", ".", "..") and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
                    for part in value.split("/")[1:]))


def internal_postgres_endpoint(*, container_id: str, container_name: str, image: str,
                               image_id: str, nonce: str, namespace: str, network_id: str) -> tuple[str, int]:
    """Read one exact owned endpoint; private address membership alone grants nothing.

    Internal bridge ports need not be published by Docker. The host can reach its
    bridge directly. Retain container/network identity on both sides of the read;
    the caller must still verify the PostgreSQL cluster before mutation/restart.
    """
    if (not _ID.fullmatch(container_id) or not _ID.fullmatch(network_id)
            or not _NAME.fullmatch(container_name) or not _NAME.fullmatch(namespace)
            or not container_name.startswith(namespace + "-")
            or not re.fullmatch(r"[0-9a-f]{32}", nonce) or not _PIN.fullmatch(image)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)):
        raise ValueError("Invalid owned PostgreSQL endpoint identity")
    expected_labels = {"getzilla.ci.namespace": namespace, "getzilla.ci.nonce": nonce}
    engine_image_id = verified_image_id(image, image_id)

    def read_binding():
        container = _inspect("container", container_id)
        network = _inspect("network", network_id)
        if (container["Id"] != container_id or container["Name"] != "/" + container_name
                or container["Config"]["Image"] != image or container["Image"] != engine_image_id
                or container["State"]["Running"] is not True
                or any(container["Config"]["Labels"].get(key) != value for key, value in expected_labels.items())
                or network["Id"] != network_id or network["Driver"] != "bridge"
                or network["Internal"] is not True or network["Scope"] != "local"
                or network.get("Ingress", False) is not False
                or not _NAME.fullmatch(network["Name"]) or not network["Name"].startswith(namespace + "-")
                or any(network["Labels"].get(key) != value for key, value in expected_labels.items())):
            raise ValueError("PostgreSQL container or internal network identity changed")
        host = container["HostConfig"]
        settings = container["NetworkSettings"]
        if (host["NetworkMode"] not in (network_id, network["Name"])
                or host.get("PortBindings") not in ({}, None)
                or not isinstance(settings.get("Ports"), dict)
                or any(binding not in (None, []) for binding in settings["Ports"].values())
                or set(settings["Networks"]) != {network["Name"]}):
            raise ValueError("PostgreSQL endpoint has additional or published connectivity")
        endpoint = settings["Networks"][network["Name"]]
        member = network["Containers"][container_id]
        address = ipaddress.IPv4Address(endpoint["IPAddress"])
        prefix = endpoint["IPPrefixLen"]
        if (not address.is_private or address.is_loopback or address.is_link_local
                or address.is_multicast or address.is_reserved or address.is_unspecified
                or str(address) != endpoint["IPAddress"] or type(prefix) is not int
                or endpoint["NetworkID"] != network_id or not _ID.fullmatch(endpoint["EndpointID"])
                or member["Name"] != container_name or member["EndpointID"] != endpoint["EndpointID"]
                or member["IPv4Address"] != f"{address}/{prefix}"):
            raise ValueError("PostgreSQL endpoint does not match its live network membership")
        matching_subnet = False
        for config in network["IPAM"]["Config"]:
            subnet = ipaddress.ip_network(config["Subnet"], strict=True)
            if subnet.version != 4:
                continue
            if (address in subnet and prefix == subnet.prefixlen
                    and address not in (subnet.network_address, subnet.broadcast_address)
                    # Moby omits the endpoint's default gateway for internal
                    # networks; IPAM still records the host bridge address.
                    and endpoint.get("Gateway") in (None, "", config.get("Gateway"))
                    and str(address) != config.get("Gateway")):
                matching_subnet = True
        if not matching_subnet:
            raise ValueError("PostgreSQL endpoint is outside the exact owned network subnet")
        return (str(address), _identity("container", container), _identity("network", network),
                endpoint, member, network["IPAM"])

    try:
        first = read_binding()
        if read_binding() != first:
            raise ValueError("PostgreSQL endpoint changed during observation")
        return first[0], 5432
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("Incomplete owned PostgreSQL endpoint observation") from error


class OwnedDocker:
    def __init__(self, manifest: Path, namespace: str):
        if not _NAME.fullmatch(namespace):
            raise ValueError("Unsafe disposable namespace")
        self.manifest = Path(manifest)
        if self.manifest.exists() or self.manifest.is_symlink():
            raise ValueError("A new ownership journal must not replace an existing one")
        self.namespace = namespace
        self.nonce = uuid.uuid4().hex
        self.resources: list[dict] = []
        self.owner_process = _process_identity(os.getpid())
        self.cleanup_status = "not_run"
        self.engine_context = _daemon_context()
        self._save()

    @classmethod
    def recover(cls, manifest: Path):
        """Called only by the observer after it confirms its child has exited."""
        path = Path(manifest)
        if path.is_symlink() or path.stat().st_size > 1024 * 1024:
            raise ValueError("Unsafe ownership journal")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != "getzilla-disposable-owner-v1":
            raise ValueError("Unknown ownership journal")
        if not _NAME.fullmatch(data.get("namespace", "")) or not re.fullmatch(r"[0-9a-f]{32}", data.get("nonce", "")):
            raise ValueError("Invalid ownership identity")
        instance = cls.__new__(cls)
        instance.manifest, instance.namespace, instance.nonce = path, data["namespace"], data["nonce"]
        instance.resources = data["resources"]
        instance.cleanup_status = data["cleanup_status"]
        instance.owner_process = data["owner_process"]
        instance.engine_context = tuple(data["engine_context"])
        if instance.engine_context != _daemon_context():
            raise CleanupUnconfirmed("Docker daemon or context differs from resource allocation")
        owner = instance.owner_process
        if type(owner.get("pid")) is not int or owner["pid"] <= 0:
            raise ValueError("Invalid allocator identity")
        if owner.get("boot") != Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip():
            raise CleanupUnconfirmed("Allocator boot identity is unavailable")
        try:
            if _process_identity(owner["pid"]) == owner:
                raise CleanupUnconfirmed("Allocator is still alive; recovery would race allocation")
        except FileNotFoundError:
            pass
        for item in instance.resources:
            if (item.get("kind") not in ("container", "volume", "network")
                    or not _NAME.fullmatch(item.get("name", ""))
                    or not item.get("name", "").startswith(instance.namespace + "-")):
                raise ValueError("Resource outside ownership namespace")
            if "id" in item and not _ID.fullmatch(item["id"]):
                raise ValueError("Invalid full container identity")
        return instance

    @property
    def labels(self):
        return {"getzilla.ci.namespace": self.namespace, "getzilla.ci.nonce": self.nonce}

    def _save(self):
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        data = {"schema": "getzilla-disposable-owner-v1", "namespace": self.namespace,
                "nonce": self.nonce, "resources": self.resources, "cleanup_status": self.cleanup_status,
                "owner_process": self.owner_process, "engine_context": self.engine_context}
        temporary = self.manifest.with_name(self.manifest.name + "." + uuid.uuid4().hex)
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                os.chmod(temporary, 0o600)
                json.dump(data, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.manifest)
        finally:
            temporary.unlink(missing_ok=True)

    def _intent(self, kind: str, suffix: str, **extra):
        if _daemon_context() != self.engine_context:
            raise CleanupUnconfirmed("Docker daemon or context changed before allocation")
        name = f"{self.namespace}-{suffix}"
        if not _NAME.fullmatch(name) or any(item["name"] == name and item["kind"] == kind for item in self.resources):
            raise ValueError("Invalid or repeated resource name")
        item = {"kind": kind, "name": name, "status": "pending", **extra}
        self.resources.append(item)
        self._save()
        return item

    def _labels(self):
        return [part for key, value in self.labels.items() for part in ("--label", f"{key}={value}")]

    def _bind(self, item, key):
        value = _inspect(item["kind"], key)
        identity = _identity(item["kind"], value)
        labels = identity.get("labels", identity.get("Labels")) or {}
        if any(labels.get(key) != val for key, val in self.labels.items()):
            raise ValueError("New resource did not retain ownership labels")
        if identity.get("name", identity.get("Name")) != item["name"]:
            raise ValueError("New resource name differs from intent")
        if item["kind"] == "container":
            if identity["name"] != item["name"] or identity["image"] != item["image"] or identity["image_id"] != item["image_id"]:
                raise ValueError("New container identity differs from intent")
            item["id"] = identity["id"]
        item["identity"], item["status"] = identity, "bound"
        self._save()
        return item

    def volume(self, suffix: str):
        item = self._intent("volume", suffix)
        _docker("volume", "create", *self._labels(), item["name"])
        return self._bind(item, item["name"])

    def network(self, suffix: str):
        item = self._intent("network", suffix)
        _docker("network", "create", "--internal", *self._labels(), item["name"])
        return self._bind(item, item["name"])



    def container(self, suffix: str, image: str, *, configuration_digest, volume=None, network=None,
                  publish_postgres=False, environment=None, command=(),
                  volume_target="/var/lib/postgresql/data", bind=None, alias=None, working_directory=None):
        if not _PIN.fullmatch(image):
            raise ValueError("Disposable containers require an immutable image digest")
        image_id = verified_image_id(image, configuration_digest)
        item = self._intent("container", suffix, image=image, image_id=image_id,
                            configuration_digest=configuration_digest)
        # Docker's daemon does not inherit this controller's affinity.
        cpus = sorted(os.sched_getaffinity(0))
        if not cpus:
            raise ValueError("Disposable CPU allocation is unavailable")
        arguments = ["run", "--detach", "--name", item["name"], "--cpus", "1",
                     "--cpuset-cpus", ",".join(map(str, cpus)), "--memory", "512m",
                     "--memory-swap", "512m", *self._labels()]
        if volume:
            if volume not in self.resources or volume["kind"] != "volume":
                raise ValueError("Volume is not owned by this run")
            if not _absolute_posix_path(volume_target):
                raise ValueError("Unsafe container volume target")
            arguments += ["--mount", f"type=volume,source={volume['name']},target={volume_target}"]
        for source, destination in (bind or {}).items():
            source = Path(source).resolve(strict=True)
            if "," in str(source) or not _absolute_posix_path(destination):
                raise ValueError("Unsafe read-only source mount")
            arguments += ["--mount", f"type=bind,source={source},target={destination},readonly"]
        if network:
            if network not in self.resources or network["kind"] != "network":
                raise ValueError("Network is not owned by this run")
            arguments += ["--network", network["name"]]
        if alias:
            if not _NAME.fullmatch(alias) or not network:
                raise ValueError("Invalid internal network alias")
            arguments += ["--network-alias", alias]
        if working_directory:
            if not _absolute_posix_path(working_directory):
                raise ValueError("Unsafe container work directory")
            arguments += ["--workdir", working_directory]
        if publish_postgres:
            arguments += ["--publish", "127.0.0.1::5432"]
        for key, value in (environment or {}).items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
                raise ValueError("Invalid container environment key")
            arguments += ["--env", f"{key}={value}"]
        identifier = _docker(*arguments, image, *command, timeout=60)
        if not _ID.fullmatch(identifier):
            raise ValueError("Docker did not return a full container ID")
        return self._bind(item, identifier)

    def _present(self, item):
        kind = item["kind"]
        if kind == "container":
            keys = _docker(kind, "ls", "--all", "--no-trunc", "--format", "{{.ID}}").splitlines()
            if item.get("id"):
                return item["id"] in keys
            # The create call may have succeeded before its ID was persisted.
            names = _docker(kind, "ls", "--all", "--format", "{{.Names}}").splitlines()
            return item["name"] in names
        return item["name"] in _docker(kind, "ls", "--format", "{{.Name}}").splitlines()

    def cleanup(self, *, deadline=None):
        limit = time.monotonic() + 60
        if deadline is not None:
            limit = min(limit, deadline)
        if _DEADLINE.get() is not None:
            limit = min(limit, _DEADLINE.get())
        token = _DEADLINE.set(limit)
        try:
            self._cleanup()
        finally:
            _DEADLINE.reset(token)

    def _cleanup(self):
        if _daemon_context() != self.engine_context:
            raise CleanupUnconfirmed("Docker daemon or context changed before cleanup")
        errors = []
        for item in reversed(self.resources):
            try:
                if not self._present(item):
                    item["status"] = "removed"
                    continue
                key = item.get("id", item["name"])
                if "identity" not in item:
                    self._bind(item, key)
                    key = item.get("id", item["name"])
                identity = _identity(item["kind"], _inspect(item["kind"], key))
                expected = item["identity"]
                if item["kind"] == "container":
                    # Existing v1 journals may retain Docker's original order.
                    # Compare semantically without rewriting that observation.
                    expected = {**expected, "mounts": _canonical_mounts(expected["mounts"])}
                labels = identity.get("labels", identity.get("Labels")) or {}
                if (identity != expected
                        or any(labels.get(key) != value for key, value in self.labels.items())):
                    fields = ("id", "name", "image_id", "image", "labels", "mounts",
                              "Name", "Labels", "Driver", "Options", "CreatedAt", "Mountpoint", "Id")
                    changed = [field for field in fields if identity.get(field) != expected.get(field)]
                    if set(identity) != set(expected):
                        changed.append("structure")
                    if any(labels.get(key) != value for key, value in self.labels.items()):
                        changed.append("ownership_labels")
                    item["cleanup_mismatch_fields"] = sorted(changed)
                    raise CleanupUnconfirmed("Live ownership identity changed fields=" + ",".join(changed))
                arguments = [item["kind"], "rm"]
                if item["kind"] == "container":
                    arguments.append("--force")
                _docker(*arguments, key)
                if self._present(item):
                    raise CleanupUnconfirmed("Successful removal did not establish absence")
                item["status"] = "removed"
            except (OSError, ValueError, KeyError, subprocess.SubprocessError, CleanupUnconfirmed) as exc:
                item["status"] = "unconfirmed"
                item["cleanup_error"] = type(exc).__name__
                errors.append(type(exc).__name__)
        self.cleanup_status = "unconfirmed" if errors else "removed"
        self._save()
        if errors:
            raise CleanupUnconfirmed("Disposable cleanup unconfirmed: " + ", ".join(errors))
