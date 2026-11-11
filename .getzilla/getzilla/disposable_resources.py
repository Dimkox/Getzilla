"""Bounded, identity-bound Docker resources for disposable CI acceptance only.

The journal is an observation, never authority by itself. Every deletion checks
the live object, and a successful independent list must confirm its absence.
"""
from __future__ import annotations

import json
import hashlib
import ipaddress
from contextlib import contextmanager
from contextvars import ContextVar
import os
from pathlib import Path
import re
import subprocess
import stat
import time
import uuid

from . import fsx

_PIN = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,100}\Z")
_ID = re.compile(r"[0-9a-f]{64}\Z")
_DEADLINE = ContextVar("disposable_cleanup_deadline", default=None)
_RECOVERY_BOOT = ContextVar("disposable_recovery_boot", default=None)
_LIMIT = 1024 * 1024


def _read(path, *, private=False):
    with fsx.ReadOnlyBoundRoot(path.parent) as root:
        snapshot = root.read(path.name, limit=_LIMIT)
        if snapshot is None:
            raise FileNotFoundError(path)
        info = fsx.lstat_at(root.handle, path.name)
        if fsx._file_identity(info) != snapshot.identity or info.st_uid != os.getuid() or private and snapshot.mode != 0o600:
            raise ValueError("Unowned or nonprivate source")
        return snapshot


def _execute(command, root, environment, *, timeout):
    from .python_test_runner import execute
    return execute(command, root, environment, timeout=timeout)


def _process_identity(pid: int) -> dict:
    try:
        current = Path("/proc/self/stat").read_text(encoding="utf-8")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
    except FileNotFoundError as error:
        raise CleanupUnconfirmed("Observer procfs identity is unavailable") from error
    if not boot or len(boot) > 128 or _RECOVERY_BOOT.get() not in (None, boot):
        raise CleanupUnconfirmed("Observer boot identity is inconsistent")
    if int(current.split(" ", 1)[0]) != os.getpid():
        raise CleanupUnconfirmed("Process and procfs namespaces disagree; resource ownership cannot be established")
    value = current if pid == os.getpid() else Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    fields = value[value.rfind(")") + 2:].split()
    return {"pid": pid, "start": fields[19], "boot": boot}


class CleanupUnconfirmed(RuntimeError):
    """A resource remains, changed identity, or could not be observed."""


def _cleanup_time():
    if _DEADLINE.get() is not None and time.monotonic() >= _DEADLINE.get():
        raise CleanupUnconfirmed("Cleanup deadline exhausted")


def image_pins(root: Path) -> dict:
    data = json.loads(_read(root / ".getzilla/config/ci-images.json").content)
    if (type(data) is not dict or set(data) != {"schema_version", "platform", "postgres", "python"}
            or type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["platform"] != "linux/amd64"):
        raise ValueError("Unknown CI image configuration")
    for key in ("postgres", "python"):
        if type(data[key]) is not dict or set(data[key]) != {"reference", "image_id", "source"} or any(type(v) is not str for v in data[key].values()):
            raise ValueError("Invalid CI image descriptor")
        if not _PIN.fullmatch(data[key]["reference"]) or not re.fullmatch(r"sha256:[0-9a-f]{64}", data[key]["image_id"]):
            raise ValueError("CI image must bind both manifest and configuration digest")
    return data


def ensure_images(root: Path, names=("postgres", "python")) -> None:
    pins = image_pins(root)
    for name in names:
        pin = pins[name]
        try:
            inspected = json.loads(_docker("image", "inspect", pin["reference"]))
        except subprocess.CalledProcessError:
            _docker("pull", "--platform", "linux/amd64", pin["reference"], timeout=120)
            inspected = json.loads(_docker("image", "inspect", pin["reference"]))
        if len(inspected) != 1 or inspected[0]["Id"] != pin["image_id"] or pin["reference"] not in inspected[0].get("RepoDigests", []):
            raise ValueError("Pulled image does not match the configured manifest and image digest")


def _docker(*args: str, timeout: int = 30) -> str:
    deadline = _DEADLINE.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CleanupUnconfirmed("Cleanup deadline exhausted; no additional Docker operation authorized")
        timeout = min(timeout, remaining)
    result = _execute(["docker", *args], Path.cwd(), dict(os.environ), timeout=timeout)
    if (result.terminal_state != "completed" or result.cleanup_error
            or result.cleanup_metadata.unavailable or result.cleanup_metadata.overflow):
        raise CleanupUnconfirmed("Docker process completion or cleanup is unconfirmed")
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, ["docker"])
    return result.stdout.strip()


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
        if type(value["Config"].get("Labels")) is not dict:
            raise ValueError("Incomplete container labels")
        if (type(value.get("Mounts")) is not list
                or any(type(m) is not dict or not {"Type", "Source", "Destination", "RW"} <= set(m)
                       or m["Type"] not in ("bind", "volume")
                       or m["Type"] == "volume" and (type(m.get("Name")) is not str or not _NAME.fullmatch(m["Name"]))
                       or type(m["RW"]) is not bool for m in value["Mounts"])):
            raise ValueError("Incomplete container observation")
        return {"id": value["Id"], "name": value["Name"].removeprefix("/"),
                "image_id": value["Image"], "image": value["Config"]["Image"],
                "labels": value["Config"].get("Labels") or {},
                "mounts": _canonical_mounts([
                    {key: item.get(key) for key in ("Type", "Name", "Source", "Destination", "RW")}
                    for item in value.get("Mounts", [])])}
    if (not {"Name", "Labels", "Driver", "Options"} <= set(value)
            or type(value["Labels"]) is not dict or type(value["Driver"]) is not str
            or not value["Driver"] or value["Options"] is not None and type(value["Options"]) is not dict):
        raise ValueError("Incomplete resource observation")
    result = {key: value[key] for key in ("Name", "Labels", "Driver", "Options")}
    if kind == "volume":
        if (type(value.get("CreatedAt")) is not str or not 0 < len(value["CreatedAt"]) <= 128
                or not _absolute_posix_path(value.get("Mountpoint"))):
            raise ValueError("Incomplete volume birth or location")
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

    def read_binding():
        container = _inspect("container", container_id)
        network = _inspect("network", network_id)
        if (container["Id"] != container_id or container["Name"] != "/" + container_name
                or container["Config"]["Image"] != image or container["Image"] != image_id
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
        self._save()
        with self._anchors(create=True):
            pass

    @classmethod
    def recover(cls, manifest: Path):
        """Called only by the observer after it confirms its child has exited."""
        path = Path(manifest)
        snapshot = _read(path, private=True)
        data = json.loads(snapshot.content)
        if (type(data) is not dict or set(data) != {"schema", "namespace", "nonce", "resources", "cleanup_status", "owner_process"}
                or data.get("schema") != "getzilla-disposable-owner-v1"):
            raise ValueError("Unknown ownership journal")
        if not _NAME.fullmatch(data.get("namespace", "")) or not re.fullmatch(r"[0-9a-f]{32}", data.get("nonce", "")):
            raise ValueError("Invalid ownership identity")
        instance = cls.__new__(cls)
        instance.manifest, instance.namespace, instance.nonce = path, data["namespace"], data["nonce"]
        instance.resources = data["resources"]
        instance.cleanup_status = data["cleanup_status"]
        instance.owner_process = data["owner_process"]
        instance._journal_identity = snapshot.identity
        parent = path.parent.stat(follow_symlinks=False)
        instance._parent_identity = (parent.st_dev, parent.st_ino)
        instance._validate()
        owner = instance.owner_process
        if type(owner.get("pid")) is not int or owner["pid"] <= 0:
            raise ValueError("Invalid allocator identity")
        try:
            boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        except FileNotFoundError as error:
            raise CleanupUnconfirmed("Allocator boot observation is unavailable") from error
        if owner.get("boot") != boot:
            raise CleanupUnconfirmed("Allocator boot identity is unavailable")
        token = _RECOVERY_BOOT.set(boot)
        try:
            try:
                observed = _process_identity(owner["pid"])
                if (type(observed) is not dict or set(observed) != set(owner)
                        or type(observed["pid"]) is not int or observed["pid"] != owner["pid"]
                        or type(observed["start"]) is not str or not 0 < len(observed["start"]) <= 128
                        or observed["boot"] != boot):
                    raise CleanupUnconfirmed("Allocator observation is incomplete or inconsistent")
                if observed == owner:
                    raise CleanupUnconfirmed("Allocator is still alive; recovery would race allocation")
            except FileNotFoundError:
                pass
        finally:
            _RECOVERY_BOOT.reset(token)
        return instance

    def _validate(self):
        if (type(self.resources) is not list or len(self.resources) > 128
                or self.cleanup_status not in ("not_run", "unconfirmed", "removed")
                or type(self.owner_process) is not dict
                or set(self.owner_process) != {"pid", "start", "boot"}
                or type(self.owner_process["pid"]) is not int or self.owner_process["pid"] <= 0
                or any(type(self.owner_process[k]) is not str or not 0 < len(self.owner_process[k]) <= 128 for k in ("start", "boot"))):
            raise ValueError("Invalid allocator journal")
        seen = set()
        for item in self.resources:
            if (type(item) is not dict or item.get("kind") not in ("container", "network", "volume", "directory")
                    or type(item.get("name")) is not str or not _NAME.fullmatch(item["name"])
                    or not item["name"].startswith(self.namespace + "-")
                    or item.get("status") not in ("pending", "bound", "unconfirmed", "removed")
                    or (item["kind"], item["name"]) in seen):
                raise ValueError("Invalid resource journal")
            allowed = {"kind", "name", "status", "identity", "cleanup_error", "cleanup_mismatch_fields"}
            if item["kind"] == "container":
                allowed |= {"id", "image", "image_id"}
            if item["kind"] == "directory":
                allowed.add("directory_removal")
            if set(item) - allowed:
                raise ValueError("Unknown resource journal fields")
            seen.add((item["kind"], item["name"]))
            if item["status"] == "bound" and type(item.get("identity")) is not dict:
                raise ValueError("Missing bound resource identity")
            identity = item.get("identity")
            if "directory_removal" in item:
                transition = item["directory_removal"]
                if (identity is None or type(transition) is not dict or set(transition) != {"marker", "nonce"}
                        or transition["nonce"] != self.nonce or type(transition["marker"]) is not list
                        or len(transition["marker"]) != 8 or any(type(v) is not int or v < 0 for v in transition["marker"])
                        or transition["marker"][2:4] != [stat.S_IFREG, 32] or transition["marker"][6:] != [1, 0o600]):
                    raise ValueError("Invalid directory removal transition")
            if identity is not None:
                keys = {"device", "inode"} if item["kind"] == "directory" else (
                    {"id", "name", "image_id", "image", "labels", "mounts"} if item["kind"] == "container" else
                    {"Name", "Labels", "Driver", "Options", *( ("CreatedAt", "Mountpoint") if item["kind"] == "volume" else ("Id",) )})
                if type(identity) is not dict or set(identity) != keys:
                    raise ValueError("Incomplete resource identity")
                if item["kind"] == "directory":
                    if any(type(identity[k]) is not int or identity[k] <= 0 for k in keys):
                        raise ValueError("Invalid directory identity")
                elif (identity.get("name", identity.get("Name")) != item["name"]
                      or identity.get("labels", identity.get("Labels")) != self.labels):
                    raise ValueError("Foreign journal identity")
                if item["kind"] == "network" and not _ID.fullmatch(identity.get("Id", "")):
                    raise ValueError("Invalid full network identity")
                if item["kind"] == "volume" and (type(identity["CreatedAt"]) is not str
                        or not 0 < len(identity["CreatedAt"]) <= 128 or not _absolute_posix_path(identity["Mountpoint"])):
                    raise ValueError("Incomplete volume journal identity")
            if item["kind"] == "container" and (not _PIN.fullmatch(item.get("image", ""))
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("image_id", ""))
                    or item["status"] == "bound" and not _ID.fullmatch(item.get("id", ""))):
                raise ValueError("Invalid container journal identity")

    @property
    def labels(self):
        return {"getzilla.ci.namespace": self.namespace, "getzilla.ci.nonce": self.nonce}

    @staticmethod
    def _private(root, name, limit=2048):
        value = root.read(name, limit=limit)
        if value is not None:
            info = fsx.lstat_at(root.handle, name)
            if value.mode != 0o600 or info.st_uid != os.getuid() or fsx._file_identity(info) != value.identity:
                raise ValueError("Unowned or changed anchor file")
        return value

    def _anchor_path(self):
        return self.manifest.parent / (".getzilla-owner-" + hashlib.sha256(os.fsencode(self.manifest.name)).hexdigest())

    @contextmanager
    def _anchors(self, create=False):
        with fsx.ReadOnlyBoundRoot(self.manifest.parent) as parent:
            info = fsx.fstat_dir(parent.handle)
            if (info.st_dev, info.st_ino) != self._parent_identity:
                raise ValueError("Anchor parent changed")
            if create:
                fsx.mkdir_at(parent.handle, self._anchor_path().name, 0o700)
            with fsx.ReadOnlyBoundRoot(self._anchor_path()) as root:
                info = fsx.fstat_dir(root.handle)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError("Unowned anchor root")
                header = {"journal": [*self._parent_identity, self.manifest.name], "namespace": self.namespace,
                          "nonce": self.nonce, "owner": self.owner_process}
                if create:
                    self._put_anchor(root, "owner", header)
                value = self._private(root, "owner")
                if value is None or value.content != json.dumps(header, sort_keys=True).encode():
                    raise ValueError("Anchor owner binding changed")
                parent.check()
                yield root

    def _anchor_bytes(self, root):
        total = 0
        with os.scandir(root.handle) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 258 or not (entry.name == "owner" or re.fullmatch(r"[0-9a-f]{64}\.(record|marker|tmp)", entry.name)):
                    raise ValueError("Unknown anchor metadata")
                value = self._private(root, entry.name)
                if value is None:
                    raise ValueError("Anchor metadata disappeared")
                total += len(value.content)
        return total

    def _put_anchor(self, root, name, value):
        raw = json.dumps(value, sort_keys=True).encode()
        if len(raw) > 2048:
            raise ValueError("Anchor record exceeds limit")
        current = self._private(root, name)
        if current is not None:
            if current.content != raw:
                raise ValueError("Anchor record changed")
            return
        temporary = name.removesuffix(".record") + ".tmp"
        pending = self._private(root, temporary)
        if pending is not None:
            if pending.content != raw:
                raise ValueError("Uncertain anchor publication")
            _cleanup_time()
            root.check()
            fsx.replace_at(root.handle, temporary, root.handle, name)
            fsx.fsync_dir(root.handle)
            return
        if len(_read(self.manifest, private=True).content) + self._anchor_bytes(root) + len(raw) + 32 * len(self.resources) > _LIMIT:
            raise ValueError("Combined metadata exceeds limit")
        _cleanup_time()
        fd = fsx.open_at(root.handle, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            root.check()
            if self._private(root, name) is not None:
                raise ValueError("Anchor publication raced")
            _cleanup_time()
            fsx.replace_at(root.handle, temporary, root.handle, name)
            fsx.fsync_dir(root.handle)
        finally:
            try:
                if _DEADLINE.get() is None or time.monotonic() < _DEADLINE.get():
                    fsx.unlink_at(root.handle, temporary)
            except FileNotFoundError:
                pass

    def _save(self):
        self._validate()
        data = {"schema": "getzilla-disposable-owner-v1", "namespace": self.namespace,
                "nonce": self.nonce, "resources": self.resources, "cleanup_status": self.cleanup_status,
                "owner_process": self.owner_process}
        payload = json.dumps(data, sort_keys=True, indent=2).encode()
        if len(payload) > _LIMIT:
            raise ValueError("Ownership journal exceeds limit")
        with fsx.ReadOnlyBoundRoot(self.manifest.parent) as root:
            info = fsx.fstat_dir(root.handle)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("Ownership journal parent is not private")
            parent_identity = (info.st_dev, info.st_ino)
            if parent_identity != getattr(self, "_parent_identity", parent_identity):
                raise ValueError("Ownership journal parent changed")
            self._parent_identity = parent_identity
            current = root.read(self.manifest.name, limit=_LIMIT)
            usage = 0
            if self._anchor_path().exists():
                with self._anchors() as anchors:
                    usage = self._anchor_bytes(anchors)
            if len(payload) + (len(current.content) if current else 0) + usage + 32 * len(self.resources) > _LIMIT:
                raise ValueError("Combined metadata exceeds limit")
            expected = getattr(self, "_journal_identity", None)
            if (None if current is None else current.identity) != expected:
                raise ValueError("Ownership journal identity changed")
            temporary = self.manifest.name + "." + uuid.uuid4().hex
            descriptor = fsx.open_at(root.handle, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                root.check()
                observed = root.read(self.manifest.name, limit=_LIMIT)
                if (None if observed is None else observed.identity) != expected:
                    raise ValueError("Ownership journal changed before publication")
                fsx.replace_at(root.handle, temporary, root.handle, self.manifest.name)
                fsx.fsync_dir(root.handle)
                self._journal_identity = root.read(self.manifest.name, limit=_LIMIT).identity
            finally:
                try:
                    fsx.unlink_at(root.handle, temporary)
                except FileNotFoundError:
                    pass

    def _intent(self, kind: str, suffix: str, **extra):
        name = f"{self.namespace}-{suffix}"
        if not _NAME.fullmatch(name) or any(item["name"] == name and item["kind"] == kind for item in self.resources):
            raise ValueError("Invalid or repeated resource name")
        item = {"kind": kind, "name": name, "status": "pending", **extra}
        self.resources.append(item)
        try:
            self._save()
        except (OSError, ValueError):
            self.resources.pop()
            raise
        return item

    def _labels(self):
        return [part for key, value in self.labels.items() for part in ("--label", f"{key}={value}")]

    def _bind(self, item, key):
        previous = dict(item)
        value = _inspect(item["kind"], key)
        identity = _identity(item["kind"], value)
        recovering = key == item["name"] and item["status"] in ("pending", "unconfirmed") and "identity" not in item
        labels = identity.get("labels", identity.get("Labels")) or {}
        if any(labels.get(key) != val for key, val in self.labels.items()):
            raise ValueError("New resource did not retain ownership labels")
        if identity.get("name", identity.get("Name")) != item["name"]:
            raise ValueError("New resource name differs from intent")
        if item["kind"] == "container":
            if (not _ID.fullmatch(identity["id"]) or not recovering and identity["id"] != key
                    or identity["image"] != item["image"] or identity["image_id"] != item["image_id"]):
                raise ValueError("New container identity differs from intent")
            item["id"] = identity["id"]
        if item["kind"] == "network" and (not _ID.fullmatch(identity["Id"]) or not recovering and identity["Id"] != key):
            raise ValueError("New network identity differs from returned ID")
        item["identity"], item["status"] = identity, "bound"
        try:
            self._save()
        except (OSError, ValueError):
            item.clear()
            item.update(previous)
            raise
        return item

    def volume(self, suffix: str):
        item = self._intent("volume", suffix)
        _docker("volume", "create", *self._labels(), item["name"])
        return self._bind(item, item["name"])

    def network(self, suffix: str):
        item = self._intent("network", suffix)
        key = _docker("network", "create", "--internal", *self._labels(), item["name"])
        if not _ID.fullmatch(key):
            raise ValueError("Docker did not return a full network ID")
        return self._bind(item, key)

    def directory(self, suffix: str):
        item = self._intent("directory", suffix)
        path = self.manifest.parent / item["name"]
        with fsx.ReadOnlyBoundRoot(self.manifest.parent) as root:
            if (fsx.fstat_dir(root.handle).st_dev, fsx.fstat_dir(root.handle).st_ino) != self._parent_identity:
                raise ValueError("Ownership parent changed")
            fsx.mkdir_at(root.handle, item["name"], 0o700)
            with fsx.ReadOnlyBoundRoot(path) as directory:
                descriptor = fsx.open_at(directory.handle, ".owner", os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as marker:
                    marker.write(self.nonce.encode())
                    marker.flush()
                    os.fsync(marker.fileno())
                value = fsx.fstat_dir(directory.handle)
                directory.check()
                item.update(identity={"device": value.st_dev, "inode": value.st_ino}, status="bound")
            root.check()
        self._save()
        return path

    def _remove_directory(self, item):
        path = self.manifest.parent / item["name"]
        key = hashlib.sha256(("directory:" + item["name"]).encode()).hexdigest()
        def marker_id(value):
            return list(value.identity[:5] + value.identity[6:])
        def expired():
            if _DEADLINE.get() is not None and time.monotonic() >= _DEADLINE.get():
                raise CleanupUnconfirmed("Cleanup deadline exhausted")
        with fsx.ReadOnlyBoundRoot(self.manifest.parent) as parent, self._anchors() as anchor:
            info = fsx.fstat_dir(parent.handle)
            if (info.st_dev, info.st_ino) != self._parent_identity:
                raise CleanupUnconfirmed("Ownership parent changed")
            saved = _read(self.manifest, private=True)
            if saved.identity != self._journal_identity:
                raise CleanupUnconfirmed("Ownership journal changed")
            proof = self._private(anchor, key + ".record")
            record = json.loads(proof.content) if proof else None
            if record is not None:
                if type(record) is not dict:
                    raise CleanupUnconfirmed("Unknown anchor record")
                marker = record.get("marker")
                expected = {"kind": "directory", "name": item["name"], "identity": item.get("identity"),
                            "nonce": self.nonce, "state": "armed", "marker": marker}
                if (record != expected or proof.content != json.dumps(expected, sort_keys=True).encode()
                        or type(marker) is not list or len(marker) != 7
                        or any(type(v) is not int or v < 0 for v in marker)
                        or marker[2:4] != [stat.S_IFREG, 32] or marker[-2:] != [1, 0o600]):
                    raise CleanupUnconfirmed("Anchor resource binding changed")
            retained = self._private(anchor, key + ".marker", 32)
            if retained is not None and (not record or marker_id(retained) != record["marker"] or retained.content != self.nonce.encode()):
                raise CleanupUnconfirmed("Live anchor marker changed")
            try:
                named = fsx.lstat_at(parent.handle, item["name"])
            except FileNotFoundError:
                named = None
            if named is not None:
                if item["status"] not in ("bound", "unconfirmed"):
                    raise CleanupUnconfirmed("Unbound directory removal")
                with fsx.ReadOnlyBoundRoot(path) as directory:
                    info = fsx.fstat_dir(directory.handle)
                    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                            or {"device": info.st_dev, "inode": info.st_ino} != item.get("identity")
                            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
                        raise CleanupUnconfirmed("Disposable directory identity changed")
                    original = self._private(directory, ".owner", 32)
                    entries = os.listdir(directory.handle)
                    if len(entries) > 2 or set(entries) - {".owner", "payload"}:
                        raise CleanupUnconfirmed("Unexpected disposable payload")
                    if original is not None:
                        if retained is not None or original.content != self.nonce.encode():
                            raise CleanupUnconfirmed("Disposable marker changed")
                        snapshots = {name: original if name == ".owner" else directory.read(name, limit=_LIMIT) for name in entries}
                        if any(directory.read(name, limit=_LIMIT) != value for name, value in snapshots.items()):
                            raise CleanupUnconfirmed("Disposable payload changed")
                        if "payload" in snapshots:
                            expired()
                            if self._private(directory, ".owner", 32) != original:
                                raise CleanupUnconfirmed("Disposable marker changed")
                            directory.check()
                            fsx.unlink_at(directory.handle, "payload")
                        expected = {"kind": "directory", "name": item["name"], "identity": item["identity"],
                                    "nonce": self.nonce, "state": "armed", "marker": marker_id(original)}
                        if record is not None and record != expected:
                            raise CleanupUnconfirmed("Original marker differs from anchor")
                        self._put_anchor(anchor, key + ".record", expected)
                        previous = item.get("directory_removal")
                        item["directory_removal"] = {"marker": list(original.identity), "nonce": self.nonce}
                        try:
                            self._save()
                        except (OSError, ValueError):
                            if previous is None:
                                item.pop("directory_removal", None)
                            else:
                                item["directory_removal"] = previous
                            raise
                        expired()
                        if self._private(directory, ".owner", 32) != original:
                            raise CleanupUnconfirmed("Original marker changed before move")
                        directory.check()
                        anchor.check()
                        fsx.replace_at(directory.handle, ".owner", anchor.handle, key + ".marker")
                        fsx.fsync_dir(directory.handle)
                        fsx.fsync_dir(anchor.handle)
                    elif record is None or retained is None or entries:
                        raise CleanupUnconfirmed("Unproved marker-less directory")
                    expired()
                    directory.check()
                    fsx.rmdir_at(parent.handle, item["name"])
                parent.check()
                try:
                    fsx.lstat_at(parent.handle, item["name"])
                except FileNotFoundError:
                    pass
                else:
                    raise CleanupUnconfirmed("Directory absence unconfirmed")
            for suffix in (".marker", ".record"):
                value = self._private(anchor, key + suffix)
                if value is not None:
                    expired()
                    if self._private(anchor, key + suffix) != value:
                        raise CleanupUnconfirmed("Anchor changed before finalization")
                    anchor.check()
                    fsx.unlink_at(anchor.handle, key + suffix)
            fsx.fsync_dir(anchor.handle)

    def container(self, suffix: str, image: str, *, volume=None, network=None,
                  publish_postgres=False, environment=None, command=(),
                  volume_target="/var/lib/postgresql/data", bind=None, alias=None, working_directory=None):
        if not _PIN.fullmatch(image):
            raise ValueError("Disposable containers require an immutable image digest")
        images = json.loads(_docker("image", "inspect", image))
        if len(images) != 1 or image not in (images[0].get("RepoDigests") or []):
            raise ValueError("Pulled image does not match the requested digest")
        image_id = images[0]["Id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("Invalid Docker image identity")
        item = self._intent("container", suffix, image=image, image_id=image_id)
        arguments = ["run", "--detach", "--name", item["name"], "--cpus", "1", "--memory", "512m", *self._labels()]
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
        errors = []
        for item in reversed(self.resources):
            try:
                if _DEADLINE.get() is not None and time.monotonic() >= _DEADLINE.get():
                    raise CleanupUnconfirmed("Cleanup deadline exhausted")
                if item["kind"] == "directory":
                    self._remove_directory(item)
                    item["status"] = "removed"
                    continue
                if not self._present(item):
                    item["status"] = "removed"
                    continue
                key = item.get("id", item["name"])
                if "identity" not in item:
                    self._bind(item, key)
                    key = item.get("id", item["name"])
                if item["kind"] == "network":
                    key = item["identity"]["Id"]
                try:
                    identity = _identity(item["kind"], _inspect(item["kind"], key))
                except ValueError as error:
                    if item["kind"] == "container" and error.args == ("Incomplete container observation",):
                        item["cleanup_mismatch_fields"] = ["mounts"]
                    raise
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
        try:
            self._save()
        except (OSError, ValueError) as error:
            errors.append(type(error).__name__)
        if errors:
            raise CleanupUnconfirmed("Disposable cleanup unconfirmed: " + ", ".join(errors))
