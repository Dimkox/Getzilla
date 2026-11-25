"""Prove that a digest reference ships no image payload in the three release archives."""
import codecs
import bz2
import gzip
import hashlib
import io
import json
import lzma
import posixpath
import re
import struct
import stat
import tarfile
import time
import zipfile

from . import security_oci as oci
from .security_artifacts import MAX_ARTIFACT_BYTES, MAX_ARCHIVE_BYTES, MAX_INDEX_BYTES, read_file
from .security_data import _json

PREFIX = ".getzilla/config/ci-image-blobs/"
PG = "e80acae3f1109e8e4533618b594918936f2858c63afc7204c4773148a673add8"
PYTHON = "70bda1e795ded2a684ef9815955e05829b14ee5bb5c3eb2a940648e88f10fce9"
MANIFEST_CONFIG = {
    PG: "fa7e2700e906190f900a3c9d47e87f9032cfa38b60d9ac25129a357f85c2da8c",
    PYTHON: "b7ddb46f14cdb6312b0ac3816e0513fe55904bd66e4525b8845058d3c1aa0f79",
}
STANDALONE = {PREFIX + sha + ".json": sha for sha in (*MANIFEST_CONFIG, *MANIFEST_CONFIG.values())}
FACTORY_REFERENCE = "postgres:17-alpine@sha256:" + PG
PRODUCTS = {"source-zip", "factory-wheel", "factory-offline"}


def validate_policy(value):
    if value != {"decision": "owner 2026-11-25, #456", "distribution": "referenced",
                 "factory_image": FACTORY_REFERENCE, "standalone_proofs": STANDALONE}:
        raise ValueError("invalid referenced image policy")
    return value


def require_factory_pin(rows, pins):
    uses = [row["source_reference"] for row in rows if row["manifest"] == "factory/compose.yaml"]
    if uses != [FACTORY_REFERENCE] or pins["postgres"]["reference"] != "postgres@sha256:" + PG:
        raise ValueError("Factory and the reviewed PostgreSQL server must use the same immutable image")


def _check_proof(path, raw):
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != STANDALONE[path]:
        raise ValueError("standalone proof size or hash differs")
    obj = _json(raw)
    def inspect(node):
        if isinstance(node, dict):
            if {"data", "urls"} & node.keys():
                raise ValueError("embedded data or external layer URL")
            for child in node.values():
                inspect(child)
        elif isinstance(node, list):
            for child in node:
                inspect(child)
    inspect(obj)
    digest = STANDALONE[path]
    if digest in MANIFEST_CONFIG:
        if (set(obj) - {"schemaVersion", "mediaType", "config", "layers", "annotations"}
                or obj.get("schemaVersion") != 2 or obj.get("mediaType") not in oci.MANIFEST_MEDIA
                or obj["config"]["mediaType"] not in {oci.CONFIG, oci.DOCKER_CONFIG}
                or obj["config"]["digest"] != "sha256:" + MANIFEST_CONFIG[digest]
                or not obj.get("layers")):
            raise ValueError("invalid standalone manifest")
    elif (set(obj) != {"architecture", "os", "config", "created", "history", "rootfs"}
          or obj["architecture"] != "amd64" or obj["os"] != "linux" or obj["rootfs"].get("type") != "layers"):
        raise ValueError("invalid standalone image config")


def _image_document(value):
    if isinstance(value, list):
        return any(_image_document(item) for item in value)
    if not isinstance(value, dict):
        return False
    media = value.get("mediaType")
    if isinstance(media, str) and media in oci.MANIFEST_MEDIA | oci.INDEX_MEDIA:
        return True
    if (value.get("schemaVersion") == 2 and ("manifests" in value or {"config", "layers"} <= value.keys())
            or isinstance(value.get("rootfs"), dict) and "diff_ids" in value["rootfs"]
            or {"Config", "RepoTags", "Layers"} <= value.keys()):
        return True
    return any(_image_document(item) for item in value.values())


def _unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("ambiguous delivery JSON")
    return result


def delivery_members(deliveries, pins):
    """Hash all regular payloads including nested archive members, under one work budget."""
    if set(deliveries) != PRODUCTS:
        raise ValueError("all three exact release outputs are required")
    if pins.get("platform") != "linux/amd64" or any(
            pins[name]["reference"] != name + "@sha256:" + digest
            or pins[name]["image_id"] != "sha256:" + MANIFEST_CONFIG[digest]
            for name, digest in (("postgres", PG), ("python", PYTHON))):
        raise ValueError("shipped metadata differs from CI declarations")
    seen_proofs, hashes, archive_hashes = set(), set(), {}
    size = count = 0
    deadline = time.monotonic() + 180

    def check_path(name):
        if (name.startswith("/") or "\\" in name or "\x00" in name or
                any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))):
            raise ValueError("ambiguous delivery path")
        parts = name.split("/")
        if "oci-layout" in parts or any(pair == ("blobs", "sha256") for pair in zip(parts, parts[1:])):
            raise ValueError("OCI layout in delivery")

    def walk(name, raw, depth, product):
        nonlocal size, count
        size += len(raw)
        count += 1
        if size > 2 * MAX_ARCHIVE_BYTES or count > 100000 or depth > 8 or time.monotonic() > deadline:
            raise ValueError("incomplete delivery traversal")
        hashes.add(hashlib.sha256(raw).hexdigest())
        relative = name.removeprefix("getzilla/")
        if product == "source-zip" and depth == 1 and name == "getzilla/" + relative and relative in STANDALONE:
            _check_proof(relative, raw)
            seen_proofs.add(relative)
        elif PREFIX in name:
            raise ValueError("unexpected standalone image proof")
        elif (name.lower().endswith(".json") or raw.lstrip(b" \r\n\t\0")[:1] in {b"{", b"["}
              or raw.startswith((codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE,
                                 codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE))):
            if len(raw) > MAX_INDEX_BYTES:
                raise ValueError("oversized document")
            try:
                obj = json.loads(raw, object_pairs_hook=_unique)
            except json.JSONDecodeError:
                # The source includes historical command transcripts and redacted examples
                # with a .json suffix. Reject ambiguous image-shaped fragments in such text.
                text = raw.decode(json.detect_encoding(raw))
                for match in re.finditer(r'"(?:[^"\\]|\\.)*"\s*:', text):
                    token = match.group().rstrip(":").strip()
                    if json.loads(token) in {"mediaType", "schemaVersion", "rootfs", "Layers", "manifests"}:
                        raise ValueError("malformed image-like document in delivery: " + name) from None
            else:
                if _image_document(obj):
                    raise ValueError("undeclared image document in delivery")
        zip_end = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
        if zip_end >= 0 and zipfile.is_zipfile(io.BytesIO(raw)) or raw.startswith((b"PK\x03\x04", b"PK\x05\x06")) or name.endswith((".whl", ".zip", ".jar")):
            if not raw.startswith((b"PK\x03\x04", b"PK\x05\x06")):
                raise ValueError("invalid ZIP signature")
            if zip_end < 0 or len(raw) - zip_end != 22:
                raise ValueError("uninspected ZIP comment or trailer")
            disk, start, disk_count, total, central_bytes, central_start, comment = struct.unpack_from("<4H2IH", raw, zip_end+4)
            if (disk or start or disk_count != total or total > 100000-count or comment
                    or central_bytes > 8 * 1024 * 1024 or central_bytes + central_start != zip_end):
                raise ValueError("ambiguous ZIP directory")
            with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
                members = bundle.infolist()
                if len(members) != total or len({m.filename for m in members}) != len(members):
                    raise ValueError("excessive or repeated ZIP members")
                for member in members:
                    check_path(member.filename)
                    if member.flag_bits & 1 or member.orig_filename != member.filename:
                        raise ValueError("unreadable ZIP member")
                    if member.is_dir():
                        if member.file_size or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFDIR}:
                            raise ValueError("invalid ZIP directory")
                        continue
                    if (stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG} or
                            member.file_size > MAX_ARTIFACT_BYTES or size + member.file_size > 2 * MAX_ARCHIVE_BYTES):
                        raise ValueError("unproved ZIP member")
                    walk(member.filename, bundle.read(member), depth + 1, product)
        elif raw.startswith((b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh")):
            opener = gzip.GzipFile if raw.startswith(b"\x1f\x8b") else (bz2.BZ2File if raw.startswith(b"BZh") else lzma.LZMAFile)
            stream = io.BytesIO(raw)
            with (opener(fileobj=stream) if opener is gzip.GzipFile else opener(stream)) as decoded:
                expanded = decoded.read(MAX_ARTIFACT_BYTES + 1)
            if len(expanded) > MAX_ARTIFACT_BYTES:
                raise ValueError("oversized compressed member")
            walk(name + ".expanded", expanded, depth + 1, product)
        elif raw[257:262] == b"ustar" or name.endswith(".tar"):
            names = set()
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as bundle:
                for member in bundle:
                    path = member.name.removeprefix("./")
                    if member.isdir() and path in {"", "."}:
                        continue
                    check_path(path)
                    if path in names or len(names) >= 100000 - count:
                        raise ValueError("duplicate or excessive TAR entries")
                    names.add(path)
                    if member.isdir():
                        continue
                    if not member.isreg() or member.size > MAX_ARTIFACT_BYTES or size + member.size > 2 * MAX_ARCHIVE_BYTES:
                        raise ValueError("unproved TAR member")
                    with bundle.extractfile(member) as stream:
                        value = stream.read(member.size + 1)
                    if len(value) != member.size:
                        raise ValueError("short TAR member")
                    walk(path, value, depth + 1, product)
                if len(raw) - bundle.offset < 1024 or any(memoryview(raw)[bundle.offset:]):
                    raise ValueError("uninspected TAR trailer")
        elif raw.startswith((b"7z\xbc\xaf\x27\x1c", b"\x28\xb5\x2f\xfd", b"!<arch>\n", b"Rar!")):
            raise ValueError("unsupported nested archive")

    for product, path in deliveries.items():
        raw = read_file(path.parent, path.name, MAX_ARTIFACT_BYTES)
        if not raw.startswith(b"PK\x03\x04"):
            raise ValueError("empty or unsupported release output")
        archive_hashes[product] = hashlib.sha256(raw).hexdigest()
        walk(posixpath.basename(path), raw, 0, product)
    if seen_proofs != set(STANDALONE):
        raise ValueError("source ZIP proof inventory incomplete")
    return hashes, archive_hashes


def distribution(facts, layers, binaries):
    if (not facts or not layers or not binaries or set(facts[1]) != PRODUCTS
            or any(not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value) for value in facts[1].values())):
        return "redistributed"
    selected = {digest.removeprefix("sha256:") for digest in layers} | set(binaries)
    return "redistributed" if selected & facts[0] else "referenced"
