"""Data-only Go build-info and h1 source proofs for two fixed checker tools.

Formats follow Go's debug/buildinfo and x/mod/sumdb/dirhash sources. A Go
module list does not identify non-Go CGO or generated/static bundled data.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import struct
import zipfile

from .security_artifacts import (
    ArtifactError,
    MAX_ARTIFACT_BYTES,
    MAX_ARCHIVE_BYTES,
    MAX_INDEX_BYTES,
    MAX_MEMBERS,
    MAX_METADATA_BYTES,
    safe_parts,
)

MAGIC = b"\xff Go buildinf:"
H1 = re.compile(r"h1:[A-Za-z0-9+/]{43}=")


def fail(code, message):
    raise ArtifactError(code, message)


def _section(raw, name):
    # Trivy's pinned compressed artifact is below MAX_ARTIFACT_BYTES, while its
    # inert ELF member uses the existing expanded-archive bound (168 MB).
    if not isinstance(raw, bytes) or not 64 <= len(raw) <= MAX_ARCHIVE_BYTES or raw[:7] != b"\x7fELF\x02\x01\x01":
        fail("go-buildinfo-format", "expected bounded ELF64 little-endian data")
    h = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    offset, size, count, names = h[6], h[11], h[12], h[13]
    if (
        h[1] not in {2, 3}
        or h[2] != 62
        or size != 64
        or not 0 < count <= MAX_MEMBERS
        or names >= count
        or offset + size * count > len(raw)
    ):
        fail("go-buildinfo-format", "unsupported ELF architecture or section table")
    rows = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * size) for i in range(count)]
    table = rows[names]
    if table[1] != 3 or table[5] > MAX_METADATA_BYTES or table[4] + table[5] > len(raw):
        fail("go-buildinfo-format", "ELF section-name table is truncated or unbounded")
    strings = raw[table[4] : table[4] + table[5]]
    selected = []
    seen = set()
    for row in rows[1:]:
        end = strings.find(b"\0", row[0])
        if row[0] >= len(strings) or end < 0:
            fail("go-buildinfo-format", "invalid ELF section name")
        label = strings[row[0] : end]
        if label in seen or row[1] != 8 and row[4] + row[5] > len(raw):
            fail("go-buildinfo-format", "ELF sections are repeated or truncated")
        seen.add(label)
        if label == name:
            if row[1] != 1 or row[5] > MAX_METADATA_BYTES:
                fail("go-buildinfo-format", "Go metadata section is not bounded PROGBITS")
            selected.append(raw[row[4] : row[4] + row[5]])
    if len(selected) != 1:
        fail("go-buildinfo-missing", "one exact Go build-info section is required")
    return selected[0]


def _string(data, index):
    length = 0
    for byte in range(10):
        if index >= len(data):
            fail("go-buildinfo-format", "truncated Go string length")
        value = data[index]
        index += 1
        if byte == 9 and value > 1:
            fail("go-buildinfo-format", "Go string length overflows uint64")
        length |= (value & 127) << (byte * 7)
        if value < 128:
            if length > MAX_METADATA_BYTES or index + length > len(data):
                fail("go-buildinfo-format", "Go string is truncated or exceeds metadata bound")
            return data[index : index + length], index + length
    fail("go-buildinfo-format", "Go string length is unbounded")


def _module(fields):
    if len(fields) not in {2, 3}:
        fail("go-buildinfo-format", "Go module row has unsupported fields")
    path, version = fields[:2]
    checksum = fields[2] if len(fields) == 3 else ""
    if not path or len(path) > 1024 or len(version) > 200 or checksum and not H1.fullmatch(checksum):
        fail("go-buildinfo-format", "Go module identity/checksum is malformed")
    return {"path": path, "version": version, "h1": checksum}


def buildinfo(raw):
    data = _section(raw, b".go.buildinfo")
    if len(data) < 32 or data[:14] != MAGIC or data[14] not in {4, 8} or data[15] & ~3 or not data[15] & 2:
        fail("go-buildinfo-format", "only Go 1.18+ inline build information is qualified")
    version, index = _string(data, 32)
    module, index = _string(data, index)
    try:
        version = version.decode("ascii")
    except UnicodeError:
        fail("go-buildinfo-format", "Go compiler version is not ASCII")
    if not re.fullmatch(r"go1\.[0-9]+(?:\.[0-9]+)?(?:[a-z]+[0-9]+)?(?:-X:[a-z0-9_,]+)?", version):
        fail("go-buildinfo-version", "unqualified Go compiler version")
    if len(module) < 33 or module[-17] != 10:
        fail("go-buildinfo-missing", "Go module framing is absent")
    try:
        text = module[16:-16].decode("utf-8")
    except UnicodeError:
        fail("go-buildinfo-format", "Go module metadata is not UTF-8")
    result = {"go_version": version, "path": None, "main": None, "dependencies": [], "settings": {}}
    last = None
    ids = set()
    for line in text.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        kind = fields.pop(0)
        if kind == "path" and len(fields) == 1 and result["path"] is None:
            result["path"] = fields[0]
            last = None
        elif kind in {"mod", "dep"}:
            item = _module(fields)
            identity = (item["path"], item["version"])
            if identity in ids:
                fail("go-buildinfo-format", "Go module identity repeats")
            ids.add(identity)
            if kind == "mod":
                if result["main"] is not None:
                    fail("go-buildinfo-format", "main Go module repeats")
                result["main"] = item
            else:
                result["dependencies"].append(item)
            last = item
        elif kind == "=>" and last is not None and "replace" not in last:
            last["replace"] = _module(fields)
            last = None
        elif kind == "build" and len(fields) == 1 and "=" in fields[0]:
            key, value = fields[0].split("=", 1)
            if not key or key in result["settings"]:
                fail("go-buildinfo-format", "Go build setting is empty or repeated")
            result["settings"][key] = value
            last = None
        else:
            fail("go-buildinfo-format", "unsupported or ambiguous Go build metadata row")
    if not result["path"] or result["main"] is None or len(result["dependencies"]) > MAX_MEMBERS:
        fail("go-buildinfo-missing", "Go main module/command identity is absent")
    return result


def _module_identity(path, version):
    if (
        not isinstance(path, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._~/-]{0,1023}", path)
        or ".." in path.split("/")
        or not isinstance(version, str)
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[A-Za-z0-9.+-]+", version)
    ):
        fail("go-module-origin", "exact public Go module path and version required")
    return path + "@" + version + "/"


def _h1(rows):
    summary = hashlib.sha256()
    for path in sorted(rows):
        safe_parts(path.rstrip("/"))
        digest = rows[path]
        if not isinstance(digest, str) or not re.fullmatch("[0-9a-f]{64}", digest):
            fail("go-module-hash", "Go source file hash is malformed")
        summary.update((digest + "  " + path + "\n").encode())
    return "h1:" + base64.b64encode(summary.digest()).decode()


def module_proof(payload, path, version, checksum):
    prefix = _module_identity(path, version)
    inventory, files = _go_zip(payload, prefix)
    rows = {name: row["sha256"] for name, row in inventory.items()}
    if (
        any(not name.startswith(prefix) for name in rows)
        or not rows
        or not H1.fullmatch(checksum)
        or _h1(rows) != checksum
    ):
        fail("go-module-hash", "Go normalized source checksum differs from embedded module metadata")
    terms = {
        name[len(prefix) :]: {"body": base64.b64encode(body).decode(), "sha256": hashlib.sha256(body).hexdigest()}
        for name, body in files.items()
        if any(
            part.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"))
            for part in name[len(prefix) :].split("/")
        )
    }
    proof = {
        "schema_version": 1,
        "kind": "go-h1-source-terms/v1",
        "module": path,
        "version": version,
        "h1": checksum,
        "archive_sha256": hashlib.sha256(payload).hexdigest(),
        "downloaded_bytes": len(payload),
        "expanded_bytes": sum(row["size"] for row in inventory.values()),
        "files": rows,
        "terms": terms,
        "origin": None,
    }
    verify_module_proof(proof, path, version, checksum)
    return proof


def verify_module_proof(proof, path, version, checksum):
    prefix = _module_identity(path, version)
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {
            "schema_version",
            "kind",
            "module",
            "version",
            "h1",
            "archive_sha256",
            "downloaded_bytes",
            "expanded_bytes",
            "files",
            "terms",
            "origin",
        }
        or type(proof["schema_version"]) is not int
        or proof["schema_version"] != 1
        or proof["kind"] != "go-h1-source-terms/v1"
        or (proof["module"], proof["version"], proof["h1"]) != (path, version, checksum)
        or not H1.fullmatch(checksum)
        or not isinstance(proof["files"], dict)
        or not 0 < len(proof["files"]) <= MAX_MEMBERS
        or not isinstance(proof["terms"], dict)
        or any(not name.startswith(prefix) for name in proof["files"])
        or _h1(proof["files"]) != checksum
    ):
        fail("go-module-hash", "compact Go source proof does not reproduce its embedded h1 commitment")
    if (
        not isinstance(proof["archive_sha256"], str)
        or not re.fullmatch("[0-9a-f]{64}", proof["archive_sha256"])
        or type(proof["downloaded_bytes"]) is not int
        or not 0 < proof["downloaded_bytes"] <= MAX_ARTIFACT_BYTES
        or type(proof["expanded_bytes"]) is not int
        or not 0 < proof["expanded_bytes"] <= 512 * 1024 * 1024
    ):
        fail("go-module-hash", "Go source transfer/expanded accounting is invalid")
    expected = {
        name[len(prefix) :]
        for name in proof["files"]
        if any(
            part.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"))
            for part in name[len(prefix) :].split("/")
        )
    }
    if set(proof["terms"]) != expected:
        fail("license-obligation-missing", "compact Go proof omits a nested legal text")
    result = {}
    for name, item in proof["terms"].items():
        safe_parts(name)
        if not isinstance(item, dict) or set(item) != {"body", "sha256"}:
            fail("go-module-hash", "Go legal text proof is malformed")
        try:
            body = base64.b64decode(item["body"], validate=True)
        except (ValueError, TypeError):
            fail("go-module-hash", "Go legal text encoding is malformed")
        if (
            len(body) > MAX_METADATA_BYTES
            or hashlib.sha256(body).hexdigest() != item["sha256"]
            or item["sha256"] != proof["files"][prefix + name]
        ):
            fail("go-module-hash", "Go legal text differs from h1-committed source bytes")
        result[name] = body
    return result


PIN_SPECS = {
    "trivy": {
        "source_path": ".getzilla/getzilla/security_acquisition.py",
        "version_name": "TRIVY_VERSION",
        "sha_name": "TRIVY_ARCHIVE_SHA256",
        "url_name": "TRIVY_URL",
        "version": "0.74.0",
        "sha256": "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
        "url": "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
        "selected": ["trivy"],
        "expanded_limit": MAX_ARCHIVE_BYTES,
        "member_limit": MAX_ARCHIVE_BYTES,
    },
    "buildkit": {
        "source_path": ".getzilla/getzilla/security_image_provision.py",
        "version_name": "VERSION",
        "sha_name": "ARCHIVE_SHA256",
        "url_name": "URL",
        "version": "0.35.0",
        "sha256": "37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c",
        "url": "https://github.com/moby/buildkit/releases/download/v0.35.0/buildkit-v0.35.0.linux-amd64.tar.gz",
        "selected": ["bin/buildctl", "bin/buildkitd", "bin/buildkit-runc"],
        "expanded_limit": 512 * 1024 * 1024,
        "member_limit": MAX_ARTIFACT_BYTES,
    },
}


def checker_declarations(checker=None):
    """Read pins as inert syntax from the accepted checker, never import a candidate."""
    import ast
    from .security_artifacts import read_file

    if checker is None:
        from .security_tools import TRUSTED_ROOT

        checker = TRUSTED_ROOT
    declared = []
    for role, spec in PIN_SPECS.items():
        raw = read_file(checker, spec["source_path"], MAX_METADATA_BYTES)
        try:
            tree = ast.parse(raw.decode("utf-8"))
        except (ValueError, SyntaxError, UnicodeError):
            fail("checker-tool-source", "accepted checker pin source is not supported Python syntax")
        names = {}
        lines = {}
        allowed = {spec["version_name"], spec["sha_name"], spec["url_name"]}
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in allowed
            ):
                name = node.targets[0].id
                if name in names:
                    fail("checker-tool-source", "accepted checker pin has duplicate definitions")
                names[name] = node.value
                lines[name] = node.lineno

        def value(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.JoinedStr):
                result = ""
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        result += part.value
                    elif (
                        isinstance(part, ast.FormattedValue)
                        and isinstance(part.value, ast.Name)
                        and part.value.id == spec["version_name"]
                        and part.conversion == -1
                        and part.format_spec is None
                    ):
                        result += value(names[spec["version_name"]])
                    else:
                        fail("checker-tool-source", "checker pin URL is not a closed literal version template")
                return result
            fail("checker-tool-source", "checker pin is not an inert literal")

        if set(names) != allowed:
            fail("checker-tool-source", "accepted checker source lacks exact tool pins")
        version, sha, url = (value(names[spec[key]]) for key in ("version_name", "sha_name", "url_name"))
        if (version, sha, url) != (spec["version"], spec["sha256"], spec["url"]):
            fail("checker-tool-source", "checker tool is outside the two reviewed finite release pins")
        declared.append(
            {
                "id": "checker-tool:" + role + ":" + sha,
                "role": role,
                "version": version,
                "archive_sha256": sha,
                "reference": url,
                "source_path": spec["source_path"],
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "source_line": lines[spec["sha_name"]],
                "platform": "linux/amd64",
                "usage": "checker-tool",
                "distribution": "internal",
            }
        )
    return declared


def observe_archive(payload, declaration):
    """Read all bounded tar data and exactly the three BuildKit or one Trivy ELF."""
    import tarfile

    if not isinstance(declaration, dict) or declaration.get("role") not in PIN_SPECS:
        fail("checker-tool-source", "unknown checker tool role")
    spec = PIN_SPECS[declaration["role"]]
    if (
        not isinstance(payload, bytes)
        or not 0 < len(payload) <= MAX_ARTIFACT_BYTES
        or hashlib.sha256(payload).hexdigest() != spec["sha256"]
        or declaration.get("archive_sha256") != spec["sha256"]
    ):
        fail("artifact-hash", "checker tool archive differs from its accepted source pin")
    selected = {}
    legal = {}
    inventory = {}
    count = 0
    total = 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r|gz") as archive:
        for member in archive:
            count += 1
            total += member.size
            if count > 1000 or member.size < 0 or total > spec["expanded_limit"]:
                fail("artifact-size", "checker release exceeds its existing archive count/expanded-byte bounds")
            name = member.name
            safe_parts(name.rstrip("/"))
            if name in inventory:
                fail("artifact-archive", "checker release repeats a member path")
            if member.isdir():
                if member.size:
                    fail("artifact-archive", "checker archive directory has content")
                inventory[name] = {"directory": True}
                continue
            if not member.isfile():
                fail("artifact-archive", "checker release contains a link or special member")
            if declaration["role"] == "buildkit" and not re.fullmatch(r"bin/[A-Za-z0-9._-]+", name):
                fail("artifact-archive", "BuildKit source archive member is outside its fixed bin namespace")
            is_selected = name in spec["selected"]
            is_legal = any(
                part.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"))
                for part in name.split("/")
            )
            if (
                is_selected
                and not 0 < member.size <= spec["member_limit"]
                or is_legal
                and member.size > MAX_METADATA_BYTES
            ):
                fail("artifact-size", "selected checker binary or legal file exceeds its existing bound")
            source = archive.extractfile(member)
            if source is None:
                fail("artifact-archive", "checker archive member cannot be read")
            digest = hashlib.sha256()
            size = 0
            chunks = []
            with source:
                while block := source.read(65536):
                    size += len(block)
                    digest.update(block)
                    if is_selected or is_legal:
                        chunks.append(block)
            if size != member.size:
                fail("artifact-archive", "checker archive member is truncated")
            inventory[name] = {"sha256": digest.hexdigest(), "size": size}
            if is_selected:
                selected[name] = {"sha256": digest.hexdigest(), "size": size, "buildinfo": buildinfo(b"".join(chunks))}
            if is_legal:
                legal[name] = b"".join(chunks)
    if set(selected) != set(spec["selected"]):
        fail("go-buildinfo-missing", "checker release lacks one selected executable")
    return {"members": inventory, "executables": selected, "expanded_bytes": total, "member_count": count}, legal


def parse_source_lock(sums, vendors):
    """Read exact source lock sums and vendored module/replacement declarations."""
    if len(sums) > MAX_METADATA_BYTES or len(vendors) > MAX_METADATA_BYTES:
        fail("go-source-lock", "source Go lock exceeds existing metadata bounds")
    try:
        sum_text = sums.decode("utf-8")
        vendor_text = vendors.decode("utf-8")
    except UnicodeError:
        fail("go-source-lock", "Go lock metadata is not UTF-8")
    checksums = {}
    for line in sum_text.splitlines():
        fields = line.split()
        if len(fields) != 3 or not H1.fullmatch(fields[2]):
            fail("go-source-lock", "Go sum row is malformed")
        path, version, checksum = fields
        if version.endswith("/go.mod"):
            continue
        _module_identity(path, version)
        key = path + "@" + version
        if key in checksums and checksums[key] != checksum:
            fail("go-source-lock", "source Go sum checksum conflicts")
        checksums[key] = checksum
    selected = {}
    declarations = []
    for line in vendor_text.splitlines():
        if not line.startswith("# ") or line.startswith("##"):
            continue
        fields = line[2:].split()
        if len(fields) < 2:
            fail("go-source-lock", "vendored module identity is malformed")
        original = {"path": fields[0], "version": fields[1]}
        effective = original
        if len(fields) > 2:
            if len(fields) != 5 or fields[2] != "=>":
                fail("go-source-lock", "local/unversioned vendor replacements are unsupported")
            effective = {"path": fields[3], "version": fields[4]}
        _module_identity(effective["path"], effective["version"])
        key = effective["path"] + "@" + effective["version"]
        if key not in checksums:
            fail("go-source-lock", "vendored Go module has no exact source-lock checksum")
        selected[key] = checksums[key]
        declarations.append({"original": original, "effective": effective})
    if not selected:
        fail("go-source-lock", "source lock has no complete vendored modules")
    return {"checksums": selected, "declarations": declarations}


def _git_node(tree):
    if (
        not isinstance(tree, dict)
        or tree.get("truncated") is not False
        or not isinstance(tree.get("tree"), list)
        or not 0 < len(tree["tree"]) <= MAX_MEMBERS
    ):
        fail("go-source-lock", "one complete bounded Git tree node is required")
    rows = {}
    entries = []
    for row in tree["tree"]:
        if not isinstance(row, dict):
            fail("go-source-lock", "Git tree row is malformed")
        name = row.get("path")
        safe_parts(name)
        mode = row.get("mode")
        sha = row.get("sha")
        if (
            "/" in name
            or name in rows
            or mode not in {"040000", "100644", "100755", "120000", "160000"}
            or not isinstance(sha, str)
            or not re.fullmatch("[0-9a-f]{40}", sha)
        ):
            fail("go-source-lock", "Git tree node is ambiguous or unsupported")
        mode = mode.lstrip("0")
        entries.append((name.encode() + (b"/" if mode == "40000" else b""), mode, name, sha))
        rows[name] = row
    body = b"".join(
        mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha) for _, mode, name, sha in sorted(entries)
    )
    digest = hashlib.sha1(b"tree " + str(len(body)).encode() + b"\0" + body, usedforsecurity=False).hexdigest()
    if digest != tree.get("sha"):
        fail("go-source-lock", "Git tree node hash differs")
    return rows


def verify_source_lock(root, descriptor, repository, revision):
    """Commit -> exact tree nodes -> exact lock/license blobs, without a source ZIP."""
    from .security_artifacts import _saved_proof

    raw, proof = _saved_proof(root, descriptor["path"], descriptor["sha256"])
    evidence = [{"path": descriptor["path"], "sha256": descriptor["sha256"], "bytes": len(raw)}]
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {"schema_version", "kind", "repository", "revision", "commit", "root_tree", "vendor_tree", "blobs"}
        or proof["schema_version"] != 1
        or proof["kind"] != "go-git-source-lock/v1"
        or proof["repository"] != repository
        or proof["revision"] != revision
        or repository not in {"moby/buildkit", "opencontainers/runc", "aquasecurity/trivy"}
        or not re.fullmatch("[0-9a-f]{40}", revision)
    ):
        fail("go-source-lock", "Go source lock belongs to another exact source revision")

    def saved(item):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            fail("go-source-lock", "source lock descriptor is malformed")
        body, value = _saved_proof(root, item["path"], item["sha256"])
        evidence.append({"path": item["path"], "sha256": item["sha256"], "bytes": len(body)})
        return value

    commit = saved(proof["commit"])
    tree = saved(proof["root_tree"])
    vendor = saved(proof["vendor_tree"])
    if commit.get("sha") != revision or commit.get("tree", {}).get("sha") != tree.get("sha"):
        fail("go-source-lock", "Go source commit/tree identity differs")
    rows = _git_node(tree)
    vrows = _git_node(vendor)
    if rows.get("vendor", {}).get("sha") != vendor.get("sha") or rows["vendor"]["mode"] != "040000":
        fail("go-source-lock", "vendor tree is outside the exact source commit")
    if not isinstance(proof["blobs"], dict) or set(proof["blobs"]) != {"go.sum", "vendor/modules.txt", "LICENSE"}:
        fail("go-source-lock", "exact source lock/license blobs are absent")
    files = {}
    for path, item in proof["blobs"].items():
        row = vrows.get("modules.txt") if path == "vendor/modules.txt" else rows.get(path)
        blob = saved(item)
        if (
            not row
            or row["mode"] != "100644"
            or blob.get("sha") != row["sha"]
            or blob.get("encoding") != "base64"
            or type(blob.get("size")) is not int
            or not 0 < blob["size"] <= MAX_METADATA_BYTES
        ):
            fail("go-source-lock", "source lock blob is not an exact regular Git file")
        try:
            body = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
        except (ValueError, KeyError, TypeError):
            fail("go-source-lock", "Go source Git blob encoding is malformed")
        digest = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body, usedforsecurity=False).hexdigest()
        if len(body) != blob["size"] or row.get("size") != len(body) or digest != row["sha"]:
            fail("go-source-lock", "Go source lock/license bytes differ from Git")
        files[path] = body
    return parse_source_lock(files["go.sum"], files["vendor/modules.txt"]), files, evidence


def _go_zip(payload, prefix):
    """Hash Go ZIP names including normal directory entries, without extraction.

    Go HashZip commits names and contents, including any directory entries.
    This provider alone uses the observed-source 512 MiB expanded ceiling.
    Generic package archive limits remain unchanged.
    """
    import stat
    from .security_artifacts import _check_git_namespace

    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ARTIFACT_BYTES:
        fail("artifact-size", "Go module ZIP exceeds the existing artifact byte bound")
    end = payload.rfind(b"PK\x05\x06", max(0, len(payload) - 65557))
    if end < 0 or len(payload) < end + 22:
        fail("go-module-zip", "Go ZIP lacks its complete end record")
    _, disk, other, on_disk, count, central_size, _, comment = struct.unpack_from("<4s4H2LH", payload, end)
    if (
        disk
        or other
        or on_disk != count
        or count > MAX_MEMBERS
        or central_size > MAX_INDEX_BYTES
        or end + 22 + comment != len(payload)
    ):
        fail("go-module-zip", "Go ZIP has unsupported volumes, ZIP64 or excessive members/directory data")
    inventory = {}
    files = {}
    total = 0
    regular = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        for member in archive.infolist():
            name = member.filename
            if member.orig_filename != name or name in inventory or not name.startswith(prefix):
                fail("go-module-zip", "Go ZIP names are ambiguous or outside the module prefix")
            safe_parts(name.rstrip("/"))
            total += member.file_size
            kind = stat.S_IFMT(member.external_attr >> 16)
            if (
                member.flag_bits & 1
                or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or kind not in {0, stat.S_IFREG, stat.S_IFDIR}
            ):
                fail("go-module-zip", "Go ZIP links, encryption and special/compression types are unsupported")
            if total > 512 * 1024 * 1024:
                fail("artifact-size", "Go ZIP exceeds its finite expanded source-data bound")
            if member.is_dir() and member.file_size:
                fail("go-module-zip", "Go ZIP directory has content")
            wanted = not member.is_dir() and any(
                part.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS", "AUTHORS"))
                for part in name[len(prefix) :].split("/")
            )
            if wanted and member.file_size > MAX_METADATA_BYTES:
                fail("artifact-size", "Go legal text exceeds its existing metadata bound")
            digest = hashlib.sha256()
            size = 0
            chunks = []
            with archive.open(member) as stream:
                while block := stream.read(65536):
                    digest.update(block)
                    size += len(block)
                    if size > member.file_size:
                        fail("go-module-zip", "Go source member exceeds its declared size")
                    if wanted:
                        chunks.append(block)
            if size != member.file_size:
                fail("go-module-zip", "Go source member is truncated")
            inventory[name] = {"sha256": digest.hexdigest(), "size": size}
            if not member.is_dir():
                regular[name] = inventory[name]
            if wanted:
                files[name] = b"".join(chunks)
    _check_git_namespace(regular)
    return inventory, files


def checker_inventory(checker=None):
    """One joined ordinary auxiliary inventory; both fixed checker uses are owned."""
    import json

    declarations = checker_declarations(checker)
    subjects = []
    for item in declarations:
        subjects.append(
            {
                "kind": "release-tool",
                "reference": item["reference"],
                "manifest": item["source_path"],
                "line": item["source_line"],
                "source_sha256": item["source_sha256"],
                "usage": "checker-tool",
                "distribution": "internal",
                "artifact_sha256": item["archive_sha256"],
                "platform": "linux/amd64",
                "delivery_context": item["id"],
            }
        )
    value = {"schema_version": 1, "dependencies": [], "tools": subjects, "images": [], "complete": True, "gaps": []}
    value["digest"] = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return value


def module_requirements(observations, source_locks=None):
    """Keep embedded and exact-source-lock checksum bases distinct per ELF use."""
    source_locks = source_locks or {}
    required = {}
    gaps = []
    for role, observation in observations.items():
        for member, executable in observation["executables"].items():
            info = executable["buildinfo"]
            main = info["main"]["path"]
            repository = main.removeprefix("github.com/")
            revision = info["settings"].get("vcs.revision")
            lock = source_locks.get(repository + "@" + str(revision))
            for original in info["dependencies"]:
                effective = original.get("replace", original)
                path, version = effective["path"], effective["version"]
                key = path + "@" + version
                checksum = effective["h1"]
                basis = "embedded-h1"
                if not checksum:
                    basis = "source-lock-h1"
                    declaration = {
                        "original": {"path": original["path"], "version": original["version"]},
                        "effective": {"path": path, "version": version},
                    }
                    if lock is None or declaration not in lock["declarations"] or key not in lock["checksums"]:
                        gaps.append(
                            {
                                "code": "go-module-checksum-missing",
                                "role": role,
                                "member": member,
                                "module": key,
                                "source_revision": revision,
                                "message": "no embedded checksum or exact source-lock/vendor bridge",
                            }
                        )
                        continue
                    checksum = lock["checksums"][key]
                _module_identity(path, version)
                use = {
                    "role": role,
                    "member": member,
                    "checksum_basis": basis,
                    "original": original["path"],
                    "original_version": original["version"],
                    "source_revision": revision,
                }
                if key in required and required[key]["h1"] != checksum:
                    fail("go-source-lock", "one module path/version has conflicting embedded/source checksums")
                required.setdefault(key, {"path": path, "version": version, "h1": checksum, "uses": []})["uses"].append(
                    use
                )
    return required, gaps


def component_from_terms(identity, terms, *, expression=None, requires=None):
    """Qualify complete actual term bytes, independently of project policy approval."""
    from .security_licenses import _license_evidence, _select_expression
    from .security_license_texts import recognized_license

    if not isinstance(terms, dict) or not terms:
        fail("license-obligation-missing", "Go component has no retained source license/notice bytes")
    prefix = "go-terms/" + hashlib.sha256(identity.encode()).hexdigest() + "/"
    files = {}
    licenses = []
    notices = []
    identifiers = set()
    for name, body in terms.items():
        safe_parts(name)
        if not isinstance(body, bytes) or not body or len(body) > MAX_METADATA_BYTES:
            fail("license-obligation-missing", "Go legal text is missing or exceeds its metadata bound")
        path = prefix + name
        files[path] = body
        base = name.rsplit("/", 1)[-1].upper()
        if base.startswith(("NOTICE", "AUTHORS", "PATENTS")):
            notices.append(path)
        else:
            licenses.append(path)
            try:
                recognized = recognized_license(body.decode("utf-8"))
            except UnicodeError:
                fail("license-text-review", "Go legal text is not UTF-8")
            if recognized:
                identifiers.add(recognized)
    if not licenses:
        fail("license-obligation-missing", "Go component has no complete license term file")
    if expression is None:
        if not identifiers:
            fail("license-text-review", "Go source license terms require exact text/expression review")
        expression = " AND ".join(sorted(identifiers))
    chosen, mentioned = _select_expression(expression, sorted(identifiers), require_all=True)
    _license_evidence(files, {"expression": expression, "license_paths": licenses}, mentioned, chosen)
    component = {
        "id": identity,
        "expression": expression,
        "requires": requires or [],
        "files": [
            {"path": path, "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
            for path, body in sorted(files.items())
        ],
        "license_paths": sorted(licenses),
        "notice_paths": sorted(notices),
    }
    return component, files


def qualified_tool_bindings(checker, artifacts, license_result, *, now=None):
    """Bind both IDs only to independently re-evaluated ordinary joined output."""
    from .security_artifacts import artifact_identity, read_file, select_family
    from .security_data import _json
    from .security_licenses import evaluate_artifacts, load_policy

    if not isinstance(license_result, dict) or license_result.get("status") != "pass" or license_result.get("gaps"):
        fail("checker-tool-unqualified", "both checker tools require one ordinary joined license pass without gaps")
    inventory = checker_inventory(checker)
    declarations = checker_declarations(checker)
    actual = evaluate_artifacts(inventory, artifacts, load_policy(checker), now=now)
    if (
        actual.get("status") != "pass"
        or actual.get("gaps")
        or license_result.get("inventory_digest") != inventory["digest"]
        or license_result.get("policy_digest") != actual["policy_digest"]
    ):
        fail(
            "checker-tool-unqualified",
            "joined checker tool output differs from independently verified source/license facts",
        )
    bundle = _json(read_file(artifacts, "manifest.json", MAX_INDEX_BYTES))
    records = bundle.get("records")
    if not isinstance(records, list) or len(records) != 2:
        fail("checker-tool-unqualified", "joined checker catalog must own exactly its two actual tool families")
    expected = {}
    bindings = {}
    for declaration, subject in zip(declarations, inventory["tools"]):
        record = select_family(subject, "tool", records)
        identity = artifact_identity(record)
        expected[identity] = subject
        fields = ("role", "version", "archive_sha256", "source_path", "source_sha256")
        bindings[declaration["id"]] = {
            "source_pins": {"kind": "checker-tool", **{key: declaration[key] for key in fields}},
            "family_artifact_id": identity,
        }
    for output in (license_result, actual):
        details = output.get("details")
        if (
            not isinstance(details, list)
            or len(details) != 2
            or {d.get("artifact_id") for d in details} != set(expected)
            or any(
                d.get("status") != "pass"
                or d.get("kind") != "tool"
                or d.get("subject") != expected.get(d.get("artifact_id"))
                for d in details
            )
        ):
            fail(
                "checker-tool-unqualified",
                "single-tool, foreign or package license output cannot qualify either checker ID",
            )
    return bindings


def verify_family(root, record, payload=None, *, checker=None, now=None):
    """Qualify a finite checker family from actual ELF/module/source term facts."""
    from .security_artifacts import _saved_proof, read_file, family_identity, artifact_context
    from .security_data import _clock, _timestamp, MAX_AGE_SECONDS

    identity = family_identity(record)
    declarations = checker_declarations(checker)
    by_id = {item["id"]: item for item in declarations}
    origin = record["origin"]
    subject = record["subject"]
    if (
        set(origin) != {"kind", "declaration", "index_url", "artifact_url"}
        or origin["kind"] != "go-checker-release/v1"
        or not isinstance(origin["declaration"], dict)
        or origin["declaration"].get("id") not in by_id
    ):
        fail("checker-tool-source", "Go family lacks an accepted checker tool declaration")
    declaration = by_id[origin["declaration"]["id"]]
    role = declaration["role"]
    spec = PIN_SPECS[role]
    expected_subject = checker_inventory(checker)["tools"][list(PIN_SPECS).index(role)]
    expected_api = (
        "https://api.github.com/repos/"
        + ("aquasecurity/trivy" if role == "trivy" else "moby/buildkit")
        + "/releases/tags/v"
        + declaration["version"]
    )
    if (
        origin["declaration"] != declaration
        or subject != expected_subject
        or record["context"] != artifact_context(subject)
        or origin["artifact_url"] != spec["url"]
        or origin["index_url"] != expected_api
        or record["filename"] != spec["url"].rsplit("/", 1)[-1]
        or record["sha256"] != spec["sha256"]
    ):
        fail("checker-tool-source", "Go family differs from its exact checker source/use")
    age = (_clock(now) - _timestamp(record["acquired_at"])).total_seconds()
    if not 0 <= age <= MAX_AGE_SECONDS:
        fail("artifact-stale", "Go checker family is future or older than 72 hours")
    if payload is None:
        payload = read_file(root, record["path"], MAX_ARTIFACT_BYTES)
    if len(payload) != record["bytes"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        fail("artifact-hash", "Go checker archive bytes differ")
    observed, archive_terms = observe_archive(payload, declaration)
    raw, proof = _saved_proof(root, record["components"]["path"], record["components"]["sha256"])
    evidence = [{"path": record["components"]["path"], "sha256": record["components"]["sha256"], "bytes": len(raw)}]
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {"schema_version", "kind", "tool_id", "release", "modules", "source_locks", "runtime", "expressions"}
        or proof["schema_version"] != 1
        or proof["kind"] != "go-checker-components/v1"
        or proof["tool_id"] != declaration["id"]
        or any(not isinstance(proof[key], dict) for key in ("modules", "source_locks", "runtime", "expressions"))
    ):
        fail("license-transitive-coverage", "unsupported Go component proof schema")

    def saved(descriptor):
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256"}:
            fail("artifact-origin", "Go source proof descriptor is malformed")
        body, value = _saved_proof(root, descriptor["path"], descriptor["sha256"])
        evidence.append({"path": descriptor["path"], "sha256": descriptor["sha256"], "bytes": len(body)})
        return value

    release = saved(proof["release"])
    if release.get("tag_name") != "v" + declaration["version"] or not isinstance(release.get("assets"), list):
        fail("artifact-origin", "Go tool release tag/asset metadata is missing")
    assets = [a for a in release["assets"] if isinstance(a, dict) and a.get("name") == record["filename"]]
    if (
        len(assets) != 1
        or assets[0].get("browser_download_url") != spec["url"]
        or assets[0].get("size") != len(payload)
        or assets[0].get("digest") != "sha256:" + spec["sha256"]
    ):
        fail("artifact-origin", "Go checker release asset URL/size/hash differs")
    locks = {}
    lock_files = {}
    for key, descriptor in proof["source_locks"].items():
        if not isinstance(key, str) or "@" not in key:
            fail("go-source-lock", "source lock needs its repository and exact Git revision")
        repository, revision = key.rsplit("@", 1)
        lock, files, items = verify_source_lock(root, descriptor, repository, revision)
        locks[key] = lock
        lock_files[key] = files
        evidence.extend(items)
    for member, executable in observed["executables"].items():
        info = executable["buildinfo"]
        if info["settings"].get("GOOS") != "linux" or info["settings"].get("GOARCH") != "amd64":
            fail("go-buildinfo-format", "Go selected executable platform differs")
        if info["settings"].get("CGO_ENABLED") != "0":
            fail(
                "go-cgo-native-unresolved",
                f"{member}: static CGO/native component source/version/terms need a separately qualified proof",
            )
    required, gaps = module_requirements({role: observed}, locks)
    if gaps:
        fail(gaps[0]["code"], gaps[0]["message"] + ": " + gaps[0]["module"])
    if set(proof["modules"]) != set(required):
        fail("license-transitive-coverage", "Go compact module proofs omit or add a selected ELF dependency")
    components = []
    retained = {}

    def component(identifier, terms):
        value, files = component_from_terms(identifier, terms, expression=proof["expressions"].get(identifier))
        components.append(value)
        retained.update(files)

    for key, module in required.items():
        source = saved(proof["modules"][key])
        terms = verify_module_proof(source, module["path"], module["version"], module["h1"])
        origin_data = source.get("origin")
        def escaped(text):
            return "".join("!" + c.lower() if c.isupper() else c for c in text)
        source_url = (
            "https://proxy.golang.org/" + escaped(module["path"]) + "/@v/" + escaped(module["version"]) + ".zip"
        )
        if (
            not isinstance(origin_data, dict)
            or origin_data.get("requested_url") != source_url
            or not isinstance(origin_data.get("fetched_at"), (int, float))
        ):
            fail("go-module-origin", "qualified Go source terms need retained exact public proxy origin/time")
        component("go-module:" + key, terms)
    versions = {item["buildinfo"]["go_version"].split("-X:", 1)[0] for item in observed["executables"].values()}
    if set(proof["runtime"]) != versions:
        fail("go-runtime-terms-missing", "every actual Go runtime version needs its own source legal metadata")
    for version, files in proof["runtime"].items():
        if not isinstance(files, dict) or set(files) != {"LICENSE", "PATENTS"}:
            fail("go-runtime-terms-missing", "Go runtime needs its exact versioned LICENSE and PATENTS bytes")
        terms = {}
        for name, item in files.items():
            if (
                not isinstance(item, dict)
                or set(item) != {"path", "sha256", "url"}
                or item["url"] != "https://raw.githubusercontent.com/golang/go/" + version + "/" + name
            ):
                fail("go-runtime-terms-missing", "Go runtime legal origin/version differs")
            body = read_file(root, item["path"], MAX_METADATA_BYTES)
            if hashlib.sha256(body).hexdigest() != item["sha256"]:
                fail("artifact-hash", "Go runtime legal bytes changed")
            evidence.append({"path": item["path"], "sha256": item["sha256"], "bytes": len(body)})
            terms[name] = body
        component("go-runtime:" + version, terms)
    mains = {}
    for executable in observed["executables"].values():
        info = executable["buildinfo"]
        main = info["main"]
        key = main["path"] + "@" + main["version"]
        mains[key] = info
    for key, info in mains.items():
        if role == "trivy":
            terms = archive_terms
        else:
            lock_key = (
                info["main"]["path"].removeprefix("github.com/") + "@" + str(info["settings"].get("vcs.revision"))
            )
            if lock_key not in lock_files:
                fail("go-root-terms-missing", "Go root module needs its exact source Git license")
            terms = {"LICENSE": lock_files[lock_key]["LICENSE"]}
        component("go-main:" + key, terms)
    ids = {c["id"] for c in components}
    if not set(proof["expressions"]) <= ids:
        fail("license-transitive-coverage", "Go expression inputs name an unowned component")
    for c in components:
        if c["id"].startswith("go-main:"):
            c["requires"] = sorted(ids - {c["id"]})
    return {
        "artifact_id": identity,
        "members": observed["members"],
        "files": retained,
        "components": components,
        "binding": {
            "artifact_id": identity,
            "artifact_sha256": record["sha256"],
            "artifact_size": len(payload),
            "subject": subject,
            "context": record["context"],
            "proofs": evidence,
            "go_module_assurance": "actual embedded/source-lock module identities; standard Go runtime included; no reproducible compiler or host OS/kernel claim",
        },
        "bound_bytes": len(payload) + sum(item["bytes"] for item in evidence),
    }
