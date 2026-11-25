"""Installed software ownership and scanner coverage from verified OCI bytes."""

from __future__ import annotations

import base64
from collections import defaultdict
import copy
import csv
from email.parser import BytesParser
import io
import posixpath
import re

from . import security_oci as oci

_PROOF = object()


def _retain(path):
    leaf = path.rsplit("/", 1)[-1].lower()
    return (
        path in {"var/lib/dpkg/status", "lib/apk/db/installed"}
        or path.startswith("var/lib/dpkg/info/") and leaf.endswith(".list")
        or ".dist-info/" in path and leaf in {"metadata", "record"}
        or leaf == "vendor.txt"
    )


def _safe(path):
    if not isinstance(path, str) or "\\" in path or "\x00" in path:
        raise oci.OCIError("Unsafe component data path")
    path = path.lstrip("/")
    value = posixpath.normpath(path)
    if value == ".." or value.startswith("../"):
        raise oci.OCIError("Component data path escapes image root")
    return value


class _Files:
    def __init__(self, rows):
        self.rows = rows

    def resolve(self, path):
        path, seen = _safe(path), set()
        for _ in range(32):
            if path in seen:
                raise oci.OCIError("Cyclic image component data alias")
            seen.add(path)
            parts, changed = path.split("/"), False
            for n in range(1, len(parts) + 1):
                prefix = "/".join(parts[:n])
                row = self.rows.get(prefix)
                if row and row["kind"] in {"symlink", "hardlink"}:
                    target = row["target"]
                    base = "" if row["kind"] == "hardlink" or target.startswith("/") else posixpath.dirname(prefix)
                    path = _safe(posixpath.join(base, target.lstrip("/"), *parts[n:]))
                    changed = True
                    break
                if row and n < len(parts) and row["kind"] != "directory":
                    raise oci.OCIError("Component path ancestor is not a directory")
            if not changed:
                return path, self.rows.get(path)
        raise oci.OCIError("Image component alias exceeds bound")

    def data(self, path):
        resolved, row = self.resolve(path)
        if row is None:
            return None
        if row["kind"] != "file" or "body" not in row:
            raise oci.OCIError("Component evidence is not retained regular data")
        return row["body"], dict(path=resolved, sha256=row["sha256"], bytes=row["bytes"], layer=row["layer"])


def _paragraphs(body):
    result = []
    for block in re.split(r"\n[ \t]*\n", body.decode("utf-8").replace("\r\n", "\n")):
        fields, key = {}, None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and key:
                fields[key] += "\n" + ("" if line[1:] == "." else line[1:])
            elif re.match(r"^[A-Za-z][A-Za-z0-9-]*:", line):
                key, value = line.split(":", 1)
                if key in fields:
                    raise oci.OCIError("Duplicate component metadata field")
                fields[key] = value.lstrip()
            elif line.strip():
                raise oci.OCIError("Malformed component metadata")
        if fields:
            result.append(fields)
    return result


def _evidence(row):
    return {key: row[key] for key in ("path", "sha256", "bytes", "layer")}


class ImageComponentObservation:
    __slots__ = ("_image", "_document", "_proof", "_files")

    def __init__(self, image, document, files, proof):
        if proof is not _PROOF:
            raise oci.OCIError("Image component observation requires held bytes")
        self._image, self._document, self._proof = image, document, proof
        self._files = files

    def _live(self):
        if self._proof is not _PROOF:
            raise oci.OCIError("Invalid image component observation")
        self._image.remaining_seconds()
        oci.scanner_identity({"Metadata": {"ImageID": self._image.config_digest}}, self._image)

    def document(self):
        self._live()
        return copy.deepcopy(self._document)

    def proof_files(self):
        """Exact regular proof data for the caller's existing bounded finalizer.

        Paths refer to final image data. This does not transfer OCI authority,
        issue a receipt, or persist anything outside the caller's owned store.
        """
        self._live()
        return dict(self._files)


def observe_components(image, *, source_root=None, packages=None, advisory_pages=None):
    """Build a component SBOM observation, never trust caller JSON as custody."""
    index, scan_receipt = packages if packages is not None else ({}, None)
    from . import security_image_authority as authority
    state = authority._LIVE
    rows = state.get("dind_cli_component_rows", {}).pop(image, None) if state else None
    if rows is not None:
        image.remaining_seconds()
    files = _Files(rows if rows is not None else oci.observe_final_files(image, _retain))
    from .security_threshold import record_filesystem
    record_filesystem(image, files.rows, state)
    postgres_check = None
    if advisory_pages is not None:
        from .security_postgresql import check_image
        postgres_check = check_image(image, files, advisory_pages)
    components, unresolved, owners = [], [], defaultdict(set)
    identities, owned_paths = set(), defaultdict(set)

    def gap(code, group, **detail):
        unresolved.append(dict(code=code, group=group, **detail))

    def add(identity, kind):
        if identity in identities:
            raise oci.OCIError("Duplicate installed component identity")
        identities.add(identity)
        component = dict(
            id=identity,
            kind=kind,
            files=[],
            evidence=[],
            requires=[],
        )
        components.append(component)
        return component

    def own(component, paths):
        for path in paths:
            resolved, row = files.resolve(path)
            if row and row["kind"] == "file":
                owners[resolved].add(component["id"])
                if resolved not in owned_paths[component["id"]]:
                    component["files"].append(_evidence(row))
                    owned_paths[component["id"]].add(resolved)

    status = files.data("var/lib/dpkg/status")
    if status:
        for package in _paragraphs(status[0]):
            if package.get("Status") != "install ok installed":
                continue
            name, version, arch = (package.get(k) for k in ("Package", "Version", "Architecture"))
            if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]+", v) for v in (name, version, arch)):
                raise oci.OCIError("Invalid installed Debian component identity")
            c = add(f"deb:{name}:{arch}@{version}", "dpkg")
            if name.startswith("postgresql") and (name, version, arch) not in index.get(("debian", ""), ()):
                gap("unsupported-postgres-components", c["id"])
            c.update(
                source_package=package.get("Source", name),
                depends=package.get("Depends"),
                pre_depends=package.get("Pre-Depends"),
            )
            c["evidence"].append(status[1])
            listing = [files.data("var/lib/dpkg/info/" + suffix + ".list") for suffix in (name, name + ":" + arch)]
            listing = [v for v in listing if v is not None]
            if len(listing) != 1:
                gap("dpkg-file-list-unproved", c["id"])
            for raw, proof in listing:
                c["evidence"].append(proof)
                own(c, raw.decode("utf-8").splitlines())
            # Maintainer scripts belong to this installed package, not to the
            # generated metadata group. Shared common texts remain references.
            own(
                c,
                [
                    p
                    for p in files.rows
                    if p.startswith("var/lib/dpkg/info/")
                    and p.rsplit("/", 1)[-1].rsplit(".", 1)[0] in {name, name + ":" + arch}
                ],
            )
    # Installed Python distributions, including additions made by built recipes.
    python_roots = []
    for path in sorted(files.rows):
        if not path.endswith(".dist-info/METADATA"):
            continue
        metadata = files.data(path)
        if metadata is None:
            continue
        message = BytesParser().parsebytes(metadata[0])
        for key in ("Name", "Version"):
            if len(message.get_all(key, [])) > 1:
                raise oci.OCIError("Duplicate installed Python metadata field")
        name, version = message.get("Name"), message.get("Version")
        if (
            not name
            or not version
            or not re.fullmatch(r"[A-Za-z0-9_.+-]+", name)
            or not re.fullmatch(r"[A-Za-z0-9_.+!-]+", version)
        ):
            raise oci.OCIError("Invalid installed Python component identity")
        c = add("pypi:" + name.lower().replace("_", "-") + "@" + version, "python")
        prefix, site = posixpath.dirname(path), posixpath.dirname(posixpath.dirname(path))
        python_roots.append((site, c))
        c["evidence"].append(metadata[1])
        record = files.data(prefix + "/RECORD")
        if not record:
            gap("python-record-missing", c["id"])
        else:
            c["evidence"].append(record[1])
            seen = set()
            for row in csv.reader(io.StringIO(record[0].decode("utf-8"))):
                if len(row) != 3 or row[0] in seen:
                    raise oci.OCIError("Malformed or duplicate installed Python RECORD")
                seen.add(row[0])
                if row[0].startswith("/") or "\\" in row[0]:
                    raise oci.OCIError("Unsafe installed Python RECORD path")
                actual, entry = files.resolve(_safe(posixpath.join(site, row[0])))
                if entry is None:
                    continue  # Deleted cache/build records are not installed components.
                own(c, [actual])
                if entry["kind"] == "file" and row[1]:
                    digest = base64.urlsafe_b64encode(bytes.fromhex(entry["sha256"])).rstrip(b"=").decode()
                    if row[1] != "sha256=" + digest or row[2] != str(entry["bytes"]):
                        gap("python-record-mismatch", c["id"], path=actual)
                elif entry["kind"] == "file" and actual != prefix + "/RECORD":
                    gap("python-record-unhashed", c["id"], path=actual)
    # pip bundles do not necessarily have separate dist-info records.
    for site, parent in python_roots:
        if not parent["id"].startswith("pypi:pip@"):
            continue
        vendor = files.data(site + "/pip/_vendor/vendor.txt")
        if not vendor:
            continue
        root = site + "/pip/_vendor/"
        for line in vendor[0].decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+)==([^\s]+)\s*", line)
            if not match:
                gap("pip-vendor-declaration-unsupported", parent["id"])
                continue
            name, version = match.groups()
            alias = "pkg_resources" if name.lower() == "setuptools" else name.lower().replace("-", "_")
            c = add("pip-vendor:" + name.lower() + "@" + version, "python-vendored")
            parent["requires"].append(c["id"])
            c["evidence"].append(vendor[1])
            paths = [p for p in files.rows if p.startswith(root + alias + "/")]
            own(c, paths)
            if not paths:
                gap("pip-vendor-files-missing", c["id"])
    # The installed CPython directory identifies source-built interpreter files.
    for path in sorted(files.rows):
        match = re.fullmatch(r"usr/local/lib/(python[0-9]+\.[0-9]+)/LICENSE.txt", path)
        if not match:
            continue
        root = "usr/local/lib/" + match[1] + "/"
        c = add("cpython-source-built:" + match[1], "source-built-python")
        own(
            c,
            [
                p
                for p in files.rows
                if not owners.get(p)
                and (
                    p.startswith(root)
                    or p.startswith("usr/local/include/" + match[1] + "/")
                    or p.startswith("usr/local/bin/" + match[1])
                    or p.startswith("usr/local/lib/lib" + match[1])
                )
            ],
        )
    installed = files.data("lib/apk/db/installed")
    if installed:
        from .security_image_package_coverage import apk_inventory
        try:
            alpine = apk_inventory(installed[0])
        except (ValueError, UnicodeError):
            alpine = {}
        if not alpine or set(alpine) != index.get(("alpine", "")):
            gap("unsupported-apk-components", "apk")
        for (name, version, arch), (_, members) in alpine.items():
            c = add(f"apk:{name}:{arch}@{version}", "apk")
            c["evidence"].append(installed[1])
            for path, checksum in members.items():
                row = files.rows.get(path)
                if not row or row["kind"] != "file" or not checksum:
                    continue
                # APK Q1 is SHA-1 (legacy). The OCI graph and every subject
                # still bind the full SHA-256 of the file and its layer.
                expected = "Q1" + base64.b64encode(bytes.fromhex(row["apk_sha1"])).decode("ascii")
                if checksum == expected:
                    own(c, [path])
    unknown = []
    go_files = []
    from .security_image_package_coverage import check_known_binary
    for path, row in files.rows.items():
        check_known_binary(row, image)
        if row.get("elf") and row.get("go_binary"):
            go_files.append(_evidence(row))
        if row["kind"] == "file" and path.endswith(".jar"):
            gap("unsupported-tool-bundle-components", "java-bundles", file=_evidence(row))
        if row["kind"] != "file" or owners.get(path):
            continue
        # Generated metadata is not an independent software component. Package
        # maintainer scripts were attributed above before this classification.
        generated = path.startswith(("var/log/", "var/cache/", "run/"))
        source = path.endswith((".py", ".pyc", ".js", ".mjs", ".cjs", ".sh", ".rb", ".pl", ".jar", ".wasm"))
        if (row.get("elf") or row.get("executable") or source) and not generated:
            unknown.append(_evidence(row))
    from .security_image_file_origins import archive_origins, postgres_source, project_origins, upstream_origin
    postgres = postgres_source(image.manifest_digest, unknown)
    if postgres is not None:
        version, origin, paths = postgres
        c = add("postgresql-source:" + version, "source-built-postgresql")
        c["source_origin"] = origin
        own(c, paths)
        # A distro client package or a dependency-only metapackage cannot attest
        # the security coverage of this upstream source-built server.
        if postgres_check is None or postgres_check["version"] != version:
            gap("unsupported-postgres-components", c["id"])
    for name, origin, paths in archive_origins(unknown):
        component = add("runner-download:" + name, "pinned-runner-artifact")
        component["source_origin"] = origin
        own(component, paths)
    for row in unknown:
        origin = upstream_origin(row)
        if origin is not None:
            c = add("upstream-file:" + row["path"], "upstream-image-file")
            c["source_origin"] = origin
            own(c, [row["path"]])
    if source_root is not None:
        matched = project_origins(unknown, source_root)
        if matched:
            component = add("getzilla:trust-ci-source", "project-source")
            component["source_files"] = matched
            own(component, [row["path"] for row in matched])
    unknown = [row for row in unknown if not owners.get(row["path"])]
    missing_go, debian_go = [], []
    for row in go_files:
        packages_for_binary = index.get(("gobinary", row["path"]))
        if not packages_for_binary:
            from .security_image_package_coverage import debian_go_coverage
            package_proof = debian_go_coverage(row, owners.get(row["path"]), index)
            if package_proof:
                debian_go.append(package_proof)
                continue
            missing_go.append(row)
            continue
        c = add("go-executable:" + row["path"], "go-binary")
        c["modules"] = sorted([name, version] for name, version, _ in packages_for_binary)
        own(c, [row["path"]])
    if missing_go:
        gap("unsupported-go-components", "go-bundles", files=missing_go)
    unknown = [row for row in unknown if not owners.get(row["path"])]
    if unknown:
        gap("unattributed-software", "final-installed-files", files=sorted(unknown, key=lambda v: v["path"]))
    if not components and not unresolved:
        gap("software-catalog-empty", "image")
    document = dict(
        schema_version=1,
        scope="final-installed-image-components",
        reference=image.reference,
        platform=image.platform,
        manifest_digest=image.manifest_digest,
        config_digest=image.config_digest,
        components=components,
        unresolved=unresolved,
        complete=not unresolved,
        qualification="observation-only; source/run/native guard and policy join required",
    )
    proofs = {path: row["body"] for path, row in files.rows.items() if "body" in row}
    if debian_go:
        document["debian_go_coverage"] = debian_go
    if postgres_check is not None:
        document["postgresql_server"] = postgres_check
    if scan_receipt is not None:
        document["trivy_package_evidence"] = scan_receipt
    document["proof_bytes"] = sum(len(body) for body in proofs.values())
    return ImageComponentObservation(image, document, proofs, _PROOF)
