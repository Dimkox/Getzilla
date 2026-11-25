"""Installed image component/term custody from LIVE verified OCI bytes.

No package or image executes. This module makes no license-policy decision and
issues no qualification receipt. Complex/unsupported source groups stay explicit.
The caller must join the observation to its normal source/run/private guard.
"""

from __future__ import annotations

import base64
from collections import Counter, defaultdict
import copy
import csv
from email.parser import BytesParser
import io
import posixpath
import re

from . import security_oci as oci
from .security_license_texts import recognized_license

_PROOF = object()


def _retain(path):
    leaf = path.rsplit("/", 1)[-1].lower()
    return (
        path in {"var/lib/dpkg/status", "lib/apk/db/installed"}
        or path.startswith("var/lib/dpkg/info/")
        or path.startswith(("usr/share/doc/", "usr/share/common-licenses/"))
        and (leaf == "copyright" or path.startswith("usr/share/common-licenses/"))
        or ".dist-info/" in path
        and leaf in {"metadata", "record", "wheel"}
        or leaf in {"vendor.txt", "license.txt", "license", "copying", "notice", "notice.txt"}
        or "license" in leaf
        or ".dist-info/licenses/" in path
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


def observe_components(image):
    """Build a component SBOM observation, never trust caller JSON as custody."""
    files = _Files(oci.observe_final_files(image, _retain))
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
            expression=None,
            files=[],
            license_paths=[],
            notice_paths=[],
            evidence=[],
            raw_license_declarations=[],
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

    def terms(component, entries, expression=None):
        recognized = set()
        for entry in entries:
            if entry is None:
                continue
            raw, proof = entry
            component["license_paths"].append(proof)
            text = raw.decode("utf-8")
            identifier = recognized_license(text)
            if identifier:
                recognized.add(identifier)
            else:
                gap("license-text-unrecognized", component["id"], path=proof["path"], sha256=proof["sha256"])
        # Exact six-license recognizer is reused without expanding policy. Other
        # retained terms are data, and require an explicit qualified term mapping.
        if expression and expression in recognized:
            component["expression"] = expression
        elif not expression and len(recognized) == 1:
            component["expression"] = next(iter(recognized))
        else:
            gap("license-term-unproved", component["id"], declared_expression=expression)

    status = files.data("var/lib/dpkg/status")
    if status:
        for package in _paragraphs(status[0]):
            if package.get("Status") != "install ok installed":
                continue
            name, version, arch = (package.get(k) for k in ("Package", "Version", "Architecture"))
            if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9.+:~_-]+", v) for v in (name, version, arch)):
                raise oci.OCIError("Invalid installed Debian component identity")
            c = add(f"deb:{name}:{arch}@{version}", "dpkg")
            if name.startswith("postgresql"):
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
            copyright = files.data("usr/share/doc/" + name + "/copyright")
            if copyright is None:
                gap("dpkg-copyright-missing", c["id"])
                continue
            c["evidence"].append(copyright[1])
            raw = copyright[0]
            if b"copyright-format" not in raw.split(b"\n\n", 1)[0]:
                c["license_paths"].append(copyright[1])
                gap("dpkg-legacy-license-scope", c["id"])
                continue
            try:
                sections = _paragraphs(raw)
            except (oci.OCIError, UnicodeDecodeError):
                c["license_paths"].append(copyright[1])
                gap("dpkg-copyright-format-unproved", c["id"], **copyright[1])
                continue
            declarations = [v for v in sections if "License" in v]
            c["raw_license_declarations"] = declarations
            scope = [v for v in declarations if v.get("Files") == "*"]
            labels = {v["License"].split("\n", 1)[0] for v in declarations}
            if len(scope) != 1 or len(labels) != 1:
                c["license_paths"].append(copyright[1])
                gap("dpkg-binary-license-scope", c["id"])
                continue
            label = scope[0]["License"].split("\n", 1)[0]
            inline = []
            for section in declarations:
                value = section["License"].partition("\n")[2]
                if value and not re.fullmatch(r"See /usr/share/common-licenses/[A-Za-z0-9_.+-]+\s*", value):
                    inline.append((value.encode(), copyright[1]))
            for reference in sorted(set(re.findall(rb"/usr/share/common-licenses/[A-Za-z0-9_.+-]+", raw))):
                entry = files.data(reference.decode().rstrip("."))
                if entry is None:
                    gap("license-common-text-missing", c["id"], path=reference.decode())
                else:
                    inline.append(entry)
            c["license_paths"].append(copyright[1])
            terms(c, inline, label)
    # Installed Python distributions, including additions made by built recipes.
    python_roots = []
    for path in sorted(files.rows):
        if not path.endswith(".dist-info/METADATA"):
            continue
        metadata = files.data(path)
        if metadata is None:
            continue
        message = BytesParser().parsebytes(metadata[0])
        for key in ("Name", "Version", "License-Expression"):
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
        c["raw_license_declarations"] = message.get_all("License-Expression", [])
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
        licenses = []
        for label in message.get_all("License-File", []):
            if label.startswith("/") or ".." in label.split("/"):
                raise oci.OCIError("Unsafe installed Python license path")
            entry = files.data(prefix + "/licenses/" + label) or files.data(prefix + "/" + label)
            if entry is None:
                gap("python-license-file-missing", c["id"], path=label)
            licenses.append(entry)
        terms(c, licenses, message.get("License-Expression"))
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
            license_entries = [
                files.data(p) for p in paths if re.match(r"(?i)^(license|copying)(\.|$)", p.rsplit("/", 1)[-1])
            ]
            if not paths:
                gap("pip-vendor-files-missing", c["id"])
            terms(c, license_entries)
    # Explicit source-built CPython group. Its umbrella text cannot prove every
    # bundled extension's terms, and static filenames do not observe target ABI.
    for path in sorted(files.rows):
        match = re.fullmatch(r"usr/local/lib/(python[0-9]+\.[0-9]+)/LICENSE.txt", path)
        if not match:
            continue
        root = "usr/local/lib/" + match[1] + "/"
        c = add("cpython-source-built:" + match[1], "source-built-python")
        license_entry = files.data(path)
        c["license_paths"].append(license_entry[1])
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
        gap("cpython-bundled-terms-unproved", c["id"])
    # Retain exact reviewed source conditions even when binary composition or
    # other original licence labels remain unresolved. Never remove those gaps.
    from .security_license_source_conditions import PROFILES, retained_conditions
    image_sha = image.manifest_digest.removeprefix("sha256:")
    for component in components:
        for profile in PROFILES:
            if profile["artifact_sha256"] != image_sha or profile["component_id"] != component["id"]:
                continue
            original = {}
            for path in profile["files"]:
                entry = files.data(path)
                if entry is not None:
                    original[path] = entry[0]
            condition = retained_conditions(image_sha, component["id"], original)
            if condition is not None:
                component["source_conditions"] = condition
    if files.data("lib/apk/db/installed"):
        gap("unsupported-apk-components", "apk")
    unknown = []
    go_files = []
    for path, row in files.rows.items():
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
    if go_files:
        gap("unsupported-go-components", "go-bundles", files=go_files)
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
    document["proof_bytes"] = sum(len(body) for body in proofs.values())
    return ImageComponentObservation(image, document, proofs, _PROOF)


_FAMILY_SEAL = object()
_FAMILY_KIND = "held-oci-components/v1"


def _family_live(inventory=None, source=None, run=None):
    from . import security_image_authority as producer, security_image_authority as native
    from .security_artifacts import ArtifactError

    state = producer._LIVE
    if (
        state is None
        or native._GUARD is None
        or state.get("native_guard") is not native._GUARD
        or inventory is not None
        and state.get("declared_inventory") != inventory
        or source is not None
        and state.get("source") != source
        or run is not None
        and state.get("run") != run
    ):
        raise ArtifactError(
            "license-image-live-required", "image component families need the actual owned source/run/guard"
        )
    return state


def _store_identity(root):
    import os
    import stat

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.getuid() or value.st_mode & 0o022:
            raise oci.OCIError("Image family store must be owned and private")
        return value.st_dev, value.st_ino
    finally:
        os.close(fd)


class _HeldFamily:
    __slots__ = (
        "record",
        "observation",
        "document",
        "proofs",
        "state",
        "source",
        "run",
        "guard",
        "store",
        "seal",
        "root",
    )

    def __init__(self, record, observation, document, proofs, state, store, seal):
        if seal is not _FAMILY_SEAL:
            raise oci.OCIError("Image family needs actual held component proof")
        self.record, self.observation, self.document, self.proofs = (
            copy.deepcopy(record),
            observation,
            copy.deepcopy(document),
            dict(proofs),
        )
        self.state, self.source, self.run = state, copy.deepcopy(state["source"]), copy.deepcopy(state["run"])
        self.guard, self.store, self.seal = state["native_guard"], store, seal


def _family_projection(observation, license_rows=()):
    """Project complete text fields, retaining their exact original data source.

    DEP5 field decoding removes only its standard continuation/dot encoding.
    It never splits legal clauses. Every projected body has its own hash and a
    bound original copyright file plus exact field index in the saved manifest.
    """
    import hashlib

    document, proofs = observation.document(), observation.proof_files()
    if document["unresolved"] != list(license_rows) or document["complete"] != (not license_rows):
        from .security_artifacts import ArtifactError

        first = document["unresolved"][0]
        raise ArtifactError(first["code"], "image component coverage unresolved: " + str(first["group"]))
    components, material, derivations = [], {}, []

    def term(body, source, derivation):
        digest = hashlib.sha256(body).hexdigest()
        path = "term-texts/" + digest
        material[path] = body
        derivations.append(dict(path=path, source=source, **derivation))
        return path

    affected = {row["group"] for row in license_rows}
    if affected - {c["id"] for c in document["components"]}:
        raise oci.OCIError("Unbound internal license observation")
    for component in document["components"]:
        c = {key: copy.deepcopy(component[key]) for key in ("id", "expression", "requires")}
        c["files"] = [{k: row[k] for k in ("path", "sha256", "bytes")} for row in component["files"]]
        c["license_paths"], c["notice_paths"] = [], []
        if component["id"] in affected and component["expression"] is None:
            # The files and the original license bytes stay in the held proof.
            # No expression or complete term is asserted for this component.
            c["license_status"] = "internal-report-only"
            for proof in component["notice_paths"]:
                path = term(proofs[proof["path"]], proof, dict(kind="identity"))
                c["notice_paths"].append(path)
            components.append(c)
            continue
        for proof in component["license_paths"]:
            raw = proofs[proof["path"]]
            if component["kind"] == "dpkg" and proof["path"].endswith("/copyright"):
                for index, section in enumerate(_paragraphs(raw)):
                    field = section.get("License", "").partition("\n")[2]
                    if field and recognized_license(field) is not None:
                        path = term(field.encode("utf-8"), proof, dict(kind="dep5-license-field", field_index=index))
                        c["license_paths"].append(path)
            elif recognized_license(raw.decode("utf-8")) is not None:
                path = term(raw, proof, dict(kind="identity"))
                c["license_paths"].append(path)
        for proof in component["notice_paths"]:
            path = term(proofs[proof["path"]], proof, dict(kind="identity"))
            c["notice_paths"].append(path)
        c["license_paths"] = sorted(set(c["license_paths"]))
        if not c["license_paths"]:
            from .security_artifacts import ArtifactError

            raise ArtifactError(
                "license-term-unproved", "complete image component lacks full retained terms: " + c["id"]
            )
        components.append(c)
    # The final installed graph keeps physical software ownership. Term paths
    # form a separate reusable namespace; no exclusive archive partition exists.
    projected = dict(components=components, term_sources=derivations)
    if license_rows:
        projected["license_observations"] = dict(status="internal-report-only",
            counts=dict(Counter(row["code"] for row in license_rows)))
    return document, proofs, projected, material


def prepare_families(root, inventory, source, run, *, now=None, policy=None):
    """Serialize actual held image families; unknown groups stop qualification."""
    import hashlib
    import os
    from pathlib import Path
    from .security_artifacts import artifact_context, family_identity, ArtifactError, MAX_INDEX_BYTES
    from .security_license_acquisition import _write
    from .public_security_context import _clock

    state = _family_live(inventory, source, run)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    store = _store_identity(root)
    current = _clock(now).isoformat()
    registry = state.setdefault("image_families", {})
    cached = state.setdefault("image_component_observations", {})
    records, charged = [], 0
    failures = []
    license_counts = Counter()
    from .security_internal_image_scope import internal_images, partition
    from .security_license_contracts import _policy
    internal = set()
    if policy is not None and "image_license_scope" in _policy(policy):
        internal = internal_images(inventory["images"], state["images"])
    state["image_family_diagnostics"] = []
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:

        def save(body):
            nonlocal charged
            digest = hashlib.sha256(body).hexdigest()
            charged += len(body)
            if charged > 512 * 1024 * 1024:
                raise ArtifactError("artifact-size", "image family proof exceeds shared package bound")
            path = "proofs/" + digest
            _write(fd, path, body, immutable=True)
            return dict(path=path, sha256=digest, bytes=len(body))

        for subject in inventory["images"]:
            image = state.get("images", {}).get(subject["reference"])
            if type(image) is not oci.VerifiedOCIImage or image.reference != subject["reference"]:
                raise ArtifactError(
                    "license-image-live-required", "source image is absent from the owned verified graph"
                )
            observation = cached.get(image.reference)
            if type(observation) is not ImageComponentObservation or observation._image is not image:
                observation = observe_components(image)
                cached[image.reference] = observation
            observed = observation.document()
            license_rows, blocking = partition(observed["unresolved"], image.reference in internal)
            license_counts.update(row["code"] for row in license_rows)
            if blocking or observed["complete"] != (not observed["unresolved"]):
                proof_rows = [
                    dict(image_path=path, **save(body)) for path, body in sorted(observation.proof_files().items())
                ]
                diagnostic = oci.canonical(
                    dict(
                        schema_version=1,
                        kind="held-image-observation-unqualified",
                        source=source,
                        run=run,
                        inventory_sha256=inventory["digest"],
                        subject=subject,
                        observation=observed,
                        proofs=proof_rows,
                    )
                )
                if len(diagnostic) > MAX_INDEX_BYTES:
                    raise ArtifactError(
                        "artifact-size", "unqualified image component diagnostic exceeds metadata bound"
                    )
                state["image_family_diagnostics"].append(save(diagnostic))
                if not blocking:
                    raise ArtifactError("license-image-components", "inconsistent held image completeness")
                failures.extend(blocking)
                continue
            observed, proofs, projected, material = _family_projection(observation, license_rows)
            proof_rows = []
            for path, body in sorted(proofs.items()):
                proof_rows.append(dict(image_path=path, **save(body)))
            terms = [dict(term_path=path, **save(body)) for path, body in sorted(material.items())]
            component_raw = oci.canonical(
                dict(schema_version=1, kind="held-image-component-inventory", complete=True, unresolved=[], **projected)
            )
            if len(component_raw) > MAX_INDEX_BYTES:
                raise ArtifactError("artifact-size", "image component inventory exceeds metadata bound")
            component_descriptor = save(component_raw)
            payload = oci.canonical(
                dict(
                    schema_version=1,
                    kind=_FAMILY_KIND,
                    source=source,
                    run=run,
                    inventory_sha256=inventory["digest"],
                    subject=subject,
                    reference=image.reference,
                    platform=image.platform,
                    manifest_digest=image.manifest_digest,
                    config_digest=image.config_digest,
                    observation_sha256=hashlib.sha256(oci.canonical(observed)).hexdigest(),
                    proofs=proof_rows,
                    terms=terms,
                    components=component_descriptor,
                )
            )
            if len(payload) > MAX_INDEX_BYTES:
                raise ArtifactError("artifact-size", "image family envelope exceeds metadata bound")
            descriptor = save(payload)
            record = dict(
                schema_version=1,
                kind="image",
                subject=copy.deepcopy(subject),
                context=artifact_context(subject),
                filename="held-image-components.json",
                **descriptor,
                acquired_at=current,
                origin=dict(
                    kind=_FAMILY_KIND,
                    manifest_digest=image.manifest_digest,
                    config_digest=image.config_digest,
                    source_sha256=hashlib.sha256(oci.canonical(source)).hexdigest(),
                    run_sha256=hashlib.sha256(oci.canonical(run)).hexdigest(),
                ),
                components={key: component_descriptor[key] for key in ("path", "sha256")},
            )
            identity = family_identity(record)
            previous = registry.get(identity)
            if (
                type(previous) is _HeldFamily
                and previous.seal is _FAMILY_SEAL
                and previous.state is state
                and previous.observation is observation
                and previous.store == store
                and {k: v for k, v in previous.record.items() if k != "acquired_at"}
                == {k: v for k, v in record.items() if k != "acquired_at"}
            ):
                record["acquired_at"] = previous.record["acquired_at"]
            registry[identity] = _HeldFamily(
                record, observation, projected, {**proofs, **material}, state, store, _FAMILY_SEAL
            )
            registry[identity].root = root
            records.append(record)
        if failures:
            error = ArtifactError(
                failures[0]["code"],
                "image component qualification refused; "
                + str(len(failures))
                + " unresolved groups; retained diagnostics: "
                + ",".join(item["path"] for item in state["image_family_diagnostics"]),
            )
            error.image_gap_counts = dict(Counter(row["code"] for row in failures))
            if license_counts:
                error.license_observations = dict(status="internal-report-only", counts=dict(license_counts))
            raise error
        return records
    finally:
        os.close(fd)


def verify_family(root, record):
    """Reread retained data against its private LIVE typed origin; never restore."""
    import hashlib
    from .security_artifacts import ArtifactError, family_identity, read_file, MAX_INDEX_BYTES

    state = _family_live()
    identity = family_identity(record)
    held = state.get("image_families", {}).get(identity)
    if (
        type(held) is not _HeldFamily
        or held.seal is not _FAMILY_SEAL
        or held.state is not state
        or held.record != record
        or held.store != _store_identity(root)
        or held.source != state["source"]
        or held.run != state["run"]
        or held.guard is not state["native_guard"]
    ):
        raise ArtifactError(
            "license-image-live-required", "saved image family cannot restore owned source/run/guard authority"
        )
    held.observation.document()  # Rehash actual full graph and retain lifetime/guard.
    payload = read_file(root, record["path"], MAX_INDEX_BYTES)
    if len(payload) != record["bytes"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise ArtifactError("artifact-hash", "held image family envelope changed")
    envelope = oci.document(payload)
    raw = read_file(root, record["components"]["path"], MAX_INDEX_BYTES)
    if hashlib.sha256(raw).hexdigest() != record["components"]["sha256"]:
        raise ArtifactError("artifact-hash", "held image component proof changed")
    component = oci.document(raw)
    if component != dict(
        schema_version=1, kind="held-image-component-inventory", complete=True, unresolved=[], **held.document
    ):
        raise ArtifactError("license-image-components", "held installed component graph differs")
    files, bound, proof_refs = {}, len(payload) + len(raw), []
    for proof in [*envelope["proofs"], *envelope["terms"]]:
        key = proof.get("image_path", proof.get("term_path"))
        expected = held.proofs.get(key)
        body = read_file(root, proof["path"], 8 * 1024 * 1024)
        if (
            expected is None
            or body != expected
            or len(body) != proof["bytes"]
            or hashlib.sha256(body).hexdigest() != proof["sha256"]
        ):
            raise ArtifactError("artifact-hash", "held image component fullterm or metadata changed")
        files[key] = body
        bound += len(body)
        proof_refs.append({key: proof[key] for key in ("path", "sha256", "bytes")})
    if bound > 512 * 1024 * 1024:
        raise ArtifactError("artifact-size", "held image proof exceeds package bound")
    proof_refs.extend(
        [
            dict(path=record["path"], sha256=record["sha256"], bytes=len(payload)),
            dict(path=record["components"]["path"], sha256=record["components"]["sha256"], bytes=len(raw)),
        ]
    )
    return dict(
        artifact_id=identity,
        files=files,
        components=component["components"],
        members={
            v["path"]: {"sha256": v["sha256"], "size": v["bytes"]} for c in component["components"] for v in c["files"]
        },
        binding=dict(
            artifact_id=identity,
            artifact_sha256=record["sha256"],
            artifact_size=len(payload),
            subject=record["subject"],
            context=record["context"],
            proofs=proof_refs,
        ),
        bound_bytes=bound,
        component_inventory_json=raw.decode("utf-8"),
        held_image=True,
        **({"license_observations": component["license_observations"]} if "license_observations" in component else {}),
    )


def replace_retained(root, retained, incoming):
    """Replace one prior held use only after its current proof independently passes.

    Other source uses and providers are preserved. Failure changes no manifest;
    the ordinary acquisition publisher remains the only final catalog writer.
    """
    from .security_artifacts import ArtifactError

    if incoming is not None and (not isinstance(incoming, list) or any(not isinstance(v, dict) for v in incoming)):
        raise ArtifactError("artifact-manifest", "held image replacements must be exact family records")
    replacements = set()
    for record in incoming or []:
        if record.get("kind") == "image" and record.get("origin", {}).get("kind") == _FAMILY_KIND:
            verify_family(root, record)
            replacements.add(oci.canonical(dict(subject=record["subject"], context=record["context"])))
    return [
        record
        for record in retained
        if not (
            record.get("kind") == "image"
            and record.get("origin", {}).get("kind") == _FAMILY_KIND
            and oci.canonical(dict(subject=record["subject"], context=record["context"])) in replacements
        )
    ]


def finding_consistent(finding, allowed, select_expression):
    """Recompute ordinary term checks from LIVE proof, not JSON declarations."""
    from .security_artifacts import family_identity, ArtifactError
    from .security_license_contracts import _license_evidence

    try:
        record = finding["family_record"]
        state = _family_live()
        held = state.get("image_families", {}).get(family_identity(record))
        if type(held) is not _HeldFamily:
            return False
        evidence = verify_family(held.root, record)
        selected, licenses, notices = [], [], []
        for component in evidence["components"]:
            if component.get("license_status") == "internal-report-only":
                if not evidence.get("license_observations") or component["expression"] is not None:
                    return False
                for path in component["notice_paths"]:
                    if not evidence["files"][path].strip():
                        return False
                continue
            chosen, identifiers = select_expression(component["expression"], allowed)
            owned = {item["path"] for item in component["files"]}
            paths = owned | set(component["license_paths"] + component["notice_paths"])
            files = {path: body for path, body in evidence["files"].items() if path in paths}
            fullterms, fullnotices = _license_evidence(files, component, identifiers, chosen)
            selected.extend(chosen)
            licenses.extend(fullterms)
            notices.extend(fullnotices)
        expected = dict(
            kind="image",
            reference=record["subject"]["reference"],
            status="pass",
            selected_expression=" AND ".join(sorted(set(selected))),
            distribution="internal",
            **evidence["binding"],
            family_record=record,
            component_inventory_json=evidence["component_inventory_json"],
            license_files=licenses,
            notice_files=notices,
            obligations="internal use; exact source/component/license evidence retained",
        )
        if "license_observations" in evidence:
            expected.update(license_observations=evidence["license_observations"],
                            obligations="internal use; partial license evidence reported")
        return finding == expected
    except (ArtifactError, ValueError, TypeError, KeyError, OSError):
        return False
