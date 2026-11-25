"""Component identities from the pinned Trivy binary and the live OCI graph."""
from pathlib import Path
import re
import tempfile

from . import security_oci as oci
from . import security_tools as tools_api


def package_index(report, image):
    if (report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image"
            or report.get("Metadata", {}).get("ImageID") != image.config_digest
            or not isinstance(report.get("Results"), list)):
        raise ValueError("Trivy package report is not bound to the selected image")
    packages = {}
    for result in report["Results"]:
        key = (result.get("Class"), result.get("Type"))
        if key not in {("os-pkgs", "debian"), ("os-pkgs", "alpine"), ("lang-pkgs", "gobinary")}:
            continue
        target = result.get("Target")
        if not isinstance(target, str) or not target:
            raise ValueError("missing Trivy package target")
        if key[1] == "gobinary":
            target = target.removeprefix("/")
            if any(part in {"", ".", ".."} for part in target.split("/")):
                raise ValueError("invalid Go executable target")
        identity = (key[1], target if key[1] == "gobinary" else "")
        if identity in packages:
            raise ValueError("duplicate Trivy package target")
        rows = result.get("Packages")
        if not isinstance(rows, list) or not rows:
            raise ValueError("empty Trivy package target")
        values = []
        for row in rows:
            if any(not isinstance(row.get(k), str) or not row[k] for k in ("Name", "Version")):
                raise ValueError("unversioned Trivy package")
            values.append((row["Name"], row["Version"], row.get("Arch", "")))
        if key[1] == "gobinary" and not any(
                row.get("Relationship") == "root" and row["Name"] != "stdlib"
                and row["Version"] not in {"(devel)", "unknown"} for row in rows):
            continue
        packages[identity] = frozenset(values)
    return packages


def scan(image, tools, trivy):
    from .security_acquisition import TRIVY_VERSION
    with tempfile.TemporaryDirectory(dir=tools, prefix="image-packages-") as temp:
        scratch = Path(temp)
        output = scratch / "sbom.json"
        target = str(image.layout) + "@" + image.manifest_digest
        config = scratch / "trivy.yaml"
        ignore = scratch / "empty.trivyignore"
        config.write_bytes(b"{}\n")
        ignore.write_bytes(b"")
        command = [str(trivy), "image", "--input", target, "--scanners", "license", "--list-all-pkgs",
                   "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                   "--skip-version-check", "--config", str(config), "--ignorefile", str(ignore), "--parallel", "1",
                   "--max-image-size", "2GB", "--format", "json", "--output", str(output)]
        from .public_security_context import _preparation_step
        with _preparation_step("image-package-scan"):
            result = tools_api._process(command, scratch, scratch, timeout=image.remaining_seconds())
            report = tools_api._process_report(output, result)
        with _preparation_step("image-package-identity"):
            oci.scanner_identity(report, image)
            index = package_index(report, image)
        import hashlib
        receipt = dict(scanner="trivy", version=TRIVY_VERSION, manifest=image.manifest_digest,
                       config=image.config_digest, report_sha256=hashlib.sha256(oci.canonical(report)).hexdigest())
        return index, receipt


def apk_inventory(payload):
    """Read apk's installed package and F/R/Z records. Unhashed files stay unproved."""
    packages = {}
    for block in payload.decode("utf-8").strip().split("\n\n"):
        fields, files = {}, {}
        directory = name = None
        for line in block.splitlines():
            key, separator, value = line.partition(":")
            if not separator or len(key) != 1:
                raise ValueError("malformed APK package field")
            if key in {"P", "V", "A", "L"}:
                if key in fields:
                    raise ValueError("duplicate APK package identity")
                fields[key] = value
            elif key == "F":
                directory, name = value, None
                if value and any(part in {"", ".", ".."} for part in value.split("/")):
                    raise ValueError("invalid APK directory")
            elif key == "R":
                if directory is None or value in {"", ".", ".."} or "/" in value:
                    raise ValueError("invalid APK member")
                name = directory + "/" + value if directory else value
                if name in files:
                    raise ValueError("duplicate APK member")
                files[name] = None
            elif key == "Z":
                if name is None or files[name] is not None:
                    raise ValueError("unbound APK checksum")
                files[name] = value
        identity = tuple(fields.get(key, "") for key in ("P", "V", "A"))
        if not all(re.fullmatch(r"[a-zA-Z0-9_.+~:-]+", item) for item in identity) or identity in packages:
            raise ValueError("invalid APK package identity")
        packages[identity] = (fields.get("L"), files)
    return packages
