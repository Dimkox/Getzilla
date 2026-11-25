"""Component identities from the pinned Trivy binary and the live OCI graph."""
from pathlib import Path
import re
import tempfile

from . import security_dind_exception as dind
from . import security_oci as oci
from . import security_tools as tools_api


class VulnerableImageBinary(oci.ImageSecurityRefusal):
    report_kind = "image-component-vulnerability"


def check_known_binary(row, image):
    # The exact official docker-29.10.1.tgz binary contains the affected
    # registry/client.(*manifests).Get symbol from this vendored module.
    # Go's GOPATH build omits the module version table parsed by Trivy.
    if row.get("sha256") == dind.CLI["executable_sha256"]:
        try:
            if dind.removed_build_input_cli(row, image):
                return
        except (OSError, ValueError, KeyError, TypeError):
            # Incomplete removal evidence leaves the original vulnerability blocking.
            pass
        raise VulnerableImageBinary("confirmed-vendored-go-vulnerability", manifest=image.manifest_digest,
            config=image.config_digest, path=row["path"], layer=row["layer"], executable_sha256=row["sha256"],
            component="github.com/docker/distribution", version="v2.8.3+incompatible",
            cves=["CVE-2026-85747"], advisory="https://osv.dev/vulnerability/GO-2026-6778",
            upstream_commit="c48360f51c53d2029ab6721ad4d012f9e14df846",
            upstream_archive_sha256="061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962")


# ELF bytes from .deb archives verified against the signed Bookworm InRelease and Packages.xz.
_DEBIAN_GO = {
    "usr/bin/containerd": (
        "62da5f012f979354dbddcf3d04ea3e0a2a719ec2fca31c2a722cd584edac42df", "containerd", "1.6.20~ds1-1+deb12u3",
        "8669d264eeb0fcdb4a0b1ba436ab88ec5dafde4a66e1278ec279d830db4c2216"),
    "usr/bin/containerd-shim": (
        "22526b47048de77e3e231c7f44c35beffc216f3bf93391976930cad0f365248c", "containerd", "1.6.20~ds1-1+deb12u3",
        "8669d264eeb0fcdb4a0b1ba436ab88ec5dafde4a66e1278ec279d830db4c2216"),
    "usr/bin/containerd-shim-runc-v1": (
        "c3a808458df2aeb8f2c653ce7ea4d62547ee87e593429a503b7a4008712953b8", "containerd", "1.6.20~ds1-1+deb12u3",
        "8669d264eeb0fcdb4a0b1ba436ab88ec5dafde4a66e1278ec279d830db4c2216"),
    "usr/bin/containerd-shim-runc-v2": (
        "f5cd2a43978e959544b35c9c73cdd26f25d417238b5c4cdeaa4e8805e79485ec", "containerd", "1.6.20~ds1-1+deb12u3",
        "8669d264eeb0fcdb4a0b1ba436ab88ec5dafde4a66e1278ec279d830db4c2216"),
    "usr/bin/ctr": (
        "b649ddda22dcf16a6cfa598ff420e7b4dba6350b8a24f8139739eca965887f5a", "containerd", "1.6.20~ds1-1+deb12u3",
        "8669d264eeb0fcdb4a0b1ba436ab88ec5dafde4a66e1278ec279d830db4c2216"),
    "usr/bin/dnet": (
        "f3ddb4cdc990fe1a8bd6a9d76171283a4ce046ae880c118e5ae8563fc36992e2", "docker.io", "20.10.24+dfsg1-1+deb12u1+b6",
        "daf8ff8f7aa53e8533d38e386fcc2a11e8f3891210776fb78a84b98feb4eea0e"),
    "usr/bin/docker": (
        "bc3982d00f5f9518b9f7fceb856767bbd7fe57b9b17d7f79484babb3e1c86959", "docker.io", "20.10.24+dfsg1-1+deb12u1+b6",
        "daf8ff8f7aa53e8533d38e386fcc2a11e8f3891210776fb78a84b98feb4eea0e"),
    "usr/sbin/docker-proxy": (
        "4c3230002788282b076edb27997d663a043f1208aae8b54117a68db45aeb14f4", "docker.io", "20.10.24+dfsg1-1+deb12u1+b6",
        "daf8ff8f7aa53e8533d38e386fcc2a11e8f3891210776fb78a84b98feb4eea0e"),
    "usr/sbin/dockerd": (
        "39ad7936d1af38671d2c4401df15e8c6610dadf38d7595bcb596b27ba30e74cc", "docker.io", "20.10.24+dfsg1-1+deb12u1+b6",
        "daf8ff8f7aa53e8533d38e386fcc2a11e8f3891210776fb78a84b98feb4eea0e"),
    "usr/sbin/ovrouter": (
        "81574a070a24e3b64d1639121a11a6649bd163da47d8f791fe0fafc76956de7c", "docker.io", "20.10.24+dfsg1-1+deb12u1+b6",
        "daf8ff8f7aa53e8533d38e386fcc2a11e8f3891210776fb78a84b98feb4eea0e"),
    "usr/sbin/runc": (
        "9a87d5bcdd630ec420ec56a6c21b70aa6960edcefe1cf4bb181cee290bdd6b98", "runc", "1.1.5+ds1-1+deb12u1",
        "a00351f8c0318de0b424ecf5cd0fdb69880a89f3511cae4f6fff7de3e57881c5"),
}


def debian_go_coverage(row, owners, index):
    pin = _DEBIAN_GO.get(row["path"])
    if pin is None:
        return None
    sha256, package, version, package_hash = pin
    identity = f"deb:{package}:amd64@{version}"
    if (row["sha256"] != sha256 or owners != {identity}
            or (package, version, "amd64") not in index.get(("debian", ""), ())):
        return None
    return dict(provider="trivy-debian", component=identity, package_sha256=package_hash,
                executable_sha256=sha256, path=row["path"], layer=row["layer"])


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
            version = row["Version"]
            if key[1] == "debian":
                # Trivy separates the dpkg epoch and Debian revision.
                epoch, release = row.get("Epoch", 0), row.get("Release", "")
                if type(epoch) is not int or epoch < 0 or not isinstance(release, str):
                    raise ValueError("invalid Trivy Debian version fields")
                version = (f"{epoch}:" if epoch else "") + version + ("-" + release if release else "")
            values.append((row["Name"], version, row.get("Arch", "")))
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
        command = [str(trivy), "image", "--input", target, "--scanners", "license", "--list-all-pkgs",
                   "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                   "--skip-version-check", *tools_api.trivy_options(scratch), "--parallel", "1",
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
        receipt["unmatched_package_targets"] = [
            dict(target=r["Target"], type=r["Type"], packages=[
                {key: row[key] for key in ("Name", "Version", "Arch", "Relationship") if key in row}
                for row in r.get("Packages", [])
                if (r["Type"] == "debian" and row["Name"].startswith("postgresql"))
                or (r["Type"] == "gobinary" and row.get("Relationship") == "root")
            ][:32])
            for r in report["Results"] if r.get("Type") == "debian" or (
                r.get("Type") == "gobinary" and ("gobinary", r["Target"].lstrip("/")) not in index)
        ][:64]
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
