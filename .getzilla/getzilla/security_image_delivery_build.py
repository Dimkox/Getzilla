"""Build the three candidate deliveries using independently held packaging code."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import zipfile

from .security_artifacts import read_file, MAX_ARTIFACT_BYTES, safe_parts
from .security_license_acquisition import bounded_default
from .security_referenced_image import delivery_members

SETUPTOOLS = "https://files.pythonhosted.org/packages/18/02/b4bbb90f8f29e334898ff45c6d9b1fffaa6f378017052b3023a06262b5f7/setuptools-84.1.0-py3-none-any.whl"
BACKEND_SHA = "5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9"
PROJECT_SHA = "f77ace35b6bea31fb6569e04544bc7a2582acc2325b6ca9a4d0504bccb97550c"


def _wheel(url, digest):
    body = bounded_default(url, maximum=MAX_ARTIFACT_BYTES)
    if hashlib.sha256(body).hexdigest() != digest:
        raise ValueError("wheel differs from pinned artifact")
    return body


def build(root, checker, directory, profile, pins):
    from .security_factory_inputs import validate_declaration, _environment
    from .security_factory_build import _command
    from .python_test_runner import execute
    from .security_tools import _environment as process_environment
    declared = validate_declaration(profile["factory_inputs"])
    with tempfile.TemporaryDirectory(prefix="delivery-", dir=directory) as temp:
        stage = Path(temp)
        spec = importlib.util.spec_from_file_location("getzilla_release_packager", checker / "scripts/package_stack.py")
        packager = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packager)
        snapshot = packager._release_snapshot_from_tracked_head(root)
        if snapshot.head_oid != profile["source"]["head_sha"]:
            raise ValueError("release source changed")
        source_zip = stage / "source.zip"
        packager.write_release_archive(root, source_zip, snapshot)
        package = stage / "package"
        package.mkdir()
        with zipfile.ZipFile(source_zip) as archive:
            for member in archive.infolist():
                if not member.filename.startswith("getzilla/factory/") or member.is_dir():
                    continue
                relative = member.filename.removeprefix("getzilla/factory/")
                target = package.joinpath(*safe_parts(relative))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(archive.read(member))
        if (hashlib.sha256((package/"pyproject.toml").read_bytes()).hexdigest() != PROJECT_SHA
                or any((package/name).exists() for name in ("setup.py", "setup.cfg", "MANIFEST.in"))):
            raise ValueError("unknown Factory packaging code")
        backend = stage / "backend"
        with zipfile.ZipFile(io.BytesIO(_wheel(SETUPTOOLS, BACKEND_SHA))) as archive:
            archive.extractall(backend)
        command = ["/usr/bin/python3.12", "-I", "-S", "-B", "-c",
                   "import sys;sys.path.insert(0,sys.argv[1]);from setuptools.build_meta import build_wheel;"
                   "build_wheel(sys.argv[2])", str(backend), str(stage)]
        env = process_environment(stage)
        env["SOURCE_DATE_EPOCH"] = "315532800"
        result = execute(command, package, env, timeout=90)
        if result.returncode or result.terminal_state != "completed" or result.cleanup_error:
            raise ValueError("Factory wheel build incomplete")
        wheel, = stage.glob("getzilla_factory-*.whl")
        wheels = stage / "wheels"
        wheels.mkdir()
        for dep in declared["dependencies"]:
            filename, = safe_parts(dep["artifact_filename"])
            (wheels / filename).write_bytes(_wheel(dep["artifact_source"], dep["artifact_sha256"]))
        builder = checker / "factory/runtime/build_offline_release.py"
        if hashlib.sha256(read_file(checker, "factory/runtime/build_offline_release.py", 1024*1024)).hexdigest() != declared["policy_profile"]["builder_sha256"]:
            raise ValueError("unreviewed offline builder")
        stem = stage / "offline"
        output = _command(["/usr/bin/python3.12", "-I", "-S", "-B", "-c",
            "import sys,runpy;sys.path.insert(0,sys.argv[1]);del sys.argv[1];p=sys.argv.pop(1);"
            "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')", str(builder.parent), str(builder),
            "--repository", str(root), "--expected-head", profile["source"]["head_sha"],
            "--wheelhouse", str(wheels), "--inventory", str(root/"factory/runtime/runtime-wheels-linux-x86_64-cpython312.json"),
            "--output", str(stem), "--product-version", declared["product_version"]], stage)
        archive = stage / "offline.zip"
        if (output["source_head"] != snapshot.head_oid or output["host_enforced"] is not True
                or not _environment(output["target_environment"]) or output["archive"] != str(archive)
                or hashlib.sha256(read_file(stage, archive.name, MAX_ARTIFACT_BYTES)).hexdigest() != output["archive_sha256"]):
            raise ValueError("Factory offline output differs")
        return delivery_members({"source-zip": source_zip, "factory-wheel": wheel, "factory-offline": archive}, pins)
