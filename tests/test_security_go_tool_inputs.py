import base64
import hashlib
import io
from pathlib import Path
import struct
import sys
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_go_tool_inputs as go
from getzilla.security_artifacts import ArtifactError


def varstr(raw):
    raw = raw.encode() if isinstance(raw, str) else raw
    n = len(raw)
    prefix = b""
    while n >= 128:
        prefix += bytes([(n & 127) | 128])
        n >>= 7
    return prefix + bytes([n]) + raw


def elf(data):
    names = b"\0.go.buildinfo\0.shstrtab\0"
    offset = 64 + len(data) + len(names)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1, 0, 0, offset, 0, 64, 0, 0, 64, 3, 2
    )
    sections = (
        bytes(64)
        + struct.pack("<IIQQQQIIQQ", 1, 1, 0, 0, 64, len(data), 0, 0, 16, 0)
        + struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, 64 + len(data), len(names), 0, 0, 1, 0)
    )
    return header + data + names + sections


def build_blob(text):
    return (
        b"\xff Go buildinf:"
        + bytes([8, 2])
        + bytes(16)
        + varstr("go1.25.5")
        + varstr(bytes(16) + text.encode() + bytes(16))
    )


class BuildInfoTests(unittest.TestCase):
    def test_inline_module_list_is_bound_to_actual_elf_section(self):
        text = (
            "path\tgithub.com/owner/tool/cmd/tool\nmod\tgithub.com/owner/tool\tv1.0.0\th1:"
            + base64.b64encode(bytes(32)).decode()
            + "\ndep\texample.org/lib\tv1.2.3\th1:"
            + base64.b64encode(b"a" * 32).decode()
            + "\nbuild\tCGO_ENABLED=0\nbuild\tGOARCH=amd64\n"
        )
        observed = go.buildinfo(elf(build_blob(text)))
        self.assertEqual(observed["go_version"], "go1.25.5")
        self.assertEqual(observed["dependencies"][0]["path"], "example.org/lib")
        self.assertEqual(observed["settings"]["CGO_ENABLED"], "0")

    def test_pointer_format_truncated_varint_and_duplicate_setting_refuse(self):
        for raw in [
            elf(b"\xff Go buildinf:" + bytes([8, 0]) + bytes(16)),
            elf(b"\xff Go buildinf:" + bytes([8, 2]) + bytes(16) + b"\xff" * 12),
            elf(build_blob("path\ttool\nbuild\tCGO_ENABLED=0\nbuild\tCGO_ENABLED=1\n")),
        ]:
            with self.subTest(raw=raw[:16]), self.assertRaises(ArtifactError):
                go.buildinfo(raw)

    def test_replace_module_retains_both_original_and_actual_source_identity(self):
        checksum = "h1:" + base64.b64encode(bytes(32)).decode()
        text = (
            "path\ttool\nmod\tmain\t(devel)\t\ndep\texample.org/lib\tv1.0.0\t"
            + checksum
            + "\n=>\texample.org/fork\tv1.1.0\t"
            + checksum
            + "\n\nbuild\tCGO_ENABLED=1\n"
        )
        observed = go.buildinfo(elf(build_blob(text)))
        self.assertEqual(observed["dependencies"][0]["replace"]["path"], "example.org/fork")
        self.assertEqual(observed["settings"]["CGO_ENABLED"], "1")


class GoHashTests(unittest.TestCase):
    def test_compact_manifest_recomputes_go_h1_and_proves_nested_terms(self):
        files = {
            "example.org/lib@v1.0.0/go.mod": b"module example.org/lib\n",
            "example.org/lib@v1.0.0/LICENSE": b"actual root terms",
            "example.org/lib@v1.0.0/vendor/NOTICE": b"actual nested notice",
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path, body in files.items():
                archive.writestr(path, body)
        rows = {path: hashlib.sha256(body).hexdigest() for path, body in files.items()}
        expected = (
            "h1:"
            + base64.b64encode(
                hashlib.sha256("".join(rows[p] + "  " + p + "\n" for p in sorted(rows)).encode()).digest()
            ).decode()
        )
        proof = go.module_proof(buffer.getvalue(), "example.org/lib", "v1.0.0", expected)
        self.assertEqual(proof["h1"], expected)
        self.assertEqual(set(proof["terms"]), {"LICENSE", "vendor/NOTICE"})
        go.verify_module_proof(proof, "example.org/lib", "v1.0.0", expected)
        proof["terms"]["LICENSE"]["body"] = base64.b64encode(b"changed terms").decode()
        with self.assertRaises(ArtifactError):
            go.verify_module_proof(proof, "example.org/lib", "v1.0.0", expected)


class DeclarationTests(unittest.TestCase):
    def test_checker_pin_declarations_bind_source_bytes_and_stable_ids(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / ".getzilla/getzilla"
            folder.mkdir(parents=True)
            (folder / "security_acquisition.py").write_text(
                "TRIVY_VERSION = '0.74.0'\nTRIVY_ARCHIVE_SHA256 = '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'\nTRIVY_URL = f'https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz'\n"
            )
            (folder / "security_image_provision.py").write_text(
                "VERSION = '0.35.0'\nARCHIVE_SHA256 = '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c'\nURL = f'https://github.com/moby/buildkit/releases/download/v{VERSION}/buildkit-v{VERSION}.linux-amd64.tar.gz'\n"
            )
            declared = go.checker_declarations(root)
            self.assertEqual([r["role"] for r in declared], ["trivy", "buildkit"])
            self.assertEqual(declared[0]["id"], "checker-tool:trivy:" + declared[0]["archive_sha256"])
            self.assertEqual(
                declared[0]["source_sha256"],
                hashlib.sha256((folder / "security_acquisition.py").read_bytes()).hexdigest(),
            )
            (folder / "security_acquisition.py").write_text(
                "raise RuntimeError('never execute candidate source')\nTRIVY_VERSION = __import__('os').getenv('TOKEN')\n"
            )
            with self.assertRaises(ArtifactError):
                go.checker_declarations(root)


class LockTests(unittest.TestCase):
    def test_go_sum_vendor_bridge_keeps_checksum_basis_distinct(self):
        checksum = "h1:" + base64.b64encode(bytes(32)).decode()
        sums = "example.org/lib v1.2.3 " + checksum + "\nexample.org/lib v1.2.3/go.mod " + checksum + "\n"
        vendors = "# example.org/lib v1.2.3\n## explicit; go 1.22\nexample.org/lib/pkg\n"
        observed = go.parse_source_lock(sums.encode(), vendors.encode())
        self.assertEqual(observed["checksums"]["example.org/lib@v1.2.3"], checksum)
        with self.assertRaises(ArtifactError):
            go.parse_source_lock(sums.encode(), vendors.replace("v1.2.3", "v1.2.4").encode())

    def test_compact_proof_omitted_legal_file_or_changed_file_manifest_refuses(self):
        files = {"example.org/lib@v1.0.0/LICENSE": b"terms", "example.org/lib@v1.0.0/NOTICE": b"notice"}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path, body in files.items():
                archive.writestr(path, body)
        rows = {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}
        checksum = (
            "h1:"
            + base64.b64encode(
                hashlib.sha256("".join(rows[p] + "  " + p + "\n" for p in sorted(rows)).encode()).digest()
            ).decode()
        )
        proof = go.module_proof(buffer.getvalue(), "example.org/lib", "v1.0.0", checksum)
        del proof["terms"]["NOTICE"]
        with self.assertRaises(ArtifactError):
            go.verify_module_proof(proof, "example.org/lib", "v1.0.0", checksum)


class JoinedScopeTests(unittest.TestCase):
    def test_failed_or_single_tool_output_never_supplies_a_live_pass_map(self):
        for output in [{}, {"status": "skip", "gaps": []}, {"status": "pass", "gaps": [{"code": "missing"}]}]:
            with self.assertRaises(ArtifactError) as error:
                go.qualified_tool_bindings(Path("/not-read"), Path("/not-read"), output)
            self.assertEqual(error.exception.code, "checker-tool-unqualified")

    def test_full_terms_are_verified_without_expanding_automatic_license_policy(self):
        import json

        fixtures = json.loads((ROOT / "tests/fixtures/security-license-texts.json").read_text())
        component, files = go.component_from_terms(
            "example.org/lib@v1.0.0", {"LICENSE": fixtures["MIT"]["text"].encode(), "NOTICE": b"actual notice"}
        )
        self.assertEqual(component["expression"], "MIT")
        self.assertEqual(len(component["notice_paths"]), 1)
        with self.assertRaises(ArtifactError):
            go.component_from_terms(
                "example.org/lib@v1.0.0", {"LICENSE": b"Permission granted; missing actual full terms"}
            )


def qualified_fixture(directory, cgo="0"):
    import json
    import tarfile
    import copy
    from datetime import datetime, timezone

    root = Path(directory)
    checker = root / "checker"
    artifacts = root / "artifacts"
    folder = checker / ".getzilla/getzilla"
    folder.mkdir(parents=True)
    artifacts.mkdir()
    fixtures = json.loads((ROOT / "tests/fixtures/security-license-texts.json").read_text())
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as z:
        z.writestr("example.org/lib@v1.0.0/LICENSE", fixtures["MIT"]["text"])
    body = source.getvalue()
    files = {"example.org/lib@v1.0.0/LICENSE": hashlib.sha256(fixtures["MIT"]["text"].encode()).hexdigest()}
    checksum = go._h1(files)
    module = go.module_proof(body, "example.org/lib", "v1.0.0", checksum)
    module["origin"] = {
        "requested_url": "https://proxy.golang.org/example.org/lib/@v/v1.0.0.zip",
        "final_url": "https://proxy.golang.org/example.org/lib/@v/v1.0.0.zip",
        "fetched_at": datetime.now(timezone.utc).timestamp(),
    }
    text = (
        "path\tgithub.com/aquasecurity/trivy/cmd/trivy\nmod\tgithub.com/aquasecurity/trivy\tv0.74.0+dirty\t\ndep\texample.org/lib\tv1.0.0\t"
        + checksum
        + "\nbuild\tCGO_ENABLED="
        + cgo
        + "\nbuild\tGOARCH=amd64\nbuild\tGOOS=linux\n"
    )
    binary = elf(build_blob(text))
    compressed = io.BytesIO()
    with tarfile.open(fileobj=compressed, mode="w:gz") as archive:
        for name, content in [("trivy", binary), ("LICENSE", fixtures["MIT"]["text"].encode())]:
            item = tarfile.TarInfo(name)
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
    payload = compressed.getvalue()
    pin = hashlib.sha256(payload).hexdigest()
    specs = copy.deepcopy(go.PIN_SPECS)
    specs["trivy"]["sha256"] = pin
    (folder / "security_acquisition.py").write_text(
        "TRIVY_VERSION = '0.74.0'\nTRIVY_ARCHIVE_SHA256 = '"
        + pin
        + "'\nTRIVY_URL = f'https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz'\n"
    )
    (folder / "security_image_provision.py").write_text(
        "VERSION = '0.35.0'\nARCHIVE_SHA256 = '37b3befbed28fb72a44d72bf42362c268610386c42feafa27cb45ee0b531369c'\nURL = f'https://github.com/moby/buildkit/releases/download/v{VERSION}/buildkit-v{VERSION}.linux-amd64.tar.gz'\n"
    )

    def save(raw):
        raw = json.dumps(raw, sort_keys=True).encode() if not isinstance(raw, bytes) else raw
        sha = hashlib.sha256(raw).hexdigest()
        (artifacts / sha).write_bytes(raw)
        return {"path": sha, "sha256": sha}

    from unittest.mock import patch

    with patch.object(go, "PIN_SPECS", specs):
        declaration = go.checker_declarations(checker)[0]
        subject = go.checker_inventory(checker)["tools"][0]
    release = {
        "tag_name": "v0.74.0",
        "assets": [
            {
                "name": go.PIN_SPECS["trivy"]["url"].rsplit("/", 1)[-1],
                "size": len(payload),
                "digest": "sha256:" + pin,
                "browser_download_url": go.PIN_SPECS["trivy"]["url"],
            }
        ],
    }
    runtime = {}
    for name, raw in [("LICENSE", fixtures["BSD-3-Clause"]["text"].encode()), ("PATENTS", b"retained patent notice")]:
        runtime[name] = {**save(raw), "url": "https://raw.githubusercontent.com/golang/go/go1.25.5/" + name}
    proof = {
        "schema_version": 1,
        "kind": "go-checker-components/v1",
        "tool_id": declaration["id"],
        "release": save(release),
        "modules": {"example.org/lib@v1.0.0": save(module)},
        "source_locks": {},
        "runtime": {"go1.25.5": runtime},
        "expressions": {},
    }
    archive = save(payload)
    from getzilla.security_artifacts import artifact_context

    record = {
        "schema_version": 1,
        "kind": "tool",
        "subject": subject,
        "filename": go.PIN_SPECS["trivy"]["url"].rsplit("/", 1)[-1],
        "path": archive["path"],
        "sha256": pin,
        "bytes": len(payload),
        "context": artifact_context(subject),
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "origin": {
            "kind": "go-checker-release/v1",
            "declaration": declaration,
            "index_url": "https://api.github.com/repos/aquasecurity/trivy/releases/tags/v0.74.0",
            "artifact_url": go.PIN_SPECS["trivy"]["url"],
        },
        "components": save(proof),
    }
    return checker, artifacts, record, specs


class QualifiedFamilyTests(unittest.TestCase):
    def test_complete_go_data_produces_real_family_evidence(self):
        import tempfile
        from unittest.mock import patch
        from getzilla import security_artifacts, security_tools

        with tempfile.TemporaryDirectory() as directory:
            checker, artifacts, record, specs = qualified_fixture(directory)
            with patch.object(go, "PIN_SPECS", specs), patch.object(security_tools, "TRUSTED_ROOT", checker):
                evidence = security_artifacts.family_evidence(artifacts, record)
            self.assertEqual(len(evidence["components"]), 3)
            self.assertEqual({c["expression"] for c in evidence["components"]}, {"MIT", "BSD-3-Clause"})
            self.assertGreater(evidence["bound_bytes"], record["bytes"])

    def test_cgo_static_native_gap_cannot_be_cleared_by_go_modules(self):
        import tempfile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            checker, artifacts, record, specs = qualified_fixture(directory, cgo="1")
            with patch.object(go, "PIN_SPECS", specs), self.assertRaises(ArtifactError) as error:
                go.verify_family(artifacts, record, checker=checker)
            self.assertEqual(error.exception.code, "go-cgo-native-unresolved")
