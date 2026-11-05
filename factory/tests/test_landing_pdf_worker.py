"""Execute the sealed bounded PDF worker as the real child process (issue #63 residual).

The sibling media tests spawn a `python -c` stub, so the shipped worker body itself
(resources/landing_pdf_worker.py) never ran here. These tests drive `extract_pdf_text`
with no Popen patching: the production spawn (`python -B -I worker.py`, empty env,
rlimits, private selector loop) executes and its structured protocol is asserted.
"""

from __future__ import annotations
import io
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from unittest import mock

from getzilla_factory import landing_media
from getzilla_factory.landing_media import LandingMediaError, extract_pdf_text

CURRENT_EPOCH_SHA = "fde60e040167c10975b00d11f578c4da6763069a"

# Mirror the worker's isolated environment exactly (landing_media.py spawns
# `python -B -I worker.py` with only PATH/LANG/LC_ALL); a parent-side probe
# would over-count a `pip install --user pypdf` and turn the parser-present
# tests red when the child still cannot import it.
_CHILD_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def _declared_pypdf_version() -> str:
    manifest = tomllib.loads((Path(__file__).parents[1] / 'pyproject.toml').read_text(encoding='utf-8'))
    pins = [item.removeprefix('pypdf==') for item in manifest['project']['dependencies']
            if item.startswith('pypdf==')]
    if len(pins) != 1:
        raise ValueError('factory must declare one exact pypdf pin')
    return pins[0]


def _child_pypdf_version() -> str | None:
    probe = subprocess.run(
        (
            str(Path(sys.executable).absolute()), "-B", "-I", "-c",
            "import importlib.metadata as m; import importlib.util; "
            "spec = importlib.util.find_spec('pypdf'); "
            "print(m.version('pypdf')) if spec is not None else None; "
            "raise SystemExit(0 if spec is not None else 3)",
        ),
        cwd="/", env=_CHILD_ENV, capture_output=True, text=True, timeout=30,
    )
    if probe.returncode == 3:
        return None
    if probe.returncode != 0 or not probe.stdout.strip():
        raise RuntimeError('isolated PDF dependency probe failed: ' + probe.stderr[-2000:])
    return probe.stdout.strip()


CHILD_PYPDF_VERSION = _child_pypdf_version()


def _child_sandbox_available() -> bool:
    # Independent public precondition measurement. A decoder failure is not
    # evidence that resource limits were unavailable and cannot select a pass.
    probe = subprocess.run(
        (str(Path(sys.executable).absolute()), "-B", "-I", "-c", """
import io,json,resource,sys
try:
    resource.setrlimit(resource.RLIMIT_CPU, (5, 6))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1048576, 512 * 1048576))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
except (OSError, ValueError, MemoryError):
    sys.stdout.buffer.write(b'unavailable')
else:
    sys.stdout.buffer.write(b'available')
"""),
        cwd="/", env=_CHILD_ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=10,
    )
    if probe.returncode != 0 or probe.stdout not in (b"available", b"unavailable") or probe.stderr:
        raise RuntimeError("isolated PDF resource precondition probe failed")
    return probe.stdout == b"available"


CHILD_SANDBOX_AVAILABLE = _child_sandbox_available()


def _single_page_pdf(text: str) -> bytes:
    body = f"BT /F1 12 Tf 20 100 Td ({text}) Tj ET".encode("ascii")
    objects = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]/Contents 4 0 R"
        b"/Resources<</Font<</F1 5 0 R>>>>>>",
        b"<</Length " + str(len(body)).encode() + b">>\nstream\n" + body + b"\nendstream",
        b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + payload + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<</Size {len(objects) + 1}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(out)


def _blank_pdf(*, page_count: int = 1) -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(page_count):
        writer.add_blank_page(width=200, height=200)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


class PdfWorkerInputGuards(unittest.TestCase):
    def test_runtime_parser_version_matches_manifest_pin(self):
        self.assertEqual(landing_media.PDF_PYPDF_VERSION, _declared_pypdf_version())

    def test_empty_payload_is_rejected_before_any_spawn(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(b"")
        self.assertEqual(ctx.exception.code, "pdf_input_limit")

    def test_decoder_drift_is_rejected_before_any_spawn(self):
        with mock.patch.object(landing_media, "PDF_DECODER_DIGEST", "0" * 64):
            with self.assertRaises(LandingMediaError) as ctx:
                extract_pdf_text(b"%PDF-1.4\n%synthetic\n%%EOF\n")
        self.assertEqual(ctx.exception.code, "pdf_decoder_drift")


class PdfWorkerSandboxContractTests(unittest.TestCase):
    def worker(self):
        spec = importlib.util.spec_from_file_location("public_pdf_worker_contract", landing_media.PDF_WORKER)
        worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(worker)
        return worker

    def test_resource_setup_failure_is_closed_before_parser_or_input(self):
        worker = self.worker()
        limits = (worker.resource.RLIMIT_CPU, worker.resource.RLIMIT_AS, worker.resource.RLIMIT_FSIZE,
                  worker.resource.RLIMIT_CORE, worker.resource.RLIMIT_NOFILE, worker.resource.RLIMIT_NPROC)
        for failed in limits:
            for error in (OSError, ValueError, MemoryError):
                with self.subTest(limit=failed, error=error.__name__):
                    output, source = io.BytesIO(), io.BytesIO(b"public inert PDF fixture")
                    def set_limit(kind, bounds):
                        if kind == failed:
                            raise error("public resource fixture")
                    with mock.patch.object(worker.resource, "setrlimit", side_effect=set_limit), \
                            mock.patch.object(worker.sys, "stdout", type("PublicOutput", (), {"buffer": output})()), \
                            mock.patch.object(worker.sys, "stdin", type("PublicInput", (), {"buffer": source})()), \
                            mock.patch.object(importlib.metadata, "version", side_effect=AssertionError("parser reached")):
                        try:
                            worker.main()
                        except (OSError, ValueError, MemoryError) as escaped:
                            self.fail("resource failure escaped the fixed protocol: " + type(escaped).__name__)
                    self.assertEqual(source.tell(), 0)
                    self.assertEqual(json.loads(output.getvalue()), {"schema_version": 1, "error": "pdf_sandbox_unavailable"})

    def test_parser_absence_after_exact_unchanged_limits_is_closed(self):
        worker = self.worker()
        output, source = io.BytesIO(), io.BytesIO(b"public inert PDF fixture")
        with mock.patch.object(worker.resource, "setrlimit") as limits, \
                mock.patch.object(worker.sys, "stdout", type("PublicOutput", (), {"buffer": output})()), \
                mock.patch.object(worker.sys, "stdin", type("PublicInput", (), {"buffer": source})()), \
                mock.patch.object(importlib.metadata, "version", side_effect=importlib.metadata.PackageNotFoundError("pypdf")):
            worker.main()
        self.assertEqual(source.tell(), 0)
        self.assertEqual(json.loads(output.getvalue()), {"schema_version": 1, "error": "pdf_parser_unavailable"})
        self.assertEqual(limits.call_args_list, [
            mock.call(worker.resource.RLIMIT_CPU, (5, 6)),
            mock.call(worker.resource.RLIMIT_AS, (512 * 1_048_576, 512 * 1_048_576)),
            mock.call(worker.resource.RLIMIT_FSIZE, (0, 0)), mock.call(worker.resource.RLIMIT_CORE, (0, 0)),
            mock.call(worker.resource.RLIMIT_NOFILE, (32, 32)), mock.call(worker.resource.RLIMIT_NPROC, (1, 1)),
        ])

    def test_parent_preserves_only_the_closed_sandbox_unavailable_status(self):
        actual_popen = subprocess.Popen
        for reason, expected in (("pdf_sandbox_unavailable", "pdf_sandbox_unavailable"),
                                 ("public_unknown", "pdf_decoder_protocol")):
            with self.subTest(reason=reason):
                children = []
                body = json.dumps({"schema_version": 1, "error": reason}).encode()
                def spawn(*args, **kwargs):
                    process = actual_popen(
                        (sys.executable, "-B", "-I", "-c", "import sys; sys.stdin.buffer.read(); "
                         "sys.stdout.buffer.write(" + repr(body) + ")"),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        env=_CHILD_ENV, start_new_session=True, close_fds=True,
                    )
                    children.append(process)
                    return process
                with mock.patch.object(landing_media.subprocess, "Popen", side_effect=spawn), \
                        self.assertRaises(LandingMediaError) as raised:
                    extract_pdf_text(b"%PDF-1.4\npublic synthetic PDF\n%%EOF\n")
                self.assertEqual(raised.exception.code, expected)
                self.assertEqual(children[0].poll(), 0)
                self.assertTrue(all(stream.closed for stream in (children[0].stdin, children[0].stdout, children[0].stderr)))

    def test_resource_precondition_probe_requires_a_closed_result(self):
        for code, stdout, stderr in ((1, b"unavailable", b""), (0, b"public_unknown", b""),
                                     (0, b"unavailable", b"public diagnostic")):
            with self.subTest(code=code, stdout=stdout, stderr=stderr):
                result = subprocess.CompletedProcess([], code, stdout, stderr)
                with mock.patch.object(subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
                    _child_sandbox_available()
        for stdout, expected in ((b"available", True), (b"unavailable", False)):
            with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout, b"")):
                self.assertIs(_child_sandbox_available(), expected)


@unittest.skipIf(CHILD_PYPDF_VERSION is not None, "pypdf present; unavailable branch cannot run")
class PdfWorkerWithoutParser(unittest.TestCase):
    def test_worker_executes_and_reports_parser_unavailable(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(b"%PDF-1.4\nnot really a pdf\n%%EOF\n")
        expected = "pdf_parser_unavailable" if CHILD_SANDBOX_AVAILABLE else "pdf_sandbox_unavailable"
        self.assertEqual(ctx.exception.code, expected)


@unittest.skipUnless(CHILD_PYPDF_VERSION is not None, "requires pypdf installed for the child interpreter")
class PdfWorkerWithPinnedParser(unittest.TestCase):
    def test_child_uses_the_manifest_parser_version(self):
        self.assertEqual(CHILD_PYPDF_VERSION, _declared_pypdf_version())

    def test_textual_pdf_returns_normalized_text(self):
        self.assertEqual(extract_pdf_text(_single_page_pdf("PDFWORKER OK")).strip(), "PDFWORKER OK")

    def test_blank_pdf_reports_empty_or_scanned(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(_blank_pdf())
        self.assertEqual(ctx.exception.code, "pdf_empty_or_scanned")

    def test_corrupt_pdf_reports_invalid(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(b"%PDF-1.4\nbroken xref\nstartxref\n999999\n%%EOF\n")
        self.assertEqual(ctx.exception.code, "pdf_invalid")

    def test_oversized_page_count_reports_page_limit(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(_blank_pdf(page_count=101))
        self.assertEqual(ctx.exception.code, "pdf_page_limit")

    def test_maximum_page_count_reaches_content_validation(self):
        with self.assertRaises(LandingMediaError) as ctx:
            extract_pdf_text(_blank_pdf(page_count=100))
        self.assertEqual(ctx.exception.code, "pdf_empty_or_scanned")


if __name__ == "__main__":
    unittest.main()
