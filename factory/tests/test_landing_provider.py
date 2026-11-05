from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import shutil
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from getzilla_factory.landing_contracts import LandingInputV1
from getzilla_factory.landing_provider import (
    FixedCommandLandingProvider,
    LandingNormalizationOutcome,
    LandingNormalizationRequest,
    LandingProviderError,
    LandingProviderProfile,
    STATIC_LANDING_SPEC_SCHEMA_SHA256,
    UnavailableLandingProvider,
    unavailable_landing_profile,
)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "landing_provider_fixture.py"
STATIC_SPEC_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "jsonschema"
    / "static-landing-spec.v1.schema.json"
)
NOW = datetime(2026, 9, 4, 11, 0, tzinfo=timezone.utc)
REPOSITORY_ID = "github.com/Dimkox/ai-dark-factory-landing"
BASE_SHA = "699010380f4f90a0193a9c22090c35e6aded7d2c"
BASE_TREE = "f7dbbd80c6e95d2a365109d937f5be76d8fe0bd4"
_FIXTURE_DIRECTORY = tempfile.TemporaryDirectory(prefix="public-landing-provider-")


def owned_fixture():
    # Keep the canonical fixture body exact, but run it with this test process's
    # actual interpreter rather than an unrelated platform /usr/bin/python3.
    python = os.fsencode(Path(sys.executable).resolve())
    if b"\n" in python or b" " in python or len(python) > 240:
        raise RuntimeError("public fixture interpreter cannot be expressed as a pinned shebang")
    target = Path(_FIXTURE_DIRECTORY.name) / ("fixture-" + digest(python) + ".py")
    if not target.exists():
        target.write_bytes(b"#!" + python + b"\n" + FIXTURE.read_bytes().partition(b"\n")[2])
        target.chmod(0o755)
    return target


def digest(value):
    return hashlib.sha256(value).hexdigest()


def landing_input(payload=b"same semantic request", *, kind="text", media_type="text/plain", job_id="job-1"):
    return LandingInputV1.from_facts(
        {
            "schema_version": 1,
            "job_id": job_id,
            "tenant_id": "tenant-1",
            "repository_id": REPOSITORY_ID,
            "exact_base_sha": BASE_SHA,
            "exact_base_tree": BASE_TREE,
            "site_id": "therealaidarkfactory.online",
            "media_kind": kind,
            "media_type": media_type,
            "byte_length": len(payload),
            "content_sha256": digest(payload),
            "quarantine_ref_digest": "1" * 64,
            "received_at": "2026-09-04T11:00:00Z",
            "expires_at": "2026-09-05T11:00:00Z",
        }
    )


def profile(mode="normal", *, executable=None, timeout_seconds=2):
    executable = Path(owned_fixture() if executable is None else executable).resolve()
    return LandingProviderProfile.from_facts(
        {
            "schema_version": 1,
            "profile_id": f"sealed-{mode}",
            "provider_id": "sealed-fixture",
            "adapter_id": "fixed-command",
            "adapter_version": "1.0.0",
            "model_id": "fixture-model-v1",
            "executable": str(executable),
            "executable_sha256": digest(executable.read_bytes()),
            "argv": [f"--mode={mode}"],
            "prompt_template_digest": "2" * 64,
            "tool_policy_digest": "3" * 64,
            "output_schema_digest": STATIC_LANDING_SPEC_SCHEMA_SHA256,
            "decoder_digest": "5" * 64,
            "timeout_seconds": timeout_seconds,
            "max_stdout_bytes": 262_144,
            "max_stderr_bytes": 65_536,
            "available": True,
        }
    )


def clock():
    values = iter((NOW, NOW + timedelta(seconds=1)))
    return lambda: next(values)


class LandingProviderTests(unittest.TestCase):
    def test_owned_fixture_uses_current_interpreter_and_exact_canonical_body(self):
        configured = profile()
        executable = Path(configured.executable)
        header, separator, body = executable.read_bytes().partition(b"\n")
        self.assertEqual(header, b"#!" + os.fsencode(Path(sys.executable).resolve()))
        self.assertEqual(separator, b"\n")
        self.assertEqual(body, FIXTURE.read_bytes().partition(b"\n")[2])
        self.assertEqual(configured.executable_sha256, digest(executable.read_bytes()))
        self.assertTrue(stat.S_ISREG(executable.lstat().st_mode))
        self.assertEqual(executable.lstat().st_nlink, 1)
        self.assertEqual(executable.lstat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(executable.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)

    def _fixture_environment(self, environment, mode="normal"):
        # Exercise actual fixture bytes with a controlled child-only environment.
        # This is a protocol fixture contrast, never native Mac qualification.
        actual_popen = subprocess.Popen
        bootstrap = (
            "import json,os,runpy,sys; os.environ.clear(); "
            "os.environ.update(json.loads(sys.argv[1])); sys.argv=sys.argv[2:]; "
            "runpy.run_path(sys.argv[0],run_name='__main__')"
        )
        def spawn(command, **kwargs):
            return actual_popen([sys.executable, "-I", "-c", bootstrap,
                                 json.dumps(environment), *command], **kwargs)
        with patch("getzilla_factory.landing_provider.subprocess.Popen", side_effect=spawn):
            configured = profile(mode, timeout_seconds=1)
            return FixedCommandLandingProvider(configured, clock=clock()).normalize(
                LandingNormalizationRequest(landing_input(), configured.profile_digest),
                lambda: b"same semantic request",
            )

    def test_fixture_accepts_only_documented_python_locale_coercion(self):
        for locale in (None, "C.UTF-8", "C.utf8", "UTF-8"):
            environment = {} if locale is None else {"LC_CTYPE": locale}
            with self.subTest(locale=locale):
                try:
                    outcome = self._fixture_environment(environment)
                except LandingProviderError as error:
                    self.fail("documented Python locale refused: " + str(error))
                self.assertEqual(outcome.evidence.disposition, "fixture_ready")

    def test_fixture_still_refuses_unregistered_environment_and_locale(self):
        for environment in ({"EXTRA": "public-fixture"}, {"LC_CTYPE": "en_US.UTF-8"},
                            {"LC_CTYPE": "UTF-8", "PATH": "/public-fixture"}):
            with self.subTest(environment=environment), self.assertRaisesRegex(LandingProviderError, "^provider_exit$"):
                self._fixture_environment(environment)

    def test_utf8_fixture_preserves_original_jsonl_and_resource_failures(self):
        cases = {"duplicate": "duplicate_json_key", "nonfinite": "nonfinite_json",
                 "invalid-utf8": "invalid_json", "missing-terminal": "missing_terminal",
                 "after-terminal": "after_terminal", "hostile": "unsafe_content",
                 "stdout-overflow": "provider_stdout_limit", "stderr-overflow": "provider_stderr_limit",
                 "sleep": "provider_timeout"}
        for mode, code in cases.items():
            with self.subTest(mode=mode), self.assertRaises(LandingProviderError) as raised:
                self._fixture_environment({"LC_CTYPE": "UTF-8"}, mode)
            self.assertEqual(str(raised.exception).partition(":")[0], code)

    def test_outcome_state_spec_and_evidence_disposition_are_closed(self):
        payload = b"bounded"
        source = landing_input(payload)
        configured = profile()
        successful = FixedCommandLandingProvider(
            configured, clock=clock()
        ).normalize(
            LandingNormalizationRequest(source, configured.profile_digest),
            lambda: payload,
        )
        unavailable_profile = unavailable_landing_profile()
        unavailable = UnavailableLandingProvider(
            unavailable_profile, clock=clock()
        ).normalize(
            LandingNormalizationRequest(source, unavailable_profile.profile_digest),
            lambda: payload,
        )

        contradictions = (
            (successful.spec, unavailable.evidence, "normalized", "normalized"),
            (None, successful.evidence, "provider_unavailable", "profile_unavailable"),
            (None, successful.evidence, "needs_human", "invalid_model_output"),
            (None, successful.evidence, "rejected", "invalid_input"),
        )
        for spec, evidence, state, reason in contradictions:
            with self.subTest(state=state), self.assertRaisesRegex(
                LandingProviderError, "normalization_evidence"
            ):
                LandingNormalizationOutcome(spec, evidence, state, reason)

    def test_unavailable_default_stops_before_blob_read_or_process_creation(self):
        source = landing_input()
        configured = unavailable_landing_profile()
        request = LandingNormalizationRequest(source, configured.profile_digest)
        reads = []

        def read_blob():
            reads.append(True)
            raise AssertionError("unavailable provider read the blob")

        with patch("getzilla_factory.landing_provider.subprocess.Popen", side_effect=AssertionError("spawned")):
            outcome = UnavailableLandingProvider(clock=clock()).normalize(request, read_blob)
        self.assertIsNone(outcome.spec)
        self.assertEqual(outcome.evidence.disposition, "provider_unavailable")
        self.assertEqual((outcome.evidence.usage_input_units, outcome.evidence.usage_output_units), (0, 0))
        self.assertEqual(reads, [])

    def test_explicit_sealed_fixture_normalizes_all_five_kinds_to_same_semantics(self):
        self.assertEqual(
            digest(STATIC_SPEC_SCHEMA.read_bytes()),
            STATIC_LANDING_SPEC_SCHEMA_SHA256,
        )
        kinds = (
            ("text", "text/plain"),
            ("audio", "audio/wav"),
            ("image", "image/png"),
            ("pdf", "application/pdf"),
            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        )
        semantic = []
        for index, (kind, media_type) in enumerate(kinds, 1):
            with self.subTest(kind=kind):
                payload = f"equivalent-{kind}".encode()
                source = landing_input(payload, kind=kind, media_type=media_type, job_id=f"job-{index}")
                configured = profile()
                outcome = FixedCommandLandingProvider(configured, clock=clock()).normalize(
                    LandingNormalizationRequest(source, configured.profile_digest), lambda: payload
                )
                self.assertEqual(outcome.evidence.disposition, "fixture_ready")
                self.assertEqual(outcome.evidence.input_digest, source.input_digest)
                self.assertEqual(outcome.spec.robots_policy, "preserve_source")
                value = outcome.spec.to_dict()
                value.pop("input_digest")
                value.pop("spec_digest")
                semantic.append(value)
        self.assertEqual(semantic, [semantic[0]] * 5)

    def test_profile_mismatch_and_executable_drift_fail_before_blob_read(self):
        source = landing_input()
        configured = profile()
        reads = []
        provider = FixedCommandLandingProvider(configured, clock=clock())
        with self.assertRaisesRegex(LandingProviderError, "profile_mismatch"):
            provider.normalize(LandingNormalizationRequest(source, "0" * 64), lambda: reads.append(True))
        self.assertEqual(reads, [])

        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "fixture"
            shutil.copyfile(FIXTURE, copied)
            copied.chmod(0o755)
            drift_profile = profile(executable=copied)
            copied.write_text("#!/usr/bin/python3\nraise SystemExit(0)\n", encoding="utf-8")
            with self.assertRaisesRegex(LandingProviderError, "executable_digest_mismatch"):
                FixedCommandLandingProvider(drift_profile, clock=clock()).normalize(
                    LandingNormalizationRequest(source, drift_profile.profile_digest), lambda: reads.append(True)
                )
        self.assertEqual(reads, [])

    def test_blob_digest_mismatch_fails_without_process(self):
        source = landing_input(b"expected")
        configured = profile()
        with patch("getzilla_factory.landing_provider.subprocess.Popen", side_effect=AssertionError("spawned")):
            with self.assertRaisesRegex(LandingProviderError, "blob_digest_mismatch"):
                FixedCommandLandingProvider(configured, clock=clock()).normalize(
                    LandingNormalizationRequest(source, configured.profile_digest), lambda: b"changed"
                )

    def test_strict_jsonl_and_closed_spec_fail_without_native_retention(self):
        source_payload = b"private source bytes"
        source = landing_input(source_payload)
        cases = {
            "duplicate": "duplicate_json_key",
            "nonfinite": "nonfinite_json",
            "invalid-utf8": "invalid_json",
            "missing-terminal": "missing_terminal",
            "after-terminal": "after_terminal",
            "hostile": "unsafe_content",
        }
        for mode, code in cases.items():
            configured = profile(mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(LandingProviderError, code) as raised:
                FixedCommandLandingProvider(configured, clock=clock()).normalize(
                    LandingNormalizationRequest(source, configured.profile_digest), lambda: source_payload
                )
            self.assertNotIn(source_payload.decode(), str(raised.exception))
            self.assertNotIn("native fixture diagnostic", str(raised.exception))

    def test_stdout_stderr_and_wall_time_are_hard_bounded(self):
        payload = b"bounded"
        source = landing_input(payload)
        cases = {
            "stdout-overflow": "provider_stdout_limit",
            "stderr-overflow": "provider_stderr_limit",
            "sleep": "provider_timeout",
        }
        for mode, code in cases.items():
            configured = profile(mode, timeout_seconds=1)
            with self.subTest(mode=mode), self.assertRaisesRegex(LandingProviderError, code):
                FixedCommandLandingProvider(configured, clock=clock()).normalize(
                    LandingNormalizationRequest(source, configured.profile_digest), lambda: payload
                )

    def test_profile_rejects_shell_or_environment_shaped_configuration(self):
        facts = profile().to_facts()
        for mutation, code in (
            ({"executable": "fixture"}, "profile_executable"),
            ({"argv": ["--mode=normal", "$(touch /tmp/nope)"]}, "profile_argv"),
            ({"output_schema_digest": "4" * 64}, "profile_output_schema"),
            ({"environment_names": ["TOKEN"]}, "unknown_fields"),
        ):
            changed = {**facts, **mutation}
            with self.subTest(code=code), self.assertRaisesRegex(LandingProviderError, code):
                LandingProviderProfile.from_facts(changed)


if __name__ == "__main__":
    unittest.main()
