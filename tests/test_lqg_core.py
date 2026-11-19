from __future__ import annotations

import dataclasses
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".getzilla"))

from getzilla.language_quality.models import AdapterCapabilities, AdapterRequest, AdapterResult, Diagnostic, ToolOutput


class AdapterContractTests(unittest.TestCase):
    def test_shared_contract_is_immutable_and_preserves_status(self):
        request = AdapterRequest("eslint", "cli", ("node", "eslint.js"), "changed", ("app.js",))
        self.assertEqual(request.files, ("app.js",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.scope = "full"
        self.assertTrue(AdapterCapabilities(False).full)
        diagnostic = Diagnostic("error", "rule", "message")
        self.assertEqual(AdapterResult("FAIL", "findings", (diagnostic,)).diagnostics, (diagnostic,))
        self.assertEqual(ToolOutput(2, "", "bad config").returncode, 2)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write(self, path, text=""):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    def policy(self, section):
        self.write(".getzilla/config/policy.json", json.dumps({"language_quality_gates": section}))

    def test_policy_defaults_and_closed_fields(self):
        from getzilla.language_quality.core import PolicyError, load_policy
        policy = load_policy(self.root)
        self.assertEqual((policy.mode, policy.enforcement, policy.scope), ("auto", "shadow", "changed"))
        for section in ({"autofix": True}, {"ai_retries": 1}, {"enforcement": "block"},
                        {"tools": {"unknown": {}}}, {"scope": "all"}, {"typo": True}):
            self.policy(section)
            with self.subTest(section=section), self.assertRaises(PolicyError):
                load_policy(self.root)
        self.write(".getzilla/config/policy.json", '{"language_quality_gates":{"mode":"off","mode":"on"}}')
        with self.assertRaises(PolicyError):
            load_policy(self.root)

    def test_packages_exclude_generated_and_keep_nested_ownership(self):
        from getzilla.language_quality.core import discover_packages
        files = ["package.json", "src/app.ts", "web/package.json", "web/app.js",
                 "vendor/ignored.js", "node_modules/pkg/index.js", "generated/schema.ts",
                 "mobile/pubspec.yaml", "mobile/lib/app.dart", "native/Package.swift", "native/App.swift"]
        packages = discover_packages(files)
        self.assertEqual([(p.path, p.language, p.files) for p in packages], [
            (".", "javascript", ("src/app.ts",)), ("mobile", "dart", ("lib/app.dart",)),
            ("native", "swift", ("App.swift",)), ("web", "javascript", ("app.js",))])
        with self.assertRaises(ValueError):
            discover_packages(["../escape.js"])

    def test_changed_scope_has_conservative_fallbacks(self):
        from getzilla.language_quality.core import discover_packages, select_scope
        package = discover_packages(["web/package.json", "web/a.js", "web/b.js"])[0]
        record = {"status": "M", "path": "web/a.js", "source": "range:" + "a" * 40}
        scope = select_scope(package, "changed", "a" * 40, [record], incremental=True)
        self.assertEqual((scope.actual, scope.files, scope.reason), ("changed", ("a.js",), None))
        for records, base, incremental, reason in (
            ([record], None, True, "untrusted-base"), (None, "a" * 40, True, "unknown-inventory"),
            ([{**record, "status": "R100", "old_path": "web/old.js"}], "a" * 40, True, "rename-or-delete"),
            ([{**record, "path": "package-lock.json"}], "a" * 40, True, "configuration-change"),
            ([record], "a" * 40, False, "adapter-full-only"),
        ):
            with self.subTest(reason=reason):
                scope = select_scope(package, "changed", base, records, incremental=incremental)
                self.assertEqual((scope.actual, scope.files, scope.reason), ("full", package.files, reason))
        with self.assertRaises(ValueError):
            select_scope(package, "changed", "a" * 40, [{**record, "path": "web/../a.js"}], incremental=True)

    def test_admission_preserves_shadow_and_refuses_blocking_nonpasses(self):
        from getzilla.language_quality.core import project_checks
        for status in ("PASS", "FAIL", "ERROR", "TIMEOUT", "CANCELLED", "NOT_CONFIGURED", "UNSUPPORTED_RUNNER"):
            item = {"tool_id": "eslint", "package": ".", "execution_status": status,
                    "enforcement": "shadow", "summary": "observed"}
            self.assertEqual(project_checks([item]), [])
            item["enforcement"] = "blocking"
            checks = project_checks([item])
            self.assertEqual(checks[0]["status"], "pass" if status == "PASS" else "cancelled" if status == "CANCELLED" else "fail")
        for status in ("NOT_APPLICABLE", "SKIPPED_BY_POLICY"):
            self.assertEqual(project_checks([{**item, "execution_status": status}]), [])

    def test_non_applicable_off_and_missing_backend_do_not_execute(self):
        from getzilla.language_quality.core import run_registry
        with patch("getzilla.language_quality.core.inventory", return_value=("app.py",)), \
             patch("getzilla.language_quality.core.changed_file_statuses", return_value=[]), \
             patch("getzilla.language_quality.core.git_head", return_value="b" * 40):
            results = run_registry(self.root, "a" * 40)
            self.assertEqual({r["execution_status"] for r in results}, {"NOT_APPLICABLE"})
        self.write("app.js", "const answer = 42;\n")
        self.write("eslint.config.js", "export default [];\n")
        self.policy({"mode": "on", "tools": {"eslint": {"version": "9.0.0", "launcher": ["/opt/bin/eslint"]}}})
        with patch("getzilla.language_quality.core.inventory", return_value=("app.js", "eslint.config.js")), \
             patch("getzilla.language_quality.core.changed_file_statuses", return_value=[]), \
             patch("getzilla.language_quality.core.git_head", return_value="b" * 40):
            results = run_registry(self.root, None)
            eslint = next(r for r in results if r["tool_id"] == "eslint")
            self.assertEqual(eslint["execution_status"], "UNSUPPORTED_RUNNER")
            self.assertFalse(eslint["cache_hit"])
            self.assertEqual(eslint["scope"], "full")
            self.policy({"mode": "off"})
            self.assertEqual({r["execution_status"] for r in run_registry(self.root, None)}, {"SKIPPED_BY_POLICY"})

    def test_policy_error_cannot_silently_become_default_shadow(self):
        from getzilla.language_quality.core import run_registry, project_checks
        self.write(".getzilla/config/policy.json", "broken")
        result = run_registry(self.root, None)
        self.assertEqual(result[0]["execution_status"], "ERROR")
        self.assertEqual(project_checks(result)[0]["status"], "fail")

    def test_snapshot_inventory_is_positive_and_excludes_unrelated_private_files(self):
        from getzilla.language_quality.core import approved_inputs, discover_packages
        files = ("package.json", "app.js", "eslint.config.js", ".npmrc", "credentials.json", "id_rsa", "README.md", "notes.txt")
        allowed = approved_inputs(files, discover_packages(files), {})
        self.assertEqual(allowed, ("app.js", "eslint.config.js", "package.json"))

    @unittest.skipUnless(os.name == 'posix', 'no-follow snapshot backend requires POSIX')
    def test_input_digest_ignores_atime_and_refuses_symlink_components(self):
        import os
        from getzilla.language_quality.core import _read_inputs
        self.write("app.js", "content")
        os.utime(self.root / "app.js", (1, 2))
        first = _read_inputs(self.root, ("app.js",))
        self.assertEqual(first, _read_inputs(self.root, ("app.js",)))
        self.write("source/private.js", "private")
        (self.root / "linked").symlink_to(self.root / "source", target_is_directory=True)
        with self.assertRaises(OSError):
            _read_inputs(self.root, ("linked/private.js",))

    @unittest.skipUnless(os.name == 'posix', 'snapshot digest requires POSIX')
    def test_registry_runs_adapter_and_binds_results_to_unchanged_inputs(self):
        from getzilla.language_quality.core import run_registry, project_checks
        from getzilla.language_quality.sandbox import Execution
        self.write("app.js", "const answer = 42;")
        self.write("eslint.config.js", "export default [];")
        self.policy({"sandbox": {"image": "lint@sha256:" + "a" * 64}, "tools": {
            "eslint": {"version": "9.0.0", "launcher": ["/opt/bin/eslint"], "enforcement": "blocking"}}})
        payload = [{"filePath": "/workspace/app.js", "messages": [], "errorCount": 0,
                    "warningCount": 0, "fatalErrorCount": 0, "fixableErrorCount": 0, "fixableWarningCount": 0}]
        backend = unittest.mock.Mock()
        backend.execute.return_value = Execution("COMPLETED", ToolOutput(0, json.dumps(payload), ""), identity="fixture-image")
        with patch("getzilla.language_quality.core.inventory", return_value=("app.js", "eslint.config.js")), \
             patch("getzilla.language_quality.core.git_head", return_value="b" * 40):
            results = run_registry(self.root, None, executor=backend)
            result = next(item for item in results if item["tool_id"] == "eslint")
            self.assertEqual(result["execution_status"], "PASS", result)
            self.assertEqual(project_checks(results)[0]["status"], "pass")
            self.assertEqual(backend.execute.call_args.kwargs["expected_digest"], result["input_digest"])
            self.assertEqual(len(result["execution_fingerprint"]), 64)
            def changed(*args, **kwargs):
                self.write("app.js", "changed during execution")
                return Execution("COMPLETED", ToolOutput(0, json.dumps(payload), ""), identity="fixture-image")
            backend.execute.side_effect = changed
            result = next(item for item in run_registry(self.root, None, executor=backend) if item["tool_id"] == "eslint")
            self.assertEqual(result["execution_status"], "ERROR")


@unittest.skipUnless(os.name == 'posix', 'container backend requires POSIX')
class SandboxTests(unittest.TestCase):
    def test_repo_image_requires_separate_operator_admission_before_any_process(self):
        from getzilla.language_quality.sandbox import ContainerExecutor
        image = "private-service@sha256:" + "b" * 64
        executor = ContainerExecutor({"image": image}, approved_images=frozenset())
        with patch("getzilla.language_quality.sandbox.bounded_process") as process:
            result = executor.execute(Path("."), ".", (), ("/opt/bin/eslint",))
        self.assertEqual(result.status, "UNSUPPORTED_RUNNER")
        process.assert_not_called()

    def test_private_scratch_creation_does_not_depend_on_umask(self):
        from getzilla.language_quality.sandbox import private_parent
        import os
        import stat
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0o002)
            try:
                parent = private_parent(Path(directory))
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
                parent.chmod(0o775)
                with self.assertRaises(ValueError):
                    private_parent(Path(directory))
            finally:
                os.umask(previous)
    def test_container_plan_has_readonly_no_network_and_no_ambient_authority(self):
        from getzilla.language_quality.sandbox import ContainerExecutor
        executor = ContainerExecutor({"image": "node@sha256:" + "a" * 64})
        argv = executor.build_argv(Path("/private/snapshot"), "web", ("/opt/bin/eslint", "."), "lqg-test")
        self.assertIn("--read-only", argv)
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--pull") + 1], "never")
        self.assertEqual(argv[argv.index("--user") + 1], "65534:65534")
        self.assertIn("type=bind,src=/private/snapshot,dst=/workspace,readonly", argv)
        self.assertIn("/workspace/web", argv)
        self.assertNotIn("--privileged", argv)
        self.assertNotIn("--env-file", argv)
        for package in ("../outside", "/absolute", "a/../b"):
            with self.assertRaises(ValueError):
                executor.build_argv(Path("/private/snapshot"), package, ("/opt/bin/eslint",), "lqg-test")

    def test_unsafe_mutable_images_and_resource_overrides_are_rejected(self):
        from getzilla.language_quality.sandbox import validate_spec
        for spec in ({"image": "node:latest"}, {"image": "node@sha256:" + "a" * 64, "network": "host"},
                     {"image": "node@sha256:" + "a" * 64, "timeout_seconds": 0},
                     {"image": "node@sha256:" + "a" * 64, "output_bytes": 2**32}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                validate_spec(spec)

    def test_bounded_process_handles_limit_timeout_and_cancellation(self):
        from getzilla.language_quality.sandbox import bounded_process
        command = [sys.executable, "-c", "print('x' * 65536)"]
        result = bounded_process(command, {}, timeout=3, output_limit=1024)
        self.assertEqual(result.status, "ERROR")
        self.assertLessEqual(len(result.output.stdout) + len(result.output.stderr), 1024)
        result = bounded_process([sys.executable, "-c", "import time; time.sleep(2)"], {}, timeout=.05, output_limit=1024)
        self.assertEqual(result.status, "TIMEOUT")
        result = bounded_process(command, {}, timeout=3, output_limit=1024, cancellation=lambda: True)
        self.assertEqual(result.status, "CANCELLED")


class CpuBudgetTests(unittest.TestCase):
    def test_reserve_uses_host_logical_count_only_once_and_caps_explicit(self):
        from getzilla.cpu_budget import cpu_budget
        for host, allowed, quota, requested, expected in (
            (28, 28, None, None, 26), (28, 22, None, None, 22), (28, 26, None, None, 26),
            (28, 26, 4, None, 4), (28, 28, None, 28, 26), (28, 28, None, 8, 8),
            (1, 1, None, None, 1), (2, 2, None, None, 1), (3, 3, None, None, 1),
        ):
            with self.subTest(host=host, allowed=allowed, quota=quota, requested=requested), \
                 patch("getzilla.cpu_budget.os.cpu_count", return_value=host), \
                 patch("getzilla.cpu_budget.os.sched_getaffinity", return_value=set(range(allowed)), create=True), \
                 patch("getzilla.cpu_budget.linux_quota_capacity", return_value=quota), \
                 patch("getzilla.cpu_budget.sys.platform", "linux"):
                self.assertEqual(cpu_budget(requested).effective, expected)
        for invalid in (0, -1, 1.5, "8", True):
            with self.assertRaises(ValueError):
                cpu_budget(invalid)
        with patch("getzilla.cpu_budget.os.sched_getaffinity", return_value=set(), create=True):
            with self.assertRaisesRegex(ValueError, "no allowed"):
                cpu_budget()


class VerificationIntegrationTests(unittest.TestCase):
    def test_advisory_evidence_and_optional_check_projection_share_one_result(self):
        from getzilla.verification import _language_quality_report
        result = {"tool_id": "eslint", "package": "web", "execution_status": "FAIL",
                  "enforcement": "shadow", "summary": "one finding", "evidence_digest": "a" * 64}
        with patch("getzilla.verification.run_language_quality", return_value=[result]):
            report, checks = _language_quality_report(Path("."), "b" * 40, None)
            self.assertEqual(report["results"], [result])
            self.assertEqual(checks, [])
            result["enforcement"] = "blocking"
            report, checks = _language_quality_report(Path("."), "b" * 40, None)
            self.assertEqual(checks[0].status, "fail")
            self.assertEqual(checks[0].details[0]["evidence_digest"], result["evidence_digest"])


@unittest.skipUnless(os.name == 'posix', 'container backend requires POSIX')
class ContainerSmokeTests(unittest.TestCase):
    def test_available_node_image_enforces_readonly_nonroot_and_clean_environment(self):
        from getzilla.language_quality.sandbox import ContainerExecutor
        image = "node@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20"
        program = ("const fs=require('fs'); const os=require('os'); "
                   "let readonly=false; try{fs.writeFileSync('/workspace/unwanted','x')}catch(e){readonly=e.code==='EROFS'||e.code==='EACCES'}; "
                   "let clean=!process.env.LQG_SECRET_TEST; let nonroot=process.getuid()!==0; "
                   "let offline=Object.keys(os.networkInterfaces()).every(x=>x==='lo'); "
                   "console.log(JSON.stringify({readonly,clean,nonroot,offline})); "
                   "process.exit(readonly&&clean&&nonroot&&offline?0:1)")
        with tempfile.TemporaryDirectory() as directory, patch.dict("os.environ", {"LQG_SECRET_TEST": "must-not-cross"}):
            root = Path(directory)
            (root / "app.js").write_text(program)
            executor = ContainerExecutor({"image": image, "timeout_seconds": 15}, approved_images=frozenset({image}))
            result = executor.execute(root, ".", ("app.js",), ("/usr/local/bin/node", "/workspace/app.js"))
            if result.status == "UNSUPPORTED_RUNNER":
                self.skipTest(result.summary)
            self.assertEqual(result.status, "COMPLETED", result.summary)
            self.assertEqual(result.output.returncode, 0, result.output.stderr)
            self.assertEqual(json.loads(result.output.stdout), {"readonly": True, "clean": True, "nonroot": True, "offline": True})
            self.assertFalse((root / "unwanted").exists())


if __name__ == "__main__":
    unittest.main()
