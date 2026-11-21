"""NEW owned source/input joins; no default producer, scanner or network runs."""

import ast
import hashlib
import importlib
import importlib.machinery
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

W = Path(__file__).resolve().parents[1]
E = W / ".getzilla/runtime/scratch/new-oci-handoff-fixtures"
sys.path.insert(0, str(W / ".getzilla"))
_GUARD = {"root": None}


def audit(event, args):
    root = _GUARD["root"]
    if root is None:
        return
    if event.startswith(("subprocess.", "socket.")):
        raise AssertionError("native/network call denied in owned fixture")
    if event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        path = os.fsdecode(args[0])
        absolute = os.path.abspath(path)
        if absolute != root and not absolute.startswith(root + os.sep):
            raise AssertionError("Root/default source read denied in owned fixture")


sys.addaudithook(audit)


class OCIInputHandoffTests(unittest.TestCase):
    def setUp(self):
        E.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tmp = tempfile.TemporaryDirectory(dir=E)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_helper_only_engine_change_invalidates_independent_consumer_binding(self):
        import getzilla
        from getzilla import security_research_catalog, verification_plan as vp, verification_policy_source
        from getzilla import verification_tool_workspace  # pre-load outside I/O guard

        self.assertTrue(callable(verification_tool_workspace.checked_path))
        tree = ast.parse(Path(verification_policy_source.__file__).read_bytes())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == "implementation_source_binding")
        names = [name for node in function.body if isinstance(node, ast.For)
                 and isinstance(node.target, ast.Name) and node.target.id == "name"
                 for name in ast.literal_eval(node.iter)]
        self.assertIn("security_oci.py", names)
        catalog = security_research_catalog.catalog_bytes()
        image_conditions = security_research_catalog.image_conditions_bytes()
        engine, consumer = self.root / "engine", self.root / "consumer"
        engine.mkdir()
        consumer.mkdir()
        (engine / "config").mkdir()
        (engine / "config/stacks.json").write_text("{}")
        (engine / "config/toolchain.json").write_text("{}", encoding="utf-8", newline="\n")
        marker = consumer / "owned-source.txt"
        marker.write_text("unchanged consumer")
        modules = {}
        for name in names:
            path = engine / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text("OWNED_SOURCE = 1\n")
            identity = name[:-3].replace("/", ".").removesuffix(".__init__")
            module = types.ModuleType("getzilla." + identity)
            module.__file__ = str(path)
            module.__loader__ = importlib.machinery.SourceFileLoader(module.__name__, str(path))
            modules["." + identity] = module

        def owned_import(name, package=None):
            self.assertIn(name, modules, "unexpected default engine import")
            return modules[name]

        before_consumer = hashlib.sha256(marker.read_bytes()).hexdigest()
        with (
            patch.object(verification_policy_source.importlib, "import_module", side_effect=owned_import),
            patch.object(security_research_catalog, "catalog_bytes", return_value=catalog),
            patch.object(security_research_catalog, "image_conditions_bytes", return_value=image_conditions),
            patch.object(getzilla, "STACK_DIR", engine),
        ):
            _GUARD["root"] = str(self.root)
            try:
                first = vp.policy_binding(consumer)
                (engine / "security_oci.py").write_text("OWNED_SOURCE = 2\n")
                second = vp.policy_binding(consumer)
            finally:
                _GUARD["root"] = None
        self.assertEqual(before_consumer, hashlib.sha256(marker.read_bytes()).hexdigest())
        self.assertNotEqual(first["digest"], second["digest"])
        self.assertNotEqual(
            first["implementation"].get("security_oci.py"), second["implementation"].get("security_oci.py")
        )

    def test_per_use_selection_binds_source_bytes_line_reference_and_platform(self):
        from getzilla import security_inventory as inv

        self.assertTrue(hasattr(inv, "qualify_image_use"), "missing actual source-use qualifier")
        source = "services:\n  api:\n    image: ${OWNED_API_IMAGE:?select image}\n"
        sha = hashlib.sha256(source.encode()).hexdigest()
        original = "${OWNED_API_IMAGE:?select image}"
        selected = "example.invalid/owned@sha256:" + "a" * 64
        binding = dict(
            manifest="compose.yaml",
            line=3,
            source_sha256=sha,
            source_reference=original,
            reference=selected,
            platform="linux/amd64",
        )
        value, gaps, used = inv.qualify_image_use(
            original, "compose.yaml", 3, sha, bindings=[binding], require_digest=True
        )
        self.assertEqual(gaps, [])
        self.assertEqual(value["reference"], selected)
        self.assertEqual(value["platform"], "linux/amd64")
        self.assertIsNotNone(used)
        for field, mutation in [("source_sha256", "b" * 64), ("line", 4), ("source_reference", "other")]:
            wrong = dict(binding)
            wrong[field] = mutation
            value, gaps, _ = inv.qualify_image_use(
                original, "compose.yaml", 3, sha, bindings=[wrong], require_digest=True
            )
            self.assertTrue(gaps)
            self.assertNotEqual(value["reference"], selected)
        with self.assertRaises(ValueError):
            inv.qualify_image_use(original, "compose.yaml", 3, sha, bindings=[binding, binding], require_digest=True)
        value, gaps, _ = inv.qualify_image_use(
            original, "compose.yaml", 3, sha, bindings=[binding], require_digest=True, platform="linux/arm64"
        )
        self.assertTrue(gaps)

    def test_explicit_compose_platform_reaches_actual_image_qualifier(self):
        from getzilla import security_inventory as inv

        self.assertTrue(hasattr(inv, "compose_image_platform"), "missing Compose platform source path")
        source = (
            "services:\n  api:\n    image: example.invalid/owned@sha256:" + "a" * 64 + "\n    platform: linux/amd64\n"
        )
        fields = inv._parse_inventory_yaml(source).value["services"].value["api"].value
        platform = inv.compose_image_platform(fields)
        self.assertEqual(platform, "linux/amd64")
        value, gaps, _ = inv.qualify_image_use(
            fields["image"].value,
            "compose.yaml",
            3,
            hashlib.sha256(source.encode()).hexdigest(),
            platform=platform,
            require_digest=True,
        )
        self.assertEqual(value["platform"], platform)
        self.assertEqual(gaps, [])

    def test_image_database_is_distinct_explicit_stage_with_denied_process(self):
        from getzilla import security_tools as tools

        self.assertTrue(hasattr(tools, "refresh_image_database"), "missing distinct DB preparation stage")
        calls = []

        def process(argv, cwd, scratch, **kwargs):
            self.assertIn("--download-db-only", argv)
            self.assertNotIn("--input", argv)
            calls.append(list(argv))
            return types.SimpleNamespace(returncode=0)

        with (
            patch("subprocess.Popen", side_effect=AssertionError("process denied")),
            patch.object(tools, "pinned_tool", return_value=self.root / "UNEXECUTED"),
            patch.object(tools, "_process", side_effect=process),
            patch.object(tools, "trivy_database_source", return_value={"source_id": "owned-mocked-db"}),
        ):
            values = tools.refresh_image_database(self.root)
        self.assertEqual(len(calls), 1)
        self.assertEqual(values[0]["source_id"], "trivy-db")
        self.assertEqual(values[0]["snapshot"]["source_id"], "owned-mocked-db")
        cli = (W / ".getzilla/getzilla/security_cli.py").read_text()
        self.assertGreaterEqual(cli.count("refresh_image_database("), 2)

    def test_owned_source_selection_and_fresh_preparation_stage_order(self):
        from getzilla import security_inventory as inv
        from getzilla import security_cli as cli
        from getzilla import security_tools as tools

        source = "services:\n  api:\n    image: ${OWNED_IMAGE:?select}\n"
        (self.root / "compose.yaml").write_text(source)
        selected = "example.invalid/owned@sha256:" + "a" * 64
        binding = dict(
            manifest="compose.yaml",
            line=3,
            source_sha256=hashlib.sha256(source.encode()).hexdigest(),
            source_reference="${OWNED_IMAGE:?select}",
            reference=selected,
            platform="linux/amd64",
        )
        catalog = dict(
            schema_version=1,
            inventory_sha256="",
            records=[dict(reference=selected, platform="linux/amd64", layout=str(self.root / "UNEXECUTED-layout"))],
            source_bindings=[binding],
        )
        catalog_path = self.root / "catalog.json"
        snapshots = dict(
            head_sha="a" * 40,
            tree_sha="b" * 40,
            checker_sha="c" * 40,
            checker_tree_sha="d" * 40,
            candidate_clean=True,
            checker_clean=True,
            same_project=True,
        )
        run = dict(
            provider="github-actions", repository="owned/fixture", run_id="71", run_attempt="1", head_sha="a" * 40
        )
        calls = []

        def owned_read(parent, name, maximum):
            value = (parent / name).read_bytes()
            self.assertLessEqual(len(value), maximum)
            return value

        def imported(*args, **kwargs):
            calls.append("local-import")
            return [{"kind": "owned-mocked-import", "status": "pass"}]

        def process(argv, *args, **kwargs):
            self.assertIn("--download-db-only", argv)
            calls.append("db")
            return types.SimpleNamespace(returncode=0)

        def obligations(*args, **kwargs):
            calls.append("obligations")
            return []

        with (
            patch.object(inv, "_tracked_files", return_value=["compose.yaml"]),
            patch.object(cli, "_policy_digest", return_value="e" * 64),
            patch.object(cli, "source_binding", return_value=snapshots),
            patch.object(cli, "read_file", side_effect=owned_read),
            patch.object(cli, "refresh_images", side_effect=imported),
            patch.object(cli, "refresh_feeds", return_value=[]),
            patch.object(cli, "acquire_pypi", return_value={"gaps": []}),
            patch.object(cli, "security_obligations", side_effect=obligations),
            patch.object(cli, "load_policy", return_value={}),
            patch.object(cli, "evaluate_artifacts", return_value={"status": "fail"}),
            patch.object(tools, "pinned_tool", return_value=self.root / "UNEXECUTED"),
            patch.object(tools, "_process", side_effect=process),
            patch.object(tools, "trivy_database_source", return_value={"source_id": "owned-mocked-db"}),
        ):
            _GUARD["root"] = str(self.root)
            try:
                parsed = inv.collect_inventory(self.root, image_bindings=[binding])
                self.assertTrue(parsed["complete"], parsed["gaps"])
                self.assertEqual(parsed["images"][0]["reference"], selected)
                changed = inv.collect_inventory(self.root, image_bindings=[dict(binding, source_sha256="f" * 64)])
                self.assertFalse(changed["complete"])
                self.assertTrue(any(row["code"] == "unused-image-source-selection" for row in changed["gaps"]))
                catalog["inventory_sha256"] = parsed["digest"]
                catalog_path.write_text(json.dumps(catalog))
                roots = [self.root / name for name in ("database", "artifacts", "tools")]
                profile = cli.prepare_inputs(
                    self.root, *roots, write_profile=True, run=run, image_artifacts=catalog_path
                )
                self.assertEqual(calls, ["local-import"])
                self.assertIn("image_artifacts_sha256", profile)
                calls.clear()
                result = cli.prepare_inputs(
                    self.root, *roots, profile=profile, run=run, refresh=True, image_artifacts=catalog_path
                )
                self.assertEqual(calls, ["local-import", "db", "obligations"])
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["qualification"], "UNVERIFIED")
                self.assertIn("required-source-plan-incomplete", result["gaps"])
            finally:
                _GUARD["root"] = None


if __name__ == "__main__":
    unittest.main(verbosity=2)
