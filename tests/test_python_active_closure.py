"""Conditional pins keep raw inventory but only active versions enter one consumer."""

import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import security_python_target as target, security_licenses as licenses
from getzilla.security_artifacts import ArtifactError


class ActiveClosureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / ".getzilla/runtime")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.rows = [self.dep("bandit", "1.9.4"), self.dep("stevedore", "5.10.0"), self.dep("stevedore", "5.8.0")]
        text = 'bandit==1.9.4\nstevedore==5.10.0; python_version >= "3.11"\nstevedore==5.8.0; python_version < "3.11"\n'
        (self.root / "requirements.txt").write_text(text)
        self.inventory = dict(
            digest="a" * 64,
            dependencies=self.rows,
            manifests=[dict(path="requirements.txt", sha256=hashlib.sha256(text.encode()).hexdigest())],
        )
        self.environment = dict(
            python_version="3.12", python_full_version="3.12.3", sys_platform="linux", platform_system="Linux"
        )

    def dep(self, name, version, manifest="requirements.txt"):
        return dict(ecosystem="PyPI", name=name, version=version, manifest=manifest, usage="build-ci", extras=[])

    def binding(self, environment=None):
        return dict(
            source_pins=target.source_pins(
                self.root, self.inventory, dict(marker_environment=environment or self.environment)
            )
        )

    def test_only_active_version_enters_exact_source_consumer_without_dropping_inventory(self):
        original = copy.deepcopy(self.inventory)
        for version, selected in [("3.12", "5.10.0"), ("3.10", "5.8.0")]:
            with self.subTest(version=version):
                env = {**self.environment, "python_version": version, "python_full_version": version + ".3"}
                graphs = target.closure_dependencies(self.rows[0], self.rows, self.binding(env))
                self.assertEqual([row["version"] for row in graphs[0] if row["name"] == "stevedore"], [selected])
                licenses._closure({"requires": ["stevedore>=5"]}, self.rows[0], graphs[0], env)
        self.assertEqual(self.inventory, original)
        self.assertEqual(len(self.inventory["dependencies"]), 3)

    def test_missing_or_wrong_source_use_observation_refuses_instead_of_assuming_active(self):
        for variant in ("missing", "wrong-context", "not-boolean"):
            with self.subTest(variant=variant):
                binding = self.binding()
                key = target.digest(target._subject(self.rows[1]))
                if variant == "missing":
                    binding["source_pins"].pop(key)
                if variant == "wrong-context":
                    binding["source_pins"][key]["context_sha256"] = "0" * 64
                if variant == "not-boolean":
                    binding["source_pins"][key]["marker_active"] = 1
                with self.assertRaises(ArtifactError):
                    target.closure_dependencies(self.rows[0], self.rows, binding)

    def test_source_marker_never_fills_missing_variable_from_ambient_host(self):
        with self.assertRaises(ArtifactError):
            self.binding({"sys_platform": "linux"})

    def test_missing_active_dependency_stays_a_coverage_gap(self):
        binding = self.binding()
        for dep in self.rows[1:]:
            binding["source_pins"][target.digest(target._subject(dep))]["marker_active"] = False
        graph = target.closure_dependencies(self.rows[0], self.rows, binding)[0]
        with self.assertRaises(ArtifactError):
            licenses._closure({"requires": ["stevedore>=5"]}, self.rows[0], graph, self.environment)

    def test_other_consumers_and_named_delivery_contexts_do_not_join_versions(self):
        other = self.dep("stevedore", "7.0", "other-requirements.txt")
        (self.root / "other-requirements.txt").write_text("stevedore==7.0\n")
        self.rows.append(other)
        self.inventory["manifests"].append(
            dict(path=other["manifest"], sha256=hashlib.sha256(b"stevedore==7.0\n").hexdigest())
        )
        binding = self.binding()
        binding["closure_graphs"] = dict(
            schema_version=1,
            inventory_sha256="a" * 64,
            evidence={},
            graphs={"project/pyproject.toml#runtime": [["requirements.txt"], ["other-requirements.txt"]]},
        )
        parent = self.dep("parent", "1", "project/pyproject.toml")
        parent["usage"] = "runtime"
        graphs = target.closure_dependencies(parent, self.rows, binding)
        self.assertEqual(
            [[row["version"] for row in graph if row["name"] == "stevedore"] for graph in graphs], [["5.10.0"], ["7.0"]]
        )
        named = [{**row, "delivery_context": "already-observed-output"} for row in self.rows[:3]]
        self.assertEqual(target.closure_dependencies(named[0], named + [other], binding), [named])
