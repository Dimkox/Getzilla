"""Offline runtime inventory excludes development-only lock entries."""

import json
from pathlib import Path
import tempfile
import unittest

from factory.tests.test_offline_release_builder import load, setup


class OfflineRuntimeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="factory-runtime-inventory-")
        self.addCleanup(self.temp.cleanup)
        self.lock = Path(self.temp.name) / "uv.lock"
        self.builder = load("build_offline_release")

    def write_lock(self, *, edge=None, extra_edge=None, duplicate=False):
        edge = edge or '{ name = "runtime", extra = ["binary"] }'
        extra_edge = extra_edge or '{ name = "binary", marker = "implementation_name != \'pypy\'" }'
        parts = [
            'version = 1\nrevision = 5\nrequires-python = ">=3.11"\n',
            '[[package]]\nname = "getzilla-factory"\nversion = "0.1.0"\n'
            f'dependencies = [{edge}]\n'
            '[package.dev-dependencies]\ndev = [{ name = "dev-only" }]\n',
        ]
        for name in ("runtime", "binary", "dev-only", "orphan", *(('runtime',) if duplicate else ())):
            parts.append(f'[[package]]\nname = {json.dumps(name)}\nversion = "1.0.0"\n'
                         f'wheels = [{{ url = "https://example.invalid/{name}-1.0.0-py3-none-any.whl", '
                         f'hash = "sha256:{"a" * 64}" }}]\n')
            if name == "runtime":
                parts.append('[package.optional-dependencies]\nbinary = [' + extra_edge + ']\n')
        self.lock.write_text("\n".join(parts), encoding="utf-8")

    def test_only_runtime_and_requested_extra_are_published(self):
        self.write_lock()
        inventory = self.builder.derive_inventory(self.lock)
        self.assertEqual([item["name"] for item in inventory["wheels"]], ["binary", "runtime"])

    def test_unrequested_extra_and_inactive_platform_are_absent(self):
        for kwargs in ({"edge": '{ name = "runtime" }'},
                       {"extra_edge": '{ name = "binary", marker = "sys_platform == \'win32\'" }'}):
            with self.subTest(kwargs=kwargs):
                self.write_lock(**kwargs)
                inventory = self.builder.derive_inventory(self.lock)
                self.assertEqual([item["name"] for item in inventory["wheels"]], ["runtime"])

    def test_ambiguous_missing_or_unsupported_runtime_edges_refuse(self):
        cases = [
            {"duplicate": True},
            {"edge": '{ name = "missing" }'},
            {"edge": '{ name = "runtime", version = "9.0.0" }'},
            {"edge": '{ name = "runtime", extra = ["missing"] }'},
            {"edge": '{ name = "runtime", extra = "binary" }'},
            {"edge": '{ name = "runtime", marker = "python_full_version < \'3.12.7\'" }'},
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.write_lock(**kwargs)
                with self.assertRaises(setup.InstallerError) as error:
                    self.builder.derive_inventory(self.lock)
                self.assertEqual(error.exception.code, "LOCK_PROFILE_UNRESOLVED")

    def test_current_runtime_wheels_are_unchanged_by_test_group(self):
        repository = Path(__file__).resolve().parents[2]
        expected = json.loads((repository / "factory/runtime/runtime-wheels-linux-x86_64-cpython312.json")
                              .read_text(encoding="utf-8"))["wheels"]
        actual = self.builder.derive_inventory(repository / "factory/uv.lock")["wheels"]
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual), 20)

    def test_incompatible_or_unresolved_python_contract_refuses(self):
        for requirement in (">=3.13", "<3.12", ">=3.12.7", ">=3.11,<4"):
            with self.subTest(requirement=requirement):
                self.write_lock()
                value = self.lock.read_text(encoding="utf-8")
                self.lock.write_text(value.replace('requires-python = ">=3.11"',
                                                    'requires-python = ' + json.dumps(requirement)),
                                     encoding="utf-8")
                with self.assertRaises(setup.InstallerError) as error:
                    self.builder.derive_inventory(self.lock)
                self.assertEqual(error.exception.code, "LOCK_PROFILE_UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
