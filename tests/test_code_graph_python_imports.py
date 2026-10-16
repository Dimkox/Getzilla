"""G03: static import resolution with internal/external/unresolved classification."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.code_graph.models import GraphConfig  # noqa: E402
from tests.code_graph_support import generation  # noqa: E402


def edges(files, config=None, source=None):
    return {(edge.source_file, edge.module): edge for edge in generation(files, config).imports
            if source is None or edge.source_file == source}


PACKAGE = {
    'pkg/__init__.py': '',
    'pkg/core.py': 'def run():\n    pass\n',
    'pkg/sub/__init__.py': '',
    'pkg/sub/leaf.py': 'from .. import core\nfrom ..core import run as go\nfrom . import sibling\n',
    'pkg/sub/sibling.py': '',
    'app.py': 'import pkg.core\nimport pkg.core as c\nfrom pkg import core\nimport json\n',
}


class PythonImportTests(unittest.TestCase):
    def test_absolute_and_relative_imports_resolve(self) -> None:
        found = edges(PACKAGE)
        self.assertEqual(found[('app.py', 'pkg.core')].target_file, 'pkg/core.py')
        self.assertEqual(found[('pkg/sub/leaf.py', 'pkg.core')].target_file, 'pkg/core.py')
        self.assertEqual(found[('pkg/sub/leaf.py', 'pkg.sub.sibling')].target_file, 'pkg/sub/sibling.py')
        self.assertEqual(found[('app.py', 'pkg.core')].resolution, 'internal')

    def test_alias_preserves_target(self) -> None:
        gen = generation({**PACKAGE, 'use.py': 'import pkg.core as c\nfrom pkg.core import run as go\nc.run()\ngo()\n'})
        calls = {edge.expression: edge for edge in gen.calls if edge.caller == 'file:use.py'}
        self.assertEqual(calls['c.run'].targets, ('sym:pkg/core.py::run',))
        self.assertEqual(calls['go'].targets, ('sym:pkg/core.py::run',))

    def test_namespace_package_profile(self) -> None:
        files = {'ns/mod.py': 'def f():\n    pass\n', 'main.py': 'import ns.mod\n'}
        disabled = edges(files)[('main.py', 'ns.mod')]
        self.assertEqual((disabled.resolution, disabled.reason), ('unresolved', 'NAMESPACE_PACKAGE_PROFILE_DISABLED'))
        enabled = edges(files, GraphConfig(namespace_packages=True))[('main.py', 'ns.mod')]
        self.assertEqual((enabled.resolution, enabled.target_file), ('internal', 'ns/mod.py'))

    def test_ambiguous_module_is_unresolved(self) -> None:
        same = edges({'dup.py': '', 'dup/__init__.py': '', 'main.py': 'import dup\n'})[('main.py', 'dup')]
        self.assertEqual((same.resolution, same.reason, same.target_file), ('unresolved', 'AMBIGUOUS_MODULE', None))
        roots = edges({'src/x.py': '', 'lib/x.py': '', 'src/main.py': 'import x\n'},
                      GraphConfig(package_roots=('src', 'lib')))[('src/main.py', 'x')]
        self.assertEqual(roots.reason, 'AMBIGUOUS_MODULE')

    def test_import_cycle_terminates(self) -> None:
        found = edges({'a.py': 'import b\n', 'b.py': 'import a\n'})
        self.assertEqual(found[('a.py', 'b')].target_file, 'b.py')
        self.assertEqual(found[('b.py', 'a')].target_file, 'a.py')

    def test_external_module_not_invented_as_local_file(self) -> None:
        found = edges({'requests_helper.py': '', 'main.py': 'import requests\nimport os.path\n'})
        for module in ('requests', 'os.path'):
            edge = found[('main.py', module)]
            self.assertEqual((edge.resolution, edge.target_file), ('external', None))
        missing = edges({'pkg/__init__.py': '', 'main.py': 'import pkg.missing\n'})[('main.py', 'pkg.missing')]
        self.assertEqual((missing.resolution, missing.reason), ('unresolved', 'INTERNAL_MODULE_NOT_FOUND'))
        outside = edges({'lib/tool.py': '', 'main.py': 'import tool\n'}, GraphConfig(package_roots=('src',)))
        self.assertEqual(outside[('main.py', 'tool')].reason, 'MODULE_NAME_IN_SCOPE_OUTSIDE_PACKAGE_ROOTS')

    def test_dynamic_import_is_coverage_gap(self) -> None:
        gen = generation({'main.py': 'import importlib\nmod = importlib.import_module(name)\n__import__("x")\n'})
        self.assertEqual(gen.coverage.dynamic_gaps, 2)
        self.assertEqual({edge.reason for edge in gen.calls if edge.expression != 'name'}, {'REFLECTION'})

    def test_relative_import_beyond_top_unresolved(self) -> None:
        edge = edges({'top.py': 'from .. import x\n'})
        self.assertEqual(next(iter(edge.values())).reason, 'RELATIVE_IMPORT_OUTSIDE_PACKAGE')


if __name__ == '__main__':
    unittest.main()
