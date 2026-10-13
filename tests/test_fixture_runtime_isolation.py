from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import _support


class FixtureRuntimeIsolationTests(unittest.TestCase):
    def test_project_copy_never_enters_machine_runtime(self):
        with tempfile.TemporaryDirectory(prefix='getzilla-runtime-source-') as tmp:
            source = Path(tmp)
            runtime = source / '.getzilla/runtime'
            runtime.mkdir(parents=True)
            (runtime / 'host-state').write_text('must remain private', encoding='utf-8')
            (source / '.getzilla/source.py').write_text('# fixture source\n', encoding='utf-8')
            scandir = os.scandir

            def bounded_scandir(path):
                if not isinstance(path, int) and Path(path) == runtime:
                    raise AssertionError('project_copy entered machine runtime')
                return scandir(path)

            for minimal in (False, True):
                with self.subTest(minimal_runtime=minimal):
                    with patch.object(_support, 'PROJECT', source), patch('os.scandir', bounded_scandir):
                        with _support.project_copy(minimal_runtime=minimal) as copied:
                            self.assertEqual((copied / '.getzilla/source.py').read_text(), '# fixture source\n')
                            self.assertEqual(
                                sorted(p.name for p in (copied / '.getzilla/runtime').iterdir()),
                                ['.gitkeep'],
                            )
