"""Historical rendering and current lab tools have separate source boundaries."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from factory.tests._showcase_custody import validate_showcase


ROOT = Path(__file__).resolve().parents[2]
PREFIX = 'side-projects/seo-landing-showcase/'
MANIFEST = ROOT / 'side-projects/seo-landing-showcase.source.json'


class ShowcaseCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='showcase-custody-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = json.loads(MANIFEST.read_text())
        self.tracked = sorted(self.manifest['current_files'])
        for name in self.tracked:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)

    def test_current_tracked_boundary_ignores_untracked_cache_and_output(self):
        cache = self.root / PREFIX / '__pycache__/cleanup-owned-directory.cpython-311.pyc'
        cache.parent.mkdir()
        cache.write_bytes(b'incidental interpreter output')
        (self.root / PREFIX / 'browser-contract.json').write_text('{}')
        validate_showcase(self.root, self.manifest, self.tracked)

    def test_unknown_tracked_source_and_tool_or_render_tampering_fail(self):
        unknown = PREFIX + 'unexpected.py'
        (self.root / unknown).write_text('pass\n')
        with self.assertRaises(ValueError):
            validate_showcase(self.root, self.manifest, self.tracked + [unknown])
        for name in ('index.html', 'browser-contract.mjs', 'cleanup-owned-directory.py', 'README.md'):
            path = self.root / PREFIX / name
            original = path.read_bytes()
            path.write_bytes(original + b'\nchanged')
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_showcase(self.root, self.manifest, self.tracked)
            path.write_bytes(original)

    def test_historical_custody_and_current_manifest_are_both_checked(self):
        self.manifest['historical']['files'][PREFIX + 'README.md'] = '0' * 64
        with self.assertRaises(ValueError):
            validate_showcase(self.root, self.manifest, self.tracked)
        self.manifest = json.loads(MANIFEST.read_text())
        self.manifest['current_files'].pop(PREFIX + 'cleanup-owned-directory.py')
        with self.assertRaises(ValueError):
            validate_showcase(self.root, self.manifest, self.tracked)

    def test_repository_manifest_matches_actual_tracked_source(self):
        tracked = subprocess.check_output(['git', 'ls-files', '--', PREFIX], cwd=ROOT, text=True).splitlines()
        validate_showcase(ROOT, self.manifest, tracked)
