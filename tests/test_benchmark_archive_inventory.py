"""Retired recipes must stay bound to the documented benchmark evidence."""
from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from getzilla import security_inventory as inventory


class BenchmarkArchiveTests(unittest.TestCase):
    def test_exact_archives_exclude_only_the_approved_recipes(self):
        recipes = inventory._RETIRED_RECIPES
        self.assertEqual({Path(name).parent.name + '/' + Path(name).name for name in recipes},
                         {'issue162/Dockerfile', 'issue162/Dockerfile.replay',
                          'issue170/Dockerfile', 'issue170/Dockerfile.tests'})
        with tempfile.TemporaryDirectory() as tmp, patch.dict(recipes):
            root = Path(tmp)
            for recipe, paths in list(recipes.items()):
                pins = {}
                for name in paths:
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = name.encode()
                    target.write_bytes(data)
                    pins[name] = (len(data), hashlib.sha256(data).hexdigest())
                recipes[recipe] = pins
            files = sorted({name for paths in recipes.values() for name in paths})
            for recipe in recipes:
                with self.subTest(recipe=recipe):
                    evidence = inventory._archival_document(root, recipe, files)
                    self.assertEqual(evidence['path'], recipe)
                    self.assertIn('SHA256SUMS.json', {Path(row['path']).name for row in evidence['provenance']})
            self.assertIsNone(inventory._archival_document(root, 'engineering/benchmarks/issue162/Dockerfile.new', files))
            for issue in ('issue162', 'issue170'):
                report = root / 'engineering/benchmarks' / issue / 'report.md'
                data = report.read_bytes()
                report.write_bytes(bytes([data[0] ^ 1]) + data[1:])
                for recipe in recipes:
                    if issue in recipe:
                        with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                            inventory._archival_document(root, recipe, files)
