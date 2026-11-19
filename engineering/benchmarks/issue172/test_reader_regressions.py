"""Supplemental issue 172 controls for the frozen issue 162 research reader.

Run directly with Python. These tests do not qualify a product read boundary.
"""

import hashlib
import importlib.util
import pathlib
import tempfile
import unittest


READER_PATH = pathlib.Path(__file__).resolve().parents[1] / "issue162/trusted_read.py"
SPEC = importlib.util.spec_from_file_location("issue162_research_reader", READER_PATH)
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ReaderRegressionControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.data = b"first\nsecond\n"
        (self.root / "real").mkdir()
        (self.root / "real/a.py").write_bytes(self.data)
        self.hit = {
            "tenant": "t1",
            "repository": "r1",
            "path": "real/a.py",
            "file_sha256": digest(self.data),
            "start": 1,
            "end": 1,
            "sha256": digest(b"first\n"),
        }

    def read(self, hit=None, allowed=None):
        return READER.read_hit(
            self.root,
            self.hit if hit is None else hit,
            "t1",
            "r1",
            {"real/a.py"} if allowed is None else allowed,
        )

    def test_whole_file_freshness_outside_selected_range(self):
        self.assertEqual(self.read(), b"first\n")
        (self.root / "real/a.py").write_bytes(b"first\nCHANGED\n")
        with self.assertRaisesRegex(ValueError, "^stale$"):
            self.read()

    def test_allowlist_rejects_existing_readable_file(self):
        (self.root / "excluded.py").write_bytes(self.data)
        hit = {**self.hit, "path": "excluded.py"}
        self.assertEqual(self.read(hit, {"excluded.py"}), b"first\n")
        with self.assertRaisesRegex(ValueError, "^path$"):
            self.read(hit, {"real/a.py"})

    def test_parent_symlink_with_regular_final_component(self):
        self.assertEqual(self.read(), b"first\n")
        (self.root / "link").symlink_to("real", target_is_directory=True)
        hit = {**self.hit, "path": "link/a.py"}
        self.assertFalse((self.root / hit["path"]).is_symlink())
        self.assertTrue((self.root / hit["path"]).resolve().is_relative_to(self.root))
        with self.assertRaisesRegex(ValueError, "^symlink$"):
            self.read(hit, {"link/a.py"})


if __name__ == "__main__":
    unittest.main()
