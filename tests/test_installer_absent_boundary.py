"""A06: the installer's absent-target boundary, pinned before Zero-Git adoption builds on it.

`--plan` never writes to a target; `--materialize-new` only creates an absent target and never
replaces one that exists or appears; `--force` cannot bypass that.
"""
from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("install_into_boundary", ROOT / "scripts/install_into.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    """Bytes and permission bits of every file under root (atime is not part of the contract)."""
    result: dict[str, tuple[bytes, int]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            result[path.relative_to(root).as_posix()] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
    return result


class InstallerAbsentBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="getzilla-boundary-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def _existing_target(self) -> Path:
        target = self.base / "existing"
        target.mkdir()
        (target / "app.py").write_text("print('client')\n", encoding="utf-8")
        marker = target / ".target-owned-marker"
        marker.write_bytes(b"owned by the target\n")
        if os.name == "posix":
            marker.chmod(0o640)
        return target

    def test_existing_target_is_not_mutated(self) -> None:
        target = self._existing_target()
        before = _snapshot(target)
        names = sorted(path.name for path in target.iterdir())
        MODULE.plan_install(ROOT, target)
        self.assertEqual(_snapshot(target), before)
        self.assertEqual(sorted(path.name for path in target.iterdir()), names)

    def test_materialize_requires_absent_target(self) -> None:
        target = self._existing_target()
        before = _snapshot(target)
        with self.assertRaises(MODULE.UnsafeInstallTarget):
            MODULE.materialize_new(ROOT, target)
        self.assertEqual(_snapshot(target), before)

    def test_force_does_not_bypass_the_boundary(self) -> None:
        target = self._existing_target()
        before = _snapshot(target)
        with self.assertRaises(SystemExit):
            MODULE.install(ROOT, target, force=True)
        self.assertEqual(_snapshot(target), before)

    def test_plan_creates_no_managed_files(self) -> None:
        absent = self.base / "absent"
        plan = MODULE.plan_install(ROOT, absent)
        self.assertFalse(absent.exists())
        self.assertTrue(plan["entries"])
        target = self._existing_target()
        plan = MODULE.plan_install(ROOT, target)
        self.assertEqual(plan["target_state"], "directory")
        for entry in plan["entries"]:
            if entry["path"] not in {"app.py", ".target-owned-marker"}:
                self.assertFalse((target / entry["path"]).exists(), entry["path"])

    def test_new_target_race_does_not_replace(self) -> None:
        target = self.base / "racing"
        real_payload = MODULE.build_payload

        def payload_then_race(*args, **kwargs):
            entries = real_payload(*args, **kwargs)
            target.mkdir()
            (target / "foreign.txt").write_bytes(b"appeared during materialize\n")
            return entries

        with patch.object(MODULE, "build_payload", side_effect=payload_then_race):
            with self.assertRaises((MODULE.UnsafeInstallTarget, OSError)):
                MODULE.materialize_new(ROOT, target)
        self.assertEqual(sorted(path.name for path in target.iterdir()), ["foreign.txt"])
        self.assertEqual((target / "foreign.txt").read_bytes(), b"appeared during materialize\n")

    def test_materialize_new_creates_an_absent_target(self) -> None:
        target = self.base / "fresh"
        MODULE.materialize_new(ROOT, target)
        self.assertTrue((target / "AGENTS.md").is_file())


if __name__ == "__main__":
    unittest.main()
