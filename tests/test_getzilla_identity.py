"""Guard the Getzilla rename: the predecessor product identity must not creep back.

Getzilla was renamed from adaptive-grok-build-pro. Three kinds of names stay on
purpose and are not checked here: the Grok Build CLI contract (.grok/, the grok
binary), Grok as a model provider (GROK_API_KEY_ENV, grok-4, ...), and live
infrastructure identities (adaptive-trust-ci*, adaptive-l5*, and the deployed
/opt/adaptive-grok-build-pro Trust CI checkout). Historical, hash-bound records
are kept verbatim and listed in HISTORICAL_PREFIXES / HISTORICAL_FILES.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

HISTORICAL_PREFIXES = (
    "engineering/changes/",
    "docs/superpowers/",
    ".superpowers/",
    "tests/fixtures/",
    "factory/tests/fixtures/",
    "trust-ci/tests/fixtures/",
)
HISTORICAL_FILES = frozenset(
    {
        "CHANGELOG.md",
        "mistakes.md",
        "decisions.md",
        "DARK_FACTORY_ROADMAP.md",
        "FACTORY_UNIFIED_UPGRADE_TZ_v1.5_FINAL.md",
        "FACTORY_TZ_v1.5_ADDENDUM_BB-01.md",
        "PROJECT_STATE.json",
    }
)
# Files that must name the legacy layout to migrate or test it.
LEGACY_AWARE_FILES = frozenset(
    {
        "scripts/install_into.py",
        "tests/test_installer.py",
        "tests/test_getzilla_identity.py",
    }
)
# Allowed references to the predecessor: links to its PRs, releases and pinned
# trees, its already-published release artifacts, and the deployed Trust CI
# checkout path on the server.
HISTORICAL_LINK = re.compile(
    r"github\.com/Dimkox/adaptive-grok-build-pro/"
    r"(?:pull|issues|releases|commit|commits|compare|tree|blob|actions|checks|runs)\b"
    r"|\badaptive-grok-build-pro-v\d"
    r"|/opt/adaptive-grok-build-pro\b"
)
FORBIDDEN = re.compile(
    r"(?<!/opt/)adaptive-grok-build-pro"
    r"|adaptive_grok"
    r"|\.grok-stack"
    r"|Adaptive Grok"
    r"|adaptive_factory"
    r"|adaptive_delivery"
    r"|scripts/grok_[a-z_*]+\.py"
)
FORBIDDEN_PATH = re.compile(r"(^|/)(\.grok-stack|adaptive_grok|adaptive_factory|adaptive_delivery)(/|$)|^scripts/grok_[a-z_]+\.py$")


def _tracked_files() -> list[str]:
    try:
        output = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return sorted(
            path.relative_to(ROOT).as_posix()
            for path in ROOT.rglob("*")
            if path.is_file() and ".git" not in path.relative_to(ROOT).parts
        )
    return sorted(item for item in output.decode("utf-8").split("\0") if item)


def _checked(relative: str) -> bool:
    return not (
        relative in HISTORICAL_FILES
        or relative in LEGACY_AWARE_FILES
        or relative.startswith(HISTORICAL_PREFIXES)
    )


class GetzillaIdentityTests(unittest.TestCase):
    def test_no_predecessor_product_paths(self) -> None:
        offenders = [
            relative
            for relative in _tracked_files()
            if _checked(relative) and FORBIDDEN_PATH.search(relative)
        ]
        self.assertEqual(offenders, [])

    def test_no_predecessor_product_names_in_live_files(self) -> None:
        offenders: list[str] = []
        for relative in _tracked_files():
            if not _checked(relative):
                continue
            path = ROOT / relative
            if path.is_symlink() or not path.is_file():
                continue
            raw = path.read_bytes()
            if b"\0" in raw[:8192]:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                match = FORBIDDEN.search(HISTORICAL_LINK.sub("", line))
                if match:
                    offenders.append(f"{relative}:{number}: {match.group(0)}")
        self.assertEqual(offenders, [], "predecessor identity found:\n" + "\n".join(offenders[:50]))

    def test_grok_build_cli_contract_is_kept(self) -> None:
        for relative in (".grok/config.toml", ".grok/hooks.json"):
            self.assertTrue((ROOT / relative).is_file(), relative)
        self.assertTrue((ROOT / ".getzilla/getzilla/__init__.py").is_file())


if __name__ == "__main__":
    unittest.main()
