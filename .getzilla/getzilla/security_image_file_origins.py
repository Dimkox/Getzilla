"""Bound software ownership for the source copies and pinned runner downloads."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .security_artifacts import read_file

# These inventories were independently matched path-by-path against the pinned
# Node TAR and the CRC-validated Nuitka member table of the pinned OpenGrep ELF.
# An extra or changed installed file rejects the entire corresponding match.
_NODE = ("node-v24.22.0-linux-x64.tar.xz", "cc2f601cee82d9a5a233302fe307abc600727035fd7d2c3a3571755989e95008",
         "opt/node/", 1228, "99ef7081113b37fc7e9ff5fcb0b7ce5f26d0b9a9cd13c7c88e32bd632799f59d")
_OPENGREP = ("opengrep_manylinux_x86", "d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4",
             "home/ci/.cache/opengrep/v1.30.1/", 78, "88d40120bdb0bc3a87b91bc8b9ce55427bd082af2b46f6f4ee56a75a7f4c158e")


def archive_origins(software):
    result = []
    for name, source_hash, prefix, count, expected in (_NODE, _OPENGREP):
        rows = sorted((r["path"], r["bytes"], r["sha256"]) for r in software if r["path"].startswith(prefix))
        if len(rows) != count:
            continue
        encoded = json.dumps(rows, separators=(",", ":")).encode()
        if hashlib.sha256(encoded).hexdigest() == expected:
            result.append((name, {"source_archive_sha256": source_hash, "installed_members_sha256": expected},
                           [r[0] for r in rows]))
    if any(r["path"] == "usr/local/bin/opengrep" and r["sha256"] == _OPENGREP[1] for r in software):
        result.append(("opengrep-executable", {"source_archive_sha256": _OPENGREP[1]}, ["usr/local/bin/opengrep"]))
    return result


def project_origins(software, root):
    result = []
    for row in software:
        path = row["path"]
        if path == "usr/local/lib/install_public_checker.py":
            source = "trust-ci/scripts/install_public_checker.py"
        elif path.startswith("opt/adaptive-trust-ci/build/lib/"):
            source = "trust-ci/src/" + path.removeprefix("opt/adaptive-trust-ci/build/lib/")
        elif path.startswith("opt/adaptive-trust-ci/"):
            source = "trust-ci/" + path.removeprefix("opt/adaptive-trust-ci/")
        else:
            continue
        try:
            data = read_file(Path(root), source, 2 * 1024 * 1024)
        except (OSError, ValueError):
            continue
        if len(data) == row["bytes"] and hashlib.sha256(data).hexdigest() == row["sha256"]:
            result.append({"source": source, "path": path, "sha256": row["sha256"]})
    return result
