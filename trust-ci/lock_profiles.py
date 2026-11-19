"""Check frozen pip profiles using stdlib; regenerate only with the pinned uv tool."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path
from lock_profile_validation import BINDING, PROFILES, check, digest


def refresh(root: Path) -> None:
    # Frozen export never resolves or updates uv.lock. uv's own version contract
    # comes from pyproject.toml. --locked check verifies the manifest first.
    subprocess.run(["uv", "lock", "--project", str(root), "--check", "--offline", "--no-python-downloads"], check=True)
    for profile, (include_test, include_runner) in PROFILES.items():
        command = [
            "uv",
            "export",
            "--project",
            str(root),
            "--frozen",
            "--offline",
            "--no-default-groups",
            "--group",
            "build",
            "--no-emit-project",
            "--no-header",
            "--no-annotate",
            "-o",
            str(root / f"requirements-{profile}.txt"),
        ]
        if include_test:
            command += ["--extra", "test"]
        if include_runner:
            command += ["--group", "runner"]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
    binding = {
        "schema_version": 1,
        "inputs": {name: digest(root / name) for name in ("uv.lock", "pyproject.toml")},
        "profiles": {name: digest(root / f"requirements-{name}.txt") for name in PROFILES},
    }
    (root / BINDING).write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n")
    errors = check(root)
    if errors:
        raise ValueError("; ".join(errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    if args.refresh:
        refresh(directory)
    failures = check(directory)
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(bool(failures))
