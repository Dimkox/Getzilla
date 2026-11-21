"""Build-time distribution of one operator-selected immutable accepted checker.

No key, service, evaluator, candidate module or scanner is used here. No args
means the existing private image. Supplying only part of a pin refuses the build.
"""

from __future__ import annotations
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def selection(repository, commit, tree):
    if not any((repository, commit, tree)):
        return None
    if (
        not isinstance(repository, str)
        or re.fullmatch("[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None
        or any(not isinstance(value, str) or re.fullmatch("[0-9a-f]{40}", value) is None for value in (commit, tree))
    ):
        raise ValueError("all-public-checker-pins-required")
    return repository, commit, tree


def checker_requirements(raw, expected_bandit):
    """Finite wheel-only, exact-hash profile; never URL/option/code requirements."""
    if type(raw) is not bytes or len(raw) > 65536:
        raise ValueError("checker-requirements-bound")
    text = raw.decode("ascii")
    logical = []
    current = ""
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        continuation = value.endswith(chr(92))
        current += value[:-1].strip() + " " if continuation else value
        if not continuation:
            logical.append(current.strip())
            current = ""
    if current or not 1 <= len(logical) <= 128:
        raise ValueError("checker-requirements-shape")
    selected = {}
    for line in logical:
        match = re.fullmatch(
            r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s+((?:--hash=sha256:[0-9a-f]{64}\s*)+)", line
        )
        if match is None:
            raise ValueError("checker-requirements-exact-hashes-required")
        name = match[1].lower().replace("_", "-")
        if name in selected:
            raise ValueError("checker-requirements-duplicate")
        selected[name] = match[2]
    if selected.get("bandit") != expected_bandit or "pyyaml" not in selected:
        raise ValueError("checker-runtime-tools-required")
    return selected


def install(repository, commit, tree):
    chosen = selection(repository, commit, tree)
    if chosen is None:
        return
    root = Path("/opt/getzilla-checker")
    if root.exists():
        raise ValueError("checker-distribution-already-exists")
    root.mkdir(mode=0o755)
    deadline = time.monotonic() + 20
    env = {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }
    prefix = [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
        "-C",
        str(root),
    ]

    def run(args):
        result = subprocess.run(
            prefix + args,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=max(0.01, deadline - time.monotonic()),
        )
        if len(result.stdout) > 65536 or time.monotonic() >= deadline:
            raise ValueError("checker-distribution-build-bound")
        return result.stdout.decode("ascii").strip()

    run(["init", "--quiet"])
    run(["remote", "add", "origin", "https://github.com/" + repository + ".git"])
    run(["fetch", "--quiet", "--no-tags", "--depth=1", "origin", commit])
    entries = run(["ls-tree", "-r", "--format=%(objectmode)", commit]).splitlines()
    if not entries or any(mode not in ("100644", "100755") for mode in entries):
        raise ValueError("checker-distribution-entry-unsupported")
    run(["-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit])
    if run(["rev-parse", "HEAD", "HEAD^{tree}"]).splitlines() != [commit, tree] or run(
        ["status", "--porcelain=v1", "--untracked-files=all"]
    ):
        raise ValueError("checker-distribution-identity-mismatch")
    if not (root / ".getzilla/getzilla/security_cli.py").is_file():
        raise ValueError("checker-distribution-incomplete")
    # Keep source and Git metadata root-owned, readable and immutable to UID10001.
    # security_cli's completed Git observations use the system scope; the engine
    # guard separately supplies exact per-command safe.directory. Never trust '*'.
    subprocess.run(
        ["git", "config", "--system", "--add", "safe.directory", str(root)],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=max(0.01, deadline - time.monotonic()),
    )
    # All packages come from an explicitly supplied hash-locked wheelhouse.
    # The base private image is unchanged; no live index/sdist is a fallback.
    inputs = Path("/opt/public-checker-inputs")
    lock = inputs / "checker-requirements.lock"
    quality = (root / ".getzilla/config/python-quality-requirements.txt").read_text()
    versions = re.findall(r"^bandit==([A-Za-z0-9.!+_-]+)$", quality, re.M)
    if len(versions) != 1:
        raise ValueError("accepted-checker-bandit-pin-unavailable")
    selected = checker_requirements(lock.read_bytes(), versions[0])
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--require-hashes",
            "--no-cache-dir",
            "--find-links=" + str(inputs / "wheels"),
            "-r",
            str(lock),
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        check=True,
        timeout=20,
    )
    import importlib.metadata

    for name in ("bandit", "pyyaml"):
        if importlib.metadata.version(name) != selected[name]:
            raise ValueError("checker-runtime-version-mismatch")
    import bandit  # noqa: F401 - explicit dependency availability, no scan
    import yaml  # noqa: F401 - explicit dependency availability, no parsing

    # Dependency availability is checked during the explicit image build, not
    # by running inventory/scanners. Origin must be the selected distribution.
    from adaptive_trust_ci.public_producer import import_core

    core = import_core(root)
    if core.report.TRUSTED_ROOT != root or core.policy_root != root:
        raise ValueError("checker-installed-root-mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "commit", "tree"):
        parser.add_argument("--" + name, default="")
    args = parser.parse_args()
    install(args.repository, args.commit, args.tree)
