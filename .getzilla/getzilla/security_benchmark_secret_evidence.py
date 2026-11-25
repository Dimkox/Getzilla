"""Exact benchmark 170 archive reviews bound to the scanner pattern set."""

import hashlib
import json


PATTERNS_SHA256 = "efd7dd5cddf7faf943dabded8686834c20c76a20d349beadc87f0d450f2d19a1"
REVIEWED = {
    "engineering/benchmarks/issue170/upstream-source.tar.gz": (
        "20fb49f2c527aa592bc142f09771fa2a2ddcf621ba3554414d2059cca48347ae",
        "All 72 TAR members reviewed; 60 regular files scanned including the two PNG byte streams.",
    ),
    "engineering/benchmarks/issue170/artifacts/source-graph.sqlite": (
        "14457261a99d1dae78e6b776f25f37bd4d20b7c3b72123f55a0e8e7b7edb08b6",
        "SQLite integrity and complete logical rows in meta, generations and active reviewed; physical bytes scanned.",
    ),
    "engineering/benchmarks/issue170/artifacts/vectors.npy": (
        "57caf2109726cf69e3a70dfbcd58baa4a6d69ef534e1bb985eba2af4c20d9a7a",
        "Validated exact NPY v1 header and 116 x 384 float32 payload; raw bytes scanned.",
    ),
    "engineering/benchmarks/issue170/artifacts/initial-vectors.npy": (
        "57caf2109726cf69e3a70dfbcd58baa4a6d69ef534e1bb985eba2af4c20d9a7a",
        "Validated exact NPY v1 header and 116 x 384 float32 payload; raw bytes scanned.",
    ),
    "engineering/benchmarks/issue170/artifacts/candidate.bundle": (
        "a18f0c118f3fb1c35cb40d22e36de3869b7368cd5099653d0b5c9a3bf7b8fa8c",
        "Strict Git fsck and all 685 decoded Git objects reviewed, including 597 blobs; two PNG byte streams scanned.",
    ),
}


def reviewed_archive(path, sha256, patterns):
    record = REVIEWED.get(path)
    if record is None or record[0] != sha256:
        return None
    profile = sorted((key, pattern.pattern, pattern.flags) for key, pattern in patterns.items())
    encoded = json.dumps(profile, separators=(",", ":")).encode()
    return record[1] if hashlib.sha256(encoded).hexdigest() == PATTERNS_SHA256 else None
