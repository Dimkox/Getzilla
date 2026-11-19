"""Canonical pure frozen-profile validation (stdlib only).

Owner: trust-ci/lock_profile_validation.py. The byte-identical Core mirror is
regenerated with scripts/getzilla_sync_lock_validation.py --write and checked
with --check. Keep CLI, subprocess and profile regeneration in lock_profiles.py.
"""

from __future__ import annotations
import ast
import operator
import hashlib
import json
import re
import tomllib
from pathlib import Path

PROFILES = {"runtime": (False, False), "test": (True, False), "runner": (True, True)}
BINDING = "lock-profiles.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


_MARKER_NAMES = frozenset(
    {"sys_platform", "platform_system", "platform_python_implementation", "implementation_name", "python_version", "python_full_version"}
)
_VERSION_NAMES = frozenset({"python_version", "python_full_version"})
_MARKER_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


def _marker_tree(expression):
    if not expression:
        return None
    if not isinstance(expression, str) or len(expression) > 1024:
        raise ValueError("marker exceeds supported bound")
    try:
        tree = ast.parse(expression, mode="eval").body
    except (SyntaxError, ValueError):
        raise ValueError("unsupported marker grammar") from None
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise ValueError("marker exceeds node bound")

    def validate(node):
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            for value in node.values:
                validate(value)
            return
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or type(node.ops[0]) not in _MARKER_OPERATORS:
            raise ValueError("unsupported marker grammar")
        operands = [node.left, node.comparators[0]]
        if sum(isinstance(value, ast.Name) for value in operands) != 1:
            raise ValueError("marker must compare a known environment and a literal")
        for value in operands:
            if isinstance(value, ast.Name):
                if value.id not in _MARKER_NAMES:
                    raise ValueError("unsupported marker variable")
            elif not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                raise ValueError("unsupported marker literal")

    validate(tree)
    return tree


def _version(value):
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", value):
        raise ValueError("unsupported marker version")
    parts = tuple(int(part) for part in value.split("."))
    return parts + (0,) * (3 - len(parts))


def _marker_applies(expression, environment):
    tree = _marker_tree(expression)
    if tree is None:
        return True

    def evaluate(node):
        if isinstance(node, ast.BoolOp):
            values = [evaluate(value) for value in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        left, right = node.left, node.comparators[0]
        variable = left.id if isinstance(left, ast.Name) else right.id
        lhs = environment[left.id] if isinstance(left, ast.Name) else left.value
        rhs = environment[right.id] if isinstance(right, ast.Name) else right.value
        if variable in _VERSION_NAMES:
            lhs, rhs = _version(lhs), _version(rhs)
        return _MARKER_OPERATORS[type(node.ops[0])](lhs, rhs)

    return evaluate(tree)


def _marker_environments(lock, rows):
    # Numeric marker comparisons are constant between literal boundaries.
    # Cover each boundary, its adjacent patch/minor regions and all supported
    # platform/interpreter classes. Unsupported grammar fails closed.
    expressions = [marker for _, marker in rows.values() if marker]
    for package in lock["package"]:
        expressions += package.get("resolution-markers", [])
        edges = list(package.get("dependencies", []))
        for values in package.get("optional-dependencies", {}).values():
            edges += values
        for values in package.get("dev-dependencies", {}).values():
            edges += values
        expressions += [edge["marker"] for edge in edges if "marker" in edge]
    versions = {(3, 11, 0), (3, 11, 1), (4, 0, 0)}
    for expression in expressions:
        tree = _marker_tree(expression)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            names = [value.id for value in (node.left, node.comparators[0]) if isinstance(value, ast.Name)]
            if not any(name in _VERSION_NAMES for name in names):
                continue
            literal = next(value.value for value in (node.left, node.comparators[0]) if isinstance(value, ast.Constant))
            major, minor, patch = _version(literal)
            versions.update(
                {
                    (major, minor, patch),
                    (major, minor, patch + 1),
                    (major, minor + 1, 0),
                    (major, minor, max(0, patch - 1)),
                    (major, max(0, minor - 1), 0),
                    (major + 1, 0, 0),
                }
            )
    versions = {value for value in versions if value >= (3, 11, 0)}
    if len(versions) > 128:
        raise ValueError("marker environment partition exceeds bound")
    for version in sorted(versions):
        for platform in ("linux", "win32", "darwin"):
            for implementation, label in (("cpython", "CPython"), ("pypy", "PyPy")):
                yield {
                    "python_full_version": ".".join(map(str, version)),
                    "python_version": ".".join(map(str, version[:2])),
                    "sys_platform": platform,
                    "platform_system": {"linux": "Linux", "win32": "Windows", "darwin": "Darwin"}[platform],
                    "implementation_name": implementation,
                    "platform_python_implementation": label,
                }


def _closure(lock: dict, profile: str, environment: dict | None = None) -> set[tuple[str, str]]:
    root = next(package for package in lock["package"] if package["source"].get("editable") == ".")
    include_test, include_runner = PROFILES[profile]
    queue = list(root.get("dependencies", [])) + root["dev-dependencies"]["build"]
    if include_test:
        queue += root["optional-dependencies"]["test"]
    if include_runner:
        queue += root["dev-dependencies"]["runner"]
    packages = {}
    for package in lock["package"]:
        packages.setdefault(package["name"], []).append(package)
    selected = set()
    visited = set()
    while queue:
        edge = queue.pop()
        if environment is not None and not _marker_applies(edge.get("marker", ""), environment):
            continue
        matches = packages.get(edge["name"], [])
        if "version" in edge:
            matches = [package for package in matches if package["version"] == edge["version"]]
        if not matches:
            raise ValueError(f"missing locked dependency {edge['name']}")
        for package in matches:
            markers = package.get("resolution-markers", [])
            if (
                environment is not None
                and markers
                and not any(_marker_applies(marker, environment) for marker in markers)
            ):
                continue
            key = package["name"], package["version"]
            extras = tuple(sorted(edge.get("extra", [])))
            if (key, extras) in visited:
                continue
            visited.add((key, extras))
            selected.add(key)
            queue += package.get("dependencies", [])
            for extra in extras:
                queue += package.get("optional-dependencies", {}).get(extra, [])
    return selected


def _rows(path: Path) -> dict[tuple[str, str], set[str]]:
    rows = {}
    pending = ""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pending += " " + line.rstrip("\\").strip()
        if line.endswith("\\"):
            continue
        match = re.match(r"^\s*([A-Za-z0-9_.-]+)==([^\s;]+)", pending)
        hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", pending))
        if not match or not hashes:
            raise ValueError(f"{path.name}: non-pinned or unhashed requirement")
        key = match[1].lower().replace("_", "-"), match[2]
        if key in rows:
            raise ValueError(f"{path.name}: duplicate requirement")
        declaration = pending.split("--hash=", 1)[0].strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s;]+(?:\s*;\s*.+)?", declaration):
            raise ValueError("unsupported requirement declaration")
        marker = declaration.split(";", 1)[1].strip() if ";" in declaration else ""
        _marker_tree(marker)
        rows[key] = (hashes, marker)
        pending = ""
    if pending:
        raise ValueError(f"{path.name}: incomplete requirement")
    return rows


def _pins(requirements: list[str]) -> set[tuple[str, str]]:
    pins = set()
    for requirement in requirements:
        requirement, separator, marker = requirement.partition(';')
        if separator:
            _marker_tree(marker.strip())
        requirement = requirement.strip()
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^\s;]+)", requirement)
        if not match:
            raise ValueError("project roots and groups must remain exact pins")
        pins.add((match[1].lower().replace("_", "-"), match[2]))
    return pins


def check(root: Path) -> list[str]:
    errors = []
    try:
        lock = tomllib.loads((root / "uv.lock").read_text())
        project = tomllib.loads((root / "pyproject.toml").read_text())
        binding = json.loads((root / BINDING).read_text())
        if set(binding["profiles"]) != set(PROFILES) or binding["schema_version"] != 1:
            raise ValueError("unknown lock profile contract")
        locked_root = next(package for package in lock["package"] if package["source"].get("editable") == ".")
        root_specs = project["project"]["dependencies"] + project["project"]["optional-dependencies"]["test"]
        locked_specs = {
            (item["name"], item["specifier"].removeprefix("==")) for item in locked_root["metadata"]["requires-dist"]
        }
        if _pins(root_specs) != locked_specs:
            errors.append("project requirements differ from locked roots")
        for group in ("build", "runner"):
            declared = _pins(project["dependency-groups"][group])
            locked = {
                (item["name"], item["specifier"].removeprefix("=="))
                for item in locked_root["metadata"]["requires-dev"][group]
            }
            if declared != locked:
                errors.append(f"{group}: declared group differs from lock")
        if project["project"]["requires-python"] != lock["requires-python"]:
            errors.append("Python support differs from lock")
        if project["build-system"]["requires"] != project["dependency-groups"]["build"]:
            errors.append("build profile differs from build-system requirements")
        for name in ("uv.lock", "pyproject.toml"):
            if binding["inputs"][name] != digest(root / name):
                errors.append(f"{name}: stale binding")
        artifact_hashes = {}
        for package in lock["package"]:
            artifacts = list(package.get("wheels", []))
            if package.get("sdist"):
                artifacts.append(package["sdist"])
            artifact_hashes[package["name"], package["version"]] = {
                artifact["hash"].removeprefix("sha256:") for artifact in artifacts
            }
        for profile in PROFILES:
            path = root / f"requirements-{profile}.txt"
            if binding["profiles"][profile] != digest(path):
                errors.append(f"{profile}: stale exported profile")
            rows = _rows(path)
            if set(rows) != _closure(lock, profile):
                errors.append(f"{profile}: incomplete or expanded dependency graph")
            for environment in _marker_environments(lock, rows):
                actual = {key for key, (_, marker) in rows.items() if _marker_applies(marker, environment)}
                if actual != _closure(lock, profile, environment):
                    errors.append(f"{profile}: marker coverage differs for {environment}")
                    break
            for key, (hashes, _marker) in rows.items():
                if hashes != artifact_hashes.get(key):
                    errors.append(f"{profile}: artifact hashes differ for {key[0]}")
    except (OSError, ValueError, KeyError, StopIteration, TypeError, AttributeError) as exc:
        errors.append(f"lock profile validation failed: {exc}")
    return errors
