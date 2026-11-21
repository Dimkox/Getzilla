"""Build a source manifest and an isolated native change for workflow tests."""
import json
from pathlib import Path


def write_manifest(root: Path, sources: list[dict[str, str]]) -> Path:
    path = root / ".getzilla/runtime/changes/change/workflow/manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"schema_version": 1, "sources": sources}), encoding="utf-8")
    return path


def workflow_root(artifacts, tmp: str, docs: list[tuple[str, str, str, str]]) -> tuple[Path, object]:
    root = Path(tmp)
    entries = []
    for source_type, role, path, content in docs:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        entries.append({"source_type": source_type, "source_version": "1", "role": role, "path": path})
    bundle = artifacts.load_source_manifest(root, write_manifest(root, entries))
    (root / ".getzilla/runtime/changes/change/change-spec.yaml").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "change_id": "change",
                "objective": {"id": "OBJ-001", "statement": "native goal"},
                "acceptance_criteria": [{"id": "AC-001", "statement": "safe import"}],
                "invariants": [{"id": "INV-001", "statement": "native authority"}],
                "forbidden_outcomes": [{"id": "FORBID-001", "statement": "no elevation"}],
            }
        ),
        encoding="utf-8",
    )
    return root, bundle
