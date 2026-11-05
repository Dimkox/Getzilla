#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))

from getzilla.workflow_artifacts import (  # noqa: E402
    WorkflowArtifactError,
    adapt_sources,
    canonical_json,
    cas_write,
    compile_task_graph,
    converge,
    effective_task_statuses,
    load_source_manifest,
    load_runtime_authority,
    projection_bytes,
    validate_stored_workflow,
    workflow_paths,
)
from getzilla.receipts import validate_evidence  # noqa: E402
from getzilla.util import find_root, tree_fingerprint  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compile untrusted workflow framework artifacts into advisory native projections."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("import", "compile", "converge", "validate"):
        command = sub.add_parser(name)
        command.add_argument("--change-id", required=True)
        if name != "validate":
            command.add_argument("--write", action="store_true")
            command.add_argument("--expected-digest")
    export = sub.add_parser("export")
    export.add_argument("framework", choices=("spec-kit", "bmad", "superpowers"))
    export.add_argument("--change-id", required=True)
    export.add_argument("--write", action="store_true")
    export.add_argument("--expected-digest")
    intake = sub.add_parser('intake')
    intake.add_argument('action', choices=('inspect','assess','apply','recover','trace'))
    intake.add_argument('--request', help='Bounded repository-relative native request JSON')
    intake.add_argument('--expected-cut', help='Exact cut digest; none only for initial publication')
    intake.add_argument('--expected-state', help='Exact raw state digest; zero SHA for initial publication')
    intake.add_argument('--publication-id')
    intake.add_argument('--criterion-id')
    return parser


def _write_requested(
    root: Path, change_id: str, target: str, payload: bytes, write: bool, expected: str | None
) -> str | None:
    if not write:
        return None
    if expected is None:
        raise WorkflowArtifactError("--write requires --expected-digest", code="cas")
    return cas_write(root, change_id, target, payload, expected)


def main() -> int:
    args = _parser().parse_args()
    try:
        root = find_root(ROOT)
        if args.command == 'intake':
            from getzilla.intake_publication import prepare_intake, recover_intake, read_intake_cut, trace_requirement, _request
            from getzilla.requirements_intake import IntakeError, project_requirements
            from getzilla.intake_readiness import assess_readiness
            from getzilla.package_status import read_package_file
            from getzilla.workflow_artifacts import _strict_json
            if args.action == 'inspect':
                result = read_intake_cut(root)
            elif args.action == 'trace':
                result = trace_requirement(root,args.criterion_id)
            elif args.action == 'recover':
                result = recover_intake(root,args.publication_id)
            else:
                if args.request is None:
                    raise IntakeError('request_required')
                request = _strict_json(read_package_file(root,args.request,1_000_000),limit=1_000_000)
                request = _request(request)
                if args.action == 'assess':
                    from getzilla.state import require_route_owner
                    require_route_owner(root)
                    projection = project_requirements(request['snapshot'])
                    result = assess_readiness(request['snapshot']['spec'],projection,request['snapshot']['policy'])
                else:
                    if args.expected_cut is None or args.expected_state is None:
                        raise IntakeError('expected_bindings_required')
                    result = prepare_intake(root,request,None if args.expected_cut=='none' else args.expected_cut,args.expected_state)
            print(json.dumps(result,sort_keys=True,indent=2))
            return 0
        route = load_runtime_authority(root, "route")
        active = load_runtime_authority(root, "change")
        from getzilla.workflow_storage import change_directory, valid_package_path
        if active.get("change_id") != args.change_id or not valid_package_path(active.get("path"), args.change_id):
            raise WorkflowArtifactError("requested change is not the active change", code="change")
        if getattr(args, "write", False):
            from getzilla.state import set_active_change
            package = change_directory(root, args.change_id, writable=True)
            set_active_change(root, {"change_id": args.change_id, "path": package.relative_to(root).as_posix()})
        paths = workflow_paths(root, args.change_id)
        bundle = load_source_manifest(root, paths["manifest"])
        if args.command == "validate":
            current_fingerprint = tree_fingerprint(root)
            receipt_errors = validate_evidence(root, route, current_fingerprint=current_fingerprint)
            result, report = validate_stored_workflow(
                root,
                args.change_id,
                route,
                current_fingerprint=current_fingerprint,
                receipt_errors=receipt_errors,
            )
            print(json.dumps({**result, "report": report}, sort_keys=True, indent=2))
            return 0 if result["ok"] else 1
        candidates = adapt_sources(bundle)
        if args.command == "import":
            payload = {
                "schema_version": 1,
                "authority": False,
                "manifest_digest": bundle.manifest_digest,
                "candidates": candidates,
            }
            digest = _write_requested(
                root,
                args.change_id,
                "projections/import.json",
                canonical_json(payload),
                args.write,
                args.expected_digest,
            )
            result = {"status": "imported", "written_digest": digest, **payload}
        elif args.command == "compile":
            graph = compile_task_graph(root, args.change_id, bundle, route)
            digest = _write_requested(
                root, args.change_id, "task-graph.json", canonical_json(graph), args.write, args.expected_digest
            )
            result = {"status": "compiled", "written_digest": digest, "graph": graph}
        elif args.command == "converge":
            graph = compile_task_graph(root, args.change_id, bundle, route)
            current_fingerprint = tree_fingerprint(root)
            receipt_errors = validate_evidence(root, route, current_fingerprint=current_fingerprint)
            report = converge(
                root,
                args.change_id,
                bundle,
                graph,
                route,
                current_fingerprint=current_fingerprint,
                receipt_errors=receipt_errors,
            )
            digest = _write_requested(
                root,
                args.change_id,
                "convergence-report.json",
                canonical_json(report),
                args.write,
                args.expected_digest,
            )
            result = {
                "status": report["status"],
                "written_digest": digest,
                "report": report,
                "effective_tasks": effective_task_statuses(graph, receipt_errors),
            }
        else:
            graph = compile_task_graph(root, args.change_id, bundle, route)
            payload = {
                "schema_version": 1,
                "framework": args.framework,
                "authority": False,
                "sources": [item for item in candidates if item["source_type"] == args.framework],
                "task_graph": graph,
            }
            data = projection_bytes(args.framework, payload)
            digest = _write_requested(
                root, args.change_id, f"exports/{args.framework}.md", data, args.write, args.expected_digest
            )
            result = {"status": "exported", "framework": args.framework, "written_digest": digest}
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result.get("status") != "block" else 1
    except (WorkflowArtifactError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            json.dumps(
                {"ok": False, "code": getattr(exc, "code", "error"), "error": str(exc)}, sort_keys=True, indent=2
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
