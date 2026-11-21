from __future__ import annotations

from . import verification_journal as diagnostics

from .verification_failure_excerpt import (
    _pytest_summary_identity as _pytest_summary_identity,
    _pytest_terminal_counts as _pytest_terminal_counts,
    _core_output_excerpt as _core_output_excerpt,
)
from .verification_progress_evidence import (
    _pytest_source_metadata as _pytest_source_metadata,
    _trusted_pytest_metadata as _trusted_pytest_metadata,
    _trusted_progress_metadata as _trusted_progress_metadata,
    _progress_failure_rows as _progress_failure_rows,
    _failure_progress_details as _failure_progress_details,
    _core_progress_details as _core_progress_details,
)

import ast
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import time as time
from datetime import datetime, timezone
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

from .agent_evals import required_suites
from .bitrix_checks import check_bitrix
from .architecture import (
    ArchitectureError, architecture_inputs_present, load_architecture,
    preflight_architecture, validate_repository_drift,
)
from .architecture_diagrams import artifact_digests, compare_generated, render_diagrams
from .architecture_diff import _git, _git_blob, git_binding_scope, select_architecture_comparison_base
from .git_ranges import (  # noqa: F401  compatibility exports retain exact shared type identity
    FOCUSED_STATIC_SEO_LANDING_MODE, GitRangeBase, GitRangeSelection, _RANGE_MODES,
    _existing_ref_candidates, _git_range_selection, _resolve_commit, _select_local_pr_target,
)
from .architecture_fitness import evaluate_fitness
from .architecture_diff import diff_architecture
from .quality_gates import evaluate_quality_gate, required_check_refused
from .expanded_security import known_vulnerability_check, run_checks as expanded_security_checks
from .language_quality.core import run_registry as run_language_quality, project_checks as language_quality_checks
from .receipts import (
    active_architecture_binding,
    active_governance_binding,
    validate_evidence,
    write_receipt,
)
from .spec import (_parse_canonical_json, canonical_spec_digest,
                   criterion_coverage, load_spec, parse_yaml_subset, spec_fingerprint, validate_spec)
from .package_status import read_package_file
from . import stack_runners  # noqa: F401  registers the Rust, .NET and PowerShell runners
from .stack_toolchains import Blocker, Toolchain, ensure_toolchain, resolve_version
from .stacks import load_registry, stack_checks
from .state import get_active_change, get_active_route, update_route
from .python_test_runner import (
    DEFAULT_CORE_CPU_RESERVE, DEFAULT_CORE_WORKER_CAP, TIMEOUT as CORE_TEST_TIMEOUT,
    OUTPUT_LIMIT as OUTPUT_LIMIT, ProcessResult, RunCancelled, RunnerError, _cancellation, core_worker_selection,
    cleanup_details, execute, run_core_tests, run_named_tests,
)
from .util import (
    find_tool,
    tool_search_path,
    changed_file_statuses,  # noqa: F401 compatibility
    changed_files,  # noqa: F401 compatibility
    command_exists,
    git_head,
    now_utc,
    read_text_limited,
    run,
    tree_fingerprint,
    resolve_command,
    unique_ordered,
)
from .workflow_artifacts import WorkflowArtifactError, validate_stored_workflow
from . import verification_dispositions as reviewed_dispositions
from .verification_scope import (
    FOCUSED_TEST_TARGETS,
    focused_command,
    is_valid_inventory_path,
    select_docs_state_scope,
)
from .verification_tools import planned_checks as planned_tool_checks
from .verification_scope import (  # noqa: F401 compatibility exports for shared selectors
    NODE_LOCKFILES,
    QUALITY_PY_PATHS,
    _CHANGE_PACKAGE_PREFIX,
    _FOCUSED_LANDING_TEST_NAME,
    _SAFE_FOCUSED_FILE_STATUSES,
    _SEMGREP_CONFIGS,
    _STATIC_LANDING_PREFIX,
    _TRIVY_FILES,
    _changed_file_inventory,
    _docs_state_status_inventory,
    _existing_quality_paths,
    _focused_file_status_findings,
    _focused_test_landing_key,
    _is_focused_landing_test,
    _is_valid_inventory_path,
    _normalize_landing_key,
    _safe_inventory_value,
    _semgrep_config,
    _trivy_config_present,
    composer_check_selection,
    node_check_selection,
    node_lockfile,
    python_check_selection,
    select_static_seo_landing_scope,
)


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    command: list[str] | None = None
    stdout: str = ''
    stderr: str = ''
    duration_hint: str | None = None
    details: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@diagnostics.observed('agent-eval-checks')
def _agent_eval_checks(root: Path, mode: str) -> list[CheckResult]:
    """Use the optional replay suites inside the existing verification gate."""
    return [CheckResult(**item) for item in required_suites(root, mode)]


class VerificationCancelled(SystemExit):
    def __init__(self, number: int, report: dict[str, object]):
        super().__init__(128 + number)
        self.signal_name = signal.Signals(number).name
        self.report = report


@dataclass
class _RunState:
    report: dict[str, object]
    results: list[CheckResult] = field(default_factory=list)
    stage: str = 'pre-dispatch'
    receipt_eligible: bool = True
    context: dict[str, Any] | None = None
    context_route_id: str | None = None
    context_error: str | None = None
    required_plan: dict | None = None


@diagnostics.observed('task-context-check')
def _task_context_check(root: Path, state: _RunState) -> CheckResult:
    from .continuity import context_binding, legacy_evidence_allowed, scope_gaps
    from .state import task_transition, route_authority_present
    error = state.context_error
    with task_transition(root):
        route = get_active_route(root)
        if not error:
            try:
                if state.context_route_id != (route or {}).get('route_id'):
                    raise ValueError('task context changed during verification')
                if state.context is not None:
                    if context_binding(root, route) != state.context:
                        raise ValueError('task context changed during verification')
                    gaps = scope_gaps(root, route)
                    if gaps:
                        raise ValueError('; '.join(gaps))
                elif (route and not legacy_evidence_allowed(route) or
                      not route and route_authority_present(root)):
                    raise ValueError('task context is unavailable or changed from legacy evidence')
            except (ValueError, RuntimeError, OSError, TypeError, KeyError) as exc:
                error = str(exc)
    if error:
        state.receipt_eligible = False
    return CheckResult('task-context', 'fail' if error else 'pass',
                       error or 'observed task context remained current')


class _CheckDispatch:
    """Retain completed results and disclose remaining scheduled work after refusal."""

    def __init__(self, results, mode, scope=None, *, keep_going=False, blocked_by=None, required_plan=None):
        self.results, self.mode, self.scope = results, mode, scope
        self.fail_fast = mode in {'pr', 'release'} and not keep_going
        self.blocked_by = blocked_by
        self.required_plan = required_plan

    def add(self, check):
        self.results.append(check)
        if self.fail_fast and self.blocked_by is None and required_check_refused(check, mode=self.mode, docs_scope=self.scope, required_plan=self.required_plan):
            self.blocked_by = check.name
        return check

    def run(self, name, callback):
        if self.blocked_by:
            return self.add(CheckResult(name, 'skip', 'not executed after required refusal', details=[{
                'severity': 'info', 'code': 'not-executed-after-required-refusal', 'path': name,
                'execution': 'not_executed', 'blocked_by': self.blocked_by,
                'message': f'not executed after {self.blocked_by} refused verification',
            }]))
        with diagnostics.span(name) as detail:
            check = callback()
            if detail is not None and check is not None:
                detail['outcome'] = check.status if check.status in {'pass', 'fail', 'skip', 'cancelled', 'error'} else 'unknown'
        return self.add(check) if check is not None else None

    def batch(self, names, callback):
        if self.blocked_by:
            for name in names:
                self.run(name, None)
        else:
            with diagnostics.span('check-batch'):
                for check in callback():
                    self.add(check)


@contextmanager
def _retain_checks(results: list[CheckResult]):
    try:
        yield
    except RunCancelled as exc:
        exc.checks = [*results, *exc.checks]
        raise


def _failure_message(exc: BaseException) -> str:
    message = ' '.join(''.join(' ' if ord(char) < 32 or ord(char) == 127 else char for char in str(exc)).split())
    return f'{type(exc).__name__}: {message}'[:512]


def _record_verification_receipt(root: Path, report: dict[str, object], fingerprint: str, *, interrupt_check=None,
                                 expected_context=None) -> None:
    report.setdefault('check_status', report['status'])
    report.setdefault('terminal_state', 'completed')
    report['evidence_status'] = 'recorded'
    try:
        write_receipt(root, 'verification', report['status'], details=report,
                      expected_tree_fingerprint=fingerprint, interrupt_check=interrupt_check,
                      expected_context=expected_context)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        report['status'] = 'fail'
        report['evidence_status'] = 'failed'
        report['checks'].append(CheckResult(
            'receipt-recording', 'fail', 'verification receipt was not recorded',
            details=[{'severity': 'error', 'path': '.getzilla/runtime/receipts',
                      'code': 'receipt-recording-failed', 'message': _failure_message(exc)}],
        ).to_dict())
        # Invalidate an older pass even when binding validation failed before publication.
        route_id = report.get('route_id')
        if isinstance(route_id, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', route_id):
            try:
                (root / '.getzilla/runtime/receipts' / route_id / 'verification.json').unlink(missing_ok=True)
            except OSError as cleanup:
                report['checks'].append(CheckResult('receipt-cleanup', 'fail', _failure_message(cleanup)).to_dict())


# New packages live in the ignored runtime namespace; tracked legacy packages stay valid.
_FACTORY_POSTGRES_EXIT_TIMEOUT_SECONDS = 900
_LIVE_FACTORY_OUTER_TIMEOUT_SECONDS = 1800


def _canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _architecture_base(root: Path, route: dict[str, object] | None) -> str:
    return select_architecture_comparison_base(root, route).comparison_base_sha


def _risk_level(route: dict[str, object] | None) -> str:
    risk = str((route or {}).get("risk") or "low")
    fallback = risk if risk in {"green", "yellow", "red"} else "red"
    return {"low": "green", "medium": "yellow", "high": "red"}.get(risk, fallback)


@diagnostics.observed('architecture-preflight-check')
def _architecture_preflight_check(root: Path) -> CheckResult:
    if not architecture_inputs_present(root):
        return CheckResult("architecture-inputs", "skip", "architecture authority inputs are absent; not executed")
    findings = preflight_architecture(root)
    if findings:
        return CheckResult(
            "architecture-inputs", "fail", findings[0].message,
            details=[asdict(finding) for finding in findings],
        )
    return CheckResult("architecture-inputs", "pass", "bounded model and referenced-input preflight executed")


@diagnostics.observed('architecture-check')
@git_binding_scope()
def _architecture_check(
    root: Path,
    route: dict[str, object] | None,
    *,
    _trusted_ranges: GitRangeSelection | None = None,
) -> tuple[CheckResult, dict[str, object]]:
    try:
        binding = (active_architecture_binding(root, route or {}) if _trusted_ranges is None else
                   active_architecture_binding(root, route or {}, _trusted_ranges=_trusted_ranges))
        if binding is None:
            return (
                CheckResult("architecture", "skip", "architecture is not configured"),
                {"configured": False, "status": "not_configured"},
            )
        snapshot = load_architecture(root)
        base_selection = select_architecture_comparison_base(root, route, _trusted_ranges=_trusted_ranges)
        base = base_selection.comparison_base_sha
        if (
            binding["architecture_base_sha"] != base
            or binding["architecture_base_kind"] != base_selection.base_kind
            or binding["architecture_bootstrap_baseline"]
            != base_selection.bootstrap_baseline
            or binding["architecture_route_base_sha"] != base_selection.route_base_sha
        ):
            raise ArchitectureError("architecture base binding is inconsistent", code="git")
        diff = diff_architecture(
            root,
            base_sha=base,
            worktree=True,
            _trusted_base_selection=base_selection,
        )
        fitness = evaluate_fitness(
            root,
            snapshot,
            diff,
            diff.changed_paths,
            pre_risk=_risk_level(route),
        )
        drift = validate_repository_drift(root, snapshot)
        rendered = render_diagrams(snapshot)
        mismatches = compare_generated(root, rendered)
        drift_status = "fail" if drift else "pass"
        diagram_status = "fail" if mismatches else "pass"
        failed = fitness.status != "pass" or bool(drift) or bool(mismatches)
        core: dict[str, object] = {
            **({'architecture_comparison_witness': binding['architecture_comparison_witness']}
               if 'architecture_comparison_witness' in binding else {}),
            "architecture_contract_version": 1,
            "adoption_digest": binding["architecture_adoption_digest"],
            "architecture_digest": binding["architecture_digest"],
            "architecture_fingerprint": binding["architecture_fingerprint"],
            "architecture_base_sha": binding["architecture_base_sha"],
            "architecture_head_commit": binding["architecture_head_commit"],
            "architecture_base_kind": binding["architecture_base_kind"],
            "architecture_bootstrap_baseline": binding[
                "architecture_bootstrap_baseline"
            ],
            "architecture_route_base_sha": binding["architecture_route_base_sha"],
            "architecture_range_mode": binding["architecture_range_mode"],
            "baseline_introduced": diff.baseline_introduced,
            "base_adoption_state": diff.base_adoption_state,
            "head_adoption_state": diff.head_adoption_state,
            "base_adoption_digest": diff.base_adoption_digest,
            "head_adoption_digest": diff.head_adoption_digest,
            "contract_inventory_digest": binding["architecture_contract_inventory_digest"],
            "diff_digest": diff.digest,
            "drift_status": drift_status,
            "exact_base_sha": diff.base_sha,
            "base_kind": "commit",
            "fitness_evidence_digest": fitness.evidence_digest,
            "fitness_status": fitness.status,
            "fitness_results": [asdict(item) for item in fitness.results],
            "generated_artifact_digests": artifact_digests(rendered),
            "head_kind": "worktree",
            "repository_inventory_digest": diff.repository_inventory_digest,
            "risk_escalation": fitness.escalation,
            "risk_post": fitness.post_risk,
            "risk_pre": fitness.pre_risk,
            "rules_digest": binding["architecture_rules_digest"],
            "schema_digest": binding["architecture_schema_digest"],
            "system_digest": binding["architecture_system_digest"],
        }
        core["architecture_evidence_digest"] = _canonical_digest(core)
        metadata = {
            "configured": True,
            "diagram_status": diagram_status,
            "diagram_mismatches": list(mismatches),
            "drift_findings": [asdict(item) for item in drift],
            "status": "fail" if failed else "pass",
            **core,
        }
        details = [asdict(item) for item in drift]
        details.extend(
            {
                "severity": "error",
                "code": "generated-diagram-drift",
                "path": path,
                "message": "generated Mermaid projection differs from the architecture model",
            }
            for path in mismatches
        )
        if fitness.status != "pass":
            details.append(
                {
                    "severity": "error",
                    "code": "architecture-fitness",
                    "path": "architecture/rules.yaml",
                    "message": f"architecture fitness status is {fitness.status}",
                }
            )
        return (
            CheckResult(
                "architecture",
                "fail" if failed else "pass",
                f"drift={drift_status}; fitness={fitness.status}; diagrams={diagram_status}",
                details=details,
            ),
            metadata,
        )
    except (ArchitectureError, RuntimeError, OSError, ValueError) as exc:
        details = [{
            "severity": "error",
            "code": getattr(exc, "code", "architecture-invalid"),
            "path": "architecture",
            "message": str(exc),
        }]
        return (
            CheckResult("architecture", "fail", str(exc), details=details),
            {"configured": True, "error": str(exc), "status": "fail"},
        )


@diagnostics.observed('governance-check')
def _governance_check(
    root: Path,
    route: dict[str, object] | None,
    architecture: dict[str, object],
    *,
    _trusted_ranges: GitRangeSelection | None = None,
) -> tuple[CheckResult, dict[str, object]]:
    try:
        checked_architecture: dict[str, object] | None = None
        if architecture.get("status") == "pass" and architecture.get("configured") is True:
            checked_architecture = {
                field: architecture.get(field)
                for field in (
                    "architecture_digest",
                    "architecture_base_sha",
                    "architecture_head_commit",
                    "architecture_route_base_sha",
                    "architecture_base_kind",
                    "architecture_comparison_witness",
                    "architecture_range_mode",
                )
            }
        binding = active_governance_binding(
            root,
            route or {},
            checked_architecture,
            **({'_trusted_ranges': _trusted_ranges} if _trusted_ranges is not None else {}),
        )
        if binding is None:
            return (
                CheckResult("governance", "skip", "governance is not configured"),
                {"configured": False, "status": "not_configured"},
            )
        if checked_architecture is None:
            raise RuntimeError(
                "governance requires a complete successful architecture check"
            )
        if (
            binding["governance_architecture_digest"]
            != checked_architecture["architecture_digest"]
            or binding["governance_applicable_base_sha"]
            != checked_architecture["architecture_base_sha"]
            or binding["governance_applicable_head_sha"]
            != checked_architecture["architecture_head_commit"]
        ):
            raise RuntimeError(
                "governance evidence does not match the checked architecture binding"
            )
        metadata = {
            "architecture_status": architecture.get("status", "unknown"),
            "configured": True,
            "status": "pass",
            **binding,
        }
        return (
            CheckResult(
                "governance",
                "pass",
                "governance registries and evidence are current",
            ),
            metadata,
        )
    except (KeyError, RuntimeError, OSError, TypeError, ValueError) as exc:
        details = [
            {
                "severity": "error",
                "code": getattr(exc, "code", "governance-invalid"),
                "path": "governance",
                "message": str(exc),
            }
        ]
        return (
            CheckResult("governance", "fail", str(exc), details=details),
            {"configured": True, "error": str(exc), "status": "fail"},
        )


@diagnostics.observed('workflow-artifacts-check')
def _workflow_artifacts_check(
    root: Path,
    route: dict[str, object] | None,
    active_change: dict[str, object] | None,
    current_fingerprint: str,
) -> tuple[CheckResult, dict[str, object]]:
    change = active_change or {}
    change_id = change.get("change_id")
    relative = change.get("path")
    if not isinstance(change_id, str) or not isinstance(relative, str):
        return CheckResult("workflow-artifacts", "skip", "no active change"), {
            "configured": False,
            "status": "not_configured",
        }
    from .workflow_storage import valid_package_path
    if not valid_package_path(relative, change_id):
        return CheckResult("workflow-artifacts", "fail", "active change path is not canonical"), {
            "configured": True,
            "status": "fail",
            "error": "active change path is not canonical",
        }
    manifest = root / relative / "workflow/manifest.json"
    try:
        metadata = manifest.lstat()
    except FileNotFoundError:
        return CheckResult("workflow-artifacts", "skip", "workflow artifacts are not configured"), {
            "configured": False,
            "status": "not_configured",
        }
    except OSError as exc:
        return CheckResult("workflow-artifacts", "fail", str(exc)), {
            "configured": True,
            "status": "fail",
            "error": str(exc),
        }
    if not manifest.is_file() or manifest.is_symlink():
        return CheckResult("workflow-artifacts", "fail", "workflow manifest is not a regular file"), {
            "configured": True,
            "status": "fail",
            "error": "unsafe manifest",
        }
    del metadata
    try:
        canonical_route = dict(route or {})
        receipt_errors = validate_evidence(
            root,
            canonical_route,
            current_fingerprint=current_fingerprint,
        )
        validation, report = validate_stored_workflow(
            root,
            change_id,
            canonical_route,
            current_fingerprint=current_fingerprint,
            receipt_errors=receipt_errors,
        )
        status = "pass" if validation["ok"] else "fail"
        details = [
            {"severity": "error", "code": "workflow-convergence", "path": f"{relative}/workflow", "message": message}
            for message in validation["errors"]
        ]
        return CheckResult("workflow-artifacts", status, f"convergence={validation['status']}", details=details), {
            "configured": True,
            "status": status,
            "graph_digest": report.get("graph_digest"),
            "report_digest": report.get("report_digest"),
            "findings": report.get("findings", []),
        }
    except (WorkflowArtifactError, OSError, TypeError, ValueError, MemoryError) as exc:
        return CheckResult(
            "workflow-artifacts",
            "fail",
            str(exc),
            details=[
                {
                    "severity": "error",
                    "code": getattr(exc, "code", "workflow-invalid"),
                    "path": f"{relative}/workflow",
                    "message": str(exc),
                }
            ],
        ), {"configured": True, "status": "fail", "error": str(exc)}


def _command_check(root: Path, name: str, command: list[str], timeout: int = 300, *, env: dict[str, str] | None = None,
                   termination_grace: float | None = None) -> CheckResult:
    environment = os.environ.copy()
    environment.update(env or {})
    if 'PATH' not in (env or {}):
        # Run the same user-installed tool that command_exists() found.
        environment['PATH'] = tool_search_path(environment.get('PATH', ''))
    try:
        # The report keeps the command as written; only the launch resolves it (Windows .cmd shims).
        options = {'termination_grace': termination_grace} if termination_grace is not None else {}
        proc = execute(resolve_command(command, environment['PATH']), root, environment, timeout=timeout, **options)
    except RunCancelled as exc:
        proc = exc.result
        exc.checks = [CheckResult(
            name, 'cancelled', f'cancelled exit={exc.code}', command=command,
            stdout=proc.stdout[-12000:] if proc else '', stderr=proc.stderr[-12000:] if proc else '',
            details=[{'stop': diagnostics.stop_details(proc if proc is not None else exc)}],
        )]
        raise
    return CheckResult(
        name=name,
        status='pass' if proc.returncode == 0 and not proc.cleanup_error else 'fail',
        summary=f'exit={proc.returncode}',
        command=command,
        stdout=proc.stdout[-12000:],
        stderr=(proc.stderr + ('\ncleanup failed: ' + proc.cleanup_error if proc.cleanup_error else ''))[-12000:],
        details=[{'stop': diagnostics.stop_details(proc)}],
    )


_EXACT_SHA = re.compile(r'^[0-9a-fA-F]{40}$')


def _focused_scope_check(scope: dict[str, object]) -> CheckResult:
    eligible = scope.get('eligible') is True
    landing_files = scope.get('landing_files') or []
    focused_tests = scope.get('focused_tests') or []
    rejected_files = scope.get('rejected_files') or []
    details = [
        {
            'severity': 'info' if eligible else 'error',
            'code': 'focused-scope',
            'path': str(path),
            'message': 'included in focused static SEO landing scope'
            if eligible else 'not eligible for focused static SEO landing scope',
        }
        for path in [*landing_files, *focused_tests, *rejected_files]
    ]
    details.extend(scope.get('status_findings') or [])
    details.extend(scope.get('unsafe_file_statuses') or [])
    return CheckResult(
        'scope-selection',
        'pass' if eligible else 'fail',
        f"profile={scope.get('profile')}; reason={scope.get('reason')}; "
        f"landing={len(landing_files)}; focused_tests={len(focused_tests)}; "
        f"ignored={len(scope.get('ignored_files') or [])}",
        details=details + ([scope['rejection']] if isinstance(scope.get('rejection'), dict) else []),
    )


def _docs_state_scope_check(scope: dict[str, object]) -> CheckResult:
    """Render the documentation/state scope decision as a first-class reported check.

    An ineligible result is not a failure: it is the ordinary full-suite path. The check
    exists so the profile that ran, and every check that profile did not run, appear in the
    receipt instead of being inferred from their absence.
    """
    eligible = scope.get('eligible') is True
    admitted = [
        *scope.get('documentation_files', []),
        *scope.get('state_files', []),
        *scope.get('artifact_files', []),
        *scope.get('changed_lockstep_tests', []),
    ]
    details: list[dict[str, str]] = [
        {
            'severity': 'info',
            'code': str(scope.get('reason_code') or 'inventory-unclassified'),
            'path': str(path),
            'message': 'admitted by the focused documentation/state profile' if eligible
            else 'not admitted by the focused documentation/state profile',
        }
        for path in (admitted if eligible else scope.get('rejected_files', []))
    ]
    if eligible:
        details.extend({
            'severity': 'warning',
            'code': 'focused-scope-skip',
            'path': str(name),
            'message': f'{name} is not measured by the focused documentation/state profile',
        } for name in scope.get('skipped_checks', []))
    else:
        details.append({
            'severity': 'info',
            'code': str(scope.get('reason_code') or 'inventory-unclassified'),
            'path': '',
            'message': f'full PR suite is required: {scope.get("reason")}',
        })
    checked = scope.get('checked_files') if eligible else []
    return CheckResult(
        'docs-state-scope',
        'pass',
        f"profile={scope.get('profile')}; evidence={scope.get('evidence_kind')}; "
        f"reason={scope.get('reason_code')}; paths={len(checked or [])}; "
        f"skipped={','.join(scope.get('skipped_checks') or []) or 'none'}",
        details=details,
    )


def _unittest_contract_failure(path: Path) -> str | None:
    try:
        source = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as exc:
        return f'contract source cannot be read safely: {exc}'
    if not source.strip():
        return 'contract file is empty'
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return f'contract file is not valid Python: {exc.msg} at line {exc.lineno}'

    unittest_modules: set[str] = set()
    testcase_names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == 'unittest':
                    unittest_modules.add(alias.asname or 'unittest')
        elif isinstance(node, ast.ImportFrom) and node.module == 'unittest':
            for alias in node.names:
                if alias.name == 'TestCase':
                    testcase_names.add(alias.asname or 'TestCase')

    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        is_test_case = any(
            (
                isinstance(base, ast.Name) and base.id in testcase_names
            ) or (
                isinstance(base, ast.Attribute)
                and base.attr == 'TestCase'
                and isinstance(base.value, ast.Name)
                and base.value.id in unittest_modules
            )
            for base in node.bases
        )
        if is_test_case and any(
            isinstance(method, ast.FunctionDef) and method.name.startswith('test_')
            for method in node.body
        ):
            return None
    return 'contract must define a unittest.TestCase subclass with a test_ method'


def _focused_landing_contract(root: Path, scope: dict[str, object], *, required_plan=None) -> CheckResult:
    if required_plan is not None:
        refs = sorted({ref for row in required_plan['obligations'] if row['check_id'] == 'static-seo-landing-contract'
                       for ref in row['expected_tests']})
        scope = dict(scope, **({'required_test_refs': refs} if refs else {}))
    focused_tests = scope.get('focused_tests')
    if not isinstance(focused_tests, list) or len(focused_tests) != 1:
        return CheckResult(
            'static-seo-landing-contract',
            'fail',
            'exactly one focused landing test is required',
        )
    relative = focused_tests[0]
    if not isinstance(relative, str) or not _is_valid_inventory_path(relative):
        return CheckResult(
            'static-seo-landing-contract',
            'fail',
            'focused landing test path is invalid',
        )
    path = root / relative
    try:
        root_resolved = root.resolve()
        resolved = path.resolve()
        resolved.relative_to(root_resolved)
        if path.is_symlink() or not path.is_file():
            raise OSError('focused landing test must be a regular file')
        current = path.parent
        while current != root:
            if current.is_symlink():
                raise OSError('focused landing test path contains a symlink')
            current = current.parent
    except (OSError, ValueError) as exc:
        return CheckResult(
            'static-seo-landing-contract',
            'fail',
            f'focused landing test is unsafe or missing: {exc}',
        )
    contract_failure = _unittest_contract_failure(path)
    if contract_failure is not None:
        return CheckResult(
            'static-seo-landing-contract',
            'fail',
            f'focused landing test is not a valid unittest contract: {contract_failure}',
            details=[{
                'severity': 'error',
                'code': 'focused-test-not-unittest-contract',
                'path': relative,
                'message': contract_failure,
            }],
        )
    from .criterion_tests import run_required_tests
    refs = scope.get('required_test_refs') or [relative]
    if not isinstance(refs, list) or any(not isinstance(ref, str) or ref.split('::', 1)[0] != relative for ref in refs):
        return CheckResult('static-seo-landing-contract', 'fail', 'required test references exceed the selected landing contract')
    observed = run_required_tests(root, refs, timeout=300)
    observed['name'] = 'static-seo-landing-contract'
    result = CheckResult(**observed)
    result.summary = f'{result.summary}; test={relative}'
    return result


@diagnostics.observed('git-diff-check')
def _git_diff_check(
    root: Path,
    mode: str,
    selection: GitRangeSelection,
) -> CheckResult:
    if not command_exists('git'):
        return CheckResult('git-diff-check', 'skip', 'git not available')
    checks: list[tuple[str, list[str]]] = [
        ('worktree', ['git', 'diff', '--check']),
        ('index', ['git', 'diff', '--cached', '--check']),
    ]
    details = list(selection.findings)
    if mode in _RANGE_MODES:
        for selected in selection.bases:
            checks.append((
                selected.kind,
                ['git', 'diff', '--check', f'{selected.comparison_base_sha}..HEAD'],
            ))
            details.append({
                'severity': 'info',
                'code': 'checked-range',
                'path': selected.source,
                'message': f'checked {selected.comparison_base_sha}..HEAD',
                'kind': selected.kind,
                'base': selected.comparison_base_sha,
                'target': selected.target_sha,
            })

    try:
        policy = reviewed_dispositions.Dispositions(root)
    except (reviewed_dispositions.DispositionError, OSError):
        policy = None
        details.append(reviewed_dispositions.invalid_finding())
    failures = bool(selection.findings) or policy is None
    failed_commands = 0
    output: list[str] = []
    errors: list[str] = []
    for label, command in checks:
        layer = label if label in {'worktree', 'index'} else 'HEAD'
        snapshots = {}
        if policy:
            try:
                snapshots = policy.snapshots(layer)
            except (reviewed_dispositions.DispositionError, OSError):
                details.append(reviewed_dispositions.invalid_finding())
                failures = True
                policy = None
        proc = run(
            command,
            cwd=root,
            timeout=60,
            encoding='utf-8',
            errors='backslashreplace',
        )
        if proc.stdout:
            output.append(f'[{label}]\n{proc.stdout}')
        if proc.stderr:
            errors.append(f'[{label}]\n{proc.stderr}')
        details.append({
            'severity': 'info', 'code': 'diff-check-command', 'path': label,
            'message': f'exit={proc.returncode}: {" ".join(command)}',
            'command': command, 'exit_code': proc.returncode,
            'stdout': proc.stdout, 'stderr': proc.stderr,
        })
        if policy:
            try:
                if snapshots != policy.snapshots(layer):
                    raise reviewed_dispositions.DispositionError('Git snapshot changed')
                policy.assert_current()
            except (reviewed_dispositions.DispositionError, OSError):
                details.append(reviewed_dispositions.invalid_finding())
                failures = True
                policy = None
        observations, parsed = reviewed_dispositions.diff_findings(proc.stdout, policy, snapshots, label)
        details.extend(observations)
        covered = (proc.returncode == 2 and not proc.stderr and parsed and bool(observations)
                   and all(item['effective_severity'] == 'info' for item in observations))
        if proc.returncode != 0 or proc.stdout or proc.stderr:
            failed_commands += 1
            failures |= not covered
            details.append({
                'severity': 'error',
                'effective_severity': 'info' if covered else 'error',
                'code': 'diff-check-failed',
                'path': label,
                'message': f'exit={proc.returncode}: {" ".join(command)}',
            })
    disposition_summary = reviewed_dispositions.summary(policy, details)
    details.append(disposition_summary)
    rendered_bases = ','.join(
        f'{item.kind}:{item.comparison_base_sha}' for item in selection.bases
    ) or 'none'
    return CheckResult(
        name='git-diff-check',
        status='fail' if failures else 'pass',
        summary=(f'{len(checks) - failed_commands}/{len(checks)} commands clean; '
                 f'{disposition_summary["disposed"]} findings disposed; '
                 f'{disposition_summary["unresolved"]} unresolved; bases={rendered_bases}'),
        stdout='\n'.join(output),
        stderr='\n'.join(errors),
        details=details,
    )


@diagnostics.observed('secret-scan')
def _secret_scan(root: Path, files: list[str]) -> CheckResult:
    from .security_tools import native_secret_observations

    observed = native_secret_observations(root, files)
    return CheckResult('secret-scan', 'pass' if observed['outcome'] == 'pass' else 'fail',
                       observed['summary'], details=observed['details'])


@diagnostics.observed('php-lint')
def _php_lint(root: Path, files: list[str]) -> CheckResult:
    php_files = [rel for rel in files if rel.lower().endswith('.php') and (root / rel).is_file()]
    if not php_files:
        return CheckResult('php-lint', 'skip', 'no changed PHP files')
    if not command_exists('php'):
        return CheckResult('php-lint', 'fail', 'PHP is required to lint changed PHP files')
    failures: list[dict[str, str]] = []
    outputs: list[str] = []
    for rel in php_files:
        proc = run(['php', '-l', rel], cwd=root, timeout=30)
        outputs.append((proc.stdout + proc.stderr).strip())
        if proc.returncode != 0:
            failures.append({'severity': 'error', 'code': 'php-syntax', 'path': rel, 'message': (proc.stdout + proc.stderr).strip()})
    return CheckResult('php-lint', 'fail' if failures else 'pass', f'{len(php_files)} files linted', stdout='\n'.join(outputs[-100:]), details=failures)


@diagnostics.observed('bitrix')
def _bitrix(root: Path, files: list[str]) -> CheckResult:
    findings = check_bitrix(root, files)
    errors = [item for item in findings if item.severity == 'error']
    return CheckResult(
        'bitrix-policy',
        'fail' if errors else 'pass',
        f'{len(errors)} errors, {len(findings) - len(errors)} warnings',
        details=[item.to_dict() for item in findings],
    )


@diagnostics.observed('contracts')
def _contracts(root: Path, files: list[str]) -> CheckResult:
    findings: list[dict[str, str]] = []
    checked = 0
    for rel in files:
        lower = rel.lower()
        path = root / rel
        if not path.is_file():
            continue
        if lower.endswith(('.json', '.schema.json')) and ('contract' in lower or 'schema' in lower):
            checked += 1
            try:
                json.loads(path.read_text(encoding='utf-8'))
            except (json.JSONDecodeError, OSError) as exc:
                findings.append({'severity': 'error', 'code': 'invalid-json-contract', 'path': rel, 'message': str(exc)})
        if lower.endswith(('.yaml', '.yml')) and any(token in lower for token in ('openapi', 'asyncapi', 'contract')):
            checked += 1
            text = read_text_limited(path)
            if 'openapi:' not in text and 'asyncapi:' not in text:
                findings.append({'severity': 'error', 'code': 'contract-version', 'path': rel, 'message': 'Missing openapi: or asyncapi: top-level version.'})
            if 'asyncapi:' in text and 'channels:' not in text:
                findings.append({'severity': 'error', 'code': 'asyncapi-channels', 'path': rel, 'message': 'AsyncAPI document has no channels.'})
            if 'openapi:' in text and 'paths:' not in text:
                findings.append({'severity': 'error', 'code': 'openapi-paths', 'path': rel, 'message': 'OpenAPI document has no paths.'})
    return CheckResult('contract-structure', 'fail' if findings else 'pass', f'{checked} contracts checked', details=findings)


@diagnostics.observed('sql-safety')
def _sql_safety(root: Path, files: list[str]) -> CheckResult:
    findings: list[dict[str, str]] = []
    for rel in files:
        if not rel.lower().endswith(('.sql', '.php')) or not (root / rel).is_file():
            continue
        text = read_text_limited(root / rel)
        for pattern, code in [
            (r'(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b', 'destructive-ddl'),
            (r'(?i)\bTRUNCATE\s+TABLE\b', 'truncate'),
            (r'(?i)\bDELETE\s+FROM\s+\S+\s*;', 'unbounded-delete'),
            (r'(?i)\bUPDATE\s+\S+\s+SET\b(?![\s\S]*\bWHERE\b)', 'unbounded-update'),
        ]:
            if re.search(pattern, text):
                findings.append({'severity': 'error', 'code': code, 'path': rel, 'message': 'Potentially destructive or unbounded SQL requires explicit migration approval.'})
    return CheckResult('sql-safety', 'fail' if findings else 'pass', f'{len(findings)} unsafe SQL findings', details=findings)


def _docs_micro_exempt(route: dict[str, object] | None, files: list[str]) -> bool:
    if not route or route.get('complexity') != 'micro' or route.get('risk') != 'low':
        return False
    product = [rel for rel in files if not rel.startswith('engineering/changes/')]
    return bool(product) and all(
        rel.startswith('docs/') or Path(rel).suffix.lower() in {'.md', '.txt', '.rst'}
        for rel in product
    )


def _historical_spec_migrations(root: Path, selected: set[str], active_rel: str | None,
                                route: dict[str, object] | None, mode: str, *,
                                ranges: GitRangeSelection | None = None) -> list[dict[str, object]]:
    """Bind archival retirement/strict relocation to actual comparison-base blobs."""
    manifest_rel = 'engineering/archived-change-specs.json'
    if not (root / manifest_rel).exists():
        return []
    manifest = _parse_canonical_json(read_package_file(root, manifest_rel), Path(manifest_rel))
    if set(manifest) != {'schema_version', 'source_base', 'entries'} or manifest['schema_version'] != 1 or not isinstance(manifest['entries'], list):
        raise ValueError('invalid historical spec migration manifest')
    if ranges is None:
        ranges = _git_range_selection(root, route, mode)
    if ranges.findings or not ranges.bases:
        raise ValueError('historical spec migration requires trusted comparison ranges')
    bases = {item.comparison_base_sha for item in ranges.bases}
    source_base = manifest['source_base']
    if not isinstance(source_base, str) or not _EXACT_SHA.fullmatch(source_base):
        raise ValueError('historical source base must be an exact commit')
    origins: dict[str, str] = {}
    for base in bases:
        raw = _git(root, ['ls-tree', '-r', '-z', base, '--', 'engineering/changes'])
        if raw is None:
            raise ValueError('historical base inventory unavailable')
        for record in raw.split(b'\0'):
            if not record:
                continue
            metadata, path_bytes = record.split(b'\t', 1)
            file_mode, kind, blob = metadata.decode('ascii').split()
            rel = os.fsdecode(path_bytes)
            if rel.endswith('/change-spec.yaml') and file_mode in {'100644', '100755'} and kind == 'blob':
                blob_id = blob
                if rel in origins and origins[rel] != blob_id:
                    raise ValueError('historical origin differs between comparison bases')
                origins[rel] = blob_id
    records: list[dict[str, object]] = []
    seen_blobs: set[str] = set()
    seen_targets: set[str] = set()
    for entry in manifest['entries']:
        if not isinstance(entry, dict) or set(entry) != {'kind', 'original_blob', 'target', 'sha256'}:
            raise ValueError('invalid historical migration entry')
        kind, blob, target, digest = (entry[key] for key in ('kind', 'original_blob', 'target', 'sha256'))
        if kind not in {'legacy_archive', 'v2_relocation'} or not isinstance(blob, str) or not _EXACT_SHA.fullmatch(blob):
            raise ValueError('invalid historical migration identity')
        suffix = '/historical-spec.yaml' if kind == 'legacy_archive' else '/change-spec.yaml'
        if not isinstance(target, str) or not is_valid_inventory_path(target) or not target.startswith('engineering/changes/') or not target.endswith(suffix):
            raise ValueError('invalid historical migration target')
        if blob in seen_blobs or target in seen_targets or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('duplicate migration or invalid digest')
        seen_blobs.add(blob)
        seen_targets.add(target)
        payload = read_package_file(root, target)
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError(f'historical migration target digest mismatch: {target}')
        archive = load_spec(root / target, allow_legacy=kind == 'legacy_archive')
        expected_version = 1 if kind == 'legacy_archive' else 2
        if type(archive.get('schema_version')) is not int or archive['schema_version'] != expected_version:
            raise ValueError(f'historical migration target version mismatch: {target}')
        sources = [rel for rel, original_blob in origins.items() if original_blob == blob]
        aliases = {str(Path(target).parent / 'change-spec.yaml')} if kind == 'legacy_archive' else set()
        affected = selected.intersection({*sources, *aliases})
        if not affected:
            continue
        if bases != {source_base} or len(sources) != 1:
            raise ValueError('migration origin is not unique in the trusted source base')
        origin = sources[0]
        original_bytes = _git_blob(root, source_base, origin, required=True)
        if original_bytes is None:
            raise ValueError('historical origin unavailable')
        try:
            original = _parse_canonical_json(original_bytes, Path(origin))
        except ValueError:
            original = parse_yaml_subset(original_bytes.decode('utf-8', 'strict'))
        if not isinstance(original, dict) or type(original.get('schema_version')) is not int or original['schema_version'] != expected_version:
            raise ValueError('only version-matched historical migrations are permitted')
        if original.get('change_id') != Path(origin).parent.name or archive.get('change_id') != Path(target).parent.name:
            raise ValueError('historical migration change identity mismatch')
        if active_rel in affected or target == active_rel or any((root / rel).exists() for rel in affected if rel != target):
            raise ValueError('active or surviving current spec cannot be retired')
        if kind == 'v2_relocation':
            selected.add(target)  # The existing strict v2 gate validates this spec below.
        selected.difference_update(affected - {target})
        records.append({**entry, 'original_path_sha256': hashlib.sha256(origin.encode('utf-8')).hexdigest(), 'selected_path_sha256': [hashlib.sha256(rel.encode('utf-8')).hexdigest() for rel in sorted(affected)], 'source_base': source_base, 'evidence_kind': 'historical_archival' if kind == 'legacy_archive' else 'strict_v2_relocation'})
    return records


@diagnostics.observed('change-specs')
def _change_specs(root: Path, files: list[str], route: dict[str, object] | None, mode: str, *,
                  ranges: GitRangeSelection | None = None) -> tuple[CheckResult, dict[str, object]]:
    gate = mode in {'pr', 'release'}
    exempt = bool(route and (route.get('light_diff') or {}).get('admitted')) or _docs_micro_exempt(route, files)
    selected = {
        rel for rel in files
        if rel.startswith('engineering/changes/') and rel.endswith('/change-spec.yaml')
    }
    active = get_active_change(root) or {}
    active_rel = None
    if active.get('path'):
        active_rel = f"{str(active['path']).rstrip('/')}/change-spec.yaml"
        selected.add(active_rel)
    findings: list[dict[str, str]] = []
    records: list[dict[str, object]] = []
    migrations: list[dict[str, object]] = []
    try:
        migrations = _historical_spec_migrations(root, selected, active_rel, route, mode, ranges=ranges)
    except (OSError, ValueError) as exc:
        findings.append({'severity': 'error', 'code': 'historical-spec-migration-invalid', 'path': 'engineering/archived-change-specs.json', 'message': str(exc)})
    if gate and route and route.get('delivery_expected') and not active_rel and not exempt:
        findings.append({'severity': 'error', 'code': 'active-spec-missing', 'path': '', 'message': 'PR/release validation requires an active typed spec: run `getzilla change start --title <task>`, which writes the package and its spec (a diff admitted to the light lane needs none).'})
    for rel in sorted(selected):
        path = root / rel
        if not path.is_file():
            findings.append({'severity': 'error', 'code': 'spec-missing', 'path': rel, 'message': 'Selected change spec is missing.'})
            continue
        errors = validate_spec(root, path, gate=gate and not exempt, route=route)
        record: dict[str, object] = {'path': rel, 'profile': 'gate' if gate else 'draft', 'valid': not errors, 'errors': errors}
        try:
            spec = load_spec(path, allow_legacy=False)
            coverage = criterion_coverage(spec)
            record['coverage'] = coverage
            if gate and not exempt:
                categories = coverage.get('categories', {})
                for category, data in categories.items():
                    if not isinstance(data, dict):
                        continue
                    unmapped = data.get('unmapped_ids')
                    if isinstance(unmapped, list) and unmapped:
                        ids = ', '.join(str(value) for value in unmapped)
                        errors.append(f"unmapped {category} criteria: {ids}")
            if not errors:
                record.update({
                    'digest': canonical_spec_digest(spec),
                    'fingerprint': spec_fingerprint(root, path, spec, route),
                })
        except (OSError, ValueError) as exc:
            if not errors:
                errors = [str(exc)]
        if errors:
            record['valid'] = False
            record['errors'] = errors
        for error in errors:
            findings.append({'severity': 'error', 'code': 'change-spec-invalid', 'path': rel, 'message': error})
        records.append(record)
    metadata: dict[str, object] = {'exempt': exempt, 'specs': records, 'historical_migrations': migrations}
    if route and (route.get('context') or {}).get('version') == 2:
        try:
            from .intake_publication import require_intake_ready
            metadata['intake'] = require_intake_ready(root,route,operation_class='verification-backstop')
        except Exception:
            findings.append({'severity':'error','code':'intake-not-ready','path':active_rel or '',
                             'message':'Current native intake does not admit implementation.'})
            metadata['intake'] = {'status':'unavailable'}
    else:
        metadata['intake'] = {'status':'not_run','reason':'semantic_intake_undeclared'}
    if active_rel:
        metadata['active_path'] = active_rel
    return CheckResult('change-spec', 'fail' if findings else ('skip' if exempt and not selected else 'pass'), f'{len(records)} specs checked; exempt={exempt}', details=findings), metadata


@diagnostics.observed('composer')
def _composer(root: Path, mode: str = 'fast', *, keep_going=False, blocked_by=None, required_plan=None) -> list[CheckResult]:
    results: list[CheckResult] = []
    with _retain_checks(results):
        return _composer_checks(root, results, _CheckDispatch(results, mode, keep_going=keep_going,
                                 blocked_by=blocked_by, required_plan=required_plan))


def _composer_checks(root: Path, results: list[CheckResult], dispatch: _CheckDispatch) -> list[CheckResult]:
    if not (root / 'composer.json').is_file():
        return results
    if command_exists('composer'):
        dispatch.run('composer-validate', lambda: _command_check(root, 'composer-validate', ['composer', 'validate', '--no-check-publish'], 120))
    else:
        dispatch.run('composer-validate', lambda: CheckResult('composer-validate', 'skip', 'composer not available'))
    for name, args in composer_check_selection(root):
        dispatch.run(name, lambda: _command_check(root, name, args, 600))
    return results


@diagnostics.observed('ruff')
def _ruff(root: Path) -> CheckResult:
    paths = _existing_quality_paths(root)
    if not paths:
        return CheckResult('ruff', 'skip', 'no python quality paths')
    if not command_exists('ruff'):
        return CheckResult('ruff', 'skip', 'ruff not available')
    # --force-exclude keeps the project's own exclude list in force for the paths named here.
    result = _command_check(root, 'ruff', ['ruff', 'check', '--force-exclude', '--', *paths], 300)
    if result.status == 'pass' and 'No Python files found' in result.stderr:
        return replace(result, status='skip', summary='ruff checked 0 files: the ruff configuration excludes every path')
    return result


@diagnostics.observed('bandit')
def _bandit(root: Path) -> CheckResult:
    paths = [rel for rel in _existing_quality_paths(root) if rel != 'tests' and not rel.startswith('tests/')]
    if not paths:
        return CheckResult('bandit', 'skip', 'no non-test python paths')
    if not command_exists('bandit'):
        return CheckResult('bandit', 'skip', 'bandit not available')
    config = ['-c', 'bandit.yaml'] if (root / 'bandit.yaml').is_file() else []
    with tempfile.TemporaryDirectory(prefix='getzilla-bandit-') as tmp:
        report_path = Path(tmp) / 'bandit.json'
        result = _command_check(root, 'bandit', ['bandit', *config, '-q', '-f', 'json', '-o', str(report_path), '-r', '--', *paths], 300)
        try:
            report = json.loads(report_path.read_text(encoding='utf-8'))
            lines = int(report['metrics']['_totals']['loc'])
            issues = list(report.get('results') or [])
            scanned = [name.removeprefix('./') for name in report['metrics'] if name != '_totals']
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return result
    if lines == 0 and result.status == 'pass':
        return replace(result, status='skip', summary='bandit scanned 0 lines: exclude_dirs in bandit.yaml covers every path')
    unscanned = [rel for rel in paths if not any(name == rel or name.startswith(rel + '/') for name in scanned)]
    if unscanned:
        result = replace(result, summary=f"{result.summary}; not scanned (bandit.yaml exclude_dirs): {', '.join(unscanned)}")
    details = [{
        'severity': str(item.get('issue_severity', '')).lower(),
        'code': str(item.get('test_id', '')),
        'path': f"{item.get('filename', '')}:{item.get('line_number', '')}",
        'message': str(item.get('issue_text', '')),
    } for item in issues[:200]]
    return replace(result, summary=f'{result.summary}; {len(issues)} issues in {lines} lines', details=details)


@diagnostics.observed('semgrep')
def _semgrep(root: Path) -> CheckResult | None:
    config = _semgrep_config(root)
    if config is None:
        return None
    if not command_exists('semgrep'):
        return CheckResult('semgrep', 'skip', 'semgrep not available')
    return _command_check(root, 'semgrep', ['semgrep', 'scan', '--error', '--config', config], 600)


def _trivy_config(root: Path) -> CheckResult | None:
    if not _trivy_config_present(root):
        return None
    if not command_exists('trivy'):
        return CheckResult('trivy-config', 'skip', 'trivy not available')
    return _command_check(root, 'trivy-config', ['trivy', 'config', '--exit-code', '1', '.'], 600)


@diagnostics.observed('known-vulnerabilities')
def _known_vulnerabilities(root: Path) -> CheckResult:
    result = known_vulnerability_check(root)
    # The full structured evidence is authoritative. Only its text projection
    # is bounded for display; no finding, exception or source proof is dropped.
    findings = result['details'][0]['findings']
    result['details'].extend(_vulnerability_detail(item) for item in findings[:200])
    return CheckResult(**result)


def _vulnerability_detail(item: dict[str, object]) -> dict[str, str]:
    """Flatten one finding and add the ``path``/``message`` keys the text report prints."""
    from .security_data import osv_alias_text
    detail = {key: osv_alias_text(value) if key == 'raw_aliases' and isinstance(value, list)
              else ', '.join(value) if isinstance(value, list) else str(value or '') for key, value in item.items()}
    advisory = detail.get('id', '')
    if detail.get('aliases'):
        advisory = f"{advisory} ({detail['aliases']})"
    message = f"{detail.get('package', '')}=={detail.get('version', '')} {advisory}"
    if detail.get('summary'):
        message += f": {detail['summary']}"
    if detail.get('fixed'):
        message += f"; fixed in {detail['fixed']}"
    detail.setdefault('path', detail.get('manifest', ''))
    detail.setdefault('message', message)
    return detail


OPENGREP_RULES = '.getzilla/sast/rules'
OPENGREP_EXCLUDES = ('.getzilla/sast', 'tests', '**/fixtures/**', 'node_modules', 'vendor', '.getzilla/runtime')


def _unpinned_opengrep(executable: Path) -> str | None:
    """Why ``executable`` must not run: PATH is not trusted, only the pinned release digest is (#39)."""
    import zipfile
    from .release_transport import OPENGREP_ASSETS, OPENGREP_VERSION, _platform_key, _sha256_file, _release_fetch

    pinned = OPENGREP_ASSETS.get(_platform_key())
    actual = _sha256_file(executable)
    if pinned is not None and actual == pinned[1]:
        return None  # Retain the immutable reviewed CI release's original #39 proof.
    from . import opengrep_releases
    try:
        opengrep_releases.verify_active(executable, fetch=_release_fetch, key=_platform_key())
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return (f'{executable} sha256 {actual} is not the reviewed OpenGrep v{OPENGREP_VERSION}; '
                f'fresh upstream integrity verification refused: {exc}; not run')
    return None


@diagnostics.observed('opengrep')
def _opengrep(root: Path) -> CheckResult:
    """Require source/rule coverage and compatible parsing before a clean result."""
    from .security_opengrep import scan_source

    rules = root / OPENGREP_RULES
    if not rules.is_dir():
        return CheckResult('opengrep', 'skip', 'no OpenGrep rules installed')
    executable = find_tool('opengrep')
    if executable is None:
        return CheckResult('opengrep', 'skip', 'opengrep not available')
    refusal = _unpinned_opengrep(Path(executable))
    if refusal:
        return CheckResult('opengrep', 'fail', refusal)
    observed = scan_source(root, rules_root=rules, executable=Path(executable), profile='native')
    command = observed.get('command')
    if observed['outcome'] == 'finding':
        return CheckResult('opengrep', 'fail',
                           f"{observed['finding_count']} taint findings from Getzilla OpenGrep rules",
                           command=command, details=observed['findings'])
    if observed['outcome'] in {'pass', 'not_applicable'}:
        return CheckResult('opengrep', 'pass', observed['summary'], command=command)
    return CheckResult('opengrep', 'fail', observed['summary'], command=command)


@diagnostics.observed('node')
def _node(root: Path, mode: str, *, keep_going=False, blocked_by=None, required_plan=None,
          requested_profiles=('frontend',)) -> list[CheckResult]:
    from .verification_plan import node_checks_required
    if not node_checks_required(root, requested_profiles):
        return []
    results: list[CheckResult] = []
    with _retain_checks(results):
        return _node_checks(root, mode, results, _CheckDispatch(results, mode, keep_going=keep_going,
                             blocked_by=blocked_by, required_plan=required_plan))


def _node_checks(root: Path, mode: str, results: list[CheckResult], dispatch: _CheckDispatch) -> list[CheckResult]:
    package = root / 'package.json'
    if not package.is_file():
        if dispatch.required_plan is not None:
            dispatch.run('package-json', lambda: CheckResult('package-json', 'fail', 'selected Node workspace or explicit frontend profile has no root package.json'))
            return results
        return []
    try:
        scripts, manager, lockfile, _names = node_check_selection(root, mode)
    except (ValueError, OSError, AttributeError):
        dispatch.run('package-json', lambda: CheckResult('package-json', 'fail', 'invalid package.json'))
        return results
    if dispatch.required_plan is not None:
        dispatch.run('package-json', lambda: CheckResult('package-json', 'pass', 'closed package scripts selected'))
    env = None
    if not command_exists('npm'):
        # No Node on this machine: deliver the pinned toolchain instead of skipping (stacks.json).
        toolchain = _node_toolchain(root)
        if not isinstance(toolchain, Toolchain):
            dispatch.run('node-tooling', lambda: CheckResult('node-tooling', 'fail', toolchain.code,
                                                             details=[toolchain.detail('package.json')]))
            return results
        env = toolchain.process_env()
    if dispatch.required_plan is not None:
        dispatch.run('node-tooling', lambda: CheckResult('node-tooling', 'pass', 'existing selected Node tooling is available'))
    node_env = {'env': env} if env else {}
    if mode in {'pr', 'release'}:
        if lockfile is None:
            dispatch.run('node-lockfile', lambda: CheckResult('node-lockfile', 'fail', 'NODE_LOCK_MISSING', details=[{
                'severity': 'error', 'code': 'NODE_LOCK_MISSING', 'path': 'package.json',
                'message': 'no package-lock.json, pnpm-lock.yaml or yarn.lock: dependencies are not reproducible',
            }]))
        else:
            if dispatch.required_plan is not None:
                dispatch.run('node-lockfile', lambda: CheckResult('node-lockfile', 'pass', 'source lock selected'))
            install = _node_install_command(root, manager, lockfile)
            dispatch.run(f'{manager}-install', lambda: _command_check(root, f'{manager}-install', install, 1800, **node_env))
    names = ['lint', 'typecheck', 'test', 'prettier', 'format']
    if mode in {'pr', 'release'}:
        names.append('build')
    prefix = _node_manager_command(manager)
    for name in names:
        if name in scripts:
            command = [*prefix, 'run', name]
            if name == 'test' and manager == 'npm':
                command.append('--')
                command.append('--runInBand') if 'jest' in str(scripts[name]) else None
            dispatch.run(f'{manager}-{name}', lambda: _command_check(root, f'{manager}-{name}', command, 900, **node_env))
    if 'typecheck' not in scripts and (root / 'tsconfig.json').is_file() and mode in {'pr', 'release'}:
        tsc = root / 'node_modules' / '.bin' / ('tsc.cmd' if os.name == 'nt' else 'tsc')
        if tsc.is_file():
            dispatch.run('tsc', lambda: _command_check(root, 'tsc', [str(tsc), '--noEmit'], 900, **node_env))
        else:
            dispatch.run('tsc', lambda: CheckResult('tsc', 'fail', 'tsconfig.json without an installed typescript', details=[{
                'severity': 'error', 'code': 'TYPESCRIPT_NOT_INSTALLED', 'path': 'tsconfig.json',
                'message': 'tsconfig.json is present and no typecheck script exists, but typescript is not installed',
            }]))
    return results


def _node_manager_command(manager: str) -> list[str]:
    # pnpm and yarn come from corepack at the version package.json pins ("packageManager").
    return [manager] if manager == 'npm' or command_exists(manager) else ['corepack', manager]


def _node_install_command(root: Path, manager: str, lockfile: str) -> list[str]:
    prefix = _node_manager_command(manager)
    if manager == 'npm':
        return [*prefix, 'ci']
    if manager == 'pnpm':
        return [*prefix, 'install', '--frozen-lockfile']
    try:
        classic = (root / lockfile).read_text(encoding='utf-8', errors='replace')[:200].find('yarn lockfile v1') >= 0
    except OSError:
        classic = False
    return [*prefix, 'install', '--frozen-lockfile' if classic else '--immutable']


def _node_toolchain(root: Path) -> Toolchain | Blocker:
    stack = load_registry(root).get('node')
    if stack is None or stack.toolchain is None:
        return Blocker('TOOLCHAIN_UNAVAILABLE', 'stacks.json has no Node toolchain')
    version, _source = resolve_version(root, stack.toolchain)
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        # Ranges (engines.node ">=20", .nvmrc "lts/*") are not exact pins: use the tested default.
        version = str(stack.toolchain['default_version'])
    return ensure_toolchain('node', stack.toolchain, version)


@diagnostics.observed('factory-unit')
def _factory_unit(root: Path) -> list[CheckResult]:
    factory_tests = root / 'factory' / 'tests'
    if not (root / 'factory/pyproject.toml').is_file():
        return []
    if not factory_tests.is_dir():
        return [CheckResult('factory-unit', 'fail', 'Factory unit source directory is missing')]
    if sys.version_info < (3, 11):
        return [CheckResult('factory-unit', 'fail',
                            'Factory units require Python >=3.11; Core source checks support Python >=3.10')]
    from . import STACK_DIR
    from .factory_tests import MAX_REPORT_BYTES, decode_document, invocation, source_matches, validate_report
    environment = {'PATH': tool_search_path(os.environ.get('PATH', '')),
                   'PYTHONPATH': os.pathsep.join((str(STACK_DIR), str(root), str(root / 'factory/src')))}
    with tempfile.TemporaryDirectory(prefix='getzilla-factory-unit-') as temporary:
        cache = Path(temporary) / 'pycache'
        cache.mkdir(mode=0o700)
        # Select the private cache before child startup; -B alone still reads old bytecode.
        environment['PYTHONPYCACHEPREFIX'] = str(cache)
        report = Path(temporary) / 'results.json'
        request = Path(temporary) / 'request.json'
        try:
            binding = invocation(root, path=environment['PATH'])
        except (OSError, ValueError, RuntimeError, SyntaxError) as exc:
            return [CheckResult('factory-unit', 'fail', 'Factory invocation unavailable: ' + str(exc))]
        request.write_text(json.dumps(binding, sort_keys=True), encoding='utf-8', newline='\n')
        result = _command_check(
            root, 'factory-unit', [sys.executable, '-P', '-m', 'getzilla.factory_tests',
                                  '--root', str(root), '--request', str(request), '--report', str(report)],
            300, env=environment,
        )
        try:
            if report.stat().st_size > MAX_REPORT_BYTES:
                raise ValueError('Factory result exceeds evidence bound')
            evidence = decode_document(report.read_text(encoding='utf-8'))
            validate_report(evidence, binding)
            if evidence['status'] != result.status or not source_matches(root, binding):
                raise ValueError('Factory result does not match subprocess outcome or current source')
            result.details.insert(0, evidence)
        except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
            result.status = 'fail'
            result.summary += '; Factory result missing or invalid: ' + str(exc)
        return [result]


@diagnostics.observed('focused-python')
def _focused_python(
    root: Path,
    results: list[CheckResult],
    scope: dict[str, object],
    replaced_runner: str = 'python-unittest',
    *,
    dispatch: _CheckDispatch | None = None,
    mode: str = 'fast',
) -> list[CheckResult]:
    """Run the admitted lockstep modules instead of full discovery or coverage measurement.

    Product statements are unchanged by an admitted inventory, so a fresh coverage number
    would restate the last full run. Every omitted check stays visible as an explicit skip,
    including the full-discovery runner this branch replaced — which is named by the caller
    because it is `pytest` in a consumer install and `python-unittest` in this repository.
    """
    targets = [str(target) for target in scope.get('focused_tests', [])]
    if not targets:
        # `python -m unittest` with no module arguments runs zero tests (exit 5, "NO TESTS RAN",
        # on this host's 3.12 and 3.14), so an empty target list must never be recorded as the
        # focused run the profile claims. Refuse with an explanatory check instead.
        results.append(CheckResult(
            'python-focused-unittest',
            'fail',
            'the focused documentation/state profile was given no test module to run',
        ))
        return results
    results.append(CheckResult(
        replaced_runner,
        'skip',
        'focused documentation/state profile runs the admitted lockstep modules '
        'instead of full test discovery',
    ))
    results.append(CheckResult(
        'coverage',
        'skip',
        'focused documentation/state profile does not measure full-suite coverage; '
        'the admitted inventory changes no executed product statement',
    ))
    dispatch = dispatch or _CheckDispatch(results, 'fast', scope)
    dispatch.run('python-focused-unittest', lambda: _command_check(root, 'python-focused-unittest', focused_command(targets), 300))
    _dispatch_factory_unit(root, dispatch)
    dispatch.run('factory-postgres-exit', lambda: CheckResult(
        'factory-postgres-exit',
        'skip',
        'focused documentation/state profile changes no factory runtime path',
    ))
    _dispatch_additional_live(root, mode, dispatch)
    return results


@diagnostics.observed('python')
def _python(root: Path, mode: str = 'fast', scope: dict[str, object] | None = None, *,
            keep_going: bool = False, blocked_by: str | None = None, required_plan=None) -> list[CheckResult]:
    results: list[CheckResult] = []
    try:
        return _python_checks(root, mode, scope, results, keep_going=keep_going, blocked_by=blocked_by,
                              **({'required_plan': required_plan} if required_plan is not None else {}))
    except RunCancelled as exc:
        exc.checks = [*results, *exc.checks]
        completed = getattr(exc, 'core_run', None)
        if completed is not None:
            process = completed.tests
            exc.checks.append(CheckResult('python-unittest', 'pass' if process.returncode == 0 else 'fail',
                                          f'exit={process.returncode}', command=process.command,
                                          stdout=process.stdout[-12000:], stderr=process.stderr[-12000:],
                                          details=[{'stop': diagnostics.stop_details(process), 'cleanup': cleanup_details(process, origin='tests')}]))
            process = exc.result
            exc.checks.append(CheckResult('coverage', 'cancelled', f'cancelled exit={exc.code}',
                                          command=process.command if process else None,
                                          stdout=process.stdout[-12000:] if process else '',
                                          stderr=process.stderr[-12000:] if process else '',
                                          details=[{'stop': diagnostics.stop_details(process if process is not None else exc), 'cleanup': cleanup_details(process if process is not None else exc,
                                              origin=('coverage_export' if process is not None and
                                                      process is getattr(completed, 'coverage_export', None)
                                                      else 'coverage_report' if process is not None else 'process'))}]))
        if not exc.checks or all(item.status in {'pass', 'skip'} for item in exc.checks):
            process = exc.result
            exc.checks.append(CheckResult('python-unittest', 'cancelled', f'cancelled exit={exc.code}',
                                          command=process.command if process else None,
                                          stdout=process.stdout[-12000:] if process else '',
                                          stderr=process.stderr[-12000:] if process else '',
                                          details=[{'stop': diagnostics.stop_details(process if process is not None else exc), 'cleanup': cleanup_details(
                                              process if process is not None else exc, origin='tests')}]))
        raise


def _dispatch_factory_unit(root: Path, dispatch: _CheckDispatch) -> None:
    if (root / 'factory/pyproject.toml').is_file():
        dispatch.batch(['factory-unit'], lambda: _factory_unit(root))


def _python_checks(root: Path, mode: str, scope: dict[str, object] | None, results: list[CheckResult], *,
                   keep_going: bool = False, blocked_by: str | None = None, required_plan=None) -> list[CheckResult]:
    dispatch = _CheckDispatch(results, mode, scope, keep_going=keep_going, blocked_by=blocked_by,
                              required_plan=required_plan)
    dispatch.run('ruff', lambda: _ruff(root))
    dispatch.run('bandit', lambda: _bandit(root))
    focused = bool(scope and scope.get('eligible') is True)
    pilot_tests = root / 'pilot' / 'tests'
    if pilot_tests.is_dir() and any(pilot_tests.glob('test*.py')):
        dispatch.run('pilot-unittest', lambda: _command_check(
                root,
                'pilot-unittest',
                [sys.executable, '-m', 'unittest', 'discover', '-s', 'pilot/tests', '-t', '.', '-v'],
                300,
            ))
    uses_pytest_runner, has_unittest_files = python_check_selection(root)
    if focused:
        # Named here rather than assumed: the focused profile replaces whichever full-discovery
        # runner this tree would have used, and the skip it reports must say so.
        return _focused_python(
            root,
            results,
            scope or {},
            'pytest' if uses_pytest_runner else 'python-unittest',
            dispatch=dispatch,
            mode=mode,
        )
    names = ['pytest' if uses_pytest_runner else 'python-unittest']
    if mode in {'pr', 'release'}:
        names.append('coverage')
    if uses_pytest_runner or has_unittest_files:
        dispatch.batch(names, lambda: _core_python_checks(root, mode, uses_pytest_runner, keep_going=keep_going,
                       **({'required_plan': required_plan} if required_plan is not None else {})))
    elif required_plan is not None:
        for name in names:
            dispatch.run(name, lambda: CheckResult(name, 'skip', 'no native Python discovery inputs'))
    factory_exit = root / 'factory/tests/run_disposable_exit.py'
    installed = (root / '.getzilla' / 'AGBP_SYNC.json').is_file()
    if installed and mode in {'pr', 'release'} and factory_exit.is_file():
        # An installed project runs source and unit checks only: the factory's container/database exit
        # is Getzilla's own infrastructure test. Record the skip instead of leaving it out silently.
        dispatch.run('factory-postgres-exit', lambda: CheckResult('factory-postgres-exit', 'skip', CONSUMER_INFRA_SKIP))
    _dispatch_factory_unit(root, dispatch)
    if not installed and mode in {'pr', 'release'} and factory_exit.is_file():
        dispatch.run('factory-postgres-exit', lambda: (
            CheckResult('factory-postgres-exit', 'skip', 'repository-sandbox has no nested-container/database capability')
            if os.environ.get('GETZILLA_VERIFY_CAPABILITY') == 'repository-sandbox' else
            (_live_cell(root, 'factory', 1500)[0] if (root / 'scripts/getzilla_live.py').is_file() else
             _command_check(root, 'factory-postgres-exit', [sys.executable, str(factory_exit.relative_to(root))],
                            _FACTORY_POSTGRES_EXIT_TIMEOUT_SECONDS))
        ))
    _dispatch_additional_live(root, mode, dispatch)
    return results


def _core_python_checks(root: Path, mode: str, uses_pytest_runner: bool, *, keep_going: bool, required_plan=None) -> list[CheckResult]:
    results: list[CheckResult] = []
    with _retain_checks(results):
        return _core_python_run(root, mode, uses_pytest_runner, results, keep_going=keep_going,
                                **({'required_plan': required_plan} if required_plan is not None else {}))


def _core_python_run(root: Path, mode: str, uses_pytest_runner: bool, results: list[CheckResult], *, keep_going: bool, required_plan=None) -> list[CheckResult]:
    dispatch = _CheckDispatch(results, mode, keep_going=keep_going, required_plan=required_plan)
    if uses_pytest_runner:
        dispatch.run('pytest', lambda: _command_check(root, 'pytest', ['pytest', '-q'], 900))
        if mode in {'pr', 'release'}:
            dispatch.run('coverage', lambda: CheckResult('coverage', 'skip',
                         'pytest runner owns tests; measure unittest trees only' if command_exists('coverage') else 'coverage not available'))
        return results
    if (root / 'tests').is_dir():
        try:
            selection = core_worker_selection(root, mode)
            workers = selection.workers
            core = run_core_tests(root, mode, workers) if workers is not None else None
        except RunnerError as exc:
            try:
                cleanup_attached = hasattr(exc, '_getzilla_cleanup_metadata')
            except BaseException:
                cleanup_attached = True
            message = 'Core runner unavailable; private cleanup details omitted' if cleanup_attached else str(exc)
            results.append(CheckResult('python-unittest', 'fail', message,
                                       details=[{'stop': diagnostics.stop_details(exc), 'cleanup': cleanup_details(exc, origin='tests')}]))
            if mode in {'pr', 'release'}:
                results.append(CheckResult('coverage', 'fail', 'required Core run unavailable'))
            core, workers = None, -1
        if core is not None:
            requested_workers, workers = workers, core.workers
            for name, process in [('python-unittest', core.tests), ('coverage', core.coverage)]:
                if process is not None:
                    backend = core.versions.get('engine', 'pytest-xdist' if workers else 'unittest')
                    exported = getattr(core, 'coverage_export', None) if name == 'coverage' else None
                    cleanup_failed = bool(process.cleanup_error or
                                          isinstance(exported, ProcessResult) and exported.cleanup_error)
                    diagnostic = process.stderr
                    # Capture cleanup can fail while preserving a successful exit.
                    # The failed check must still cross the pytest privacy cut.
                    pytest_failure = (name == 'python-unittest' and backend == 'pytest-xdist'
                                      and (process.returncode != 0 or cleanup_failed))
                    failed_output = process.returncode != 0 or pytest_failure
                    trusted = (_trusted_pytest_metadata(root, process.stdout + '\n' + process.stderr)
                               if name == 'python-unittest' and failed_output else None)
                    if pytest_failure:
                        diagnostic = _core_output_excerpt(process.stderr, failed=True, trusted=trusted, pytest_output=True)
                    if name == 'python-unittest' and process.terminal_state == 'timeout':
                        diagnostic += (
                            '\nInspect the measured CPU allocation, then run a fresh full gate with '
                            'GETZILLA_TEST_WORKERS=N python3 scripts/getzilla_verify.py --mode pr '
                            '(N must fit the available task allocation). This failed run is not reusable evidence.'
                        )
                    reported_command = list(process.command)
                    if name == 'python-unittest' and backend == 'pytest-xdist':
                        for option in ('--getzilla-progress-dir', '--getzilla-progress-nonce'):
                            if option in reported_command:
                                index = reported_command.index(option) + 1
                                if index < len(reported_command):
                                    reported_command[index] = '<private-progress-value>'
                    results.append(CheckResult(
                        name, 'pass' if process.returncode == 0 and not cleanup_failed else 'fail',
                        f'{backend} workers={workers} exit={process.returncode} seconds={process.seconds:.3f} '
                        f'source={selection.source} requested_workers={requested_workers} test_timeout={CORE_TEST_TIMEOUT}s',
                        command=reported_command, stdout=_core_output_excerpt(
                            process.stdout, failed=failed_output,
                            trusted=trusted, pytest_output=pytest_failure),
                        stderr=(diagnostic + ('\ncleanup failed: details omitted' if cleanup_failed else ''))[-12000:],
                        details=[{'severity': 'info', 'path': 'tests',
                                  'message': f'backend={backend}; fresh invocation-owned coverage',
                                  'requested_workers': str(requested_workers),
                                  'actual_workers': str(workers),
                                  'selection_source': selection.source,
                                  'observed_capacity': selection.capacity,
                                  'default_worker_cap': DEFAULT_CORE_WORKER_CAP if selection.source == 'default' else None,
                                  'default_cpu_reserve': DEFAULT_CORE_CPU_RESERVE if selection.source == 'default' else None,
                                  'backend': backend,
                                  'test_timeout_seconds': CORE_TEST_TIMEOUT,
                                  'terminal_state': process.terminal_state,
                                  'stop': diagnostics.stop_details(process),
                                  **({'coverage_export_stop': diagnostics.stop_details(exported)} if exported is not None else {}),
                                  'cleanup': cleanup_details(process,
                                      origin='tests' if name == 'python-unittest' else 'coverage_report',
                                      extra=exported),
                                  **({'progress': _core_progress_details(root, getattr(core, 'progress', None))}
                                     if name == 'python-unittest' else {}),
                                  'versions': json.dumps(core.versions, sort_keys=True),
                                  'coverage': json.dumps(core.coverage_metadata, sort_keys=True)}],
                    ))
        elif workers == -1:
            pass
        elif mode in {'pr', 'release'} and command_exists('coverage'):
            with tempfile.TemporaryDirectory(prefix='grok-legacy-coverage-') as directory:
                coverage_env = {'COVERAGE_FILE': str(Path(directory) / '.coverage')}
                dispatch.run('python-unittest', lambda: _command_check(
                    root, 'python-unittest',
                    ['coverage', 'run', '--rcfile=.coveragerc', '-m', 'unittest', 'discover', '-s', 'tests'],
                    900, env=coverage_env,
                ))
                dispatch.run('coverage', lambda: _command_check(
                    root, 'coverage', ['coverage', 'report', '--rcfile=.coveragerc'],
                    120, env=coverage_env,
                ))
        else:
            results.append(
                _command_check(
                    root,
                    'python-unittest',
                    [sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                    900,
                )
            )
            if mode in {'pr', 'release'}:
                results.append(CheckResult('coverage', 'skip', 'coverage not available'))
    return results


def summarize_verification_report(report: dict[str, object]) -> dict[str, object]:
    """Validate and summarize a bounded, explicitly sample-labelled report.

    This function is deliberately pure: it does not run checks, inspect Git, write a
    receipt, or infer merge authority.
    """
    allowed = {"schema_version", "sample_id", "status", "checks"}
    unknown = set(report) - allowed
    if unknown:
        raise ValueError(f"verification report has unknown fields: {sorted(unknown)}")
    if set(report) != allowed:
        raise ValueError("verification report is missing required fields")
    if report.get("schema_version") != 1 or report.get("status") != "sample_evidence":
        raise ValueError("verification report version or sample status is invalid")
    sample_id = report.get("sample_id")
    checks = report.get("checks")
    if not isinstance(sample_id, str) or not sample_id or len(sample_id) > 128:
        raise ValueError("verification report sample_id is invalid")
    if not isinstance(checks, list) or len(checks) > 64:
        raise ValueError("verification report checks are invalid")
    normalized: list[dict[str, str]] = []
    counts = {status: 0 for status in ("pass", "fail", "skip")}
    for index, item in enumerate(checks):
        if not isinstance(item, dict) or set(item) != {"name", "status", "summary"}:
            raise ValueError(f"verification check {index} has unknown or missing fields")
        name, status, summary = item["name"], item["status"], item["summary"]
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ValueError(f"verification check {index} name is invalid")
        if status not in counts:
            raise ValueError(f"verification check {index} status is invalid")
        if not isinstance(summary, str) or not summary or len(summary) > 512:
            raise ValueError(f"verification check {index} summary is invalid")
        counts[status] += 1
        normalized.append({"name": name, "status": status, "summary": summary})
    overall = "fail" if counts["fail"] else "pass"
    return {
        "sample_id": sample_id,
        "status": overall,
        **counts,
        "checks": normalized,
        "digest": _canonical_digest(report),
    }


def _verify_focused_static_seo_landing(
    root: Path,
    route: dict[str, object] | None,
    active_profiles: list[str],
    git_ranges: GitRangeSelection,
    files: list[str],
    changed_file_inventory: dict[str, object],
    checked_fingerprint: str,
    *,
    record: bool,
    state: _RunState | None = None,
    requested_profiles=None,
) -> dict[str, object]:
    active_change = get_active_change(root) or {}
    change_package = active_change.get('path')
    range_findings = list(git_ranges.findings)
    if route is None:
        range_findings.append({
            'severity': 'error',
            'code': 'route-unavailable',
            'path': '.getzilla/runtime/active-route.json',
            'message': 'focused verification requires an active route',
        })
    scope = select_static_seo_landing_scope(
        files,
        change_package=change_package if isinstance(change_package, str) else None,
        range_findings=range_findings,
        range_base_count=len(git_ranges.bases),
        file_statuses=changed_file_inventory.get('status_records'),
        status_inventory_trusted=(
            changed_file_inventory.get('status_inventory_trusted') is True
        ),
    )
    scope['mode'] = FOCUSED_STATIC_SEO_LANDING_MODE
    state = state or _RunState({})
    required_plan = _capture_required_plan(root, FOCUSED_STATIC_SEO_LANDING_MODE, requested_profiles, state, scope)
    results: list[CheckResult] = state.results if state else []
    if state:
        state.report['verification_scope'] = scope
        state.stage = 'focused-landing'
    results.append(_git_diff_check(root, FOCUSED_STATIC_SEO_LANDING_MODE, git_ranges))
    results.append(_focused_scope_check(scope))
    if scope.get('eligible') is True:
        results.append(_focused_landing_contract(root, scope, required_plan=required_plan))

    if required_plan is not None:
        dispatch = _CheckDispatch(results, FOCUSED_STATIC_SEO_LANDING_MODE, required_plan=required_plan,
                                 blocked_by=None if scope.get('eligible') is True else 'scope-selection')
        for name, callback in [('secret-scan', lambda: _secret_scan(root, files)),
                               ('known-vulnerabilities', lambda: _known_vulnerabilities(root)),
                               ('opengrep', lambda: _opengrep(root)), ('bandit', lambda: _bandit(root))]:
            dispatch.run(name, callback)
        if _semgrep_config(root) is not None:
            dispatch.run('semgrep', lambda: _semgrep(root))
        if _trivy_config_present(root):
            dispatch.run('trivy-config', lambda: _trivy_config(root))
        _dispatch_required_obligations(root, state, dispatch)

    final_fingerprint = tree_fingerprint(root)
    source_stable = final_fingerprint == checked_fingerprint
    results.append(
        CheckResult(
            'source-stability',
            'pass' if source_stable else 'fail',
            'repository fingerprint remained stable'
            if source_stable else 'repository changed during verification checks',
        )
    )
    if state:
        results.append(_task_context_check(root, state))
    if required_plan is not None:
        from .verification_plan import bind_result
        for item in results:
            bind_result(required_plan, item)
    gate = _required_quality_gate(root, FOCUSED_STATIC_SEO_LANDING_MODE, requested_profiles, results, required_plan, scope)
    results.append(CheckResult('quality-gate', gate.status, gate.summary, details=gate.details))
    failures = [result for result in results if result.status == 'fail']
    not_run = {
        'status': 'not_run',
        'reason': 'focused static SEO landing mode checks only scope, diff integrity, and its explicit contract',
    }
    report = state.report if state else {}
    report.update({
        'schema_version': 1,
        'created_at': now_utc(),
        'mode': FOCUSED_STATIC_SEO_LANDING_MODE,
        'profiles': active_profiles,
        'route_id': route.get('route_id') if route else None,
        'tree_fingerprint': final_fingerprint,
        'changed_files': files,
        'changed_file_inventory': changed_file_inventory,
        'verification_scope': scope,
        'spec': not_run,
        'architecture': not_run,
        'governance': not_run,
        'workflow_artifacts': not_run,
        'status': 'pass' if not failures else 'fail',
        'checks': [item.to_dict() for item in results],
        'check_status': 'pass' if not failures else 'fail',
        'terminal_state': 'completed',
        'evidence_status': 'not_recorded',
    })
    with _cancellation() as cancellation:
        cancellation.check()
    if record and route and source_stable and (not state or state.receipt_eligible):
        if state:
            state.stage = 'receipt-publication'
        _record_verification_receipt(root, report, final_fingerprint, interrupt_check=cancellation.check,
                                     expected_context=state.context if state else None)
    return report


def verify_named_tests(root: Path, targets: list[str], *, budget: int = 180) -> dict[str, object]:
    """Observe explicit tests on a clean committed HEAD; never publish a receipt."""
    head_before = git_head(root)
    status = run(['git', 'status', '--porcelain=v1', '--untracked-files=all'], cwd=root, timeout=30)
    if not head_before or status.returncode != 0 or status.stdout:
        raise RunnerError('named smoke requires a clean committed HEAD')
    fingerprint = tree_fingerprint(root)
    cancelled = None
    try:
        process = run_named_tests(root, targets, budget=budget)
    except RunCancelled as exc:
        cancelled = exc
        process = exc.result
        if process is None:
            process = ProcessResult([sys.executable, '-m', 'unittest', *targets], exc.code, terminal_state='cancelled')
    head_after, final_fingerprint = git_head(root), tree_fingerprint(root)
    checks = [CheckResult(
        'python-named-smoke', 'cancelled' if cancelled else ('pass' if process.returncode == 0 and not process.cleanup_error else 'fail'),
        f'exit={process.returncode} seconds={process.seconds:.3f} budget={budget}', command=process.command,
        stdout=process.stdout[-12000:], stderr=(process.stderr + process.cleanup_error)[-12000:],
        details=[{'severity': 'info', 'path': 'tests', 'message': 'observation only; no verification receipt',
                  'stop': diagnostics.stop_details(process)}],
    ), CheckResult(
        'source-stability', 'pass' if head_before == head_after and fingerprint == final_fingerprint else 'fail',
        'repository fingerprint remained stable' if head_before == head_after and fingerprint == final_fingerprint
        else 'repository changed during named smoke',
    )]
    report = {
        'schema_version': 1, 'created_at': now_utc(), 'mode': 'fast', 'profiles': [], 'route_id': None,
        'tree_fingerprint': final_fingerprint, 'fingerprint_before': fingerprint,
        'head_before': head_before, 'head_after': head_after, 'changed_files': [],
        'diagnostics': getattr(process, 'diagnostics', {'status': 'unavailable'}),
        'checks': [check.to_dict() for check in checks],
        'status': 'fail' if any(check.status in {'fail', 'cancelled'} for check in checks) else 'pass',
        'terminal_state': 'cancelled' if cancelled else 'completed', 'evidence_status': 'not_recorded',
    }
    if cancelled:
        report['cancellation'] = {'signal': signal.Signals(cancelled.signal_number).name, 'stage': 'python-named-smoke'}
        raise VerificationCancelled(cancelled.signal_number, report)
    return report


@diagnostics.observed('diff-risk-check')
def _diff_risk_check(root: Path, route: dict[str, object] | None, mode: str, git_ranges: GitRangeSelection,
                     fingerprint: str) -> tuple[CheckResult, dict[str, object]]:
    """Rederive and persist the same source-bound plan exposed before dispatch."""
    if not git_ranges.bases and mode not in {'pr', 'release'}:
        return CheckResult('diff-risk', 'skip', 'no comparison base in this mode; assessment remains provisional'), {'status': 'not_run'}
    from .review_plan import assess, reconcile_route
    previous = list((route or {}).get('required_evidence', []))
    try:
        current = reconcile_route(root, selection=git_ranges, fingerprint=fingerprint) if route else assess(root, None, git_ranges, fingerprint)
    except (OSError, ValueError, RuntimeError) as exc:
        return CheckResult('diff-risk', 'fail', f'DIFF_RISK_UNAVAILABLE: {_failure_message(exc)}'), {'status': 'error', 'gaps': [str(exc)]}
    assessment = current['risk_assessment']
    metadata = {**assessment, 'status': 'computed' if assessment['status'] == 'complete' else 'incomplete',
                'effective_risk': current['risk'], 'diff_risk': current['risk'],
                'route_risk': (route or {}).get('risk'), 'review_plan_digest': current['review_plan']['digest'],
                'added_reviewers': [item for item in current['review_agents'] if item not in (route or {}).get('review_agents', [])],
                'added_evidence': [item for item in current['required_evidence'] if item not in previous], 'waived_evidence': []}
    if assessment['status'] != 'complete':
        return CheckResult('diff-risk', 'fail', 'DIFF_RISK_INCOMPLETE: ' + '; '.join(assessment['gaps'])), metadata
    summary = f"diff risk {current['risk']}; exact-source review plan {current['review_plan']['digest'][:12]}"
    if route and mode in {'pr', 'release'} and metadata['added_evidence']:
        missing = validate_evidence(root, current, current_fingerprint=fingerprint)
        metadata['missing_evidence'] = missing
        if missing:
            return CheckResult('diff-risk', 'fail', 'ROUTE_ESCALATED_EVIDENCE_MISSING: ' + '; '.join(missing)), metadata
    return CheckResult('diff-risk', 'pass', summary), metadata


@diagnostics.observed('cost-guard-check')
def _cost_guard_check(root: Path, route: dict[str, object] | None, mode: str,
                      git_ranges: GitRangeSelection) -> tuple[CheckResult, dict[str, object]]:
    """Paid or unbounded operations need a budget contract and a tested bound before pr/release."""
    from . import cost_guard
    from .project_ingestion import IngestionError
    from .receipts import _exact_head
    from .util import runtime_dir
    bases = sorted({base.comparison_base_sha for base in git_ranges.bases})
    if not bases and not cost_guard.route_has_cost_signal(route):
        return CheckResult('cost-guard', 'skip', 'no comparison base and no paid-operation signal'), {'status': 'not_run'}
    active = get_active_change(root) or {}
    package = root / str(active['path']) if active.get('path') else None
    try:
        report = cost_guard.evaluate(root, route, mode, bases, 'HEAD', package)
        head = _exact_head(root) or 'HEAD'
        cost_guard.write_state(runtime_dir(root), head, report.findings)
    except (IngestionError, OSError, ValueError) as exc:
        status = 'fail' if mode in {'pr', 'release'} else 'skip'
        return CheckResult('cost-guard', status, f'COST_GUARD_UNAVAILABLE: {_failure_message(exc)}'), {
            'status': 'error', 'error': _failure_message(exc)}
    details = [{'severity': 'error' if report.status == 'fail' else 'warning', 'path': '.', 'code': problem.split(':', 1)[0],
                'message': problem} for problem in report.problems[:20]]
    return CheckResult('cost-guard', report.status, report.summary, details=details), report.to_dict()


@diagnostics.observed('eu-ai-act-check')
def _eu_ai_act_check(root: Path, mode: str, git_ranges: GitRangeSelection) -> tuple[CheckResult, dict[str, object]]:
    """Optional EU AI Act evidence gate; silent unless the compliance:eu-ai-act component is installed."""
    from . import eu_ai_act
    from .project_ingestion import IngestionError
    if not eu_ai_act.enabled(root):
        return CheckResult('eu-ai-act', 'skip', 'EU AI Act component not installed'), {'status': 'not_installed'}
    bases = sorted({base.comparison_base_sha for base in git_ranges.bases})
    try:
        report = eu_ai_act.evaluate(root, mode, bases, 'HEAD')
    except (IngestionError, OSError, ValueError) as exc:
        status = 'fail' if mode in {'pr', 'release'} else 'skip'
        return CheckResult('eu-ai-act', status, f'EU_AI_ACT_UNAVAILABLE: {_failure_message(exc)}'), {
            'status': 'error', 'error': _failure_message(exc)}
    details = [{'severity': 'error' if report.status == 'fail' else 'warning', 'path': '.', 'code': problem.split(':', 1)[0],
                'message': problem} for problem in report.problems[:20]]
    return CheckResult('eu-ai-act', report.status, report.summary, details=details), report.to_dict()


@diagnostics.observed('hook-health-check')
def _hook_health_check(root: Path, route: dict[str, object] | None, mode: str,
                       diff_metadata: dict[str, object]) -> tuple[CheckResult, dict[str, object]]:
    """Hooks that failed open during this route mean policy did not run; high risk does not pass that."""
    from .hook_health import route_degraded_events, summary
    events = route_degraded_events(root, route)
    metadata = summary(events)
    if not events:
        return CheckResult('hook-health', 'pass', 'no hook failed open during this route'), metadata
    effective = str(diff_metadata.get('effective_risk') or (route or {}).get('risk') or 'low')
    message = (f"{len(events)} hook call(s) failed open during this route ({', '.join(metadata['by_hook'])}); "
               'Getzilla policy did not run for them')
    if effective == 'high' and mode in {'pr', 'release'}:
        return CheckResult('hook-health', 'fail', (
            f'HOOKS_DEGRADED_ON_HIGH_RISK: {message}. Fix the hook error, start a new route and verify the '
            'high-risk change again under working hooks.')), metadata
    return CheckResult('hook-health', 'pass', message, details=[
        {'severity': 'warning', 'path': '.getzilla/runtime/hook-events.jsonl', 'code': 'hook-degraded', 'message': message}]), metadata


CONSUMER_INFRA_SKIP = 'consumer source-only/unit-only policy prohibits infrastructure execution'
CI_BASELINE_SKIP = 'CI runner: the workflow baseline belongs to the agent machine; security tools are checked by their own steps'
NOT_INSTALLED_SKIP = 'not an installed Getzilla project (no .getzilla/AGBP_SYNC.json): the baseline is checked where Getzilla was installed'


@diagnostics.observed('workflow-baseline-check')
def _workflow_baseline_check(root: Path, mode: str) -> tuple[CheckResult, dict[str, object]]:
    """Pinned Superpowers, BMAD and Spec Kit must be installed for this user and connected to this project."""
    import os
    from .baseline import detect_agent, inspect
    from .release_transport import home_dir
    if os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true':
        return CheckResult('workflow-baseline', 'skip', CI_BASELINE_SKIP), {'status': 'not_run', 'reason': 'ci'}
    if not (root / '.getzilla' / 'AGBP_SYNC.json').is_file():
        return CheckResult('workflow-baseline', 'skip', NOT_INSTALLED_SKIP), {'status': 'not_run', 'reason': 'source'}
    agent = detect_agent(root)
    try:
        status = inspect(home_dir(), root, agent)
    except (OSError, ValueError, KeyError) as exc:
        return CheckResult('workflow-baseline', 'fail' if mode in {'pr', 'release'} else 'skip',
                           f'WORKFLOW_BASELINE_UNAVAILABLE: {_failure_message(exc)}'), {'status': 'error'}
    metadata = {'status': 'complete' if status.complete else 'incomplete', 'agent': agent, **status.to_dict()}
    workflow_missing = [item for item in status.missing if not item.startswith('SECURITY_BASELINE_MISSING')]
    if not workflow_missing:
        return CheckResult('workflow-baseline', 'pass', f'bound Superpowers, BMAD and Spec Kit connected for {agent}; freshness={status.details.get("freshness", "not_checked")}'), metadata
    message = (', '.join(workflow_missing) + '. Install: scripts/getzilla_update.py --only baseline; connect: '
               f'scripts/getzilla_baseline.py apply --project . --agent {agent}')
    if mode in {'pr', 'release'}:
        return CheckResult('workflow-baseline', 'fail', message), metadata
    return CheckResult('workflow-baseline', 'pass', 'will fail pr/release: ' + message, details=[
        {'severity': 'warning', 'path': '.', 'code': 'workflow-baseline-missing', 'message': message}]), metadata


def verify(root: Path, mode: str = 'pr', profiles: list[str] | None = None, record: bool = True, *,
           keep_going: bool = False) -> dict[str, object]:
    report = {
        'schema_version': 1, 'created_at': now_utc(), 'mode': mode,
        'profiles': profiles or ['base'], 'route_id': None, 'tree_fingerprint': None,
        'requested_profiles': None if profiles is None else list(profiles),
        'changed_files': [], 'changed_file_inventory': {}, 'checks': [],
        'spec': {}, 'architecture': {}, 'governance': {}, 'workflow_artifacts': {},
        'status': 'fail', 'terminal_state': 'interrupted', 'evidence_status': 'not_recorded',
    }
    state = _RunState(report)
    with diagnostics.session(root, 'verify', report), _cancellation() as cancellation:
        try:
            result = _verification_run(root, mode, profiles, record, state, cancellation, keep_going=keep_going)
            if record:
                from .metrics_journal import record_verify
                record_verify(root, result)
            return result
        except (RunCancelled, KeyboardInterrupt, SystemExit) as exc:
            number = getattr(exc, 'signal_number', None)
            if isinstance(exc, KeyboardInterrupt):
                number = signal.SIGINT
            elif number is None and isinstance(exc, SystemExit) and type(exc.code) is int:
                number = {130: signal.SIGINT, 143: signal.SIGTERM, -2: signal.SIGINT, -15: signal.SIGTERM}.get(exc.code)
            if number is None:
                raise
            state.results.extend(getattr(exc, 'checks', []))
            report.setdefault('check_status', 'fail' if any(item.status == 'fail' for item in state.results) else 'incomplete')
            report['status'] = 'fail'
            report['terminal_state'] = 'cancelled'
            report['cancellation'] = {'signal': signal.Signals(number).name, 'stage': state.stage}
            retained_checks = report['checks'] or [item.to_dict() for item in state.results]
            report['checks'] = retained_checks + [CheckResult(
                'verification-interrupted', 'cancelled', f'verification cancelled during {state.stage}',
                details=[{'severity': 'info', 'path': '.', 'message': f'signal={number}; stage={state.stage}'}],
            ).to_dict()]
            # One terminal publication attempt. Signals remain deferred and idempotent here.
            try:
                fingerprint = tree_fingerprint(root)
                stable = report['tree_fingerprint'] in (None, fingerprint)
                report['tree_fingerprint'] = fingerprint
                if record and state.receipt_eligible and report['route_id'] and stable:
                    _record_verification_receipt(root, report, fingerprint, expected_context=state.context)
            except (OSError, RuntimeError, TypeError, ValueError) as cleanup:
                report['evidence_status'] = 'failed' if state.receipt_eligible else 'not_recorded'
                report['checks'].append(CheckResult('cancellation-finalization', 'fail', _failure_message(cleanup)).to_dict())
            raise VerificationCancelled(number, report) from None


def _required_quality_gate(root, mode, profiles, results, required_plan, docs_scope=None):
    """Failed admission cannot supply fresh bindings; other paths still rederive them."""
    from .verification_plan import current_required_plan
    from .expanded_security import validate_data_source
    hard_failure = any(isinstance(item, CheckResult) and item.status in {'fail', 'cancelled'} for item in results)
    current = None
    if not hard_failure:
        try:
            observed = current_required_plan(root, mode=mode, profiles=profiles, docs_scope=docs_scope)
            if observed == required_plan:
                current = observed['binding']
        except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
            pass
    decision = evaluate_quality_gate(mode=mode, checks=results, docs_scope=docs_scope,
        required_plan=required_plan, current_binding=current, now_utc=datetime.now(timezone.utc),
        data_source_validator=lambda source, *, now: validate_data_source(source, root=root, now=now))
    if hard_failure:
        decision.details.append({'severity': 'info', 'code': 'required-plan-revalidation-unexecuted',
            'path': 'required_plan', 'message': 'Final plan revalidation not executed after a prior failed or cancelled check; current binding unavailable.'})
    return decision


def _capture_required_plan(root, mode, profiles, state, docs_scope=None):
    from .verification_plan import current_required_plan
    try:
        plan = current_required_plan(root, mode=mode, profiles=profiles, docs_scope=docs_scope)
    except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
        state.receipt_eligible = False
        state.results.append(CheckResult('required-plan', 'fail', 'current required plan cannot be established'))
        return None
    state.required_plan = plan
    state.report['required_plan'] = plan
    state.results.append(CheckResult('required-plan', 'pass', 'current source-bound obligations captured before dispatch'))
    return plan
def _language_quality_report(root: Path, base: str | None, cancellation):
    results = run_language_quality(root, base, cancellation=cancellation)
    return ({'schema_version': 1, 'status': 'observed', 'results': results},
            [CheckResult(**check) for check in language_quality_checks(results)])


def _verification_run(root: Path, mode: str, profiles: list[str] | None, record: bool,
                      state: _RunState, cancellation, *, keep_going: bool = False) -> dict[str, object]:
    report = state.report
    cancellation.check()
    checked_fingerprint = tree_fingerprint(root)
    route = get_active_route(root)
    if diagnostics.current():
        diagnostics.current().bind_source(checked_fingerprint, session_id=(route or {}).get('session_id'))
    from .continuity import context_binding, legacy_evidence_allowed, scope_gaps
    state.context_route_id = (route or {}).get('route_id')
    if route and not legacy_evidence_allowed(route):
        try:
            state.context = context_binding(root, route)
            report['continuity'] = state.context
            gaps = scope_gaps(root, route)
            if gaps:
                raise ValueError('; '.join(gaps))
        except (ValueError, RuntimeError, OSError, TypeError, KeyError) as exc:
            state.context_error = str(exc)
    initial_context = _task_context_check(root, state)
    if initial_context.status == 'fail':
        state.results.append(initial_context)
    active_profiles = profiles or (route.get('quality_profiles', ['base']) if route else ['base'])
    report.update(tree_fingerprint=checked_fingerprint, route_id=route.get('route_id') if route else None,
                  profiles=active_profiles)
    git_ranges = _git_range_selection(root, route, 'pr' if mode == 'fast' and route and route.get('delivery_lane') == 'light' else mode)
    files, changed_file_inventory = _changed_file_inventory(
        root,
        route,
        mode,
        git_ranges,
    )
    report.update(changed_files=files, changed_file_inventory=changed_file_inventory)
    cancellation.check()

    if mode == FOCUSED_STATIC_SEO_LANDING_MODE:
        return _verify_focused_static_seo_landing(
            root,
            route,
            active_profiles,
            git_ranges,
            files,
            changed_file_inventory,
            checked_fingerprint,
            record=record,
            state=state,
            requested_profiles=profiles,
        )

    # Admission precedes package checks: the prompt lane is provisional until source is measured.
    diff_check, diff_metadata = _diff_risk_check(root, route, mode, git_ranges, checked_fingerprint)
    route = get_active_route(root) if route else None
    if route and (route.get('delivery_lane') == 'light' or route.get('light_lane_candidate') or 'light_diff' in route):
        from .light_lane import inspect_light_diff
        from .review_plan import escalate_route
        light = inspect_light_diff(root, sorted({item.comparison_base_sha for item in git_ranges.bases}),
            risk=str(diff_metadata.get('effective_risk', 'high')),
            complete=diff_metadata.get('status') == 'computed' and not diff_metadata.get('gaps') and not git_ranges.findings)
        if light['admitted']:
            route = {**route, 'delivery_lane': 'light', 'light_diff': light, 'light_lane_candidate': True,
                     'review_agents': route['review_agents'], 'required_evidence': route['required_evidence']}
        else:
            full = escalate_route({**route, 'delivery_lane': 'light'}, str(diff_metadata.get('effective_risk', route.get('risk', 'low'))), root, force_full=True)
            route = {**route, 'delivery_lane': 'full', 'light_diff': light, 'light_lane_candidate': True,
                     'review_agents': full['review_agents'], 'required_evidence': full['required_evidence'],
                     'allowed_agents': unique_ordered([*(route.get('allowed_agents') or []), *full['review_agents']])}
        update_route(root, **{key: route[key] for key in ('delivery_lane', 'light_diff', 'light_lane_candidate', 'review_agents', 'required_evidence', 'allowed_agents')})
        report['light_diff'] = light
    spec_check, spec_metadata = _change_specs(root, files, route, mode, ranges=git_ranges)
    report['spec'] = spec_metadata
    cancellation.check()
    if mode in _RANGE_MODES - {FOCUSED_STATIC_SEO_LANDING_MODE}:
        status_records, status_trusted = _docs_state_status_inventory(root, git_ranges)
    else:
        status_records, status_trusted = None, None
    docs_scope = select_docs_state_scope(
        mode,
        files,
        range_findings=list(git_ranges.findings),
        range_base_count=len(git_ranges.bases),
        file_statuses=status_records,
        status_inventory_trusted=status_trusted,
        route_present=route is not None,
        available_test_targets=[
            target for target in FOCUSED_TEST_TARGETS if (root / target).is_file()
        ],
    )
    required_plan = _capture_required_plan(root, mode, profiles, state, docs_scope)
    state.stage = 'architecture-inputs'
    architecture_inputs = _architecture_preflight_check(root)
    preflight_failed = architecture_inputs.status == 'fail'
    # Retain the primary refusal before any subsequent consumer can cancel.
    state.results.append(architecture_inputs)
    dispatch = _CheckDispatch(state.results, mode, docs_scope, keep_going=keep_going, required_plan=required_plan)
    if required_plan is None and mode in {'pr', 'release'} and not keep_going:
        dispatch.blocked_by = 'required-plan'
    if required_check_refused(architecture_inputs, mode=mode, docs_scope=docs_scope) and not keep_going:
        dispatch.blocked_by = architecture_inputs.name
    dispatch.add(_docs_state_scope_check(docs_scope))
    dispatch.add(spec_check)
    if spec_check.status == 'fail':
        state.receipt_eligible = False
        report['receipt_refusal'] = 'change specification cannot provide the current binding'
    if preflight_failed:
        state.receipt_eligible = False
        report['receipt_refusal'] = 'architecture input preflight failed'
        architecture_inputs.details.append({
            'severity': 'info', 'code': 'receipt-not-recorded', 'path': '.getzilla/runtime/receipts',
            'message': 'receipt not recorded: refused architecture inputs cannot provide the current binding',
        })
        architecture_check = CheckResult('architecture', 'fail', architecture_inputs.summary, details=architecture_inputs.details)
        architecture_metadata = {
            'configured': True, 'status': 'fail', 'error': architecture_inputs.summary,
            'receipt_status': 'not_recorded', 'receipt_reason': report['receipt_refusal'],
        }
        dispatch.add(architecture_check)
        if mode in {'pr', 'release'}:
            dispatch.blocked_by = 'architecture-inputs'
            governance_check = dispatch.run('governance', None)
        else:
            governance_check = dispatch.add(CheckResult('governance', 'skip', 'architecture input preflight failed; not executed'))
        governance_metadata = {'configured': True, 'status': 'not_run'}
    else:
        if dispatch.blocked_by:
            architecture_check = dispatch.run('architecture', None)
            architecture_metadata = {'status': 'not_run'}
        else:
            architecture_check, architecture_metadata = _architecture_check(root, route, _trusted_ranges=git_ranges)
            dispatch.add(architecture_check)
        if dispatch.blocked_by:
            governance_check = dispatch.run('governance', None)
            governance_metadata = {'status': 'not_run'}
        else:
            governance_check, governance_metadata = _governance_check(root, route, architecture_metadata,
                                                                     _trusted_ranges=git_ranges)
            dispatch.add(governance_check)
    if architecture_check.status == 'fail' or governance_check.status == 'fail':
        state.receipt_eligible = False
        report.setdefault('receipt_refusal', 'architecture or governance cannot provide the current binding')
    report.update(docs_state_scope=docs_scope, architecture=architecture_metadata)
    cancellation.check()
    if dispatch.blocked_by:
        workflow_check = dispatch.run('workflow-artifacts', None)
        workflow_metadata = {'status': 'not_run'}
    else:
        workflow_check, workflow_metadata = _workflow_artifacts_check(
            root, route, get_active_change(root), checked_fingerprint,
        )
        dispatch.add(workflow_check)
    report.update(governance=governance_metadata, workflow_artifacts=workflow_metadata)
    cancellation.check()
    if not dispatch.blocked_by:
        for check in _agent_eval_checks(root, mode):
            dispatch.add(check)
    cancellation.check()

    results = state.results
    state.stage = 'diff-risk'
    cancellation.check()
    if mode == 'fast' and route and route.get('light_lane_candidate') and not (route.get('light_diff') or {}).get('admitted'):
        dispatch.add(CheckResult('light-lane', 'fail', 'Measured diff requires the full PR gate and review floor'))
    dispatch.add(diff_check)
    report['diff_risk'] = diff_metadata
    state.stage = 'cost-guard'
    cancellation.check()
    cost_check, cost_metadata = _cost_guard_check(root, route, mode, git_ranges)
    dispatch.add(cost_check)
    report['cost_guard'] = cost_metadata
    eu_check, eu_metadata = _eu_ai_act_check(root, mode, git_ranges)
    dispatch.add(eu_check)
    report['eu_ai_act'] = eu_metadata
    hook_check, hook_metadata = _hook_health_check(root, route, mode, diff_metadata)
    dispatch.add(hook_check)
    report['hook_health'] = hook_metadata
    baseline_check, baseline_metadata = _workflow_baseline_check(root, mode)
    dispatch.add(baseline_check)
    report['workflow_baseline'] = baseline_metadata
    state.stage = 'repository'
    dispatch.run('git-diff-check', lambda: _git_diff_check(root, mode, git_ranges))
    # Preserve the successful report inventory order while authority checks run first.
    results.insert(1, results.pop())
    for name, check in (('secret-scan', _secret_scan), ('contract-structure', _contracts), ('sql-safety', _sql_safety)):
        cancellation.check()
        dispatch.run(name, lambda: check(root, files))
    if 'php' in active_profiles or 'bitrix' in active_profiles or any(rel.endswith('.php') for rel in files):
        state.stage = 'php'
        cancellation.check()
        dispatch.run('php-lint', lambda: _php_lint(root, files))
        for check in _composer(root, mode, keep_going=keep_going, blocked_by=dispatch.blocked_by, required_plan=required_plan):
            dispatch.add(check)
    if 'bitrix' in active_profiles:
        state.stage = 'bitrix'
        cancellation.check()
        dispatch.run('bitrix', lambda: _bitrix(root, files))
    from .verification_plan import node_checks_required
    if node_checks_required(root, profiles):
        state.stage = 'node'
        cancellation.check()
        for check in _node(root, mode, keep_going=keep_going, blocked_by=dispatch.blocked_by,
                           required_plan=required_plan, requested_profiles=profiles):
            dispatch.add(check)
    state.stage = 'stacks'
    cancellation.check()
    # Every detected stack is either checked or reported as not verified (stacks.json).
    if dispatch.blocked_by:
        dispatch.run('stacks', None)
        stack_metadata: dict[str, object] = {'status': 'not_run'}
    else:
        stack_results, stack_metadata = stack_checks(root, mode, files, make=CheckResult, command=_command_check, required_plan=required_plan)
        for check in stack_results:
            dispatch.add(check)
    report['stacks'] = stack_metadata
    state.stage = 'semgrep'
    cancellation.check()
    if _semgrep_config(root) is not None:
        dispatch.run('semgrep', lambda: _semgrep(root))
    state.stage = 'trivy'
    cancellation.check()
    if _trivy_config_present(root):
        dispatch.run('trivy-config', lambda: _trivy_config(root))
    state.stage = 'known-vulnerabilities'
    cancellation.check()
    dispatch.run('known-vulnerabilities', lambda: _known_vulnerabilities(root))
    state.stage = 'expanded-security'
    from .verification_plan import SECURITY_FAMILIES
    dispatch.batch([name for name in SECURITY_FAMILIES if name != 'known-vulnerabilities'],
                   lambda: [CheckResult(**item) for item in expanded_security_checks(root)])
    state.stage = 'opengrep'
    cancellation.check()
    dispatch.run('opengrep', lambda: _opengrep(root))
    state.stage = 'verification-tools'
    for name, callback in planned_tool_checks(root, mode, make=CheckResult):
        cancellation.check()
        dispatch.run(name, callback)
    state.stage = 'language-quality'
    cancellation.check()
    if dispatch.blocked_by:
        language_report = {'schema_version': 1, 'status': 'not_run', 'results': [],
                           'reason': 'required verification refused: ' + dispatch.blocked_by}
    else:
        bases = {item.comparison_base_sha for item in git_ranges.bases}
        language_base = next(iter(bases)) if len(bases) == 1 and not git_ranges.findings else None
        language_report, language_checks = _language_quality_report(root, language_base, cancellation)
        for check in language_checks:
            dispatch.add(check)
    report.setdefault('advisory', {})['lqg'] = language_report
    cancellation.check()
    state.stage = 'python'
    cancellation.check()
    if preflight_failed and mode not in {'pr', 'release'}:
        results.append(CheckResult('python-unittest', 'skip', 'architecture input preflight failed; discovery not started'))
        if (root / 'factory/tests').is_dir():
            results.append(CheckResult('factory-unit', 'skip', 'architecture input preflight failed; not started'))
    else:
        results.extend(_python(root, mode, docs_scope, keep_going=keep_going, blocked_by=dispatch.blocked_by, required_plan=required_plan))
    if required_plan is not None:
        references = sorted({reference for item in required_plan['obligations'] if item['check_id'] == 'criterion-tests'
                             for reference in item['expected_tests']})
        if references:
            from .criterion_tests import run_required_tests
            dispatch.run('criterion-tests', lambda: CheckResult(**run_required_tests(root, references)))
    state.stage = 'source-stability'
    try:
        final_fingerprint = tree_fingerprint(root)
    except (OSError, RuntimeError, ValueError) as exc:
        results.append(CheckResult('source-stability', 'fail', _failure_message(exc)))
        final_fingerprint = None
    source_stable = final_fingerprint == checked_fingerprint
    results.append(
        CheckResult(
            "source-stability",
            "pass" if source_stable else "fail",
            (
                "repository fingerprint remained stable"
                if source_stable
                else "repository changed during verification checks"
            ),
        )
    )
    results.append(_task_context_check(root, state))
    if required_plan is not None:
        from .verification_plan import bind_result
        for item in results:
            bind_result(required_plan, item)
    quality_gate = _required_quality_gate(root, mode, profiles, results, required_plan, docs_scope)
    results.append(
        CheckResult(
            "quality-gate",
            quality_gate.status,
            quality_gate.summary,
            details=quality_gate.details,
        )
    )

    failures = [result for result in results if result.status in {'fail', 'cancelled'}]
    report.update({
        'schema_version': 1,
        'created_at': now_utc(),
        'mode': mode,
        'profiles': active_profiles,
        'route_id': route.get('route_id') if route else None,
        'tree_fingerprint': final_fingerprint,
        'changed_files': files,
        'changed_file_inventory': changed_file_inventory,
        # `verification_scope` stays reserved for the landing profile, which is a distinct
        # explicit mode; the two profiles must never share one report key.
        'docs_state_scope': docs_scope,
        'spec': spec_metadata,
        'architecture': architecture_metadata,
        'governance': governance_metadata,
        'workflow_artifacts': workflow_metadata,
        'status': 'pass' if not failures else 'fail',
        'check_status': 'pass' if not failures else 'fail',
        'checks': [item.to_dict() for item in results],
        'terminal_state': 'completed',
        'evidence_status': 'not_recorded',
    })
    cancellation.check()
    if record and state.receipt_eligible and route and governance_check.status != 'fail' and source_stable:
        state.stage = 'receipt-publication'
        _record_verification_receipt(root, report, final_fingerprint, interrupt_check=cancellation.check,
                                     expected_context=state.context)
    cancellation.check()
    return report


def _live_cell(root: Path, cell: str, budget: int) -> list[CheckResult]:
    from .live_evidence import CELLS
    import uuid
    names = CELLS[cell]
    output = root / '.getzilla/runtime/live' / (cell + '-' + uuid.uuid4().hex)
    result = _command_check(root, names[0], [sys.executable, 'scripts/getzilla_live.py', '--cell', cell,
                            '--output', str(output), '--timeout-seconds', str(budget)],
                            budget + 300, termination_grace=180)
    try:
        record = json.loads((output / 'manifest.json').read_text(encoding='utf-8'))
        checks = record['checks']
        from .live_evidence import evidence_name, _held_bytes
        files = record.get('files')
        if (not isinstance(files, list) or not 1 <= len(files) <= 128
                or any(not isinstance(row, dict) or set(row) != {'path', 'sha256'}
                       or not isinstance(row['path'], str) or Path(row['path']).name != row['path']
                       or not evidence_name(row['path']) for row in files)
                or len({row['path'] for row in files}) != len(files)):
            raise ValueError('live retained-file index is incomplete or malformed')
        for row in files:
            if hashlib.sha256(_held_bytes(output / row['path'])).hexdigest() != row['sha256']:
                raise ValueError('live retained component bytes changed')
        from .live_evidence import read_document, valid_binding, validate_components, _producer_digest
        binding = read_document(output / 'invocation.json')
        if (not valid_binding(binding) or record.get('binding') != binding
                or binding['cell'] != cell or binding['head'] != git_head(root)
                or binding['tree'] != _git(root, ['rev-parse', 'HEAD^{tree}']).decode('ascii').strip()
                or binding['producer_sha256'] != _producer_digest(root, cell)
                or cell != 'factory' and not validate_components(output, cell, binding)):
            raise ValueError('live source or sealed component identity differs')
        if (record.get('status') != 'pass' or {item['id'] for item in checks} != set(names)
                or len(checks) != len(names) or any(item['status'] != 'pass' for item in checks)):
            raise ValueError('live component evidence did not pass')
    except (OSError, ValueError, KeyError, TypeError):
        result.status = 'fail'
        result.summary += '; live evidence missing or failed'
    return [CheckResult(name, result.status, result.summary, command=result.command,
                        stdout=result.stdout, stderr=result.stderr,
                        details=[{'kind': 'live-acceptance-observation', 'cell': cell,
                                  'manifest': str(output / 'manifest.json'), 'authority': 'local observation only'}])
            for name in names]


def _dispatch_additional_live(root: Path, mode: str, dispatch: _CheckDispatch) -> None:
    if mode not in {'pr', 'release'} or not (root / 'scripts/getzilla_live.py').is_file():
        return
    installed = (root / '.getzilla/AGBP_SYNC.json').is_file()
    for cell, names, budget in (('trust-ci', ['trust-ci-postgres', 'trust-ci-postgres-restart'], 1200),
                                ('lifecycle', ['factory-lifecycle'], 900)):
        if installed or os.environ.get('GETZILLA_VERIFY_CAPABILITY') == 'repository-sandbox':
            reason = CONSUMER_INFRA_SKIP if installed else 'repository-sandbox has no nested-container/database capability'
            dispatch.batch(names, lambda names=names, reason=reason: [CheckResult(name, 'skip', reason) for name in names])
        else:
            dispatch.batch(names, lambda cell=cell, budget=budget: _live_cell(root, cell, budget))


def _expanded_security_checks(root: Path) -> list[CheckResult]:
    from .expanded_security import run_checks
    return [CheckResult(**item) for item in run_checks(root)]


def _dispatch_required_obligations(root: Path, state: _RunState, dispatch) -> None:
    plan = state.required_plan
    if plan is None:
        return
    for name in ('python-unittest', 'coverage'):
        selected = [item for item in plan['obligations'] if item['check_id'] == name]
        if selected and all(item['applicability'] == 'not_applicable' for item in selected) and not any(
                check.name == name for check in state.results):
            def observe_absence(name=name):
                uses_pytest, has_unittest = python_check_selection(root)
                return CheckResult(name, 'fail' if uses_pytest or has_unittest else 'skip',
                    'Python discovery inputs changed after planning' if uses_pytest or has_unittest
                    else 'no native Python discovery inputs', details=[{
                        'kind': 'native-python-applicability', 'uses_pytest': uses_pytest,
                        'has_unittest_files': has_unittest}])
            dispatch.run(name, observe_absence)
    names = sorted({item['check_id'] for item in plan['obligations'] if item['check_id'].startswith('security-')})
    if names:
        dispatch.batch(names, lambda: _expanded_security_checks(root))
    refs = sorted({ref for item in plan['obligations'] if item['check_id'] == 'criterion-tests'
                   for ref in item['expected_tests']})
    if refs:
        from .criterion_tests import run_required_tests
        dispatch.run('criterion-tests', lambda: CheckResult(**run_required_tests(root, refs)))
