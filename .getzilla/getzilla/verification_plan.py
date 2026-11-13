"""One required plan embedded in the native verification report and receipt.

These bindings are local observations, not an independent security attestation.
Consumers rederive policy and source before accepting a stored report.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import zipimport
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .util import git_head, run, tree_fingerprint

MAX_OBLIGATIONS = 4096
MAX_PLAN_BYTES = 2 * 1024 * 1024
FOCUSED_MODE = 'focused-static-seo-landing'
SECURITY_FAMILIES = {'security-inventory': 'inventory', 'known-vulnerabilities': 'vulnerabilities',
    'security-kev': 'known-exploitation', 'security-epss': 'exploit-prediction',
    'security-malicious-packages': 'malicious-packages', 'security-licenses': 'licenses',
    'security-container-images': 'container-images'}
SECURITY_IDS = frozenset(SECURITY_FAMILIES)
_KEYS = {'id', 'check_id', 'requirement_ids', 'applicability', 'reason', 'evidence', 'expected_tests', 'data_sources'}
_UNREAD_DOCUMENTS = object()
_POLICY_PATHS = (
    '.getzilla/getzilla/verification_plan.py', '.getzilla/getzilla/quality_gates.py',
    '.getzilla/getzilla/verification.py', '.getzilla/getzilla/criterion_tests.py',
    '.getzilla/getzilla/expanded_security.py', '.getzilla/getzilla/security_data.py',
    '.getzilla/getzilla/stacks.py', '.getzilla/getzilla/stack_runners.py',
    '.getzilla/config/diff-risk-rules.json', '.getzilla/config/routing.json',
    '.getzilla/config/stacks.json',
    '.getzilla-verification.json', '.getzilla-test-runner.json', '.getzilla-evals.json',
    'architecture/system.yaml', 'architecture/rules.yaml',
)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _strings(value: Any, maximum: int = 10000) -> bool:
    return (isinstance(value, list) and len(value) <= maximum and
            all(isinstance(item, str) and 0 < len(item) <= 2048 for item in value) and
            len(value) == len(set(value)))


def _obligation(value: Any) -> dict:
    if not isinstance(value, dict) or set(value) != _KEYS:
        raise ValueError('invalid closed required verification obligation')
    if (any(not isinstance(value[key], str) or not value[key] or len(value[key]) > 2048
            for key in ('id', 'check_id', 'reason')) or
            not _strings(value['requirement_ids'], 2000) or not _strings(value['expected_tests']) or
            value['applicability'] not in {'required', 'not_applicable'} or
            not isinstance(value['evidence'], dict) or not isinstance(value['data_sources'], list) or
            len(value['data_sources']) > 128 or any(not isinstance(item, dict) for item in value['data_sources'])):
        raise ValueError('invalid verification obligation fields')
    if value['applicability'] == 'not_applicable' and not value['evidence']:
        raise ValueError('not_applicable needs source-derived applicability evidence')
    return copy.deepcopy(value)


def _module_source(module) -> bytes:
    """Read corresponding engine source through its actual closed loader; never execute it."""
    loader = getattr(module, '__loader__', None)
    if type(loader) not in {importlib.machinery.SourceFileLoader,
                            importlib.machinery.SourcelessFileLoader, zipimport.zipimporter}:
        raise ValueError('verification policy source loader is unavailable')
    try:
        filename = loader.get_filename(module.__name__)
        if filename != module.__file__:
            raise ValueError('verification policy source identity differs')
        source = filename
        if source.endswith('.pyc'):
            try:
                source = importlib.util.source_from_cache(source)
            except ValueError:
                source = source[:-1]
        if not source.endswith('.py'):
            raise ValueError('verification policy has no corresponding Python source')
        content = loader.get_data(source)
        if not isinstance(content, bytes) or not 0 < len(content) <= 4 * 1024 * 1024:
            raise ValueError('verification policy source is unavailable or excessive')
        return content
    except (AttributeError, ImportError, OSError, TypeError) as exc:
        raise ValueError('verification policy source cannot be bound') from exc


def policy_binding(root: Path) -> dict:
    from .verification_tool_workspace import checked_path
    values = {}
    for name in _POLICY_PATHS:
        path = checked_path(root, name)
        if not path.exists():
            values[name] = None
            continue
        if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('verification policy path is not a bounded regular file: ' + name)
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    implementation = {}
    for name in ('verification_plan.py', 'verification.py', 'quality_gates.py', 'criterion_tests.py',
                 'stacks.py', 'stack_runners.py', 'stack_toolchains.py',
                 'python_test_runner.py', 'factory_tests.py', 'agent_evals.py',
                 'verification_scope.py', 'verification_tool_workspace.py',
                 'expanded_security.py', 'security_inventory.py', 'security_licenses.py', 'security_tools.py',
                 'security_intelligence.py', 'security_data.py', 'security_osv_snapshot.py',
                 'process_limits.py', 'architecture.py', 'architecture_diff.py', 'architecture_fitness.py',
                 'architecture_diagrams.py', 'receipts.py', 'verification_tool_reports.py', 'verification_tools.py',
                 'review_plan.py', 'light_lane.py', 'queue_provenance.py', 'python_source_proof.py', 'git_binding_guard.py'):
        module = importlib.import_module('.' + name[:-3], __package__)
        implementation[name] = hashlib.sha256(_module_source(module)).hexdigest()
    from . import STACK_DIR
    registry = STACK_DIR / 'config' / 'stacks.json'
    if not registry.is_file() or registry.is_symlink() or registry.stat().st_size > 4 * 1024 * 1024:
        raise ValueError('engine stack registry source is unavailable')
    implementation['stacks.json'] = hashlib.sha256(registry.read_bytes()).hexdigest()
    content = {'inputs': values, 'implementation': implementation}
    return {'schema_version': 1, **content, 'digest': digest(content)}


def build_required_plan(root: Path, *, mode: str, context: dict | None, source: dict,
                        inventory: dict, risk: dict, selection: dict,
                        extra_obligations=()) -> dict:
    """Normalize policy-derived descriptors; current_required_plan supplies native policy."""
    if mode not in {'fast', 'pr', 'release', FOCUSED_MODE}:
        raise ValueError('required plan only supports qualifying verification modes')
    if not all(isinstance(item, dict) for item in (context, source, inventory, risk, selection)):
        raise ValueError('required plan inputs must be explicit bindings')
    obligations = [_obligation(item) for item in extra_obligations]
    if not 0 < len(obligations) <= MAX_OBLIGATIONS or len({item['id'] for item in obligations}) != len(obligations):
        raise ValueError('required plan has empty, duplicate or excessive obligations')
    obligations.sort(key=lambda item: item['id'])
    value = {'schema_version': 1,
             'binding': {'mode': mode, 'context': copy.deepcopy(context), 'source': copy.deepcopy(source),
                         'inventory': copy.deepcopy(inventory), 'risk': copy.deepcopy(risk),
                         'selection': copy.deepcopy(selection), 'policy': policy_binding(root)},
             'obligations': obligations}
    value['digest'] = digest(value)
    if len(json.dumps(value, ensure_ascii=True).encode()) > MAX_PLAN_BYTES:
        raise ValueError('required verification plan exceeds byte bound')
    return value


def _finding(code: str, path: str, message: str) -> dict[str, str]:
    return {'severity': 'error', 'code': code, 'path': path, 'message': message}


def _value(result: Any, name: str, default=None):
    return result.get(name, default) if isinstance(result, dict) else getattr(result, name, default)


def _executed_references(plan, result):
    try:
        return _observed_references(plan, result)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return []


def _observed_references(plan, result):
    """Derive credit from exact individual observations, never a claimed list or Core total."""
    name = _value(result, 'name')
    items = [item for item in plan['obligations'] if item['check_id'] == name]
    details = _value(result, 'details', [])
    if name in {'criterion-tests', 'static-seo-landing-contract'}:
        from .criterion_tests import _verified_references
        references = sorted({ref for item in items for ref in item['expected_tests']})
        ownership = {}
        for item in items:
            for path, value in item['evidence'].get('test_sources', {}).items():
                if path in ownership and ownership[path] != value:
                    return []
                ownership[path] = value
        reports = [row for row in details if isinstance(row, dict) and row.get('kind') == 'criterion-test-execution']
        return _verified_references(reports[0], references, ownership) if len(reports) == 1 else []
    if isinstance(name, str) and name.startswith('tool:'):
        from .verification_tool_reports import evaluate_criteria
        mapping = {key: refs for item in items for key, refs in item['evidence'].get('criteria', {}).items()}
        if len(details) != 1 or not isinstance(details[0], dict):
            return []
        detail = details[0]
        executions = detail.get('executions', [])
        if not executions or any(row.get('returncode') != 0 or row.get('terminal_state') != 'completed'
                                 or row.get('cleanup_error') for row in executions):
            return []
        try:
            evaluated = evaluate_criteria(detail['report'], mapping)
        except (KeyError, TypeError, ValueError):
            return []
        if evaluated != detail.get('criteria'):
            return []
        return sorted({ref for row in evaluated if row.get('status') == 'pass' for ref in row['tests']})
    return []


def plan_gaps(plan: Any, results, *, current_binding: dict, now_utc: datetime,
              data_source_validator: Callable | None = None) -> list[dict[str, str]]:
    """Missing, repeated, unexecuted or stale observations never become PASS."""
    try:
        if (not isinstance(plan, dict) or set(plan) != {'schema_version', 'binding', 'obligations', 'digest'} or
                type(plan['schema_version']) is not int or plan['schema_version'] != 1 or
                not isinstance(plan['obligations'], list) or not 0 < len(plan['obligations']) <= MAX_OBLIGATIONS or
                digest({key: value for key, value in plan.items() if key != 'digest'}) != plan['digest']):
            raise ValueError('invalid required plan schema or digest')
        obligations = [_obligation(item) for item in plan['obligations']]
        if len({item['id'] for item in obligations}) != len(obligations):
            raise ValueError('duplicate required obligation')
        if not isinstance(current_binding, dict) or plan['binding'] != current_binding:
            raise ValueError('current source, intent, criteria, inventory or policy differs from required plan')
        if now_utc.tzinfo is None or now_utc.utcoffset() is None:
            raise ValueError('freshness requires an aware current timestamp')
        if not callable(data_source_validator):
            raise ValueError('trusted current source validator is required')
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        return [_finding('required-plan-invalid', 'required_plan', str(exc))]
    try:
        results = list(results)
        if len(results) > MAX_OBLIGATIONS * 2 or any(not isinstance(_value(item, 'name'), str) for item in results):
            raise ValueError('invalid or excessive verification results')
        counts = Counter(_value(item, 'name') for item in results)
    except (TypeError, ValueError) as exc:
        return [_finding('required-results-invalid', 'checks', str(exc))]
    gaps = []
    planned = {item['check_id'] for item in obligations}
    for name, count in counts.items():
        if count > 1:
            gaps.append(_finding('required-result-duplicate', str(name), 'duplicate check results cannot be overwritten'))
        if name not in planned and name != 'quality-gate':
            gaps.append(_finding('required-result-unplanned', name, 'result has no source-bound declaration'))
    for result in results:
        if _value(result, 'status') not in {'pass', 'skip'}:
            gaps.append(_finding('required-result-unverified', _value(result, 'name'),
                                 'verification contains status=' + str(_value(result, 'status'))))
    named = {_value(item, 'name'): item for item in results}
    checked_sources = set()
    for obligation in obligations:
        name = obligation['check_id']
        if obligation['evidence'].get('producer_declared') is False:
            gaps.append(_finding('required-producer-unavailable', obligation['id'], 'explicit required producer is not declared by the current source'))
        result = named.get(name)
        if result is None:
            gaps.append(_finding('required-check-missing', name, 'required obligation was not dispatched: ' + obligation['id']))
            continue
        details = _value(result, 'details', [])
        if not isinstance(details, list):
            details = []
        bindings = [item for item in details if isinstance(item, dict) and item.get('kind') == 'required-plan-result']
        if (len(bindings) != 1 or bindings[0].get('schema_version') != 1 or
                bindings[0].get('plan_digest') != plan['digest'] or bindings[0].get('check_id') != name):
            gaps.append(_finding('required-result-binding', name, 'result is not bound to this invocation plan and check'))
            continue
        status = _value(result, 'status')
        if obligation['applicability'] == 'required' and status != 'pass':
            gaps.append(_finding('required-check-unverified', name, 'required check status=' + str(status)))
        elif obligation['applicability'] == 'not_applicable':
            if status not in {'skip', 'pass'} or bindings[0].get('applicability') != obligation['evidence']:
                gaps.append(_finding('required-applicability-unproven', name, 'not_applicable lacks the exact source-derived exclusion'))
        executed = bindings[0].get('executed_tests', [])
        if executed != _executed_references(plan, result):
            gaps.append(_finding('required-test-proof-mismatch', name, 'individual observations differ from credited references'))
            executed = []
        if not _strings(executed):
            gaps.append(_finding('required-test-results-invalid', name, 'invalid or duplicate executed test identifiers'))
            executed = []
        missing = sorted(set(obligation['expected_tests']) - set(executed))
        if missing:
            gaps.append(_finding('required-test-not-executed', obligation['id'], 'individual required tests not verified: ' + ', '.join(missing)[:2000]))
        expected_sources = list(obligation['data_sources'])
        sources = []
        security = [item for item in details if isinstance(item, dict) and item.get('kind') == 'security-result']
        for detail in security:
            if name in SECURITY_FAMILIES and (detail.get('schema_version') != 1 or detail.get('family') != SECURITY_FAMILIES[name]):
                gaps.append(_finding('required-security-family', name, 'security family/schema differs from the planned check'))
            outcome = detail.get('outcome')
            if outcome not in ({'pass'} if obligation['applicability'] == 'required' else {'not_applicable'}):
                gaps.append(_finding('required-security-outcome', name, 'security result outcome=' + str(outcome)))
            for key in ('inventory_sha256', 'policy_sha256'):
                if key in obligation['evidence'] and detail.get(key) != obligation['evidence'][key]:
                    gaps.append(_finding('required-security-binding', name, key + ' differs from plan'))
            observed = detail.get('data_sources', [])
            if not isinstance(observed, list) or any(not isinstance(item, dict) for item in observed):
                gaps.append(_finding('required-data-source-invalid', name, 'malformed security source evidence'))
            else:
                sources.extend(observed)
        if name in SECURITY_IDS and len(security) != 1:
            gaps.append(_finding('required-security-result', name, 'exactly one structured security result is required'))
        if Counter(digest(item) for item in sources) != Counter(digest(item) for item in expected_sources):
            gaps.append(_finding('required-data-source-binding', name, 'actual source projections differ from the required plan'))
        for source in [*expected_sources, *sources]:
            identity = digest(source)
            if identity in checked_sources:
                continue
            checked_sources.add(identity)
            try:
                if data_source_validator is None:
                    raise ValueError('current source validator is unavailable')
                acquired = source['acquisition']['last_verified_sync_utc']
                if not isinstance(acquired, str):
                    raise ValueError('source acquisition time is unavailable')
                stamp = datetime.fromisoformat(acquired.replace('Z', '+00:00'))
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    raise ValueError('source acquisition time is not aware')
                age = (now_utc - stamp).total_seconds()
                if not 0 <= age <= 259200:
                    raise ValueError('source acquisition is future or stale')
                validated = data_source_validator(source, now=now_utc)
                if validated is not True:
                    raise ValueError('current data source validator refused the source')
            except (ValueError, OSError, RuntimeError, KeyError, TypeError):
                gaps.append(_finding('required-data-source-stale', name, 'current source identity or acquisition freshness could not be verified'))
    return gaps


def obligation(name: str, *, required=True, reason='native verification policy', evidence=None,
               requirement_ids=(), expected_tests=(), identifier=None) -> dict:
    return {'id': identifier or name, 'check_id': name, 'requirement_ids': list(requirement_ids),
            'applicability': 'required' if required else 'not_applicable', 'reason': reason,
            'evidence': evidence or {}, 'expected_tests': list(expected_tests), 'data_sources': []}


def declared_check_obligations(spec, *, available=()) -> list[dict]:
    """Typed check references declare work; they confer no attestation or execution authority."""
    result = []
    for collection in ('acceptance_criteria', 'invariants', 'forbidden_outcomes'):
        for item in spec.get(collection, []):
            names = [row['attestation'][6:] for row in item.get('evidence', [])
                     if isinstance(row.get('attestation'), str) and row['attestation'].startswith('check:')]
            if len(names) != len(set(names)):
                raise ValueError('duplicate typed producer reference')
            for name in sorted(names):
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,121}', name):
                    raise ValueError('invalid typed producer reference')
                result.append(obligation(name, identifier=item['id'] + ':check:' + name,
                    requirement_ids=[item['id']], reason='explicit typed producer requirement',
                    evidence={'producer_declared': name in available, 'requirement': item['id']}))
    return result


def _plan_documents(root: Path, route: dict) -> dict | None:
    """Read supported legacy selection without relaxing modern attachment or inventing package data."""
    from . import state
    from .continuity import has_task_context, legacy_evidence_allowed, package_documents, validate_package_state
    from .package_status import read_package_file
    from .spec import MAX_SPEC_BYTES, _parse_canonical_json, _validate_document, canonical_spec_digest
    from .workflow_storage import valid_package_path
    if has_task_context(route) or not legacy_evidence_allowed(route):
        return package_documents(root, route)
    active = state.get_active_change(root)
    if active is None:
        if route.get('change_id') is not None:
            raise ValueError('legacy task has no selected package')
        return None
    if (not route or not isinstance(active, dict) or set(active) != {'change_id', 'path'} or
            not valid_package_path(active['path'], active['change_id']) or
            route.get('change_id') not in (None, active['change_id'])):
        raise ValueError('legacy selected package does not match its task')
    relative = active['path']
    raw = read_package_file(root, relative + '/change-spec.yaml', MAX_SPEC_BYTES)
    spec = _parse_canonical_json(raw, root / relative / 'change-spec.yaml')
    _validate_document(spec, gate=True, root=root)
    if spec.get('change_id') != active['change_id']:
        raise ValueError('legacy typed spec change identity mismatch')
    package_state = None
    state_path = root / relative / 'state.json'
    if state_path.exists() or state_path.is_symlink():
        package_state = state._route_document(root, state_path)
        validate_package_state(package_state, route, active['change_id'])
    requirements_digest = None
    requirements_path = root / relative / 'requirements.md'
    if requirements_path.exists() or requirements_path.is_symlink():
        requirements = read_package_file(root, relative + '/requirements.md')
        requirements.decode('utf-8', 'strict')
        requirements_digest = hashlib.sha256(requirements).hexdigest()
    return {'path': relative, 'state': package_state, 'spec': spec,
            'spec_digest': canonical_spec_digest(spec), 'requirements_digest': requirements_digest}


def _native_obligations(root: Path, mode: str, route: dict, docs_scope: dict, *, files=None, profiles=None,
                        bases=None, documents=_UNREAD_DOCUMENTS) -> list[dict]:
    from .quality_gates import MANDATORY_PR_CHECKS, MANDATORY_PYTHON_PR_CHECKS
    from .verification import (_existing_quality_paths, _semgrep_config, _trivy_config_present,
                               composer_check_selection, node_check_selection, python_check_selection)
    from .verification_tools import load_checks
    names = {'required-plan', 'source-stability', 'task-context'}
    files = files or []
    profiles = profiles or route.get('quality_profiles', ['base'])
    if mode == FOCUSED_MODE:
        names.update({'git-diff-check', 'scope-selection', 'static-seo-landing-contract'})
    if mode != FOCUSED_MODE:
        names.update({'secret-scan', 'known-vulnerabilities', 'opengrep', 'bandit'})
        names |= MANDATORY_PR_CHECKS | MANDATORY_PYTHON_PR_CHECKS
        names.update({'diff-risk', 'cost-guard', 'hook-health', 'eu-ai-act', 'workflow-baseline'})
    if documents is _UNREAD_DOCUMENTS:
        documents = _plan_documents(root, route)
    if documents and mode != FOCUSED_MODE:
        names.add('change-spec')
    # A JavaScript-only tests/ directory is not evidence that Python quality tools apply.
    # Keep the existing configured roots and inspect their actual Python source presence.
    python_paths = [name for name in _existing_quality_paths(root)
                    if (root / name).is_file() and (root / name).suffix == '.py' or
                    (root / name).is_dir() and any((root / name).rglob('*.py'))]
    no_python = not python_paths
    # Match the existing producers' applicability rules; no capability or missing-tool skip qualifies.
    exclusions = {}
    if mode != FOCUSED_MODE:
        from . import cost_guard, eu_ai_act
        if bases == [] and mode == 'fast':
            exclusions['diff-risk'] = 'no comparison base in this mode; assessment remains provisional'
        if bases == [] and not cost_guard.route_has_cost_signal(route):
            exclusions['cost-guard'] = 'no comparison base and no paid-operation signal'
        if not eu_ai_act.enabled(root):
            exclusions['eu-ai-act'] = 'EU AI Act component not installed'
        if os.environ.get('CI') == 'true' or os.environ.get('GITHUB_ACTIONS') == 'true':
            exclusions['workflow-baseline'] = 'CI runner policy'
        elif not (root / '.getzilla/AGBP_SYNC.json').is_file():
            exclusions['workflow-baseline'] = 'not an installed Getzilla project'
    if no_python:
        exclusions.update(ruff='no python quality paths', bandit='no non-test python paths')
    elif not any(not item.startswith('tests') for item in python_paths):
        exclusions['bandit'] = 'no non-test python paths'
    if not (root / '.getzilla/sast/rules').is_dir():
        exclusions['opengrep'] = 'no OpenGrep rules installed'
    if not documents and (route.get('light_diff') or {}).get('admitted'):
        exclusions['change-spec'] = '0 specs checked; exempt=True'
    if not (root / 'architecture/system.yaml').exists() and not (root / 'architecture/rules.yaml').exists():
        exclusions.update({'architecture-inputs': 'architecture authority inputs are absent; not executed',
                           'architecture': 'architecture is not configured'})
    if not (root / 'governance').exists():
        exclusions['governance'] = 'governance is not configured'
    if not route.get('change_id'):
        exclusions['workflow-artifacts'] = 'no active change'
    elif documents and not (root / documents['path'] / 'workflow/manifest.json').exists():
        exclusions['workflow-artifacts'] = 'workflow artifacts are not configured'
    pytest, unittest_files = python_check_selection(root)
    tests = mode != FOCUSED_MODE and (pytest or unittest_files)
    if tests:
        runner = 'pytest' if pytest else 'python-unittest'
        names.add(runner)
        if docs_scope.get('eligible') is True:
            names.add('python-focused-unittest')
        if mode in {'pr', 'release'}:
            names.add('coverage')
            if pytest:
                exclusions['coverage'] = 'pytest runner owns tests; measure unittest trees only'
    elif mode != FOCUSED_MODE:
        names.add('python-unittest')
        exclusions['python-unittest'] = 'no native Python discovery inputs'
        if mode in {'pr', 'release'}:
            names.add('coverage')
            exclusions['coverage'] = 'no native Python discovery inputs'
    if mode != FOCUSED_MODE and (root / 'factory/pyproject.toml').is_file():
        names.add('factory-unit')
    if mode != FOCUSED_MODE:
        if any((root / 'pilot/tests').glob('test*.py')):
            names.add('pilot-unittest')
        if 'php' in profiles or 'bitrix' in profiles or any(path.endswith('.php') for path in files):
            names.add('php-lint')
            if not any(path.endswith('.php') for path in files):
                exclusions['php-lint'] = 'no changed PHP files'
            if (root / 'composer.json').is_file():
                names.add('composer-validate')
                names.update(name for name, _args in composer_check_selection(root))
        if 'bitrix' in profiles:
            names.add('bitrix')
        if 'frontend' in profiles and not (root / 'package.json').is_file():
            names.add('package-json')
        if (root / 'package.json').is_file():
            try:
                names.update(node_check_selection(root, mode)[3])
            except (ValueError, OSError):
                names.add('package-json')
    if (root / 'factory/tests/run_disposable_exit.py').is_file() and mode in {'pr', 'release'}:
        names.add('factory-postgres-exit')
        if (root / '.getzilla/AGBP_SYNC.json').is_file():
            exclusions['factory-postgres-exit'] = 'consumer source-only/unit-only policy prohibits infrastructure execution'
        elif os.environ.get('GETZILLA_VERIFY_CAPABILITY') == 'repository-sandbox':
            exclusions['factory-postgres-exit'] = 'repository-sandbox has no nested-container/database capability'
    if docs_scope.get('eligible') is True:
        names.update(docs_scope.get('skipped_checks', []))
        exclusions.update({name: 'admitted documentation/state scope' for name in docs_scope.get('skipped_checks', [])})
    fingerprint = tree_fingerprint(root)
    result = [obligation(name, required=name not in exclusions, evidence=(
        {'kind': 'native-applicability', 'reason': exclusions[name], 'source': fingerprint}
        if name in exclusions else {})) for name in sorted(names)]
    if mode != FOCUSED_MODE:
        from .stacks import planned_stack_checks
        result.extend(obligation(item['check_id'], required=item['applicability'] == 'required',
                                 reason=item['reason'], evidence=item['evidence'])
                      for item in planned_stack_checks(root, mode, files))
        from . import agent_evals
        if (root / agent_evals.CONFIG).exists() or (root / agent_evals.CONFIG).is_symlink():
            try:
                config, _ = agent_evals._read(root, agent_evals.CONFIG)
                suites = config['suites']
                if not isinstance(suites, list) or not 1 <= len(suites) <= 16:
                    raise ValueError('invalid suite declarations')
                selected = ['agent-eval:' + row['id'] for row in suites if mode in row['modes']]
                if len(selected) != len(set(selected)):
                    raise ValueError('duplicate suite declarations')
                result.extend(obligation(name) for name in selected)
            except (ValueError, KeyError, TypeError, agent_evals.EvalError):
                result.append(obligation('agent-eval:configuration'))
    if mode != FOCUSED_MODE and _semgrep_config(root) is not None:
        result.append(obligation('semgrep'))
    if mode != FOCUSED_MODE and _trivy_config_present(root):
        result.append(obligation('trivy-config'))
    external_criteria: dict[str, set[str]] = {}
    for check in load_checks(root, mode) if mode != FOCUSED_MODE else []:
        expected = sorted({test for tests in check['criteria'].values() for test in tests})
        result.append(obligation('tool:' + check['id'], requirement_ids=sorted(check['criteria']), expected_tests=expected,
                                 evidence={'criteria': check['criteria']}))
        for identifier, tests in check['criteria'].items():
            external_criteria.setdefault(identifier, set()).update(tests)
    focused_refs = set(docs_scope.get('focused_tests', [])) if mode == FOCUSED_MODE else set()
    if documents:
        result.extend(declared_check_obligations(documents['spec'], available={row['check_id'] for row in result}))
        for collection in ('acceptance_criteria', 'invariants', 'forbidden_outcomes'):
            for item in documents['spec'].get(collection, []):
                refs = sorted({entry['test'] for entry in item['evidence'] if 'test' in entry} - external_criteria.get(item['id'], set()))
                if refs:
                    if mode == FOCUSED_MODE and any(ref.split('::', 1)[0] not in focused_refs for ref in refs):
                        raise ValueError('focused mode does not cover all typed test evidence; select pr/release for the full scope')
                    producer = 'static-seo-landing-contract' if mode == FOCUSED_MODE else 'criterion-tests'
                    from .criterion_tests import _source_ownership
                    sources = _source_ownership(root, refs)[0]
                    result.append(obligation(producer, requirement_ids=[item['id']], expected_tests=refs,
                                             evidence={'test_sources': sources},
                                             identifier=item['id'] + ':tests', reason='typed criterion test references'))
    if mode == FOCUSED_MODE:
        from .criterion_tests import _source_ownership
        sources = _source_ownership(root, sorted(focused_refs))[0]
        for item in result:
            if item['check_id'] == 'static-seo-landing-contract':
                item['expected_tests'] = sorted(focused_refs)
                item['evidence']['test_sources'] = sources
    return result


def current_required_plan(root: Path, *, mode: str, profiles=None, docs_scope=None) -> dict:
    """Read the current native source and policy; never trust the old plan to select obligations."""
    from .state import get_active_route
    from .verification import GitRangeSelection, _git_range_selection
    route = get_active_route(root) or {}
    range_mode = 'pr' if mode == 'fast' and route.get('delivery_lane') == 'light' else mode
    ranges = _git_range_selection(root, route or None, range_mode)
    if ranges.qualification_bases is not None:
        ranges = GitRangeSelection(list(ranges.qualification_bases), list(ranges.findings))
    return _compile_required_plan(root, mode=mode, profiles=profiles, docs_scope=docs_scope,
                                  route=route, ranges=ranges)


def _compile_required_plan(root: Path, *, mode: str, profiles, docs_scope, route: dict, ranges) -> dict:
    """Compile live policy and observations from already proved explicit ranges.

    No range acquisition or receipt lookup occurs here. Prior qualification can
    therefore be checked without re-entering its own witness reader.
    """
    from .continuity import context_binding, legacy_evidence_allowed
    from .verification import _changed_file_inventory
    from .review_plan import assess
    from .verification_scope import select_docs_state_scope, FOCUSED_TEST_TARGETS
    from .verification import _docs_state_status_inventory
    from .expanded_security import security_obligations
    documents = _plan_documents(root, route)
    context = context_binding(root, route) if route and not legacy_evidence_allowed(route) else {
        'version': 1, 'variant': 'legacy' if route else 'unrouted', 'route_id': route.get('route_id'),
        'task_digest': digest({'task': route.get('task'), 'context': route.get('context')})}
    if context.get('variant') == 'legacy' and documents is not None:
        context['package'] = {'path': documents['path'], 'change_id': documents['spec']['change_id'],
                              'spec_digest': documents['spec_digest'],
                              'requirements_digest': documents['requirements_digest']}
    files, metadata = _changed_file_inventory(root, route or None, mode, ranges)
    fingerprint = tree_fingerprint(root)
    head = git_head(root)
    proc = run(['git', 'rev-parse', 'HEAD^{tree}'], cwd=root)
    tree = proc.stdout.strip() if proc.returncode == 0 else None
    source = {'head': head, 'tree': tree, 'base': sorted({item.comparison_base_sha for item in ranges.bases}), 'fingerprint': fingerprint}
    if any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', value) for value in (head, tree)):
        raise ValueError('required verification plan needs exact Git head and tree')
    risk = assess(root, route or None, ranges, fingerprint)['risk_assessment'] if ranges.bases else {
        'status': 'provisional', 'risk': route.get('risk', 'high'), 'rules_digest': policy_binding(root)['digest']}
    inventory = {'complete': not ranges.findings and all(isinstance(item, str) for item in files),
                 'paths': files, 'digest': digest({'paths': files, 'metadata': metadata})}
    if route.get('delivery_lane') == 'light' or route.get('light_lane_candidate'):
        from .light_lane import inspect_light_diff
        light = inspect_light_diff(root, source['base'], risk=risk['risk'],
                                   complete=risk.get('status') == 'complete' and inventory['complete'])
        route = {**route, 'delivery_lane': 'light' if light['admitted'] else 'full', 'light_diff': light}
    if docs_scope is None and mode == FOCUSED_MODE:
        from .state import get_active_change
        from .verification import select_static_seo_landing_scope
        active = get_active_change(root) or {}
        findings = list(ranges.findings)
        if not route:
            findings.append({'code': 'route-unavailable', 'path': '.getzilla/runtime/active-route.json',
                             'message': 'focused verification requires an active route', 'severity': 'error'})
        docs_scope = select_static_seo_landing_scope(files, change_package=active.get('path'),
            range_findings=findings, range_base_count=len(ranges.bases),
            file_statuses=metadata.get('status_records'),
            status_inventory_trusted=metadata.get('status_inventory_trusted') is True)
        docs_scope['mode'] = FOCUSED_MODE
    elif docs_scope is None:
        statuses, trusted = _docs_state_status_inventory(root, ranges) if mode in {'pr', 'release'} else (None, None)
        docs_scope = select_docs_state_scope(mode, files, range_findings=list(ranges.findings),
            range_base_count=len(ranges.bases), file_statuses=statuses, status_inventory_trusted=trusted,
            route_present=bool(route), available_test_targets=[name for name in FOCUSED_TEST_TARGETS if (root / name).is_file()])
    selection = {'delivery_lane': route.get('delivery_lane', 'full'), 'profiles': profiles or route.get('quality_profiles', ['base']),
                 'delivery_expected': route.get('delivery_expected', False),
                 'light_diff': route.get('light_diff'), 'mode': mode, 'docs_scope': docs_scope}
    obligations = _native_obligations(root, mode, route, docs_scope, files=files,
                                     profiles=selection['profiles'], bases=source['base'], documents=documents)
    security = security_obligations(root) if mode != FOCUSED_MODE else []
    if mode != FOCUSED_MODE and (not isinstance(security, list) or len(security) != len(SECURITY_IDS) or
            {item.get('check_id') for item in security if isinstance(item, dict)} != SECURITY_IDS or
            any(item.get('id') != item.get('check_id') for item in security)):
        raise ValueError('expanded security plan must declare every required family exactly once')
    obligations = [item for item in obligations if item['id'] not in SECURITY_IDS]
    obligations.extend(security)
    return build_required_plan(root, mode=mode, context=context, source=source, inventory=inventory,
                               risk=risk, selection=selection, extra_obligations=obligations)


def bind_result(plan: dict, result) -> None:
    """Attach the plan observed before dispatch, after the actual producer returned."""
    name = _value(result, 'name')
    items = [item for item in plan['obligations'] if item['check_id'] == name]
    if not items:
        return
    details = _value(result, 'details', [])
    executed = _executed_references(plan, result)
    binding = {'schema_version': 1, 'kind': 'required-plan-result', 'check_id': name,
               'plan_digest': plan['digest'], 'executed_tests': sorted(executed),
               'command': _value(result, 'command'),
               'producer_policy_digest': plan['binding']['policy']['digest'],
               'environment': {'platform': sys.platform, 'python_version': sys.version.split()[0]}}
    if items[0]['applicability'] == 'not_applicable':
        binding['applicability'] = items[0]['evidence']
    details.append(binding)


def report_gaps(root: Path, report: Any, *, now: datetime | None = None) -> list[dict[str, str]]:
    """Receipt consumption rechecks the current complete plan, not a historical PASS."""
    try:
        if not isinstance(report, dict) or not isinstance(report.get('required_plan'), dict):
            raise ValueError('qualifying verification requires an embedded required_plan')
        current = current_required_plan(root, mode=report.get('mode'), profiles=report.get('profiles'))
        gaps = _report_plan_gaps(root, report, current, now=now)
        if not gaps and current_required_plan(root, mode=report.get('mode'), profiles=report.get('profiles')) != current:
            return [_finding('required-plan-changed', 'required_plan',
                             'current complete binding changed during result validation')]
        return gaps
    except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
        return [_finding('required-plan-unavailable', 'required_plan', 'current required plan and evidence could not be established')]


def _report_plan_gaps(root: Path, report: dict, current: dict, *, now=None) -> list[dict[str, str]]:
    """Validate complete results against a freshly compiled plan, without acquiring ranges."""
    try:
        selected = current['binding']['selection']
        if report.get('mode') == 'fast' and selected.get('delivery_expected') and selected.get('delivery_lane') != 'light':
            return [_finding('required-qualifying-mode', 'mode', 'full task completion requires pr/release; fast qualifies only a measured light diff')]
        plan = report['required_plan']
        if current != plan:
            raise ValueError('required plan no longer matches current obligations, source or policy')
        def validate_source(value, *, now):
            from .expanded_security import validate_data_source
            return validate_data_source(value, root=root, now=now)
        from .quality_gates import evaluate_quality_gate
        return evaluate_quality_gate(mode=report.get('mode'), checks=report.get('checks', []),
            docs_scope=current['binding']['selection'].get('docs_scope'), required_plan=plan,
            current_binding=current['binding'], now_utc=now or datetime.now(timezone.utc),
            data_source_validator=validate_source).details
    except (ValueError, OSError, RuntimeError, ImportError, KeyError, TypeError):
        return [_finding('required-plan-unavailable', 'required_plan', 'current required plan and evidence could not be established')]
