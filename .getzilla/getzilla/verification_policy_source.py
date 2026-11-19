"""Closed-loader acquisition for the exact loaded verification policy source set.

Dynamic module loading stays at this boundary so ordinary plan exports retain
a closed namespace for demand-based source analysis.
"""
from __future__ import annotations

import hashlib
import json
import importlib
import importlib.machinery
import importlib.util
import zipimport


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


def implementation_source_binding() -> dict:
    implementation = {}
    for name in ('agent_eval_authoring.py', 'grant_authoring.py', 'security_license_contracts.py', 'live_evidence.py', 'workflow_storage.py', 'workflow_inputs.py', 'verification_policy_source.py', 'verification_actions.py', 'git_ranges.py', 'verification_plan.py', 'verification.py', 'quality_gates.py', 'criterion_tests.py',
                 'stacks.py', 'stack_runners.py', 'stack_toolchains.py',
                 'python_test_runner.py', 'factory_tests.py', 'agent_evals.py',
                 'verification_scope.py', 'verification_tool_workspace.py',
                 'expanded_security.py', 'security_cli.py', 'security_inventory.py', 'security_licenses.py', 'security_tools.py',
                 'public_security_context.py', 'security_oci.py',
                 'security_build_inputs.py', 'security_image_registry.py', 'security_image_backend.py',
                 'security_image_producer.py', 'security_image_authority.py', 'security_image_provision.py', 'security_image_job.py',
                 'security_acquisition.py', 'startup_cpu.py', '_cpu_capacity.py',
                 'security_intelligence.py', 'security_data.py', 'security_publication.py', 'security_data_windows.py', 'security_windows_publication.py', 'security_osv_snapshot.py',
                 'security_artifacts.py', 'security_license_acquisition.py', 'security_packagist.py',
                 'cost_guard.py',
                 'baseline.py', 'baseline_assets.py', 'toolchain.py', 'updater.py', 'release_transport.py',
                 'current_workflows.py', 'latest_releases.py', 'managed_runtime.py', 'managed_source_build.py',
                 'managed_environment.py', 'managed_pyyaml.py', 'managed_npm.py', 'managed_software.py', 'opengrep_releases.py',
                 'process_limits.py', 'architecture.py', 'architecture_diff.py', 'architecture_fitness.py',
                 'architecture_diagrams.py', 'governance.py', 'governance_records.py', 'receipts.py', 'verification_tool_reports.py', 'verification_tools.py',
                 'review_plan.py', 'light_lane.py', 'queue_provenance.py', 'python_source_proof.py', 'git_binding_guard.py',
                 'verification_journal.py', 'metrics_journal.py', 'route_metrics.py', 'queue_refusal.py', 'harnesses.py'):
        module = importlib.import_module('.' + name[:-3], __package__)
        implementation[name] = hashlib.sha256(_module_source(module)).hexdigest()
    from . import STACK_DIR
    for name, label in (('stacks.json', 'stack'), ('toolchain.json', 'toolchain')):
        registry = STACK_DIR / 'config' / name
        if not registry.is_file() or registry.is_symlink() or registry.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('engine ' + label + ' registry source is unavailable')
        implementation[name] = hashlib.sha256(registry.read_bytes()).hexdigest()
    return implementation


def _producer_digest(root, cell):
    from .live_evidence import _held_bytes
    names = ('live_acceptance', 'disposable_resources', 'factory_tests', 'python_test_runner',
             'live_lifecycle', 'live_contracts', 'live_evidence', 'verification_policy_source')
    hashes = {}
    for name in names:
        module = importlib.import_module('getzilla.' + name)
        hashes[module.__name__] = hashlib.sha256(module.__loader__.get_data(module.__file__)).hexdigest()
    files = {'factory': ('factory/tests/run_live_suite.py', 'factory/tests/run_disposable_exit.py',
                         'factory/tests/postgres_restart_probe.py', 'factory/tests/test_postgres_integration.py',
                         'factory/tests/test_execution_persistence_postgres.py'),
             'trust-ci': ('trust-ci/tests/run_postgres_suite.py', 'trust-ci/tests/postgres_restart_probe.py'),
             'lifecycle': ('scripts/getzilla_live_lifecycle.py',)}[cell]
    for name in files:
        hashes[name] = hashlib.sha256(_held_bytes(root/name)).hexdigest()
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
