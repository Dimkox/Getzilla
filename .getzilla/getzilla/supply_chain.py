"""Offline source facts and fail-closed MCP admission; neither confers authority."""
from __future__ import annotations

import hashlib
from pathlib import Path

MCP_IDENTITY_UNVERIFIED = (
    'mcp_identity_unverified: external MCP identity is unsupported. '
    'A tool name, policy declaration or operation grant does not prove endpoint provenance.'
)

# References to existing identities and consumers, not another component registry.
# Read only these public source files; never follow config paths or payload values.
_SOURCES = (
    ('.getzilla/config/policy.json', 'tool-policy', 'policy.evaluate_pre_tool', 'declaration'),
    ('.getzilla/config/toolchain.json', 'toolchain', 'toolchain.check_toolchain', 'minimum-and-tested-version'),
    ('.getzilla/config/model-continuation.json', 'model-candidates', 'model_continuation.load_policy', 'declaration'),
    ('.getzilla/config/optional-modules.json', 'optional-modules', 'optional_modules', 'declaration'),
    ('.getzilla/config/skill-catalog.json', 'skill-provenance', 'skill_preflight', 'declaration'),
    ('.getzilla/config/python-test-requirements.txt', 'test-dependencies', 'verification', 'declared-versions'),
    ('.getzilla/config/python-quality-requirements.txt', 'quality-dependencies', 'verification', 'declared-versions'),
    ('factory/src/getzilla_factory/model_rotator_registry.py', 'model-list-provenance', 'model_rotator_registry', 'upstream-commit-and-hashes'),
    ('factory/src/getzilla_factory/landing_http.py', 'provider-profiles', 'landing_live_executors', 'profile-digest-model-aliases-mixed'),
    ('factory/src/getzilla_factory/settings.py', 'credential-contract', 'FactorySettings', 'source-contract-only'),
    ('factory/src/getzilla_factory/service.py', 'factory-stop-authority', 'FactoryService.set_kill', 'source-contract-only'),
    ('trust-ci/scripts/verify-supply-chain.sh', 'deployment-provenance', 'trust-ci-deployment-verifier', 'signed-image-manifest-contract'),
)
_MAX_SOURCE_BYTES = 262_144
_MAX_TOTAL_BYTES = 1_048_576


def check_tool_trust(root: Path, event: dict) -> tuple[bool, str | None]:
    """No current host adapter proves an external MCP server's identity.

    Do not inspect arguments, read credentials, probe endpoints or infer trust
    from the read/write classifier. Supported local tools keep their own policy.
    """
    del root
    name = event.get('tool_name')
    if isinstance(name, str) and name.startswith('mcp__'):
        return False, MCP_IDENTITY_UNVERIFIED
    return True, None


def audit(root: Path) -> dict:
    """Hash a closed, bounded source inventory without executing its contents.

    Missing optional/candidate source stays missing. No result establishes
    installed identity, credential scope, current provider version or trust.
    """
    from .package_status import InspectionError, read_package_file

    entries = []
    total = 0
    for path, kind, consumer, pin in _SOURCES:
        entry = {'path': path, 'kind': kind, 'consumer': consumer, 'pin_kind': pin,
                 'state': 'unavailable', 'sha256': None, 'bytes': None}
        try:
            raw = read_package_file(root, path, min(_MAX_SOURCE_BYTES, _MAX_TOTAL_BYTES - total))
        except InspectionError as error:
            entry['state'] = 'missing' if error.code == 'file_missing' else 'unavailable'
        else:
            total += len(raw)
            entry.update(state='observed', sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
        entries.append(entry)
    return {
        'schema_version': 1, 'authority': 'none', 'mcp_identity': 'unsupported',
        'credential_scope': 'unverified-source-contract-only',
        'stop_status': 'not_observed', 'sources': entries,
        'audit_complete': all(entry['state'] == 'observed' for entry in entries),
        'source_identity': 'sha256-of-observed-source-bytes',
        'limitations': ['No credential or deployed configuration was read.',
                        'Source declarations do not prove installed tool or endpoint identity.',
                        'Model aliases and upstream model lists do not pin served weights.',
                        'Stop contracts do not prove active-process or remote cancellation.'],
    }
