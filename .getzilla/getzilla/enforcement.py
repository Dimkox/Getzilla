"""What Getzilla actually enforces in this repository, as opposed to what it only advises.

Levels, lowest confirmed wins:

- `advisory`: only agent hooks. They warn, and they fail open on their own errors.
- `ci-enforced`: the default branch requires the Getzilla checks on the exact head.
- `external`: a Trust CI check outside the agent's reach is also required.

Branch protection is read through an injected `github(path)` client (GitHub REST, read-only);
without one, or when GitHub does not answer, it is `unknown` and never counted as protected.
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

HOOK_CONFIGS = {
    'claude': '.claude/settings.json', 'codex': '.codex/hooks.json', 'qwen': '.qwen/settings.json',
    'gemini': '.gemini/settings.json', 'grok': '.grok/hooks.json', 'copilot': '.github/hooks/getzilla.json',
}
CONSUMER_CHECK = 'getzilla-verify'
SOURCE_CHECKS = ('linux', 'windows')
TRUST_CI_MARKERS = ('trust-ci', 'trust ci', 'getzilla-trust')

GitHub = Callable[[str], Any]


@dataclass
class EnforcementReport:
    level: str
    hooks: dict[str, dict[str, Any]] = field(default_factory=dict)
    self_test: dict[str, Any] = field(default_factory=dict)
    stop_gate: str = 'soft; strict at high effective risk'
    ci_workflow: str | None = None
    branch_protection: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {'schema_version': 'getzilla-enforcement-v1', 'level': self.level, 'hooks': self.hooks,
                'self_test': self.self_test, 'stop_gate': self.stop_gate, 'ci_workflow': self.ci_workflow,
                'branch_protection': self.branch_protection, 'notes': self.notes}


def installed_hooks(root: Path) -> dict[str, dict[str, Any]]:
    hooks = {}
    for agent, relative in HOOK_CONFIGS.items():
        path = root / relative
        try:
            text = path.read_text(encoding='utf-8')
        except OSError:
            continue
        hooks[agent] = {'config': relative, 'pre_tool_use': 'pre_tool_use.py' in text, 'stop_gate': 'stop_gate.py' in text}
    return hooks


def _run_hook(root: Path, payload: Mapping[str, Any]) -> dict[str, Any]:
    script = root / '.grok' / 'hooks' / 'pre_tool_use.py'
    result = subprocess.run([sys.executable, str(script)], cwd=root, input=json.dumps(payload).encode('utf-8'),
                            capture_output=True, check=False, timeout=60)
    try:
        return json.loads(result.stdout.decode('utf-8', 'replace').strip() or '{}')
    except json.JSONDecodeError:
        return {}


def _denied(verdict: Mapping[str, Any]) -> bool:
    text = json.dumps(verdict).lower()
    return '"deny"' in text or '"block"' in text or '"permissiondecision": "deny"' in text


def hook_self_test(root: Path) -> dict[str, Any]:
    """A harmless command must pass and a write into .git must be denied; otherwise policy is not in effect."""
    from .hook_health import degraded_events
    if not (root / '.grok' / 'hooks' / 'pre_tool_use.py').is_file():
        return {'status': 'absent', 'allows_harmless': False, 'denies_protected_write': False}
    before = len(degraded_events(root))
    harmless = _run_hook(root, {'cwd': str(root), 'tool_name': 'Bash', 'tool_input': {'command': 'echo getzilla-self-test'}})
    protected = _run_hook(root, {'cwd': str(root), 'tool_name': 'Write',
                                 'tool_input': {'file_path': str(root / '.git' / 'getzilla-self-test'), 'content': 'x'}})
    degraded = len(degraded_events(root)) - before
    allows, denies = not _denied(harmless), _denied(protected)
    status = 'pass' if allows and denies and not degraded else 'fail'
    return {'status': status, 'allows_harmless': allows, 'denies_protected_write': denies, 'degraded_during_test': degraded}


def default_gh_client(root: Path) -> GitHub | None:
    """Read-only GitHub REST through the gh CLI when it is installed and signed in."""
    from shutil import which
    gh = which('gh')
    if gh is None:
        return None

    def client(path: str) -> Any:
        result = subprocess.run([gh, 'api', path], cwd=root, capture_output=True, check=False, timeout=60)
        if result.returncode != 0:
            message = result.stderr.decode('utf-8', 'replace')
            if 'Not Found' in message or 'Branch not protected' in message or '404' in message:
                return {'_status': 404}
            return None
        return json.loads(result.stdout.decode('utf-8') or 'null')

    return client


def _required_contexts(protection: Mapping[str, Any]) -> list[str]:
    checks = protection.get('required_status_checks') or {}
    contexts = list(checks.get('contexts') or [])
    contexts.extend(item.get('context') for item in checks.get('checks') or [] if isinstance(item, dict))
    return sorted({str(item) for item in contexts if item})


def inspect_enforcement(root: Path, *, slug: str | None = None, branch: str = 'main', github: GitHub | None = None,
                        run_self_test: bool = True) -> EnforcementReport:
    root = Path(root)
    report = EnforcementReport(level='advisory')
    report.hooks = installed_hooks(root)
    if not report.hooks:
        report.notes.append('no agent hook configuration found: Getzilla does not even advise in this repository')
    report.self_test = hook_self_test(root) if run_self_test else {'status': 'not_run'}
    if report.self_test.get('status') == 'fail':
        report.notes.append('hook self-test failed: the policy is not in effect for agent actions')
    source_repository = (root / '.github' / 'workflows' / 'getzilla.yml').is_file()
    workflow = '.github/workflows/getzilla.yml' if source_repository else '.github/workflows/getzilla-verify.yml'
    report.ci_workflow = workflow if (root / workflow).is_file() else None
    expected = list(SOURCE_CHECKS) if source_repository else [CONSUMER_CHECK]
    protection: dict[str, Any] = {'state': 'unknown', 'branch': branch, 'expected_checks': expected}
    if github is not None and slug:
        answer = github(f'repos/{slug}/branches/{branch}/protection')
        if isinstance(answer, dict) and answer.get('_status') == 404:
            protection['state'] = 'unprotected'
        elif isinstance(answer, dict):
            contexts = _required_contexts(answer)
            strict = bool((answer.get('required_status_checks') or {}).get('strict'))
            admins = bool((answer.get('enforce_admins') or {}).get('enabled'))
            if not admins:
                report.notes.append('enforce_admins is off: repository admins can merge without the required checks')
            protection.update(state='protected', required_checks=contexts, strict=strict, enforce_admins=admins,
                              requires_getzilla=all(check in contexts for check in expected),
                              requires_trust_ci=any(marker in check.lower() for check in contexts for marker in TRUST_CI_MARKERS))
    else:
        report.notes.append('branch protection unknown: no GitHub access (gh not signed in or no repository slug); '
                            'it is not counted as enforced')
    report.branch_protection = protection
    hooks_work = report.self_test.get('status') in {'pass', 'not_run'} and bool(report.hooks)
    if protection.get('requires_getzilla') and report.ci_workflow:
        report.level = 'external' if protection.get('requires_trust_ci') else 'ci-enforced'
    elif not hooks_work:
        report.level = 'none'
    return report
