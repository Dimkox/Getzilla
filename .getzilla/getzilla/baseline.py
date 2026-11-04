"""Mandatory baseline: security data plus pinned Superpowers, BMAD and Spec Kit for the agent in use.

`install_user` fetches the configured exact source pins. `apply_project` consumes
reviewable generated assets tied to those pins, full archive hashes, dependency locks,
and fixed generation commands. It never invokes ambient npx/specify or upstream code.
No native sandbox is required on consumer machines. Semantic safety remains unqualified.
`inspect` reports missing baseline data; it does not claim tools or permissions exist.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping
from . import STACK_DIR

TOOLCHAIN = STACK_DIR / 'config' / 'toolchain.json'
BASELINE_DIR = 'baseline'
SKILL_SOURCE = '.agents/skills'
AGENT_SKILL_DIRS = {'claude': '.claude/skills', 'qwen': '.qwen/skills', 'gemini': '.gemini/skills',
                    'grok': '.grok/skills', 'codex': '.agents/skills'}
AGENTS = ('claude', 'codex', 'qwen', 'gemini', 'grok', 'copilot')

Runner = Callable[[list[str], Path | None], subprocess.CompletedProcess]


@dataclass(frozen=True)
class Step:
    component: str
    status: str  # ok, fail, skip
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {'component': self.component, 'status': self.status, 'detail': self.detail}


def _env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1'})
    return env


def default_runner(command: list[str], cwd: Path | None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding='utf-8', errors='replace',
                          check=False, env=_env(), timeout=1800)


def components(path: Path = TOOLCHAIN) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding='utf-8'))
    return {str(item['id']): item for item in data['workflow_sources']['components']}


def _tail(process: subprocess.CompletedProcess) -> str:
    text = ((process.stderr or '') + (process.stdout or '')).strip().splitlines()
    return text[-1][:300] if text else f'exit {process.returncode}'


def pinned_checkout(home: Path) -> Path:
    return home / BASELINE_DIR


def _head(run: Runner, target: Path) -> str | None:
    process = run(['git', '-C', str(target), 'rev-parse', 'HEAD'], None)
    return (process.stdout or '').strip() if process.returncode == 0 else None


def _upstream(url: str) -> str:
    return url


def install_user(home: Path, *, run: Runner = default_runner, which: Callable[[str], str | None] = shutil.which,
                 config: Mapping[str, Mapping[str, Any]] | None = None,
                 locate: Callable[[str], str] = _upstream) -> list[Step]:
    """Pinned workflow sources and tools for this user; a mismatch or a missing prerequisite fails.

    ``locate`` maps each upstream Git URL to the one to use (the updater's offline mirror).
    """
    config = config or components()
    steps: list[Step] = []
    root = pinned_checkout(home)
    root.mkdir(parents=True, exist_ok=True)
    for component_id, component in sorted(config.items()):
        target = root / component_id
        expected = component['pinned_commit']
        if target.is_dir() and _head(run, target) == expected:
            steps.append(Step(f'baseline:{component_id}', 'ok', f"{component['pinned']} ({expected[:12]}, already installed)"))
            continue
        if target.exists():
            shutil.rmtree(target)
        process = run(['git', '-c', 'advice.detachedHead=false', 'clone', '-q', '--depth', '1', '--branch',
                       component['upstream_tag'], locate(f"https://github.com/{component['repository']}.git"), str(target)],
                      None)
        if process.returncode != 0:
            steps.append(Step(f'baseline:{component_id}', 'fail', f"clone {component['upstream_tag']}: {_tail(process)}"))
            continue
        head = _head(run, target)
        if head != expected:
            shutil.rmtree(target, ignore_errors=True)
            steps.append(Step(f'baseline:{component_id}', 'fail',
                              f"PINNED_COMMIT_MISMATCH: {component['upstream_tag']} is {head}, expected {expected}"))
            continue
        steps.append(Step(f'baseline:{component_id}', 'ok', f"{component['pinned']} ({expected[:12]})"))
    from .baseline_assets import load
    for component_id in ('superpowers', 'bmad', 'spec-kit'):
        try:
            load(component_id, 'claude')
        except ValueError as exc:
            steps.append(Step(f'baseline:{component_id}-assets', 'fail', str(exc)))
        else:
            steps.append(Step(f'baseline:{component_id}-assets', 'ok',
                              'bound generated assets; no ambient workflow CLI installed or required'))

    return steps


def apply_project(project: Path, agent: str, home: Path, *, run: Runner = default_runner,
                  config: Mapping[str, Mapping[str, Any]] | None = None, windows: bool = os.name == 'nt') -> list[Step]:
    """Validate the whole pinned asset batch, then copy data without running upstream tools.

    Existing BMAD/Spec Kit directories remain untouched. Imported skill prose is
    not semantic approval and never grants tool, network or secret permissions.
    """
    from .baseline_assets import load, materialize, preflight_destination
    if agent not in AGENTS:
        return [Step('project:agent', 'fail', f'unknown agent {agent!r}; expected one of {", ".join(AGENTS)}')]
    config = config or components()
    prepared = []
    try:
        for component_id in ('superpowers', 'bmad', 'spec-kit'):
            spec = config[component_id]
            if _head(run, pinned_checkout(home) / component_id) != spec['pinned_commit']:
                raise ValueError('PINNED_COMMIT_MISMATCH:' + component_id)
            payload = load(component_id, agent, windows=windows)
            if spec.get('asset_inputs', {}).get('source_commit') != spec['pinned_commit']:
                raise ValueError('ASSET_SOURCE_BINDING_MISMATCH:' + component_id)
            preflight_destination(project, payload)
            prepared.append(payload)
    except (ValueError, KeyError, OSError) as exc:
        return [Step('project:preflight', 'fail', 'NEEDS_REVIEW:' + str(exc)[:200])]
    steps = []
    for payload in prepared:
        try:
            result = materialize(project, payload)
        except (ValueError, OSError) as exc:
            steps.append(Step('project:' + payload.component, 'fail', str(exc)[:200]))
            break
        detail = (f"{result['marker']} already present; left as it is; byte custody unqualified" if result['status'] == 'preserved'
                  else f"{result['added']} bound asset files added; semantic safety unqualified; no native execution")
        steps.append(Step('project:' + payload.component, 'ok', detail))
    return steps


@dataclass
class BaselineStatus:
    complete: bool
    missing: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {'complete': self.complete, 'missing': self.missing, 'details': self.details}


def inspect(home: Path, project: Path | None = None, agent: str | None = None, *,
            run: Runner = default_runner, which: Callable[[str], str | None] = shutil.which,
            environ: Mapping[str, str] | None = None) -> BaselineStatus:
    env = os.environ if environ is None else environ
    config = components()
    missing: list[str] = []
    details: dict[str, Any] = {}
    osv = Path(env.get('GETZILLA_OSV_DB') or home / 'osv')
    osv_ok = env.get('GETZILLA_OSV_ONLINE', '').strip() == '1' or any(osv.glob('*/all.zip'))
    opengrep_ok = any((home / 'bin' / name).is_file() for name in ('opengrep', 'opengrep.exe')) or bool(which('opengrep'))
    details['security'] = {'osv': osv_ok, 'opengrep': opengrep_ok}
    if not osv_ok:
        missing.append('SECURITY_BASELINE_MISSING:osv')
    if not opengrep_ok:
        missing.append('SECURITY_BASELINE_MISSING:opengrep')
    pinned = {}
    for component_id, component in sorted(config.items()):
        head = _head(run, pinned_checkout(home) / component_id) if (pinned_checkout(home) / component_id).is_dir() else None
        pinned[component_id] = {'expected': component['pinned_commit'], 'installed': head}
        if head != component['pinned_commit']:
            missing.append(f'WORKFLOW_BASELINE_MISSING:{component_id}')
    details['workflow'] = pinned
    if project is not None:
        skills = pinned_checkout(home) / 'superpowers' / 'skills'
        names = sorted(path.name for path in skills.iterdir() if path.is_dir()) if skills.is_dir() else []
        project_state = {
            'superpowers': bool(names) and all((project / SKILL_SOURCE / name / 'SKILL.md').is_file() for name in names),
            'bmad': (project / '_bmad').is_dir(),
            'spec-kit': (project / '.specify').is_dir(),
        }
        if agent in AGENT_SKILL_DIRS and names:
            project_state['agent_skills'] = all((project / AGENT_SKILL_DIRS[agent] / name / 'SKILL.md').is_file()
                                                for name in names)
        details['project'] = project_state
        missing.extend(f'PROJECT_BASELINE_MISSING:{name}' for name, ok in project_state.items() if not ok)
    return BaselineStatus(not missing, missing, details)


def detect_agent(project: Path, environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    chosen = env.get('GETZILLA_AGENT', '').strip().lower()
    if chosen in AGENTS:
        return chosen
    for agent, marker in (('claude', '.claude'), ('codex', '.codex'), ('qwen', '.qwen'), ('gemini', '.gemini'),
                          ('grok', '.grok/agents')):
        if (project / marker).exists():
            return agent
    return 'qwen'
