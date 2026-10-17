"""Mandatory baseline: security data plus pinned Superpowers, BMAD and Spec Kit for the agent in use.

Nothing here is optional. `install_user` (run by the installer through `getzilla_update.py --only
baseline`) fetches the exact pinned tag of each workflow source, checks that it resolves to the
pinned commit, and installs the pinned Spec Kit CLI. `apply_project` wires them into a project:
Superpowers skills into the canonical `.agents/skills` and the agent's skill directory, BMAD and
Spec Kit through their own installers run in an empty staging directory and merged without
overwriting anything that already exists. `inspect` says what is missing; verify and doctor turn
that into a red result.
"""
from __future__ import annotations

import filecmp
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

TOOLCHAIN = Path(__file__).resolve().parents[1] / 'config' / 'toolchain.json'
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


def install_user(home: Path, *, run: Runner = default_runner, which: Callable[[str], str | None] = shutil.which,
                 config: Mapping[str, Mapping[str, Any]] | None = None) -> list[Step]:
    """Pinned workflow sources and tools for this user; a mismatch or a missing prerequisite fails."""
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
                       component['upstream_tag'], f"https://github.com/{component['repository']}.git", str(target)], None)
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
    spec_kit = config.get('spec-kit')
    if spec_kit:
        if not which('uv'):
            steps.append(Step('baseline:specify-cli', 'fail', 'uv is required for the Spec Kit CLI; install uv and re-run'))
        else:
            process = run([which('uv') or 'uv', 'tool', 'install', '--force', 'specify-cli', '--from',
                           f"git+https://github.com/{spec_kit['repository']}.git@{spec_kit['upstream_tag']}"], None)
            steps.append(Step('baseline:specify-cli', 'ok' if process.returncode == 0 else 'fail',
                              spec_kit['upstream_tag'] if process.returncode == 0 else _tail(process)))
    if 'bmad' in config:
        steps.append(Step('baseline:node', 'ok' if which('npx') else 'fail',
                          'npx available for the pinned BMAD installer' if which('npx') else
                          'Node.js (npx) is required for the BMAD installer; install Node.js and re-run'))
    return steps


def _merge_without_overwrite(source: Path, target: Path) -> tuple[list[str], list[str]]:
    added, conflicts = [], []
    for path in sorted(source.rglob('*')):
        relative = path.relative_to(source)
        if relative.parts and relative.parts[0] == '.git' or path.is_dir() or path.is_symlink():
            continue
        destination = target / relative
        if destination.exists():
            if not filecmp.cmp(path, destination, shallow=False):
                conflicts.append(relative.as_posix())
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        added.append(relative.as_posix())
    return added, conflicts


def _staged_install(component_id: str, command: list[str], project: Path, run: Runner, marker: str) -> Step:
    if (project / marker).exists():
        return Step(f'project:{component_id}', 'ok', f'{marker} already present; left as it is')
    with tempfile.TemporaryDirectory(prefix=f'getzilla-{component_id}-') as tmp:
        stage = Path(tmp)
        process = run([part.replace('{stage}', str(stage)) for part in command], stage)
        if process.returncode != 0:
            return Step(f'project:{component_id}', 'fail', _tail(process))
        if not (stage / marker).exists():
            return Step(f'project:{component_id}', 'fail', f'installer did not create {marker}')
        added, conflicts = _merge_without_overwrite(stage, project)
    detail = f'{len(added)} files added'
    if conflicts:
        detail += f'; {len(conflicts)} existing files kept (not overwritten): {", ".join(conflicts[:5])}'
    return Step(f'project:{component_id}', 'ok', detail)


def apply_project(project: Path, agent: str, home: Path, *, run: Runner = default_runner,
                  config: Mapping[str, Mapping[str, Any]] | None = None, windows: bool = os.name == 'nt') -> list[Step]:
    """Wire the pinned baseline into one project for one agent; never overwrites an existing file."""
    if agent not in AGENTS:
        return [Step('project:agent', 'fail', f'unknown agent {agent!r}; expected one of {", ".join(AGENTS)}')]
    config = config or components()
    steps: list[Step] = []
    source = pinned_checkout(home) / 'superpowers' / 'skills'
    if not source.is_dir():
        steps.append(Step('project:superpowers', 'fail', 'pinned Superpowers is not installed; run getzilla_update.py --only baseline'))
    else:
        license_file = pinned_checkout(home) / 'superpowers' / 'LICENSE'
        targets = [SKILL_SOURCE] + ([AGENT_SKILL_DIRS[agent]] if agent in AGENT_SKILL_DIRS else [])
        added = conflicts = 0
        for skill in sorted(path for path in source.iterdir() if path.is_dir()):
            for directory in dict.fromkeys(targets):
                destination = project / directory / skill.name
                new, kept = _merge_without_overwrite(skill, destination)
                added += len(new)
                conflicts += len(kept)
                if license_file.is_file() and not (destination / 'LICENSE').exists():
                    shutil.copy2(license_file, destination / 'LICENSE')
        if agent == 'copilot':
            steps.append(Step('project:superpowers', 'ok', f'{added} skill files in {SKILL_SOURCE}; Copilot also needs '
                              '`copilot plugin install superpowers@superpowers-marketplace` (upstream marketplace, not pinned)'))
        else:
            steps.append(Step('project:superpowers', 'ok', f"{config['superpowers']['pinned']}: {added} files added, "
                              f'{conflicts} existing kept'))
    bmad = config['bmad']
    tool = bmad['install']['tools'][agent]
    steps.append(_staged_install('bmad', ['npx', '--yes', f"bmad-method@{bmad['pinned']}", 'install', '--directory',
                                          '{stage}', '--tools', tool, '--yes'], project, run, '_bmad'))
    spec = config['spec-kit']
    integration = spec['install']['integrations'][agent]
    steps.append(_staged_install('spec-kit', ['specify', 'init', '--here', '--integration', integration, '--non-interactive',
                                              '--ignore-agent-tools', '--script', 'ps' if windows else 'sh'],
                                 project, run, '.specify'))
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
