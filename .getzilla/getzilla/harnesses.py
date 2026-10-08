from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

HARNESSES = ('qwen', 'claude', 'codex', 'grok')
GENERATED_ROOTS = ('.qwen', '.claude', '.codex')
HOOK_SOURCE = '.grok/hooks.json'
AGENT_SOURCE = '.grok/agents'
SKILL_SOURCE = '.agents/skills'
CODEX_HOOK_EVENTS = ('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop')
QWEN_READ_ONLY_BLOCK = ('write_file', 'edit')
CLAUDE_READ_ONLY_TOOLS = ('Read', 'Grep', 'Glob', 'Bash', 'WebFetch', 'WebSearch')
LOCAL_FILES = frozenset({'settings.local.json', 'CLAUDE.local.md', '.env'})
_SCRIPT = re.compile(r'\.grok/hooks/([A-Za-z0-9_]+\.py)')


def _hook_events(root: Path) -> list[tuple[str, str, int]]:
    data = json.loads((root / HOOK_SOURCE).read_text(encoding='utf-8'))
    events: list[tuple[str, str, int]] = []
    for event, groups in data['hooks'].items():
        for group in groups:
            for hook in group['hooks']:
                match = _SCRIPT.search(hook['command'])
                if match is None:
                    raise ValueError(f'{HOOK_SOURCE}: {event} names no .grok/hooks script')
                events.append((event, match.group(1), int(hook.get('timeout', 60))))
    return events


def _command(script: str, harness: str) -> str:
    """A launcher that runs the project's own hook wherever the agent was started.

    The project directory the agent reports (CLAUDE_PROJECT_DIR, QWEN_PROJECT_DIR or
    GEMINI_PROJECT_DIR) wins; otherwise the outermost `.grok/hooks/<script>` above the
    working directory is used, so a hook planted in a subdirectory can never replace
    the project's. A relative path would also fail from a subdirectory with exit code
    2, which Claude-compatible agents treat as a blocking error. The hook learns which
    agent launched it through --harness. Only single quotes are used inside, so the
    same text works in sh, cmd and PowerShell.
    """
    target = f".grok/hooks/{script}"
    code = (
        "import os,pathlib,runpy,sys;"
        f"t='{target}';"
        "p=pathlib.Path;"
        "d=p.cwd();"
        "e=[p(os.environ[k]) for k in ('CLAUDE_PROJECT_DIR','QWEN_PROJECT_DIR','GEMINI_PROJECT_DIR') if os.environ.get(k)];"
        "f=next(q/t for q in (*e,*reversed(d.parents),d) if (q/t).is_file());"
        "sys.path.insert(0,str(f.parent));"
        f"sys.argv=[str(f),'--harness','{harness}'];"
        "runpy.run_path(str(f),run_name='__main__')"
    )
    return f'python3 -c "{code}" || python -c "{code}"'


def _hooks_block(events: list[tuple[str, str, int]], *, harness: str, milliseconds: bool,
                 only: tuple[str, ...] | None = None) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if only is not None and event not in only:
            continue
        block.setdefault(event, []).append({'hooks': [{
            'type': 'command',
            'command': _command(script, harness),
            'timeout': timeout * 1000 if milliseconds else timeout,
        }]})
    return block


def _json(data: dict) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _agents(root: Path) -> list[tuple[str, dict]]:
    agents = []
    for path in sorted((root / AGENT_SOURCE).glob('*.toml')):
        data = tomllib.loads(path.read_text(encoding='utf-8'))
        agents.append((path.stem, data))
    return agents


def _agent_markdown(name: str, data: dict, *, extra: list[str]) -> bytes:
    lines = ['---', f'name: {name}', f'description: {_yaml_string(data["description"])}', *extra, '---', '']
    body = data['developer_instructions'].strip()
    return ('\n'.join(lines) + body + '\n').encode('utf-8')


def _skills(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    base = root / SKILL_SOURCE
    for path in sorted(base.rglob('*')):
        if path.is_file():
            files[path.relative_to(base).as_posix()] = path.read_bytes()
    return files


def render(root: Path) -> dict[str, bytes]:
    events = _hook_events(root)
    agents = _agents(root)
    skills = _skills(root)
    out: dict[str, bytes] = {}

    out['.qwen/settings.json'] = _json({
        'context': {'fileName': ['AGENTS.md']},
        'hooks': _hooks_block(events, harness='qwen', milliseconds=True),
    })
    out['.claude/settings.json'] = _json({
        'hooks': _hooks_block(events, harness='claude', milliseconds=False),
    })
    out['.claude/CLAUDE.md'] = b'@../AGENTS.md\n'
    out['.codex/hooks.json'] = _json({
        'hooks': _hooks_block(events, harness='codex', milliseconds=False, only=CODEX_HOOK_EVENTS),
    })
    out['.codex/config.toml'] = b'[features]\ncodex_hooks = true\n'

    for name, data in agents:
        read_only = data.get('sandbox_mode') == 'read-only'
        qwen_extra = ['disallowedTools:', *[f'  - {tool}' for tool in QWEN_READ_ONLY_BLOCK]] if read_only else []
        claude_extra = [f'tools: {", ".join(CLAUDE_READ_ONLY_TOOLS)}'] if read_only else []
        out[f'.qwen/agents/{name}.md'] = _agent_markdown(name, data, extra=qwen_extra)
        out[f'.claude/agents/{name}.md'] = _agent_markdown(name, data, extra=claude_extra)
        out[f'.codex/agents/{name}.toml'] = (root / AGENT_SOURCE / f'{name}.toml').read_bytes()

    for rel, content in skills.items():
        out[f'.qwen/skills/{rel}'] = content
        out[f'.claude/skills/{rel}'] = content
    return out


def drift(root: Path) -> list[str]:
    expected = render(root)
    problems = []
    for rel, content in sorted(expected.items()):
        path = root / rel
        if not path.is_file():
            problems.append(f'missing {rel}')
        elif path.read_bytes() != content:
            problems.append(f'stale {rel}')
    for base in GENERATED_ROOTS:
        for path in sorted((root / base).rglob('*')) if (root / base).is_dir() else []:
            rel = path.relative_to(root).as_posix()
            if path.is_file() and rel not in expected and path.name not in LOCAL_FILES:
                problems.append(f'unexpected {rel}')
    return problems


def write(root: Path) -> list[str]:
    expected = render(root)
    changed = []
    for base in GENERATED_ROOTS:
        if not (root / base).is_dir():
            continue
        for path in sorted((root / base).rglob('*'), reverse=True):
            rel = path.relative_to(root).as_posix()
            if path.is_file() and rel not in expected and path.name not in LOCAL_FILES:
                path.unlink()
                changed.append(f'removed {rel}')
            elif path.is_dir() and not any(path.iterdir()):
                path.rmdir()
    for rel, content in sorted(expected.items()):
        path = root / rel
        if path.is_file() and path.read_bytes() == content:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        changed.append(f'wrote {rel}')
    return changed
