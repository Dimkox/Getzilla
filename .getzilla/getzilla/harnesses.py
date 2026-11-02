from __future__ import annotations

import json
import copy
import re
import tomllib
from pathlib import Path, PurePosixPath

from . import fsx as fsx
from .component_state import (
    MANIFEST, V2, KNOWN_AGENTS, BoundRoot, ComponentTransaction, FileSnapshot,
    ManifestState, agent_of, component_transaction, encode_manifest,
    matches_owned, mode_matches, owned_proof, read_state, record_owned,
    read_keep_contract, kept_file_state, match_kept_local, validate_manifest_publication,
)

HARNESSES = ('qwen', 'claude', 'codex', 'gemini', 'copilot', 'grok')
CURSOR_OUTPUT = '.cursor/rules/getzilla'
GENERATED_ROOTS = ('.grok/skills', '.qwen', '.claude', '.codex', '.gemini', '.github/hooks', '.github/agents', CURSOR_OUTPUT)
HOOK_SOURCE = '.grok/hooks.json'
CODEX_HOOK_SOURCE = '.grok/codex-hooks.json'
AGENT_SOURCE = '.grok/agents'
SKILL_SOURCE = '.agents/skills'
CURSOR_SOURCE = '.grok/cursor-rules'
CURSOR_MARKER = '<!-- Generated from .grok/cursor-rules/'  # marks the files Getzilla owns in .cursor/rules
CURSOR_KEYS = frozenset({'description', 'always_apply', 'globs', 'instructions'})
CURSOR_BUDGET = {True: 4096, False: 8192}  # bytes per always-applied core / per scoped rule
# Cursor splits `globs` on commas (https://cursor.com/docs/context/rules), so a pattern
# may not contain a comma, brace list, quote or whitespace; a leading `!` (a YAML tag,
# negation is undocumented) is rejected too.
_CURSOR_GLOB = re.compile(r'(?![/!])(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.*?/!\[\]-]+')
CODEX_HOOK_EVENTS = ('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'PostToolUse', 'Stop')
GEMINI_EVENTS = {
    'SessionStart': 'SessionStart',
    'UserPromptSubmit': 'BeforeAgent',
    'PreToolUse': 'BeforeTool',
    'PostToolUse': 'AfterTool',
    'PreCompact': 'PreCompress',
    'Stop': 'AfterAgent',
    'SessionEnd': 'SessionEnd',
}
COPILOT_EVENTS = {
    'SessionStart': 'sessionStart',
    'UserPromptSubmit': 'userPromptSubmitted',
    'PreToolUse': 'preToolUse',
    'PostToolUse': 'postToolUse',
    'SessionEnd': 'sessionEnd',
}
COPILOT_HOOKS = '.github/hooks/getzilla.json'
QWEN_READ_ONLY_BLOCK = ('write_file', 'edit')
COPILOT_READ_ONLY_TOOLS = ('read', 'search', 'shell')
CLAUDE_READ_ONLY_TOOLS = ('Read', 'Grep', 'Glob', 'Bash', 'WebFetch', 'WebSearch')
LOCAL_FILES = frozenset({'settings.local.json', 'CLAUDE.local.md', '.env'})
_SCRIPT = re.compile(r'\.grok/hooks/([A-Za-z0-9_]+\.py)')


def _source(binding: BoundRoot | ComponentTransaction, path: str) -> bytes:
    snapshot = binding.read(path)
    if snapshot is None:
        raise ValueError(f'missing canonical source: {path}')
    return snapshot.content


def _hook_events(binding: BoundRoot | ComponentTransaction) -> list[tuple[str, str, int]]:
    return _events_from_bytes(_source(binding, HOOK_SOURCE))


def _events_from_bytes(content: bytes) -> list[tuple[str, str, int]]:
    data = json.loads(content)
    events: list[tuple[str, str, int]] = []
    for event, groups in data['hooks'].items():
        for group in groups:
            for hook in group['hooks']:
                match = _SCRIPT.search(hook['command'])
                if match is None:
                    raise ValueError(f'{HOOK_SOURCE}: {event} names no .grok/hooks script')
                events.append((event, match.group(1), int(hook.get('timeout', 60))))
    return events


def _codex_hooks(events: list[tuple[str, str, int]], overlay: bytes | None) -> bytes:
    hooks = _hooks_block(events, harness='codex', milliseconds=False, only=CODEX_HOOK_EVENTS)
    if overlay is not None:
        data = json.loads(overlay)
        if type(data) is not dict or set(data) != {'hooks'} or type(data['hooks']) is not dict:
            raise ValueError('invalid canonical Codex overlay')
        for event, groups in data['hooks'].items():
            if type(groups) is not list:
                raise ValueError('invalid canonical Codex hook groups')
            entire_commands: set[str] = set()
            for group in groups:
                if type(group) is not dict or type(group.get('hooks')) is not list:
                    raise ValueError('invalid canonical Codex hook group')
                for hook in group['hooks']:
                    if type(hook) is not dict or type(hook.get('command')) is not str:
                        raise ValueError('invalid canonical Codex hook')
                    command = hook['command']
                    if 'entire hooks codex ' in command:
                        if command in entire_commands:
                            raise ValueError(f'duplicate Entire Codex hook: {event}')
                        entire_commands.add(command)
            hooks.setdefault(event, []).extend(groups)
    return _json({'hooks': hooks})


def render_codex_hooks(canonical_hooks: bytes, overlay: bytes | None) -> bytes:
    """Render immutable incoming guards with a retained consumer overlay."""
    return _codex_hooks(_events_from_bytes(canonical_hooks), overlay)


def _command(script: str, harness: str) -> str:
    """A launcher that runs the project's own hook wherever the agent was started.

    The project directory the agent reports (CLAUDE_PROJECT_DIR, QWEN_PROJECT_DIR or
    GEMINI_PROJECT_DIR) wins; otherwise the nearest installed project at cwd or an ancestor is used.
    An installed project has `.getzilla` and the requested canonical hook, so a
    hook-only subdirectory cannot replace its project. A relative path would also fail from a subdirectory with exit code
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
        "f=next(q/t for q in (*e,d,*d.parents) if (q/'.getzilla').is_dir() and (q/t).is_file());"
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


def _renamed_hooks_block(events: list[tuple[str, str, int]], *, harness: str, names: dict[str, str]) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if event in names:
            block.setdefault(names[event], []).append({'hooks': [{
                'type': 'command',
                'command': _command(script, harness),
                'timeout': timeout * 1000,
            }]})
    return block


def _copilot_hooks(events: list[tuple[str, str, int]]) -> dict:
    block: dict[str, list] = {}
    for event, script, timeout in events:
        if event in COPILOT_EVENTS:
            command = _command(script, 'copilot')
            block.setdefault(COPILOT_EVENTS[event], []).append({
                'type': 'command',
                'bash': command,
                'powershell': command,
                'cwd': '.',
                'timeoutSec': timeout,
            })
    return {'version': 1, 'hooks': block}


def _json(data: dict) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False) + '\n').encode('utf-8')


def _yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _agents(binding: BoundRoot | ComponentTransaction) -> list[tuple[str, dict, bytes]]:
    agents = []
    for path in binding.files(AGENT_SOURCE):
        if path.endswith('.toml'):
            content = _source(binding, path)
            data = tomllib.loads(content.decode('utf-8'))
            agents.append((PurePosixPath(path).stem, data, content))
    return agents


def _agent_markdown(name: str, data: dict, *, extra: list[str]) -> bytes:
    lines = ['---', f'name: {name}', f'description: {_yaml_string(data["description"])}', *extra, '---', '']
    body = data['developer_instructions'].strip()
    return ('\n'.join(lines) + body + '\n').encode('utf-8')


def _skills(binding: BoundRoot | ComponentTransaction) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in binding.files(SKILL_SOURCE, recursive=True):
        files[path.removeprefix(SKILL_SOURCE + '/')] = _source(binding, path)
    return files


def _cursor_rules(binding: BoundRoot | ComponentTransaction) -> dict[str, bytes]:
    """Prompt-only Cursor project rules; Cursor has no hooks, so it is not in HARNESSES."""
    out: dict[str, bytes] = {}
    always = 0
    for source in binding.files(CURSOR_SOURCE):
        path = PurePosixPath(source)
        if path.suffix != '.toml':
            continue
        rule = tomllib.loads(_source(binding, source).decode('utf-8'))
        globs, scoped = rule.get('globs', []), rule.get('always_apply') is False
        if (set(rule) - CURSOR_KEYS or type(rule.get('always_apply')) is not bool
                or not isinstance(rule.get('description'), str) or not rule['description'].strip()
                or not isinstance(rule.get('instructions'), str) or not rule['instructions'].strip() or not isinstance(globs, list)
                or scoped != bool(globs) or not all(isinstance(g, str) and _CURSOR_GLOB.fullmatch(g) for g in globs)):
            raise ValueError(f'{source}: needs description, instructions and always_apply, and globs '
                             'exactly when always_apply is false; globs hold no comma, brace, quote or space '
                             'and start with neither / nor !')
        always += not scoped
        head = ['---', f'description: {_yaml_string(rule["description"])}']
        head += [f'globs: {",".join(globs)}'] if globs else []
        head += [f'alwaysApply: {str(not scoped).lower()}', '---', '',
                 f'{CURSOR_MARKER}{path.name} by scripts/getzilla_harness.py --write; do not edit. -->', '', '']
        content = ('\n'.join(head) + rule['instructions'].strip() + '\n').encode('utf-8')
        if len(content) > CURSOR_BUDGET[not scoped] or content.count(b'\n') > 500:
            raise ValueError(f'{source}: rendered rule exceeds its context budget')
        out[f'{CURSOR_OUTPUT}/{path.stem}.mdc'] = content
    if always != 1:
        raise ValueError(f'{CURSOR_SOURCE}: exactly one rule must set always_apply = true')
    return out


def _selection(root: Path, state: ManifestState, binding: BoundRoot | ComponentTransaction,
               repository_all: bool) -> tuple[str, ...]:
    if not repository_all:
        return state.require_selection()
    if not all(binding.read(path) is not None for path in ('scripts/install_into.py', 'factory/pyproject.toml')):
        raise ValueError('--repository-all requires the full Getzilla source checkout')
    if state.kind == 'absent':
        return KNOWN_AGENTS
    selected = state.require_selection()
    if set(selected) != set(KNOWN_AGENTS):
        raise ValueError('--repository-all cannot override an established adapter selection')
    return selected


def render(root: Path, *, repository_all: bool = False) -> dict[str, bytes]:
    with BoundRoot(root) as binding:
        state = read_state(root, binding=binding)
        selected = _selection(root, state, binding, repository_all)
        return _render(binding, selected)


def _render(binding: BoundRoot | ComponentTransaction, selected: tuple[str, ...]) -> dict[str, bytes]:
    if not selected:
        return {}
    execution = bool(set(selected) & {'qwen', 'claude', 'codex', 'gemini', 'copilot'})
    events = _hook_events(binding) if execution else []
    agents = _agents(binding) if execution else []
    skills = _skills(binding) if set(selected) & {'qwen', 'claude', 'gemini', 'grok'} else {}
    out: dict[str, bytes] = {}

    out['.qwen/settings.json'] = _json({
        'context': {'fileName': ['AGENTS.md']},
        'hooks': _hooks_block(events, harness='qwen', milliseconds=True),
    })
    out['.claude/settings.json'] = _json({
        'hooks': _hooks_block(events, harness='claude', milliseconds=False),
    })
    out['.claude/CLAUDE.md'] = b'@../AGENTS.md\n'
    overlay = binding.read(CODEX_HOOK_SOURCE) if 'codex' in selected else None
    out['.codex/hooks.json'] = _codex_hooks(events, overlay.content if overlay else None)
    out['.codex/config.toml'] = b'[features]\ncodex_hooks = true\n'
    out['.gemini/settings.json'] = _json({
        'context': {'fileName': ['AGENTS.md']},
        'hooks': _renamed_hooks_block(events, harness='gemini', names=GEMINI_EVENTS),
    })
    out[COPILOT_HOOKS] = _json(_copilot_hooks(events))

    for name, data, original in agents:
        read_only = data.get('sandbox_mode') == 'read-only'
        qwen_extra = ['disallowedTools:', *[f'  - {tool}' for tool in QWEN_READ_ONLY_BLOCK]] if read_only else []
        claude_extra = [f'tools: {", ".join(CLAUDE_READ_ONLY_TOOLS)}'] if read_only else []
        out[f'.qwen/agents/{name}.md'] = _agent_markdown(name, data, extra=qwen_extra)
        out[f'.claude/agents/{name}.md'] = _agent_markdown(name, data, extra=claude_extra)
        out[f'.codex/agents/{name}.toml'] = original
        out[f'.gemini/agents/{name}.md'] = _agent_markdown(name, data, extra=[])
        copilot_extra = [f'tools: {json.dumps(list(COPILOT_READ_ONLY_TOOLS))}'] if read_only else []
        out[f'.github/agents/{name}.agent.md'] = _agent_markdown(name, data, extra=copilot_extra)

    for rel, content in skills.items():
        out[f'.grok/skills/{rel}'] = content
        out[f'.qwen/skills/{rel}'] = content
        out[f'.claude/skills/{rel}'] = content
        out[f'.gemini/skills/{rel}'] = content
    if 'cursor' in selected:
        out.update(_cursor_rules(binding))
    return {path: content for path, content in out.items() if agent_of(path) in selected}


_GENERATED_PATH = re.compile(
    r'(?:\.(?:qwen|claude|gemini)/settings\.json|\.claude/CLAUDE\.md|'
    r'\.(?:qwen|claude|gemini)/agents/[^/]+\.md|\.codex/agents/[^/]+\.toml|'
    r'\.codex/(?:hooks\.json|config\.toml)|\.github/hooks/getzilla\.json|'
    r'\.github/agents/[^/]+\.agent\.md|\.(?:qwen|claude|gemini|grok)/skills/.+|'
    r'\.cursor/rules/getzilla/[^/]+\.mdc)'
)


def _generation_plan(binding: BoundRoot | ComponentTransaction, state: ManifestState,
                     selected: tuple[str, ...]) -> tuple[list[str], list[tuple], list[tuple], dict]:
    expected = _render(binding, selected)
    manifest = copy.deepcopy(state.manifest) if state.kind == 'selected' else {
        'schema_version': V2, 'agents': list(selected), 'components': {},
    }
    problems: list[str] = []
    changes: list[tuple[str, bytes, FileSnapshot | None]] = []
    retirements: list[tuple[str, FileSnapshot]] = []
    generated = set(expected) | {
        path for record in manifest['components'].values() for path in record.get('owned', {})
        if agent_of(path) in selected and _GENERATED_PATH.fullmatch(path)
    }
    kept, kept_digests = read_keep_contract(binding)
    kept, kept_digests = match_kept_local(kept, kept_digests, generated)
    codex_pair = {'.codex/hooks.json', '.codex/config.toml'}
    if 'codex' in selected and codex_pair & kept:
        # A keep declaration never activates or rebuilds the other half of the
        # Codex pair. Preserve only an already coherent unit; otherwise refuse.
        for relative in sorted(codex_pair):
            try:
                current = binding.read(relative)
                if current is None or current.content != expected[relative] or not mode_matches(current.mode, 0o644):
                    problems.append(f'conflict kept-local Codex pair: {relative}')
            except (OSError, ValueError):
                problems.append(f'conflict kept-local Codex pair: {relative}')
    for relative in sorted(generated & kept):
        try:
            current = binding.read(relative)
            kept_file_state(relative, current.content if current else None, expected.get(relative), kept_digests.get(relative))
        except (OSError, ValueError) as exc:
            problems.append(f'conflict kept-local {relative}: {exc}')
            continue
        for record in manifest['components'].values():
            record.get('owned', {}).pop(relative, None)
    for relative, content in sorted(expected.items()):
        if relative in kept:
            continue
        try:
            current = binding.read(relative)
        except (OSError, ValueError):
            problems.append(f'conflict {relative}')
            continue
        if current is None:
            problems.append(f'missing {relative}')
            changes.append((relative, content, None))
        elif current.content != content or not mode_matches(current.mode, 0o644):
            if relative == '.codex/config.toml' or not matches_owned(current, owned_proof(manifest, relative)):
                problems.append(f'conflict {relative}')
                continue
            problems.append(f'stale {relative}')
            changes.append((relative, content, current))
        record_owned(manifest, relative, content, 0o644)
    for record in manifest['components'].values():
        for relative, proof in list(record.get('owned', {}).items()):
            if relative in expected or relative in kept or agent_of(relative) not in selected or not _GENERATED_PATH.fullmatch(relative):
                continue
            try:
                current = binding.read(relative)
            except (OSError, ValueError):
                problems.append(f'conflict {relative}')
                continue
            if current is not None:
                if not matches_owned(current, proof):
                    problems.append(f'conflict {relative}')
                    continue
                problems.append(f'unexpected {relative}')
                retirements.append((relative, current))
            del record['owned'][relative]
            record['files'].remove(relative)
    try:
        validate_manifest_publication(binding.read(MANIFEST),
                                      encode_manifest(manifest) if manifest != state.manifest else None,
                                      kept, kept_digests)
    except (OSError, ValueError) as exc:
        problems.append(f'conflict kept component manifest: {exc}')
    return problems, changes, retirements, manifest


def drift(root: Path, *, repository_all: bool = False) -> list[str]:
    with BoundRoot(root) as binding:
        state = read_state(root, binding=binding)
        selected = _selection(root, state, binding, repository_all)
        problems, _changes, _retirements, _manifest = _generation_plan(binding, state, selected)
        return problems


def write(root: Path, *, repository_all: bool = False) -> list[str]:
    def plan(binding: BoundRoot | ComponentTransaction) -> tuple[ManifestState, tuple]:
        state = read_state(root, binding=binding)
        selected = _selection(root, state, binding, repository_all)
        source_checkout = all(binding.read(path) is not None for path in ('scripts/install_into.py', 'factory/pyproject.toml'))
        if source_checkout and not repository_all:
            raise ValueError('source checkout generation requires --repository-all')
        result = _generation_plan(binding, state, selected)
        conflicts = [problem for problem in result[0] if problem.startswith('conflict ')]
        if conflicts:
            raise ValueError(f'no generated files written; resolve {", ".join(conflicts)}')
        return state, result

    with BoundRoot(root) as binding:
        plan(binding)
    with component_transaction(root) as transaction:
        state, (_problems, changes, retirements, manifest) = plan(transaction)
        original = transaction.read(MANIFEST)
        encoded = encode_manifest(manifest) if manifest != state.manifest else None
        changed: list[str] = []
        try:
            for relative, content, current in changes:
                transaction.write(relative, content, 0o644, expected=current)
                changed.append(f'wrote {relative}')
            for relative, current in retirements:
                transaction.remove(relative, expected=current)
                changed.append(f'removed {relative}')
            if encoded is not None:
                transaction.write(MANIFEST, encoded, 0o644, expected=original)
                if not changed:
                    changed.append('updated component ownership')
        except (ValueError, OSError) as exc:
            raise ValueError(f'generation incomplete after {changed}; inspect outputs and component manifest: {exc}') from exc
        return changed
