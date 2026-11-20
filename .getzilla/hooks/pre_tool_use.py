#!/usr/bin/env python3
"""PreToolUse — policy gate; a policy that fails to load still refuses protected actions (#78)."""
from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import json
import math
import os
import re
import shlex
import stat
import sys
sys.dont_write_bytecode = True
import time
import zipimport
from pathlib import Path
from typing import Any

# Standard library only: used when the Getzilla policy or its helper library did not load (#78).
_DEGRADED_SHELL_TOOLS = frozenset({'Bash', 'bash', 'run_shell_command', 'shell', 'exec_command', 'PowerShell',
                                   'powershell', 'Monitor', 'monitor', 'terminal', 'run_in_terminal',
                                   'run_terminal_command', 'local_shell', 'container.exec'})
_DEGRADED_WRITE_TOOLS = frozenset({'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'write_file', 'edit', 'replace',
                                   'edit_file', 'apply_patch', 'create_file', 'str_replace_editor'})
_DEGRADED_CONTROL_PLANE = re.compile(r'(?:^|[\s/"\'=>:])(?:\.getzilla/|\.grok/|\.claude/|\.codex/|\.qwen/|\.gemini/|AGENTS\.md\b)')
_DEGRADED_SHELL_WRITE = re.compile(r'>|\b(?:tee|cp|mv|rm|install|ln|chmod|truncate|touch|rsync)\b|\bsed\s+-i|\bperl\s+-\S*i')
_MAX_TOOL_PAYLOAD_BYTES = 1_048_576
_INVALID_TOOL_REQUEST = 'invalid_tool_request: request classification is unavailable.'


def _payload_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('invalid-tool-request')
        result[key] = value
    return result


def _payload_constant(value):
    raise ValueError('invalid-tool-request')


def _payload_tree(value):
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 128 or nodes > 65_536:
            raise ValueError('invalid-tool-request')
        if isinstance(item, dict):
            pending.extend((part, depth + 1) for pair in item.items() for part in pair)
        elif isinstance(item, list):
            pending.extend((part, depth + 1) for part in item)
        elif isinstance(item, str):
            item.encode('utf-8', errors='strict')
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('invalid-tool-request')


def _read_tool_payload() -> dict[str, Any]:
    """Decode a bounded request before any fallback can call it a local read."""
    stream = getattr(sys.stdin, 'buffer', None)
    raw = stream.read(_MAX_TOOL_PAYLOAD_BYTES + 1) if stream is not None else sys.stdin.read(_MAX_TOOL_PAYLOAD_BYTES + 1)
    if isinstance(raw, str):
        raw = raw.encode('utf-8', errors='strict')
    if len(raw) > _MAX_TOOL_PAYLOAD_BYTES:
        raise ValueError('invalid-tool-request')
    value = json.loads(raw.decode('utf-8-sig', errors='strict'), object_pairs_hook=_payload_object,
                       parse_constant=_payload_constant)
    _payload_tree(value)
    if not isinstance(value, dict):
        raise ValueError('invalid-tool-request')
    names = [value[key] for key in ('tool_name', 'toolName') if key in value]
    if (not names or any(not isinstance(name, str) or not name.strip() or len(name) > 512
                         or any(ord(char) < 32 for char in name) for name in names)):
        raise ValueError('invalid-tool-request')
    for key in ('tool_input', 'toolInput', 'toolArgs'):
        if key not in value or value[key] is None:
            continue
        inputs = value[key]
        if isinstance(inputs, str):
            try:
                inputs = json.loads(inputs, object_pairs_hook=_payload_object, parse_constant=_payload_constant)
            except ValueError:
                # Some native shell envelopes carry toolArgs as plain command
                # text. A JSON-looking value still needs the strict decoder.
                if all(name in {'apply_patch', 'functions.apply_patch'} for name in names):
                    inputs = {'input': inputs}
                elif (key != 'toolArgs' or not inputs.strip()
                        or inputs.lstrip()[0] in '{["' or inputs.strip() in {'null', 'true', 'false'}
                        or not all(name in _DEGRADED_SHELL_TOOLS for name in names)):
                    raise
                else:
                    inputs = {'command': inputs}
            _payload_tree(inputs)
        if not isinstance(inputs, dict):
            raise ValueError('invalid-tool-request')
        value[key] = inputs
    candidates = [value[key] for key in ('tool_input', 'toolInput', 'toolArgs') if key in value and value[key] is not None]
    if candidates and any(candidate != candidates[0] for candidate in candidates):
        raise ValueError('invalid-tool-request')
    return value




def _degraded_intake_required(root: Path | None = None) -> bool:
    """Read only the bounded canonical native marker when package imports fail.

    Unknown existing task state cannot downgrade an enabled task. No approval or
    source data is accepted through this fallback.
    """
    root = root or next((path for path in (Path.cwd(),*Path.cwd().parents) if (path/'.getzilla').is_dir()),None)
    if root is None:
        return False
    def read(parts):
        handles=[]
        try:
            if os.name == 'nt':
                raise ValueError('descriptor fallback unavailable')
            directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            handles.append(directory)
            for part in parts[:-1]:
                directory=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                handles.append(directory)
            descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            handles.append(descriptor)
            before=os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size>1_048_576:
                raise ValueError('unavailable marker')
            raw=b''
            while len(raw)<=1_048_576:
                chunk=os.read(descriptor,min(65536,1_048_577-len(raw)))
                if not chunk:
                    break
                raw+=chunk
            after=os.fstat(descriptor)
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ValueError('changed marker')
            return json.loads(raw)
        finally:
            for descriptor in reversed(handles):
                os.close(descriptor)
    try:
        pointer=read(('.getzilla','runtime','active-route.json'))
    except FileNotFoundError:
        return (root/'.getzilla/runtime/sessions').exists()
    except Exception:
        return True
    try:
        route_id=pointer['route_id']
        if not isinstance(route_id,str) or re.fullmatch('[A-Za-z0-9_-]{1,128}',route_id) is None:
            return True
        try:
            route=read(('.getzilla','runtime','routes',route_id+'.json'))
        except FileNotFoundError:
            if 'task_context_version' in pointer or set(pointer)<= {'route_id','session_id'}:
                return True
            route=pointer
        context=route.get('context') or {}
        return context.get('version')==2 or 'intake' in context or ('task_context_version' in route and context.get('version')!=1)
    except Exception:
        return True



# Kept independent of _lib/policy: both can be unavailable here. Defaults are
# covered through the real hook protocol, including every normal secret pattern.
_DEGRADED_SECRET_PATHS = (
    '.env', '.env.*', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
    '**/id_rsa', '**/id_ed25519', '**/credentials*', '**/secrets/**', 'trust-ci/env/*.env', 'trust-ci/runtime/**',
    '**/id_ecdsa', '**/id_dsa', '**/.ssh/**', '**/.git-credentials', '**/.netrc', '**/_netrc', '**/.npmrc', '**/.pypirc',
    '**/.pgpass', '**/.config/gh/hosts.yml', '**/.config/gh/**', '**/.docker/config.json', '**/.kube/config', '**/.aws/**',
    '**/.claude/.credentials.json', '**/.codex/auth.json', '**/.vault-token',
    '**/.composer/auth.json', '**/.config/composer/auth.json', '**/.config/gcloud/**',
    '**/.azure/**', '**/.terraform.d/credentials.tfrc.json', '**/.cargo/credentials*', '**/.gem/credentials',
)
_DEGRADED_PUBLIC_NAMES = (
    '*.pub', '.env.example', '.env.sample', '.env.template', '.env.dist',
    'known_hosts', 'known_hosts.old', 'authorized_keys', 'authorized_keys2',
)
_DEGRADED_READ_TOOLS = frozenset({'read', 'read_file', 'read_many_files', 'open_file', 'fs_read',
                                    'view', 'grep', 'notebookread', 'search'})
_DEGRADED_PATH_KEYS = frozenset({'path', 'file', 'filename', 'file_path', 'filepath', 'absolute_path',
                                     'notebook_path', 'directory', 'target', 'paths', 'file_paths', 'files', 'glob'})
_DEGRADED_REASON = (
    'Getzilla policy did not load. Protected actions and unresolved reads are refused until the hook is repaired '
    '(see .getzilla/runtime/hook-events.jsonl). Explicit public file reads and ordinary structured edits stay allowed.'
)


def _degraded_patterns() -> tuple[str, ...] | None:
    """Admit bounded regular config before reading; special files never wait for a writer."""
    path = Path(__file__).resolve().parents[2] / '.getzilla/config/policy.json'
    try:
        before = path.lstat()
    except FileNotFoundError:
        return _DEGRADED_SECRET_PATHS
    except OSError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_size > 65536 or not before.st_mode & 0o444:
        return None
    descriptor = None
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as handle:
            descriptor = None
            observed = os.fstat(handle.fileno())
            if (not stat.S_ISREG(observed.st_mode) or observed.st_size > 65536
                    or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)):
                return None
            raw = handle.read(65537)
            after = os.fstat(handle.fileno())
        if len(raw) > 65536 or (observed.st_size, observed.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            return None
        config = json.loads(raw)
        extra = config.get('secret_read_paths', []) if isinstance(config, dict) else None
        if (not isinstance(extra, list) or len(extra) > 128
                or any(not isinstance(item, str) or not item or len(item) > 4096 for item in extra)):
            return None
        return (*_DEGRADED_SECRET_PATHS, *extra)
    except (OSError, ValueError, RuntimeError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _degraded_public_path(value: Any, directory: Path, patterns: tuple[str, ...], *, allow_directory=False) -> bool:
    """Check names and symlink metadata only. Directories and expansions need the full policy."""
    if (not isinstance(value, str) or not value or len(value) > 4096
            or any(char in value for char in '$`*?[]{}~\x00\r\n')):
        return False
    try:
        raw = value.replace('\\', '/')
        # A drive/URI has no unambiguous POSIX meaning; Windows resolves native drives below.
        if ':' in raw and (sys.platform != 'win32' or len(raw) < 3 or raw[1] != ':' or ':' in raw[2:]):
            return False
        if any(part.endswith((' ', '.')) and part not in {'.', '..'} for part in raw.split('/')):
            return False
        path = Path(raw)
        path = path if path.is_absolute() else directory / path
        resolved = path.resolve()
        is_directory = resolved.is_dir()
        if is_directory and not allow_directory:
            return False
        for candidate in (path, resolved):
            name = candidate.as_posix().lower()
            if not is_directory and any(fnmatch.fnmatchcase(candidate.name.lower(), public) for public in _DEGRADED_PUBLIC_NAMES):
                enclosing = candidate.parent.as_posix().lower().rstrip('/') + '/'
                stronger = [pattern for pattern in patterns if pattern != '**/.ssh/**']
                if not any(fnmatch.fnmatchcase(enclosing, pattern.lower())
                           or fnmatch.fnmatchcase(enclosing, '*/' + pattern.lower()) for pattern in stronger):
                    continue
            if any(fnmatch.fnmatchcase(name, pattern.lower())
                   or fnmatch.fnmatchcase(name, '*/' + pattern.lower()) for pattern in patterns):
                return False
            if is_directory:
                for parent in (candidate, *candidate.parents):
                    names = (parent.as_posix().lower(), parent.as_posix().lower().rstrip('/') + '/')
                    if any(fnmatch.fnmatchcase(item, pattern.lower())
                           or fnmatch.fnmatchcase(item, '*/' + pattern.lower())
                           for item in names for pattern in patterns):
                        return False
        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _degraded_executable(word: str) -> str | None:
    """Known native names or exact standard POSIX paths; arbitrary basenames prove nothing."""
    system = {'cat', 'head', 'tail', 'wc', 'ls', 'pwd', 'echo', 'printf', 'git'}
    bare = system | {'get-content', 'Get-Content', 'gc', 'type'}
    if word in bare:
        return word.lower()
    if sys.platform == 'win32' and word.lower() in {name.lower() for name in bare}:
        return word.lower()
    prefixes = ('/usr/bin/', '/bin/') if sys.platform != 'win32' else ()
    for prefix in prefixes:
        if word.startswith(prefix) and word[len(prefix):] in system:
            return word[len(prefix):]
    return None


def _degraded_shell_read(command: Any, directory: Path, patterns: tuple[str, ...]) -> bool:
    """Allow a small explicit grammar, not a second shell evaluator or approval system."""
    if isinstance(command, list):
        if not command or any(not isinstance(part, str) for part in command):
            return False
        command = shlex.join(command)
    if (not isinstance(command, str) or not command.strip() or len(command) > 131072
            or any(char in command for char in '$`;&|<>(){}\\\x00\r\n')):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    offset = 0
    while offset < min(len(words), 16) and words[offset] == 'command':
        offset += 1
    words = words[offset:]
    if not words:
        return False
    name = _degraded_executable(words[0])
    operands = words[1:]
    if name in {'pwd', 'echo', 'printf'}:
        return True
    if name == 'ls':
        paths, options = [], True
        for word in operands:
            if options and word == '--':
                options = False
            elif options and word.startswith('-'):
                if (re.fullmatch(r'-[1adlAh]+', word) is None
                        and word not in {'--all', '--almost-all', '--directory', '--color=never'}):
                    return False
            else:
                paths.append(word)
        return len(paths) <= 128 and all(_degraded_public_path(
            path, directory, patterns, allow_directory=True) for path in (paths or ['.']))
    if name == 'git':
        return bool(operands) and operands[0] == 'status' and all(word.startswith('-') for word in operands[1:])
    if name not in {'cat', 'head', 'tail', 'wc', 'get-content', 'gc', 'type'}:
        return False
    paths = []
    index = 0
    options = True
    while index < len(operands):
        word = operands[index]
        if options and word == '--':
            options = False
        elif options and word in {'-n', '-c', '--lines', '--bytes'} and name in {'head', 'tail'}:
            index += 1
            if index == len(operands) or not operands[index].isdigit():
                return False
        elif options and word.startswith('-'):
            # Unknown options can load files or change interpretation. Keep the subset closed.
            if word not in {'-n', '-b', '-s', '-E', '-T', '-v', '-l', '-w', '-c'}:
                return False
        else:
            paths.append(word)
        index += 1
    return bool(paths) and len(paths) <= 128 and all(
        _degraded_public_path(path, directory, patterns) for path in paths
    )


def _degraded_denial(tool: str, inputs: Any, execution_cwd: Any = ..., *, root: Path | None = None) -> str | None:
    if tool.startswith('mcp__'):
        return 'mcp_identity_unverified: external MCP identity is unsupported while the policy is unavailable.'
    if _degraded_intake_required(root):
        affected = tool in _DEGRADED_WRITE_TOOLS or tool in _DEGRADED_SHELL_TOOLS or tool.startswith('mcp__')
        if tool in _DEGRADED_SHELL_TOOLS and isinstance(inputs, dict):
            command = inputs.get('command', inputs.get('cmd', ''))
            try:
                argv = shlex.split(command) if isinstance(command, str) else []
            except ValueError:
                argv = []
            if argv and argv[0] in {'pwd', 'cat', 'head', 'tail', 'wc'} and not any(char in str(command) for char in '><;&|`$()'):
                affected = False
        if affected:
            return 'Semantic intake cannot be loaded; this product mutation is refused.'
    """Keep protected actions denied without trusting imports that just failed."""
    if not tool or not isinstance(inputs, dict):
        return _DEGRADED_REASON
    lowered = tool.lower()
    is_read = lowered in _DEGRADED_READ_TOOLS or (tool.startswith('mcp__') and 'read' in lowered)
    if tool in _DEGRADED_SHELL_TOOLS or is_read:
        try:
            directory = Path.cwd() if execution_cwd is ... else Path(execution_cwd)
            if not directory.is_absolute():
                return _DEGRADED_REASON
            patterns = _degraded_patterns()
            if patterns is None:
                return _DEGRADED_REASON
            if tool in _DEGRADED_SHELL_TOOLS:
                command = inputs.get('command', inputs.get('cmd'))
                return None if _degraded_shell_read(command, directory, patterns) else _DEGRADED_REASON
            paths = []
            pending = [inputs]
            inspected = 0
            while pending:
                item = pending.pop()
                inspected += 1
                if inspected > 256:
                    return _DEGRADED_REASON
                if isinstance(item, dict):
                    if len(item) > 128:
                        return _DEGRADED_REASON
                    for key, value in item.items():
                        if key.lower() in _DEGRADED_PATH_KEYS:
                            values = value if isinstance(value, list) else [value]
                            if not values or len(values) > 128:
                                return _DEGRADED_REASON
                            paths.extend(values)
                        elif isinstance(value, (dict, list)):
                            pending.append(value)
                elif isinstance(item, list):
                    if len(item) > 128:
                        return _DEGRADED_REASON
                    pending.extend(item)
            if not paths or len(paths) > 128 or not all(_degraded_public_path(path, directory, patterns) for path in paths):
                return _DEGRADED_REASON
            return None
        except (OSError, TypeError, ValueError, RuntimeError):
            return _DEGRADED_REASON
    if tool in _DEGRADED_WRITE_TOOLS:
        targets = [str(inputs.get(key)) for key in ('file_path', 'path', 'notebook_path', 'filePath') if inputs.get(key)]
        targets += [str(inputs.get(key)) for key in ('patch', 'input') if isinstance(inputs.get(key), str)]
        if any(_DEGRADED_CONTROL_PLANE.search(target.replace('\\', '/')) for target in targets):
            return _DEGRADED_REASON
    return None


def _degraded_output(reason: str | None) -> str:
    args = sys.argv[1:]
    index = args.index('--harness') + 1 if '--harness' in args else len(args)
    harness_name = args[index] if index < len(args) else 'grok'
    if reason is None:
        return '{"decision":"allow"}' if harness_name == 'grok' else '{}'
    specific = {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                'permissionDecisionReason': reason}
    if harness_name == 'copilot':
        return json.dumps({'permissionDecision': 'deny', 'permissionDecisionReason': reason})
    if harness_name == 'gemini':
        return json.dumps({'decision': 'deny', 'reason': reason})
    if harness_name != 'grok':
        return json.dumps({'hookSpecificOutput': specific})
    return json.dumps({
        'decision': 'deny', 'reason': reason,
        'hookSpecificOutput': specific,
    })


def _degraded_tool(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 128:
        return None
    if value == 'functions.exec_command':
        value = 'exec_command'
    elif value == 'functions.apply_patch':
        value = 'apply_patch'
    elif value.startswith('functions.mcp__') and re.fullmatch(r'functions\.mcp__[A-Za-z0-9_-]+__[A-Za-z0-9_-]+', value):
        value = value.removeprefix('functions.')
    if value.lower() in {name.lower() for name in _DEGRADED_SHELL_TOOLS}:
        return 'Bash'
    if value.startswith('mcp__'):
        return value
    if value.lower() in _DEGRADED_READ_TOOLS or (value.startswith('mcp__') and 'read' in value.lower()):
        return 'Read'
    if value.lower() in {name.lower() for name in _DEGRADED_WRITE_TOOLS} | {'write', 'create', 'str_replace', 'search_replace'}:
        return 'Write'
    # Unclassified native executors and dispatch envelopes cannot become an allow.
    return None


def _degraded_request(payload: Any) -> tuple[str, Any, Any]:
    """Normalize the native aliases once; conflicting evidence never selects a permissive value."""
    try:
        if not isinstance(payload, dict):
            return '', None, None
        names = [_degraded_tool(payload[key]) for key in ('tool_name', 'toolName') if key in payload]
        if not names or names[0] is None or any(name != names[0] for name in names):
            return '', None, None
        candidates = []
        for key in ('tool_input', 'toolInput', 'toolArgs'):
            if key in payload:
                value = payload[key]
                if isinstance(value, str) and len(value) <= 262144:
                    try:
                        value = json.loads(value)
                    except ValueError:
                        if key != 'toolArgs' or names[0] != 'Bash':
                            return '', None, None
                        value = {'command': value}
                if not isinstance(value, dict):
                    return '', None, None
                candidates.append(value)
        if not candidates or any(value != candidates[0] for value in candidates):
            return '', None, None
        inputs = dict(candidates[0])
        origin = payload.get('cwd', str(Path.cwd()))
        if (not isinstance(origin, str) or len(origin) > 4096 or not Path(origin).is_absolute()
                or any(char in origin for char in '$`*?[]{}~\x00\r\n')):
            return '', None, None
        directory = Path(origin).resolve(strict=True)
        if not directory.is_dir():
            return '', None, None
        declared = []
        for key in ('workdir', 'cwd', 'working_directory', 'workingDirectory', 'directory'):
            if key in inputs:
                value = inputs[key]
                if (not isinstance(value, str) or not value or len(value) > 4096
                        or any(char in value for char in '$`*?[]{}~\x00\r\n')):
                    return '', None, None
                path = Path(value)
                path = (path if path.is_absolute() else directory / path).resolve(strict=True)
                if not path.is_dir():
                    return '', None, None
                declared.append(path)
        if declared:
            if any(path != declared[0] for path in declared):
                return '', None, None
            directory = declared[0]
        if names[0] == 'Bash':
            commands = []
            for key in ('command', 'cmd'):
                if key in inputs:
                    value = inputs[key]
                    if key == 'command' and isinstance(value, list) and value and all(isinstance(part, str) for part in value):
                        value = shlex.join(value)
                    if not isinstance(value, str) or not value.strip() or len(value) > 131072:
                        return '', None, None
                    commands.append(value)
            if not commands or any(value != commands[0] for value in commands):
                return '', None, None
            inputs['command'] = commands[0]
        return names[0], inputs, directory
    except (OSError, TypeError, ValueError, RuntimeError):
        return '', None, None


def _degraded_payload() -> tuple[str, Any, Any] | None:
    try:
        request = _degraded_request(_read_tool_payload())
        return request if request[0] else None
    except (OSError, UnicodeError, ValueError, RuntimeError, RecursionError, TypeError):
        return None


# Make stack importable even when cwd is project root
_ROOT_CANDIDATES = [
    Path.cwd(),
    Path.cwd() / ".getzilla",
]
for _p in _ROOT_CANDIDATES:
    s = str(_p)
    if s not in sys.path:
        sys.path.append(s)

_BOOTSTRAP_READY = False
try:
    # Never resolve a missing local bootstrap from ambient PYTHONPATH/cwd.
    _bootstrap_file = Path(__file__).resolve().parent / '_lib.py'
    if not stat.S_ISREG(_bootstrap_file.lstat().st_mode):
        raise ImportError('mandatory local bootstrap is not a regular file')
    from _lib import (
        record_degraded,
        RootContext,
        _shell_tokens,
        agent_generation,
        agent_id,
        emit,
        permission_output,
        root_context,
        session_id,
        tool_input,
        tool_name,
    )
    _BOOTSTRAP_READY = True
except Exception as _lib_error:
    # The stdlib boundary can admit only classified fallback operations.
    # A refusal exits2 so native hosts cannot ignore it as a nonblocking error.
    # Standard library only: the Getzilla package is what failed to import.
    import contextlib as _contextlib
    with _contextlib.suppress(Exception):
        import datetime as _datetime
        import json as _json
        _start = Path.cwd()
        _root = next((_path for _path in (_start, *_start.parents) if (_path / '.getzilla').is_dir()), None)
        if _root is not None:
            (_root / '.getzilla' / 'runtime').mkdir(parents=True, exist_ok=True)
            with (_root / '.getzilla' / 'runtime' / 'hook-events.jsonl').open('a', encoding='utf-8', newline='\n') as _handle:
                _handle.write(_json.dumps({
                    'ts': _datetime.datetime.now(_datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'kind': 'HOOK_DEGRADED', 'hook': 'pre_tool_use', 'harness': 'unknown',
                    'error': f'{type(_lib_error).__name__}: {_lib_error}'[:300],
                }) + '\n')
    _fallback_request = _degraded_payload()
    _fallback_reason = (_INVALID_TOOL_REQUEST if _fallback_request is None else
                        _degraded_denial(*_fallback_request))
    print(_degraded_output(_fallback_reason))
    if _fallback_reason is not None:
        raise SystemExit(2)
    # Return normally after an admitted fallback. Legacy wrappers must not
    # mistake SystemExit(0) for a failed bootstrap and replace this safe verdict.


_DENIAL_WINDOW_SECONDS = 15 * 60
_DENIAL_MAX_ENTRIES = 128
_EXACT_CIRCUIT_BREAKER_GUIDANCE = (
    'Circuit breaker: this exact tool invocation was denied again. Do not retry it, mutate it cosmetically, '
    'or create a speculative grant. Mark only this operation objective BLOCKED and stop only subagents and '
    'checks that require it. Continue independent permitted work under normal policy. '
    'Report the denied operation, its actual dependencies and the missing condition; '
    'do not declare the whole task blocked while independent permitted work remains. '
    'Changing tools, sessions or routes, or clearing the denial ledger, does not authorize a retry.'
)
_OBJECTIVE_CIRCUIT_BREAKER_GUIDANCE = (
    'Circuit breaker: the rewritten invocation was denied for the same objective. Do not retry this objective '
    'again or create a speculative grant. Mark only this operation objective BLOCKED and stop only subagents '
    'and checks that require it. Continue independent permitted work under normal policy. '
    'Report the denied operation, its actual dependencies and the missing condition; '
    'do not declare the whole task blocked while independent permitted work remains. '
    'Changing tools, sessions or routes, or clearing the denial ledger, does not authorize a retry.'
)
_CONTROL_PLANE_BATCH_GUIDANCE = (
    'Create one exact protected-path grant covering every target, then use Edit/Write/apply_patch. '
    'For an atomic multi-file batch, put the manifest outside the repository '
    'and run `python3 scripts/getzilla_protected_write.py --manifest <path>`.'
)


def _actionable_reason(reason: str) -> str:
    if 'control-plane shell mutation' not in reason:
        return reason
    if 'getzilla_protected_write.py' in reason:
        return reason
    return f'{reason} {_CONTROL_PLANE_BATCH_GUIDANCE}'


def _fingerprint(material: dict[str, Any]) -> str:
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
        default=str,
    ).encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()


def _ledger_reason(action: str) -> str:
    if action == 'external-write':
        return 'External write denied by repository policy.'
    if action == 'protected-path-write':
        return 'Protected path write denied by repository policy.'
    if action.startswith('git-push') or action in {
        'pull-request-merge', 'docker-push', 'npm-publish', 'github-release', 'workflow-dispatch'
    }:
        return f'Production action {action} denied by repository policy.'
    return f'Action {action} denied by repository policy.'


def _grants_digest(context: RootContext) -> str | None:
    root = context.ledger_root
    if root is None:
        return None
    try:
        return hashlib.sha256((Path(root) / '.getzilla/runtime/approvals.json').read_bytes()).hexdigest()
    except OSError:
        return None


def _denial_fingerprints(
    session: str,
    tool: str,
    input_data: dict[str, Any],
    reason: str,
    context: RootContext,
    action: str,
) -> tuple[str, str]:
    roots = {
        'session_root': str(context.session_root) if context.session_root else None,
        'effective_root': str(context.effective_root) if context.effective_root else None,
        'resolution_status': context.resolution_status,
        # A grant recorded after a denial makes the retry a new attempt, not a blind repeat.
        'grants_sha256': _grants_digest(context),
    }
    exact = _fingerprint({
        'session_id': session,
        'tool_name': tool,
        'tool_input': input_data,
        'reason': _ledger_reason(action),
        'reason_sha256': hashlib.sha256(reason.encode('utf-8')).hexdigest(),
        'root_context': roots,
    })
    objective_material = {
        'session_id': session,
        'tool_name': tool,
        'reason': reason,
        'action': action,
        'root_context': roots,
    }
    if action == 'ambiguous-sensitive-shell' or not context.sensitive_safe:
        # One root-resolution reason covers every ambiguous command; the operands tell independent objectives
        # apart, while respacing or reordering flags stays the same objective (#80).
        objective_material['target_sha256'] = _command_target(input_data)
    objective = _fingerprint(objective_material)
    return exact, objective


# What the agent can do instead, by the reason the command's directory could not be established.
_ROOT_HINTS = (
    ('command.inline-program',
     ' Inline interpreter code (python -c, php -r, node -e, a heredoc into an interpreter) can touch any path, '
     'so it is not run. Write the program to .getzilla/runtime/scratch/<name>.py (no grant needed) and run it '
     'as a file: python3 .getzilla/runtime/scratch/<name>.py.'),
    ('command.dynamic-substitution',
     ' $(...) and backticks hide the directory. Run the inner command on its own, then use its output as a '
     'literal path.'),
    ('command.control-flow',
     ' Only && and ; are followed. Split pipes, || and & into separate commands. '
     "For file discovery, use `rg --files --hidden -g '!.git' --iglob '*<name>*'`."),
)


def _root_hint(context: Any) -> str:
    sources = set(getattr(context, 'command_workdirs', {}) or {})
    for source, hint in _ROOT_HINTS:
        if source in sources:
            return hint
    status = getattr(context, 'resolution_status', '')
    if status == 'ambiguous-command-root':
        return (' Use one literal directory: no $VARIABLES, globs or braces in cd, pushd or git -C, and no two '
                'repositories in one command. Split it: one command per repository, each starting with '
                'cd <that repository>, and write long text such as a commit message to a file first.')
    if status == 'cross-root':
        return (f' The command runs in {getattr(context, "effective_root", None)}, but the session is in '
                f'{getattr(context, "session_root", None)}. Cross-root pushes require a registered linked '
                'worktree, a literal target directory or git -C, and its own exact grant. '
                'For PR creation, use that worktree as the absolute tool workdir or one literal cd &&, '
                'then gh pr create --repo <own owner/repo> --head <current non-protected branch> '
                'with its exact external-write grant. '
                'Other cross-root actions require a session in the target repository.')
    return ''


def _command_target(input_data: dict[str, Any]) -> str | None:
    command = input_data.get('command') if isinstance(input_data, dict) else None
    if not isinstance(command, str):
        return None
    try:
        words = [token.value for token in _shell_tokens(command) if not token.operator]
    except ValueError:
        words = command.split()
    operands = sorted({word for word in words if not word.startswith('-')})
    return hashlib.sha256(json.dumps(operands, ensure_ascii=False).encode('utf-8')).hexdigest()


def _fresh_entries(value: Any, now: float) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    fresh: dict[str, dict[str, Any]] = {}
    for key, entry in value.items():
        if not isinstance(entry, dict):
            continue
        updated_at = entry.get('updated_at')
        if isinstance(updated_at, (int, float)) and now - float(updated_at) <= _DENIAL_WINDOW_SECONDS:
            fresh[str(key)] = entry
    return fresh


def _increment_entry(
    entries: dict[str, dict[str, Any]],
    fingerprint: str,
    *,
    session: str,
    tool: str,
    now: float,
    evidence: dict[str, Any],
) -> int:
    previous = entries.get(fingerprint, {})
    previous_count = previous.get('count', 0) if isinstance(previous, dict) else 0
    count = int(previous_count) + 1 if isinstance(previous_count, int) else 1
    entries[fingerprint] = {
        'count': count,
        'session_id': session,
        'tool_name': tool,
        'updated_at': now,
        **evidence,
    }
    return count


def _cap_entries(entries: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if len(entries) <= _DENIAL_MAX_ENTRIES:
        return entries
    ordered = sorted(
        entries.items(),
        key=lambda item: float(item[1].get('updated_at', 0)),
        reverse=True,
    )[:_DENIAL_MAX_ENTRIES]
    return dict(ordered)


def _source_sha256(module: Any, filename: str) -> str:
    """Digest of a hook source; one inside the engine archive (getzilla.zip) is read through its import loader."""
    try:
        data = Path(filename).read_bytes()
    except OSError:
        data = module.__loader__.get_data(filename)
    return hashlib.sha256(data).hexdigest()


def _record_denial(
    root: Path,
    session: str,
    tool: str,
    input_data: dict[str, Any],
    reason: str,
    context: RootContext,
    action: str,
) -> tuple[int, int]:
    from getzilla import _policy_legacy
    from getzilla.state import runtime_lock
    from getzilla.util import dump_json, load_json, runtime_dir

    now = time.time()
    exact_fingerprint, objective_fingerprint = _denial_fingerprints(
        session,
        tool,
        input_data,
        reason,
        context,
        action,
    )
    path = runtime_dir(root) / 'tool-denials.json'
    command = input_data.get('command')
    sources = {
        'hook': (sys.modules.get(__name__), __file__),
        'root_parser': (sys.modules.get(root_context.__module__), root_context.__code__.co_filename),
        'policy_parser': (_policy_legacy, _policy_legacy.__file__),
    }
    evidence = {
        'session_cwd': context.session_cwd,
        'session_root': str(context.session_root) if context.session_root else None,
        'command_workdirs': {
            key: '<ambiguous>' if value == '<ambiguous>' else '<declared>'
            for key, value in context.command_workdirs.items()
        },
        'command_workdir_sources': sorted(context.command_workdirs),
        'root_failure_sources': sorted(
            key for key, value in context.command_workdirs.items() if value == '<ambiguous>'
        ),
        'hook_implementation': {
            name: {'path': str(Path(filename).resolve()), 'sha256': _source_sha256(module, filename)}
            for name, (module, filename) in sources.items()
        },
        'effective_root': str(context.effective_root) if context.effective_root else None,
        'resolution_status': context.resolution_status,
        'action': action,
        'reason': _ledger_reason(action),
        'reason_sha256': hashlib.sha256(reason.encode('utf-8')).hexdigest(),
        'tool_input_sha256': _fingerprint(input_data),
        'command_sha256': hashlib.sha256(command.encode('utf-8')).hexdigest() if isinstance(command, str) else None,
    }
    with runtime_lock(root, 'tool-denials'):
        data = load_json(path, {}) or {}
        if not isinstance(data, dict):
            data = {}
        exact_entries = _fresh_entries(data.get('exact', data.get('entries')), now)
        objective_entries = _fresh_entries(data.get('objectives'), now)
        exact_count = _increment_entry(
            exact_entries,
            exact_fingerprint,
            session=session,
            tool=tool,
            now=now,
            evidence=evidence,
        )
        objective_count = _increment_entry(
            objective_entries,
            objective_fingerprint,
            session=session,
            tool=tool,
            now=now,
            evidence=evidence,
        )
        dump_json(path, {
            'schema_version': 3,
            'exact': _cap_entries(exact_entries),
            'objectives': _cap_entries(objective_entries),
        })
    return exact_count, objective_count


def _warn_observer_failure() -> None:
    try:
        sys.stderr.write('Getzilla: lifecycle observation unavailable; authorization continues.\n')
    except Exception:
        # A broken diagnostics sink cannot bypass mandatory authorization either.
        return


# Same bound as the policy's command scan. An oversize Bash command is refused here,
# before root_context or the policy parses it, so the verdict lands well inside the
# harness hook timeout instead of racing it (review round 3).
MAX_BASH_COMMAND_CHARS = 131072


def _oversize_bash_command(current_tool: str, current_input: Any) -> bool:
    if current_tool != 'Bash':
        return False
    command = current_input.get('command') if isinstance(current_input, dict) else current_input
    size = len(command) if isinstance(command, str) else len(json.dumps(command, default=str))
    return size > MAX_BASH_COMMAND_CHARS


def _deny(payload: dict[str, Any], current_tool: str, current_input: dict[str, Any],
          reason: str, *, context: RootContext | None = None,
          action: str = 'policy-denial') -> None:
    """An established denial stays denied when context or recording fails."""
    message = reason
    try:
        message = _actionable_reason(reason)
        if context is None:
            context_input = current_input
            if action in {'invalid-tool-input', 'oversize-command'}:
                # Refused commands are not parsed to establish ledger identity.
                context_input = {key: value for key, value in current_input.items()
                                 if key not in {'command', 'cmd'}}
            context = root_context(payload, context_input, current_tool)
        ledger_root = context.ledger_root
        if ledger_root is None:
            raise RuntimeError('no recognized repository root for denial ledger')
        exact_count, objective_count = _record_denial(
            ledger_root, session_id(payload), current_tool, current_input,
            message, context, action,
        )
        if exact_count >= 2:
            message = f'{_EXACT_CIRCUIT_BREAKER_GUIDANCE} Original denial: {message}'
        elif objective_count >= 2:
            message = f'{_OBJECTIVE_CIRCUIT_BREAKER_GUIDANCE} Original denial: {message}'
    except Exception:
        message = f'{message} Denial recording unavailable; repeat counts are not established.'
    emit(permission_output(False, message))


def _path_miss(current_tool: str, current_input: dict[str, Any], payload: dict[str, Any], root: Path | None) -> str | None:
    """A read whose every named path is missing is refused with the real paths (getzilla.path_hints)."""
    command = current_input.get('command')
    if current_tool != 'Bash' or root is None or not isinstance(command, str):
        return None
    try:
        from getzilla.path_hints import command_cwd, refusal
        return refusal(root, command, command_cwd(root, payload, current_input))
    except Exception:
        try:
            sys.stderr.write('Getzilla: path hints unavailable; the command runs unchecked.\n')
        except Exception:
            # Diagnostics are advisory; an allowed command still runs.
            return None
        return None


def _unread_edit(current_tool: str, current_input: dict[str, Any], payload: dict[str, Any], root: Path | None) -> str | None:
    """A patch that changes an existing file this session never read is refused (getzilla.read_ledger)."""
    command = current_input.get('command')
    if current_tool != 'apply_patch' or root is None or not isinstance(command, str):
        return None
    try:
        from getzilla.path_hints import command_cwd
        from getzilla.read_ledger import refusal
        return refusal(root, session_id(payload), command, command_cwd(root, payload, current_input))
    except Exception:
        # The ledger is a guard against blind edits; when it cannot be read, the patch runs.
        return None


def _serial_batch(current_tool: str, current_input: dict[str, Any], payload: dict[str, Any], root: Path | None) -> str | None:
    """A serial batch of heavy commands is refused with the parallel command (getzilla.parallel)."""
    command = current_input.get('command')
    if current_tool != 'Bash' or root is None or not isinstance(command, str):
        return None
    try:
        from getzilla.parallel import serial_refusal
        from getzilla.path_hints import command_cwd
        return serial_refusal(root, command, command_cwd(root, payload, current_input))
    except Exception:
        try:
            sys.stderr.write('Getzilla: parallel guard unavailable; the command runs unchecked.\n')
        except Exception:
            # Diagnostics are advisory; an allowed command still runs.
            return None
        return None


def _progress_loop(current_tool: str, current_input: dict[str, Any], payload: dict[str, Any], root: Path | None) -> str | None:
    """Advisory retries are checked only after ordinary policy authorization."""
    if current_tool != 'Bash' or root is None:
        return None
    try:
        from getzilla.path_hints import command_cwd
        from getzilla.session_progress import refusal, scope_id
        scope = scope_id(root, session_id(payload), agent_id(payload), agent_generation(payload))
        return refusal(root, scope, current_input, command_cwd(root, payload, current_input))
    except Exception:
        try:
            sys.stderr.write('Getzilla: progress observations unavailable; ordinary authorization still applies.\n')
        except Exception:
            return None
        return None


def _local_policy_source_present() -> bool:
    """Accept only this installation's loose or zipimport policy source."""
    stack = Path(__file__).resolve().parents[1]
    if (stack / 'getzilla/policy.py').is_file():
        return True
    try:
        spec = importlib.util.find_spec('getzilla.policy')
        expected = stack / 'getzilla.zip/getzilla/policy.py'
        return (spec is not None and spec.origin is not None
                and Path(spec.origin).resolve() == expected.resolve()
                and isinstance(spec.loader, zipimport.zipimporter)
                and isinstance(spec.loader.get_data(spec.origin), bytes))
    except (ImportError, OSError, ValueError, AttributeError):
        return False


def main() -> None:
    current_tool, current_input = '', {}
    classified = False
    try:
        payload = _read_tool_payload()
        current_tool = tool_name(payload)
        if any(tool_name({'tool_name': payload[key]}) != current_tool
               for key in ('tool_name', 'toolName') if key in payload):
            raise ValueError('invalid-tool-request')
        current_input = tool_input(payload)
        classified = True
        if not _local_policy_source_present():
            _deny(payload, current_tool, current_input, 'Mandatory policy module is missing.')
            return
        try:
            from getzilla.state import bind_session
        except ImportError:
            pass
        else:
            bind_session(session_id(payload))
        if current_input.get('_getzilla_input_error'):
            _deny(payload, current_tool, current_input, current_input['_getzilla_input_error'],
                  action='invalid-tool-input')
            return
        if _oversize_bash_command(current_tool, current_input):
            _deny(payload, current_tool, current_input, (
                f'Blocked a Bash command longer than {MAX_BASH_COMMAND_CHARS} characters; '
                'split it or write the payload to a file first.'
            ), action='oversize-command')
            return
        context = root_context(payload, current_input, current_tool)
        try:
            from getzilla.policy import evaluate_pre_tool, read_protection_reason, sensitive_action
        except Exception as error:
            # Policy stack not importable: record it, refuse protected actions, allow the rest (#78).
            record_degraded('pre_tool_use', error, payload)
            degraded_tool, degraded_input, degraded_cwd = _degraded_request(payload)
            denial = _DEGRADED_REASON
            if context.execution_cwd is not None and degraded_cwd == context.execution_cwd:
                denial = _degraded_denial(degraded_tool, degraded_input, degraded_cwd, root=context.effective_root or context.session_root)
            emit(permission_output(denial is None, denial))
            return

        # Selecting a workdir chooses operation authority; it cannot erase the
        # session project's independent read protections, including nested roots.
        if context.session_root is not None and context.session_root != context.effective_root:
            try:
                read_reason = read_protection_reason(context.session_root, {
                    'tool_name': current_tool, 'tool_input': current_input,
                }, execution_cwd=context.execution_cwd)
            except Exception:
                read_reason = 'Session project read protection is unavailable; this operation is refused.'
            if read_reason:
                if context.execution_cwd is None:
                    read_reason = (f'Sensitive read denied: root resolution status is {context.resolution_status}.'
                                   + _root_hint(context))
                _deny(payload, current_tool, current_input, read_reason, context=context, action='secret-read')
                return

        classification_root = context.effective_root or context.session_root or Path.cwd()
        action = sensitive_action(classification_root, {
            'tool_name': current_tool,
            'tool_input': current_input,
        }, execution_cwd=context.execution_cwd)
        if current_tool == 'Bash' and context.has_ambiguous_command_evidence and action is None:
            action = 'ambiguous-sensitive-shell'
        root = context.effective_root or context.session_root
        if root is not None:
            try:
                from getzilla.agent_lifecycle import observe_tool
                observe_tool(root, agent_id(payload), agent_generation(payload))
            except Exception:
                # Observation is advisory; failure must never skip authorization.
                _warn_observer_failure()
        if action and not context.sensitive_safe:
            allowed = False
            reason = (f'Sensitive action {action} denied: root resolution status is {context.resolution_status}.'
                      + _root_hint(context))
        elif root is None and current_tool.startswith('mcp__'):
            allowed, reason = False, 'mcp_identity_unverified: external MCP identity is unsupported without a trusted root.'
        elif root is None:
            allowed, reason = True, None
        else:
            try:
                allowed, reason = evaluate_pre_tool(root, {
                    'tool_name': current_tool,
                    'tool_input': current_input,
                }, execution_cwd=context.execution_cwd)
            except Exception:
                if action:
                    allowed, reason = False, f'Sensitive action {action} denied: policy evaluation failed closed.'
                else:
                    raise
        if allowed:
            miss = (_path_miss(current_tool, current_input, payload, root)
                    or _unread_edit(current_tool, current_input, payload, root)
                    or _serial_batch(current_tool, current_input, payload, root)
                    or _progress_loop(current_tool, current_input, payload, root))
            emit(permission_output(miss is None, miss))
            return

        _deny(payload, current_tool, current_input, reason or 'Blocked by Getzilla policy',
              context=context, action=action or 'policy-denial')
    except Exception as error:
        # Preserve local fallback and record failure. Unknown MCP never gains trust from a hook error.
        if not classified:
            try:
                record_degraded('pre_tool_use', 'invalid-tool-request')
            except Exception:
                pass
            emit(permission_output(False, _INVALID_TOOL_REQUEST))
            return
        record_degraded('pre_tool_use', error)
        reason = (_DEGRADED_REASON if 'context' not in locals() else
                  _degraded_denial(locals().get('current_tool',''),locals().get('current_input',{}),root=locals().get('root')))
        emit(permission_output(reason is None,reason))


if __name__ == '__main__' and _BOOTSTRAP_READY:
    main()
