from __future__ import annotations

import codecs
import fnmatch
import os
import re
import shlex
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from . import fsx
from .state import active_write_agents, get_active_route, has_valid_approval
from .util import git_output, load_json, safe_relative_path

WRITE_ROLES = {
    'general_implementer', 'php_implementer', 'bitrix_implementer', 'frontend_implementer',
    'integration_implementer', 'data_implementer', 'ai_implementer',
}

DEFAULT_CONTROL_PLANE = [
    '.agents/**', '.grok/**', '.qwen/**', '.claude/**', '.codex/**', '.gemini/**', '.getzilla/**', '.github/**', 'trust-ci/**',
    '**/.grok/**', '**/.qwen/**', '**/.claude/**', '**/.codex/**', '**/.gemini/**', '_lib.py',
    '.gitignore', 'AGENTS.md', 'README.md', 'CHANGELOG.md', 'VERSION',
    'decisions.md', 'mistakes.md', 'Makefile', 'ruff.toml', 'bandit.yaml', '.coveragerc',
    'scripts/getzilla_*.py', 'scripts/install_into.py', 'scripts/package_stack.py',
    'user_prompt_submit.py', 'pre_tool_use.py', 'post_tool_use.py', 'pre_compact.py',
    'session_start.py', 'session_end.py', 'stop_gate.py', 'subagent_start.py', 'subagent_stop.py',
    'tests/_support.py', 'tests/test_*.py', 'engineering/runbooks/publish-v*.md',
]
DEFAULT_PROTECTED = [
    '.git/**', '.env', '.env.*', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
    *DEFAULT_CONTROL_PLANE, 'bitrix/**',
]
DEFAULT_SECRET_READ = [
    '.env', '.env.*', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
    '**/id_rsa', '**/id_ed25519', '**/credentials*', '**/secrets/**', 'trust-ci/env/*.env', 'trust-ci/runtime/**',
    '**/id_ecdsa', '**/id_dsa', '**/.ssh/**', '**/.git-credentials', '**/.netrc', '**/_netrc', '**/.npmrc', '**/.pypirc',
    '**/.pgpass', '**/.config/gh/hosts.yml', '**/.docker/config.json', '**/.kube/config', '**/.aws/**',
]
# Names that match a secret glob but are templates or public halves; never secret.
SECRET_READ_EXCEPTIONS = ('*.pub', '.env.example', '.env.sample', '.env.template', '.env.dist')
DESTRUCTIVE_COMMANDS = [
    r'\bgit\s+reset\s+--hard\b',
    r'\bgit\s+clean\s+[^\n]*(?:-f|-x)',
    r'\bgit\s+push\s+[^\n]*(?:--force|-f\b)',
    r'\bterraform\s+(?:destroy|apply)\b',
    r'\btofu\s+(?:destroy|apply)\b',
    r'\bkubectl\s+(?:delete|apply|exec|port-forward)\b',
    r'\bhelm\s+(?:install|upgrade|uninstall)\b',
    r'\bdrop\s+(?:database|schema|table)\b',
    r'\btruncate\s+table\b',
    r'\brm\s+-rf\s+(?:/|~|\$HOME)\b',
    r'\bchmod\s+-R\s+777\b',
]
_COMMAND_SPLIT = re.compile(r'(?:&&|\|\||[;|\n])')
_WRAPPERS = {'sudo', 'doas', 'command', 'time', 'nohup', 'nice'}
_EXECUTION_WRAPPERS = {'command', 'nice', 'nohup', 'setsid', 'time', 'timeout'}
_UNWRAP_SHELL = re.compile(
    r'''^\s*(?:(?:sudo|doas)\s+)?(?:/(?:usr/)?bin/)?(?:bash|sh|zsh|dash|ksh)\s+-\S*c\S*\s+(?P<rest>.+?)\s*$''',
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_SHELL_REDIRECTION = re.compile(
    r'''(?:^|[\s;&|])(?:\d*>>?|&>>?)\s*(?P<target>"[^"]+"|'[^']+'|[^\s;&|]+)''',
    re.IGNORECASE | re.VERBOSE,
)
_SHELL_MUTATION_SIGNAL = re.compile(
    r'''
    (?:^|[;&|]\s*|\s)(?:rm|mv|cp|install|touch|truncate|mkdir|rmdir|ln|chmod|chown|chgrp|tee|patch|rsync)\b
    |\bsed\b[^\n]*\s-i(?:\b|[A-Za-z])
    |\bperl\b[^\n]*\s-[^\s\n]*i[^\s\n]*\b
    |\b(?:python(?:3(?:\.\d+)?)?|node|ruby|php)\b[^\n]*\s(?:-c|-e|-r)\b
    |\bgit\b[^\n]*\s(?:apply|checkout|restore|rm|mv|clean)\b
    |\bruff\b[^\n]*--fix\b
    |\bcurl\b[^\n]*\s(?:-o|--output)(?:\s|=)
    |\bwget\b[^\n]*\s(?:-O|--output-document)(?:\s|=)
    |\bdd\b[^\n]*\bof=
    |\b(?:tar|unzip)\b[^\n]*(?:\s-(?:x|[^\s\n]*x[^\s\n]*)|\bextract\b)
    ''',
    re.IGNORECASE | re.VERBOSE | re.DOTALL,
)
_GLOB_META = re.compile(r'[*?[]')
_HTTP_URL = re.compile(r'https?://[^\s"\']+', re.IGNORECASE)
SIDE_EFFECT_TOOL = re.compile(
    r'(?:^|__)(?:create|update|delete|remove|send|write|publish|deploy|merge|close|execute|apply|archive|trash|move)(?:_|$)',
    re.IGNORECASE,
)

# Native Windows only (``fsx.WINDOWS``); POSIX parsing below is unchanged.
_WINDOWS_LAUNCHER_SUFFIXES = ('.exe', '.cmd', '.bat', '.com')
_WINDOWS_LAUNCHER = re.compile(r'(?<=\w)\.(?:exe|cmd|bat|com)(?=$|[\s;&|)])', re.IGNORECASE)
_WINDOWS_SHELL_EXECUTABLES = {'cmd', 'powershell', 'pwsh'}
_WINDOWS_PATH_CHARACTERS = frozenset('._-~@+')


def _executable_name(token: str) -> str:
    """Lower-cased command name of ``token``.

    POSIX keeps ``Path(token).name``. Windows also treats ``\\`` and a drive as
    directory syntax and drops a launcher suffix, so ``C:\\Git\\cmd\\git.exe`` and
    ``git.EXE`` are both ``git`` rather than an unknown, unclassified program.
    """
    if not fsx.WINDOWS:
        return Path(token).name.lower()
    name = PureWindowsPath(token).name.lower()
    for suffix in _WINDOWS_LAUNCHER_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return name


def _windows_literal_backslashes(text: str) -> str:
    """Double the backslashes that are Windows directory separators.

    POSIX ``shlex`` drops an unquoted backslash, so ``C:\\Git\\git.exe`` would
    become ``C:Gitgit.exe``. A backslash followed by a path character outside
    single quotes is doubled; every other escape (``\\"``, ``\\'``, ``\\\\``, an
    escaped space, ``\\;``) and single-quoted text keep their POSIX meaning.
    """
    result: list[str] = []
    quote = ''
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ''
            result.append(char)
        elif char == '\\':
            following = text[index + 1:index + 2]
            if following and (following.isalnum() or following in _WINDOWS_PATH_CHARACTERS):
                result.append('\\\\')
            else:
                result.append(char + following)
                index += 1
        else:
            if char == '"':
                quote = '' if quote == '"' else '"'
            elif char == "'" and not quote:
                quote = "'"
            result.append(char)
        index += 1
    return ''.join(result)


def _split_words(text: str) -> list[str]:
    """``shlex.split``; on Windows a path backslash survives as a separator."""
    if fsx.WINDOWS:
        text = _windows_literal_backslashes(text)
    return shlex.split(text)


def _windows_sequence_split(chunk: str) -> list[str]:
    """Split a chunk at a lone ``&`` outside quotes (cmd.exe/PowerShell sequencing).

    ``&&`` is already a chunk separator; ``2>&1``, ``&>file``, ``\\&`` and ``^&``
    are redirections or escapes, not sequencing.
    """
    parts: list[str] = []
    current: list[str] = []
    quote = ''
    for index, char in enumerate(chunk):
        if quote:
            if char == quote:
                quote = ''
        elif char in {'"', "'"}:
            quote = char
        elif (
            char == '&'
            and chunk[index - 1:index] not in {'>', '<', '\\', '^'}
            and chunk[index + 1:index + 2] != '>'
        ):
            parts.append(''.join(current))
            current = []
            continue
        current.append(char)
    parts.append(''.join(current))
    return parts


def _windows_command_variant(command: str) -> str:
    """Fold a Windows spelling onto the POSIX one the substring patterns describe.

    ``"C:\\Program Files\\Git\\cmd\\git.exe" push --force`` becomes
    ``C:/Program Files/Git/cmd/git push --force``: separators, quotes and the
    launcher suffix are not allowed to hide a destructive or external command.
    """
    folded = command.replace('\\', '/').replace('"', '').replace("'", '')
    return _WINDOWS_LAUNCHER.sub('', folded)


def _windows_path_key(path: str) -> str:
    """NTFS spelling of one file: case, trailing dots/spaces and ``:stream`` are folded."""
    parts: list[str] = []
    for part in path.split('/'):
        name = part.split(':', 1)[0].rstrip(' .')
        parts.append(name or part)
    return '/'.join(parts).casefold()


def _destructive_pattern(command: str, patterns: list[str]) -> str | None:
    """First configured destructive pattern found in ``command``.

    Windows also checks the folded spelling from ``_windows_command_variant``.
    """
    candidates = [command]
    if fsx.WINDOWS:
        variant = _windows_command_variant(command)
        if variant != command:
            candidates.append(variant)
    for pattern in patterns:
        if any(re.search(pattern, candidate, flags=re.IGNORECASE) for candidate in candidates):
            return pattern
    if any(_recursive_remove_of_root(candidate) for candidate in candidates):
        return RECURSIVE_REMOVE_POLICY
    return None


RECURSIVE_REMOVE_POLICY = 'rm -r of /, an absolute path, ~, $HOME, . or *'
_RM_GLOB_ONLY = re.compile(r'^[*?./]+$')


def _leading_env(tokens: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split a simple command's leading ``VAR=value`` assignments from its argv."""
    env: dict[str, str] = {}
    index = 0
    while index < len(tokens) and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', tokens[index]):
        name, _, value = tokens[index].partition('=')
        env[name] = value
        index += 1
    return env, tokens[index:]


def _shell_commands(command: str, depth: int = 0) -> list[tuple[dict[str, str], list[str]] | None]:
    """``(leading env assignments, argv)`` of every simple command, unwrapping ``sh -c``.

    ``None`` marks a piece that ``shlex`` cannot tokenize. The env map is retained so
    target binding cannot be spoofed by a ``GH_REPO=``/``GH_HOST=`` assignment prefix;
    an outer assignment is propagated into any ``sh -c`` payload it exports to.
    """
    pieces: list[tuple[dict[str, str], list[str]] | None] = []
    for chunk in _command_chunks(command):
        try:
            tokens = _split_words(chunk)
        except ValueError:
            pieces.append(None)
            continue
        env, tokens = _leading_env(tokens)
        if not tokens:
            continue
        payload = None
        for index, token in enumerate(tokens):
            if _executable_name(token) in _SHELL_EXECUTABLES:
                for option_index in range(index + 1, len(tokens) - 1):
                    if re.fullmatch(r'-[A-Za-z]*c[A-Za-z]*', tokens[option_index]):
                        payload = tokens[option_index + 1]
                        break
                break
        if payload is not None and depth < 4:
            for sub in _shell_commands(payload, depth + 1):
                pieces.append(None if sub is None else ({**env, **sub[0]}, sub[1]))
            continue
        pieces.append((env, tokens))
    return pieces

_PUNCTUATION = frozenset(';&|()<>\n')
_ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
_ANSI_C_QUOTE = re.compile(r"\$'((?:[^'\\]|\\.)*)'")
# Wrappers that run their operand as a command, with the options that take a value.
_COMMAND_WRAPPERS = {
    'sudo': {'-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U'}, 'doas': {'-u', '-C'}, 'env': {'-u', '-C'},
    'command': set(), 'builtin': set(), 'exec': {'-a'}, 'nice': {'-n', '--adjustment'}, 'nohup': set(),
    'setsid': set(), 'time': {'-f', '-o'}, 'timeout': {'-s', '-k', '--signal', '--kill-after'},
    'stdbuf': {'-i', '-o', '-e'}, 'xargs': {'-a', '-d', '-E', '-I', '-L', '-n', '-P', '-s', '--arg-file', '--delimiter'},
}
_SHELL_COMMAND_OPTION = re.compile(r'-[A-Za-z]*c[A-Za-z]*')
_GIT_FILTER_OPTIONS = frozenset({
    '--setup', '--env-filter', '--tree-filter', '--index-filter', '--parent-filter', '--msg-filter', '--commit-filter',
    '--tag-name-filter',
})


def _ansi_c(match: re.Match[str]) -> str:
    """``$'\x2eenv'`` -> ``'.env'``: decode ANSI-C quoting before tokenizing."""
    try:
        return shlex.quote(codecs.decode(match.group(1), 'unicode_escape'))
    except (UnicodeDecodeError, ValueError):
        return shlex.quote(match.group(1))


def _env_assignments(words: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split a simple command's leading ``VAR=value`` assignments from its argv."""
    env: dict[str, str] = {}
    index = 0
    while index < len(words) and _ASSIGNMENT.match(words[index]):
        name, _, value = words[index].partition('=')
        env[name] = value
        index += 1
    return env, words[index:]


def _command_env(command: str) -> dict[str, str]:
    """Env bindings a command establishes before it runs: ``export``/``env`` and bare assignments.

    A grant binds to the target ``gh`` will actually reach, so a ``GH_REPO``/``GH_HOST`` set by
    any of these spellings (not only a leading assignment) rebinds the resource (review S53-1).
    """
    env: dict[str, str] = {}
    try:
        words = _words(command)
    except ValueError:
        return env
    current: list[str] = []
    for word in [*words, ';']:
        if word and set(word) <= _PUNCTUATION:
            assignments, argv = _env_assignments(current)
            env.update(assignments)
            name = _executable_name(argv[0]) if argv else ''
            if name == 'export':
                for token in argv[1:]:
                    if _ASSIGNMENT.match(token):
                        key, _, value = token.partition('=')
                        env[key] = value
            elif name == 'env':
                for token in argv[1:]:
                    if _ASSIGNMENT.match(token):
                        key, _, value = token.partition('=')
                        env[key] = value
                    elif not token.startswith('-'):
                        break
            current = []
            continue
        current.append(word)
    return env


def _words(text: str) -> list[str]:
    """Shell words and operator tokens (``;``, ``&&``, ``|``, ``(``, ``>``, newline), quotes removed."""
    if fsx.WINDOWS:
        text = _windows_literal_backslashes(text)
    lexer = shlex.shlex(_ANSI_C_QUOTE.sub(_ansi_c, text), posix=True, punctuation_chars=''.join(sorted(_PUNCTUATION)))
    lexer.whitespace, lexer.whitespace_split, lexer.commenters = ' \t\r', True, ''
    return list(lexer)


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Drop ``VAR=value`` prefixes and command wrappers (``sudo -u x``, ``env``, ``timeout 5``, ``xargs -n1``)."""
    for _depth in range(8):
        while argv and _ASSIGNMENT.match(argv[0]):
            argv = argv[1:]
        name = _executable_name(argv[0]) if argv else ''
        if name not in _COMMAND_WRAPPERS:
            return argv
        index = 1
        while index < len(argv) and (argv[index].startswith('-') or (name == 'env' and _ASSIGNMENT.match(argv[index]))):
            if argv[index] == '--':
                index += 1
                break
            index += 2 if argv[index] in _COMMAND_WRAPPERS[name] else 1
        argv = argv[index + (1 if name == 'timeout' else 0):]
    return argv


def _nested_commands(argv: list[str]) -> list[str | list[str] | None]:
    """Command strings (``str``) or argv lists that ``argv`` itself runs.

    ``sh -c``, ``cmd /c``, ``powershell -Command``, ``git submodule foreach``,
    ``git rebase -x``, ``git bisect run``, ``git filter-branch --*-filter``,
    ``git -c alias.x=!cmd`` and ``find -exec``; ``None`` for an opaque payload
    (``powershell -EncodedCommand``).
    """
    name, lowered = argv[0], [word.lower() for word in argv]
    if name in _SHELL_EXECUTABLES:
        index = next((i for i, word in enumerate(argv[1:-1], 1) if _SHELL_COMMAND_OPTION.fullmatch(word)), None)
        return [argv[index + 1]] if index else []
    if name == 'cmd':
        index = next((i for i, word in enumerate(lowered) if word in {'/c', '/k'}), None)
        return [' '.join(argv[index + 1:])] if index else []
    if name in {'powershell', 'pwsh'}:
        if any(word in {'-e', '-ec'} or (len(word) > 3 and '-encodedcommand'.startswith(word)) for word in lowered[1:]):
            return [None]
        index = next(
            (i for i, word in enumerate(lowered[1:], 1) if word == '-c' or (len(word) > 3 and '-command'.startswith(word))),
            None,
        )
        return [' '.join(argv[index + 1:])] if index else []
    if name == 'find':
        nested: list[str | list[str] | None] = []
        for index, word in enumerate(argv):
            if word in {'-exec', '-execdir', '-ok', '-okdir'}:
                end = next((i for i in range(index + 1, len(argv)) if argv[i] in {';', '+'}), len(argv))
                nested.append(argv[index + 1:end])
        return nested
    if name != 'git':
        return []
    nested = [value.split('=', 1)[1][1:] for option, value in zip(lowered, argv[1:]) if option == '-c' and '=!' in value]
    sub, index = _git_subcommand(lowered)
    rest = argv[index + 1:]
    if sub == 'submodule' and 'foreach' in lowered[index + 1:]:
        after = rest[lowered[index + 1:].index('foreach') + 1:]
        while after and after[0].startswith('-'):
            after = after[1:]
        nested.append(' '.join(after))
    elif sub == 'bisect' and rest[:1] == ['run']:
        nested.append(rest[1:])
    elif sub in {'rebase', 'filter-branch'}:
        for position, word in enumerate(rest):
            option, _, attached = word.partition('=')
            if (sub == 'rebase' and option in {'-x', '--exec'}) or (sub == 'filter-branch' and option in _GIT_FILTER_OPTIONS):
                nested.append(attached or (rest[position + 1] if position + 1 < len(rest) else ''))
            elif sub == 'rebase' and word.startswith('-x') and len(word) > 2:
                nested.append(word[2:])
    return nested


def _simple_commands(command: str, depth: int = 0) -> list[list[str] | None]:
    """Normalized argv of every simple command ``command`` runs, nested command strings included.

    Operators split commands (quotes respected), redirection operators are dropped
    (their targets stay operands), wrappers are removed, ``argv[0]`` is the
    lower-cased basename and ``git-<sub>`` helpers become ``git <sub>``. ``None``
    marks text that cannot be tokenized or nesting deeper than four levels.
    """
    if depth > 4:
        return [None]
    try:
        words = _words(command)
    except ValueError:
        return [None]
    commands: list[list[str] | None] = []
    current: list[str] = []
    for word in [*words, ';']:
        if word and set(word) <= _PUNCTUATION:
            if '<' not in word and '>' not in word and current:
                commands.extend(_expand_command(current, depth))
                current = []
            continue
        current.append(word)
    return commands


def _expand_command(argv: list[str], depth: int) -> list[list[str] | None]:
    argv = _strip_wrappers(argv)
    if not argv:
        return []
    name = _executable_name(argv[0])
    argv = ['git', name[4:], *argv[1:]] if name.startswith('git-') and len(name) > 4 else [name, *argv[1:]]
    result: list[list[str] | None] = [argv]
    for nested in _nested_commands(argv):
        if nested is None or depth >= 4:
            result.append(None)
        elif isinstance(nested, str):
            result.extend(_simple_commands(nested, depth + 1))
        elif nested:
            result.extend(_expand_command(nested, depth + 1))
    return result


def _shell_pieces(command: str) -> list[list[str] | None]:
    """Compatibility name for :func:`_simple_commands`."""
    return _simple_commands(command)


def _dangerous_remove_target(operand: str) -> bool:
    """Root, home, absolute, drive or expansion-dependent (``$``, ``{``, backtick) targets fail closed."""
    lowered = operand.lower().replace('\\', '/')
    if lowered.startswith(('/', '~', '$', '%')) or re.match(r'^[a-z]:', lowered) or any(c in operand for c in '{`'):
        return True
    return _RM_GLOB_ONLY.fullmatch(operand) is not None and operand.strip('/') in {
        '', '.', '..', '*', '.*', './*', '**',
    }


def _remove_operands(argv: list[str]) -> list[str] | None:
    """Operands of a recursive delete (``rm -r``, ``del /s``, ``rd /s``, ``Remove-Item -Recurse``), else ``None``."""
    name, words = argv[0], argv[1:]
    if name in {'del', 'erase', 'rd', 'rmdir'} and any(re.fullmatch(r'(?:/[a-z])*/s(?:/[a-z])*', w.lower()) for w in words):
        return [w for w in words if not re.fullmatch(r'(?:/[a-z?])+', w.lower())]
    if name in {'remove-item', 'ri', 'rm', 'rmdir', 'del', 'erase', 'rd'} and any(
        len(w) > 1 and '-recurse'.startswith(w.lower()) for w in words
    ):
        return [w for w in words if not w.startswith('-')]
    if name != 'rm':
        return None
    recursive = options_done = False
    operands: list[str] = []
    for word in words:
        option = word.split('=', 1)[0]
        if not options_done and word == '--':
            options_done = True
        elif not options_done and word.startswith('--'):
            # GNU getopt accepts any unambiguous prefix: --rec == --recursive, --no == --no-preserve-root.
            recursive = recursive or (len(option) > 2 and '--recursive'.startswith(option)) or (
                len(option) > 3 and '--no-preserve-root'.startswith(option)
            )
        elif not options_done and word.startswith('-') and len(word) > 1:
            recursive = recursive or 'r' in word[1:].lower()
        else:
            operands.append(word)
    return operands if recursive else None


def _recursive_remove_of_root(command: str) -> bool:
    """A recursive delete (any spelling, nested or wrapped) of a root-like or expansion-dependent target."""
    for argv in _simple_commands(command):
        if argv is None:
            if re.search(r'\brm\b[^\n]*\s-[A-Za-z-]*[rR]', command) and re.search(
                r'\brm\b[^\n]*\s["\']?(?:/|~|\$|\.\s|\.$|\*|\{)', command,
            ):
                return True
            continue
        operands = _remove_operands(argv)
        if operands and any(_dangerous_remove_target(operand) for operand in operands):
            return True
    return False


def write_roles(root: Path) -> set[str]:
    data = load_json(root / '.getzilla/config/routing.json', None)
    if isinstance(data, dict):
        roles = data.get('write_roles')
        if isinstance(roles, list):
            names = {str(item).strip() for item in roles if isinstance(item, str) and item.strip()}
            if names:
                return names
    return set(WRITE_ROLES)


def _configured_patterns(config: dict[str, Any], key: str, defaults: list[str]) -> list[str]:
    value = config.get(key)
    if isinstance(value, list):
        patterns = [str(item).strip() for item in value if isinstance(item, str) and item.strip()]
        if patterns:
            return patterns
    return list(defaults)


def _strip_leading_dot_slash(value: str) -> str:
    """Drop leading './' and '/' segments only; '.env' must not collapse to 'env'."""
    normalized = value.replace('\\', '/')
    while True:
        stripped = normalized.lstrip('/')
        if stripped.startswith('./'):
            normalized = stripped[2:]
            continue
        return stripped


def _glob_match(path: str, pattern: str) -> bool:
    normalized = _strip_leading_dot_slash(path)
    candidate = _strip_leading_dot_slash(pattern)
    candidates = [candidate]
    if candidate.startswith('**/'):
        # fnmatch has no globstar: '**/x' needs a parent directory, so a root-level
        # 'server.key' or 'secrets/x' escaped '**/*.key' and '**/secrets/**'.
        candidates.append(candidate[3:])
    if fsx.WINDOWS:
        # NTFS opens AGENTS.md for agents.MD, "AGENTS.md." and "AGENTS.md::$DATA".
        key = _windows_path_key(normalized)
        return any(fnmatch.fnmatchcase(key, item.casefold()) for item in candidates)
    return any(fnmatch.fnmatchcase(normalized, item) for item in candidates)


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(_glob_match(path, pattern) for pattern in patterns)


def _literal_pattern_prefix(pattern: str) -> str:
    normalized = pattern.replace('\\', '/').lstrip('./')
    match = _GLOB_META.search(normalized)
    if match:
        normalized = normalized[:match.start()]
    return normalized.rstrip('/')


def _mentions_control_plane(command: str, patterns: list[str]) -> bool:
    normalized = command.replace('\\', '/').casefold()
    return any(prefix and prefix.casefold() in normalized for prefix in map(_literal_pattern_prefix, patterns))


def _redirects_to_control_plane(command: str, patterns: list[str]) -> bool:
    for match in _SHELL_REDIRECTION.finditer(command):
        target = match.group('target').strip('"\'')
        if _mentions_control_plane(target, patterns):
            return True
    return False


def _is_control_plane_shell_mutation(command: str, patterns: list[str]) -> bool:
    if _redirects_to_control_plane(command, patterns):
        return True
    return _mentions_control_plane(command, patterns) and _SHELL_MUTATION_SIGNAL.search(command) is not None


def _extract_paths(value: Any) -> list[str]:
    paths: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {
                'path', 'file', 'filename', 'file_path', 'filepath', 'absolute_path', 'notebook_path',
                'directory', 'target',
            } and isinstance(item, str):
                paths.append(item)
            elif key.lower() in {'paths', 'file_paths'} and isinstance(item, list):
                paths.extend(entry for entry in item if isinstance(entry, str))
            else:
                paths.extend(_extract_paths(item))
    elif isinstance(value, list):
        for item in value:
            paths.extend(_extract_paths(item))
    return paths


def _extract_patch_paths(command: str) -> list[str]:
    patterns = [
        r'^\*\*\* (?:Update|Add|Delete) File:\s*(.+?)\s*$',
        r'^\+\+\+\s+(?:b/)?(.+?)\s*$',
        r'^---\s+(?:a/)?(.+?)\s*$',
    ]
    result: list[str] = []
    for line in command.splitlines():
        for pattern in patterns:
            match = re.match(pattern, line)
            if match and match.group(1) != '/dev/null':
                result.append(match.group(1))
    return result


def _command_chunks(command: str) -> list[str]:
    chunks = [part for part in _COMMAND_SPLIT.split(command) if part.strip()]
    if fsx.WINDOWS:
        # cmd.exe and PowerShell also sequence commands with a single '&'.
        chunks = [piece for chunk in chunks for piece in _windows_sequence_split(chunk) if piece.strip()]
    return chunks


def _unwrap_execution_wrappers(tokens: list[str]) -> tuple[list[str], bool]:
    """Return a command behind a small literal wrapper grammar, or flag unsafe syntax."""
    remaining = list(tokens)
    for _depth in range(8):
        if not remaining:
            return [], True
        wrapper = _executable_name(remaining[0])
        if wrapper not in _EXECUTION_WRAPPERS:
            return remaining, False
        index = 1
        if wrapper == 'nice':
            while index < len(remaining):
                option = remaining[index]
                if option == '--':
                    index += 1
                    break
                if option in {'-n', '--adjustment'}:
                    if index + 1 >= len(remaining):
                        return [], True
                    index += 2
                    continue
                if option.startswith('--adjustment='):
                    index += 1
                    continue
                if option.startswith('-'):
                    return [], True
                break
        elif wrapper == 'time':
            while index < len(remaining) and remaining[index] == '-p':
                index += 1
            if index < len(remaining) and remaining[index] == '--':
                index += 1
            elif index < len(remaining) and remaining[index].startswith('-'):
                return [], True
        elif wrapper in {'command', 'nohup', 'setsid'}:
            if index < len(remaining) and remaining[index] == '--':
                index += 1
            elif index < len(remaining) and remaining[index].startswith('-'):
                return [], True
        elif wrapper == 'timeout':
            if index < len(remaining) and remaining[index] == '--':
                index += 1
            if index >= len(remaining) or remaining[index].startswith('-'):
                return [], True
            index += 1  # duration
        remaining = remaining[index:]
    return [], True


def _leading_argv(chunk: str) -> list[str]:
    stripped = chunk.split('#', 1)[0].strip()
    try:
        tokens = _split_words(stripped)
    except ValueError:
        tokens = stripped.split()
    while tokens and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', tokens[0]):
        tokens = tokens[1:]
    if tokens and _executable_name(tokens[0]) in {'sudo', 'doas', 'env'}:
        commands = {'git', 'gh', 'docker', 'npm', 'bash', 'sh', 'zsh', 'dash', 'ksh'}
        command_index = next(
            (index for index, token in enumerate(tokens[1:], 1) if _executable_name(token) in commands),
            None,
        )
        if command_index is not None:
            tokens = tokens[command_index:]
    tokens, ambiguous_wrapper = _unwrap_execution_wrappers(tokens)
    if ambiguous_wrapper:
        return []
    if tokens:
        tokens[0] = _executable_name(tokens[0])
    return [token.lower() for token in tokens]


def _unwrap_shell(chunk: str) -> str:
    try:
        tokens = _split_words(chunk)
    except ValueError:
        tokens = []
    shells = {'bash', 'sh', 'zsh', 'dash', 'ksh'}
    for index, token in enumerate(tokens):
        if _executable_name(token) not in shells:
            continue
        for option_index in range(index + 1, len(tokens) - 1):
            if re.fullmatch(r'-[A-Za-z]*c[A-Za-z]*', tokens[option_index]):
                return tokens[option_index + 1]
        break
    match = _UNWRAP_SHELL.match(chunk)
    if not match:
        return chunk
    rest = match.group('rest')
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in {'"', "'"}:
        return rest[1:-1]
    return rest


# Global options that consume the next token, per executable (argv is lower-cased,
# so git -C/-c and gh -R share one spelling). Every other leading '-' token is a
# flag; '--opt=value' and attached short values are single tokens.
_GIT_VALUE_OPTIONS = frozenset({'-c', '--git-dir', '--work-tree', '--namespace', '--super-prefix', '--config-env'})
_GH_VALUE_OPTIONS = frozenset({'-r', '--repo', '--hostname'})
_DOCKER_VALUE_OPTIONS = frozenset({
    '-h', '--host', '-c', '--context', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey',
})
_NPM_VALUE_OPTIONS = frozenset({
    '--registry', '--userconfig', '--globalconfig', '--prefix', '-w', '--workspace', '--tag', '--otp',
    '--access', '--cache', '--loglevel', '--scope',
})
_GIT_PUSH_SUBCOMMANDS = frozenset({'push', 'send-pack', 'http-push'})


def _positionals(
    argv: list[str], value_options: frozenset[str], limit: int,
) -> tuple[list[str], list[int]]:
    """First ``limit`` operands of ``argv[1:]`` with their indexes, skipping options."""
    positionals: list[str] = []
    indexes: list[int] = []
    index = 1
    while index < len(argv) and len(positionals) < limit:
        token = argv[index]
        if token == '--':  # nosec B105
            index += 1
            while index < len(argv) and len(positionals) < limit:
                positionals.append(argv[index])
                indexes.append(index)
                index += 1
            break
        if token in value_options:
            index += 2
            continue
        if token.startswith('-') and len(token) > 1:
            index += 1
            continue
        positionals.append(token)
        indexes.append(index)
        index += 1
    return positionals, indexes


def _git_subcommand(argv: list[str]) -> tuple[str | None, int]:
    """Git subcommand and its index after global options (``-c`` aliases stay ambiguous upstream)."""
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in _GIT_VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith('-'):
            index += 1
            continue
        break
    if index >= len(argv):
        return None, index
    return argv[index], index


def _git_push_action(arguments: list[str]) -> str:
    if '--tags' in arguments or any(item.startswith('refs/tags/') for item in arguments):
        return 'git-push-tag'
    candidates = [item for item in arguments if not item.startswith('-')]
    if any(re.fullmatch(r'v?\d+\.\d+\.\d+(?:[-+].+)?', item) for item in candidates):
        return 'git-push-tag'
    return 'git-push-branch'


def _gh_command(argv: list[str]) -> tuple[str, ...]:
    """``(group, command)`` of a gh invocation, ignoring -R/--repo/--hostname anywhere before them."""
    positionals, _ = _positionals(argv, _GH_VALUE_OPTIONS, 2)
    return tuple(positionals)


def _production_action(argv: list[str]) -> str | None:
    if not argv:
        return None
    executable = argv[0]
    if executable == 'git':
        subcommand, index = _git_subcommand(argv)
        # git-remote-<transport> helpers speak the push protocol on stdin.
        if subcommand in _GIT_PUSH_SUBCOMMANDS or (subcommand or '').startswith('remote-'):
            return _git_push_action(argv[index + 1:])
        return None
    if executable == 'gh':
        command = _gh_command(argv)
        if command == ('pr', 'merge'):
            return 'pull-request-merge'
        if command[:1] == ('api',):
            request = _gh_api_request(argv[_positionals(argv, _GH_VALUE_OPTIONS, 1)[1][0] + 1:])
            if request and request[0] == 'PUT' and _GITHUB_PULL_MERGE.search(request[2]):
                return 'pull-request-merge'
        if command == ('workflow', 'run'):
            return 'workflow-dispatch'
        if len(command) == 2 and command[0] == 'release' and command[1] in {'create', 'upload', 'edit'}:
            return 'github-release'
        return None
    if executable in {'docker', 'podman', 'buildah'}:
        positionals, _ = _positionals(argv, _DOCKER_VALUE_OPTIONS, 2)
        if positionals[:1] == ['push'] or positionals in (['image', 'push'], ['manifest', 'push'], ['compose', 'push']):
            return 'docker-push'
        if (positionals[:1] == ['build'] or positionals[:1] == ['buildx']) and '--push' in argv:
            return 'docker-push'
        return None
    if executable == 'npm':
        positionals, indexes = _positionals(argv, _NPM_VALUE_OPTIONS, 2)
        if positionals[:1] == ['publish']:
            return 'npm-publish'
        # An unknown option may take the next word as its value: 'npm --opt value publish'.
        if positionals[1:2] == ['publish'] and argv[indexes[0] - 1].startswith('-'):
            return 'npm-publish'
        return None
    if executable in {'pnpm', 'yarn'}:
        positionals, _ = _positionals(argv, _NPM_VALUE_OPTIONS, 2)
        return 'npm-publish' if 'publish' in positionals[:2] else None
    return None


@dataclass(frozen=True)
class AuthorityAnalysis:
    actions: tuple[str, ...]
    ambiguous: bool
    context_proven: bool


_AUTHORITY_EXECUTABLES = {'git', 'gh', 'docker', 'npm', 'pnpm', 'yarn', 'podman', 'buildah'}
_AUTHORITY_WORDS = re.compile(r'\b(?:git|gh|docker|npm|pnpm|yarn|podman|buildah)\b', re.IGNORECASE)
_AUTHORITY_META = re.compile(r'[$`*?\[\]{}()]')
_INERT_EXECUTABLES = {'echo', 'printf'}
_SHELL_EXECUTABLES = {'bash', 'sh', 'zsh', 'dash', 'ksh'}


def _is_authority(token: str) -> bool:
    name = _executable_name(token)
    return name in _AUTHORITY_EXECUTABLES or (name.startswith('git-') and len(name) > 4)


def _git_config_defines_command(argv: list[str]) -> bool:
    """``git config`` writing ``alias.*``/``include*`` (a later bare ``git <alias>`` would run anything)."""
    words = [word.lower() for word in argv[2:]]
    if not any(word.startswith(('alias.', 'include.', 'includeif.')) for word in words):
        return False
    return not any(word in {'--get', '--get-all', '--get-regexp', '-l', '--list', 'get', 'list'} for word in words)


def _authority_token_is_dynamic(token: str) -> bool:
    return _AUTHORITY_META.search(token) is not None


def _literal_xargs_target(tokens: list[str]) -> list[str] | None:
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == '--':  # nosec B105
            return tokens[index + 1:]
        if token in {'-a', '--arg-file'}:
            if index + 1 >= len(tokens):
                return None
            index += 2
            continue
        if token.startswith('--arg-file='):
            index += 1
            continue
        if token.startswith('-'):
            return None
        return tokens[index:]
    return []


def _git_selector_index(argv: list[str]) -> int:
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in {'-C', *_GIT_VALUE_OPTIONS}:
            if index + 1 >= len(argv):
                return len(argv)
            index += 2
            continue
        if token.startswith('-'):
            index += 1
            continue
        break
    return index


def _candidate_authority(argv: list[str]) -> tuple[str | None, bool]:
    if not argv:
        return None, False
    executable = _executable_name(argv[0])
    if executable.startswith('git-') and len(executable) > 4:
        argv, executable = ['git', executable[4:], *argv[1:]], 'git'
    normalized = [executable, *[token.lower() for token in argv[1:]]]
    action = _production_action(normalized)
    if executable == 'git' and (
        (_git_subcommand(normalized)[0] == 'config' and _git_config_defines_command(normalized))
        or any(a == '-c' and b.startswith('alias.') for a, b in zip(normalized, normalized[1:]))
    ):
        return action, True
    if executable == 'gh' and _gh_command(normalized) in {('alias', 'set'), ('alias', 'import')}:
        return action, True
    if executable == 'git':
        selector_index = _git_selector_index(argv)
        if selector_index >= len(argv):
            return action, False
        if _authority_token_is_dynamic(argv[selector_index]):
            return action, True
        if argv[selector_index].lower() in _GIT_PUSH_SUBCOMMANDS and any(
            _authority_token_is_dynamic(token) for token in argv[selector_index + 1:]
        ):
            return action, True
    elif executable in _AUTHORITY_EXECUTABLES - {'git', 'gh'}:
        if len(argv) > 1 and _authority_token_is_dynamic(argv[1]):
            return action, True
        if action and any(_authority_token_is_dynamic(token) for token in argv[2:]):
            return action, True
    elif executable == 'gh':
        if len(argv) > 1 and _authority_token_is_dynamic(argv[1]):
            return action, True
        if len(argv) > 2 and argv[1].lower() in {'pr', 'release', 'workflow'}:
            if _authority_token_is_dynamic(argv[2]):
                return action, True
            if action and any(_authority_token_is_dynamic(token) for token in argv[3:]):
                return action, True
    return action, False


def _command_tokens(chunk: str) -> list[str] | None:
    try:
        tokens = _split_words(chunk)
    except ValueError:
        return None
    while tokens and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', tokens[0]):
        tokens = tokens[1:]
    return tokens


def _bounded_command(tokens: list[str]) -> tuple[list[str], bool]:
    remaining = list(tokens)
    if remaining and _executable_name(remaining[0]) == 'sudo':
        index = 1
        if index < len(remaining) and remaining[index] == '-E':
            index += 1
        if index >= len(remaining) or remaining[index].startswith('-'):
            return remaining, False
        remaining = remaining[index:]
    elif remaining and _executable_name(remaining[0]) == 'doas':
        index = 1
        if index + 1 < len(remaining) and remaining[index] == '-u':
            index += 2
        if index >= len(remaining) or remaining[index].startswith('-'):
            return remaining, False
        remaining = remaining[index:]
    elif remaining and _executable_name(remaining[0]) == 'env':
        index = 1
        while index < len(remaining) and re.match(
            r'^[A-Za-z_][A-Za-z0-9_]*=', remaining[index]
        ):
            index += 1
        if index >= len(remaining) or remaining[index].startswith('-'):
            return remaining, False
        remaining = remaining[index:]
    remaining, ambiguous_wrapper = _unwrap_execution_wrappers(remaining)
    return remaining, not ambiguous_wrapper


def _literal_shell_payload(tokens: list[str]) -> str | None:
    if not tokens or _executable_name(tokens[0]) not in _SHELL_EXECUTABLES:
        return None
    if len(tokens) == 3 and tokens[1] in {'-c', '-lc'}:
        return tokens[2]
    if len(tokens) == 4 and tokens[1] == '--noprofile' and tokens[2] in {'-c', '-lc'}:
        return tokens[3]
    return None


def _exact_outer_shell_payload(raw_command: str) -> str | None:
    tokens = _command_tokens(raw_command)
    if tokens is None:
        return None
    bounded, proven = _bounded_command(tokens)
    if not proven:
        return None
    return _literal_shell_payload(bounded)


def _analyze_authority_pieces(
    raw_command: str,
    *,
    shell_depth: int = 0,
) -> AuthorityAnalysis:
    actions: list[str] = []
    ambiguous = False
    context_proven = True

    def record(argv: list[str], *, proven: bool) -> None:
        nonlocal ambiguous, context_proven
        action, candidate_ambiguous = _candidate_authority(argv)
        if action and action not in actions:
            actions.append(action)
        if candidate_ambiguous:
            ambiguous = True
        if (action or candidate_ambiguous) and not proven:
            context_proven = False

    for chunk in _command_chunks(raw_command):
        raw_tokens = _command_tokens(chunk)
        if raw_tokens is None:
            if _AUTHORITY_WORDS.search(chunk):
                ambiguous = True
                context_proven = False
            continue
        tokens, bounded = _bounded_command(raw_tokens)
        if not tokens:
            continue
        outer = _executable_name(tokens[0])
        if outer in _INERT_EXECUTABLES:
            continue
        if outer == 'xargs':
            target = _literal_xargs_target(tokens)
            if target is None:
                if any(_is_authority(token) for token in tokens[1:]):
                    ambiguous = True
                    context_proven = False
                continue
            target, target_bounded = _bounded_command(target)
            if not target or _executable_name(target[0]) in _INERT_EXECUTABLES:
                continue
            if _is_authority(target[0]):
                record(target, proven=False)
            elif any(_is_authority(token) for token in target):
                for index, token in enumerate(target):
                    if _is_authority(token):
                        record(target[index:], proven=False)
            if not target_bounded:
                context_proven = False
            continue
        if outer in _SHELL_EXECUTABLES:
            payload = _literal_shell_payload(tokens)
            if payload is None or shell_depth > 0:
                continue
            inner = _analyze_authority_pieces(payload, shell_depth=shell_depth + 1)
            for action in inner.actions:
                if action not in actions:
                    actions.append(action)
            ambiguous = ambiguous or inner.ambiguous
            if (inner.actions or inner.ambiguous) and (not bounded or not inner.context_proven):
                context_proven = False
            continue
        if fsx.WINDOWS and outer in _WINDOWS_SHELL_EXECUTABLES:
            # cmd /c, powershell -Command and their options are not modelled: the
            # authority they carry is reported but never proven.
            if shell_depth > 1:
                if _AUTHORITY_WORDS.search(chunk):
                    ambiguous = True
                    context_proven = False
                continue
            inner = _analyze_authority_pieces(' '.join(tokens[1:]), shell_depth=shell_depth + 1)
            for action in inner.actions:
                if action not in actions:
                    actions.append(action)
            ambiguous = ambiguous or inner.ambiguous
            if inner.actions or inner.ambiguous:
                context_proven = False
            continue
        if _is_authority(tokens[0]):
            record(tokens, proven=bounded)
            continue
        for index, token in enumerate(tokens[1:], 1):
            if _is_authority(token):
                record(tokens[index:], proven=False)

    return AuthorityAnalysis(tuple(actions), ambiguous, context_proven)


def analyze_command_authority(raw_command: str) -> AuthorityAnalysis:
    """Conservatively classify production authority without evaluating shell syntax.

    The literal pass proves the context of top-level commands; a second pass over
    every nested command string (``git submodule foreach``, ``rebase -x``, nested
    ``sh -c``, ``find -exec``) reports what it finds there as unproven.
    """
    shell_payload = _exact_outer_shell_payload(raw_command)
    if shell_payload is not None:
        analysis = _analyze_authority_pieces(shell_payload, shell_depth=1)
    else:
        analysis = _analyze_authority_pieces(raw_command)
    actions, ambiguous, proven = list(analysis.actions), analysis.ambiguous, analysis.context_proven
    for argv in _simple_commands(raw_command):
        if argv is None or argv[0] in _INERT_EXECUTABLES:
            continue
        action, candidate_ambiguous = _candidate_authority(argv)
        ambiguous = ambiguous or candidate_ambiguous
        if action and action not in actions:
            actions.append(action)
            proven = False
    return AuthorityAnalysis(tuple(actions), ambiguous, proven)


def production_action(command: str) -> str | None:
    analysis = analyze_command_authority(command)
    if analysis.ambiguous or not analysis.context_proven:
        return None
    return analysis.actions[0] if analysis.actions else None


def is_production_invocation(command: str) -> bool:
    return production_action(command) is not None


def _http_write_resource(command: str, root: Path | None = None) -> str | None:
    resource = _http_write_resource_text(command, root)
    if resource is None and fsx.WINDOWS:
        variant = _windows_command_variant(command)
        if variant != command:
            resource = _http_write_resource_text(variant, root)
    return resource


_GH_API_FIELD_OPTIONS = frozenset({'-f', '-F', '--field', '--raw-field', '--input'})
_GH_API_VALUE_OPTIONS = frozenset({
    '-X', '--method', '-H', '--header', '-q', '--jq', '-t', '--template', '--hostname', '-p', '--preview', '--cache',
    *_GH_API_FIELD_OPTIONS,
})
_GH_API_READ_METHODS = frozenset({'GET', 'HEAD'})
_GITHUB_PULL_MERGE = re.compile(r'(?:^|/)repos/([^/]+/[^/]+)/pulls/(\d+)/merge/?$', re.IGNORECASE)
_GITHUB_PULL_URL = re.compile(r'^https?://[^/]+/([^/]+/[^/]+)/pull/(\d+)', re.IGNORECASE)
PROTECTED_BRANCHES = frozenset({'main', 'master'})


def _gh_api_request(arguments: list[str], default_host: str = 'api.github.com') -> tuple[str, str, str] | None:
    """``(METHOD, host, endpoint)`` of ``gh api <arguments>`` when it writes, else ``None``.

    A write is any non-GET method, or request fields/body (gh then defaults to POST).
    """
    method: str | None = None
    fields = False
    host = default_host
    endpoint = ''
    index = 0
    while index < len(arguments):
        token = arguments[index]
        # Classification may see lower-cased argv: gh api has no '-x'/'-h' of its own.
        token = {'-x': '-X', '-h': '-H'}.get(token, token)
        name, _, attached = token.partition('=') if token.startswith('--') else (token, '', '')
        value: str | None = attached if attached else None
        if name in _GH_API_VALUE_OPTIONS and not attached:
            value = arguments[index + 1] if index + 1 < len(arguments) else ''
            index += 1
        elif token[:2] in {'-X', '-x'} and len(token) > 2:
            name, value = '-X', token[2:].lstrip('=')
        elif re.match(r'^-[fF]\S', token):
            name = '-f'
        if name in {'-X', '--method'}:
            method = (value or '').strip().upper()
        elif name in _GH_API_FIELD_OPTIONS:
            fields = True
        elif name == '--hostname':
            host = (value or host).lower()
        elif not token.startswith('-') and not endpoint:
            endpoint = token
        index += 1
    method = method or ('POST' if fields else 'GET')
    if method in _GH_API_READ_METHODS:
        return None
    url = re.match(r'^https?://([^/]+)/(.*)$', endpoint)
    if url:
        host, endpoint = url.group(1).lower(), url.group(2)
    return method, host, endpoint.lstrip('/')


def _gh_host(argv: list[str], env: dict[str, str] | None) -> str | None:
    """Target host of a gh command: ``--hostname`` flag, else ``GH_HOST`` from the prefix."""
    for index, word in enumerate(argv):
        if word == '--hostname' and index + 1 < len(argv):
            return argv[index + 1].lower()
        if word.startswith('--hostname='):
            return word.split('=', 1)[1].lower()
    if env and env.get('GH_HOST'):
        return env['GH_HOST'].lower()
    return None


def _gh_repo_flag(argv: list[str]) -> str | None:
    """Value of gh's ``-R``/``--repo`` in any pflag spelling: ``-R x``, ``-Rx``, ``-R=x``, ``--repo x``, ``--repo=x``."""
    for index, word in enumerate(argv):
        if word in {'-R', '--repo'}:
            return argv[index + 1].lower() if index + 1 < len(argv) else ''
        if word.startswith('--repo='):
            return word.split('=', 1)[1].lower()
        if word.startswith('-R') and len(word) > 2:
            return word[3:].lower() if word[2] == '=' else word[2:].lower()
    return None


def _gh_repository(argv: list[str], root: Path | None, env: dict[str, str] | None = None) -> str:
    """``owner/repo`` (lower-cased) a gh command targets.

    Resolution order is the explicit ``-R``/``--repo`` flag, then a ``GH_REPO=`` prefix
    assignment, then the repository's origin. A non-default ``--hostname``/``GH_HOST``
    is prepended as ``host/owner/repo`` so a grant bound to the default host cannot be
    spoofed onto another GitHub host by an env prefix (review S53-1).
    """
    repo = _gh_repo_flag(argv)
    if repo is None and env and env.get('GH_REPO'):
        repo = env['GH_REPO'].lower()
    if repo is None:
        if root is not None:
            from .state import _repository_identity

            try:
                repo = _repository_identity(root).lower()
            except RuntimeError:
                repo = '.'
        else:
            repo = '.'
    host = _gh_host(argv, env)
    if host and host != 'github.com':
        return f'{host}/{repo}'
    return repo


def _gh_pull_request(argv: list[str], index: int, root: Path | None, env: dict[str, str] | None = None) -> str | None:
    """``owner/repo#N`` for the PR a ``gh pr <command>`` names after ``argv[index]``, or ``None``."""
    selectors, _ = _positionals(['gh', *argv[index + 1:]], frozenset({
        '-R', '--repo', '-b', '--body', '-F', '--body-file', '-t', '--subject', '--match-head-commit', '-A', '--author-email',
    }), 1)
    if not selectors:
        return None
    url = _GITHUB_PULL_URL.match(selectors[0])
    if url:
        return f'{url.group(1).lower()}#{url.group(2)}'
    return f'{_gh_repository(argv, root, env)}#{selectors[0]}'


def _api_host(env: dict[str, str] | None) -> str:
    """Default host for a ``gh api`` call: ``GH_HOST`` from the prefix, else api.github.com."""
    if env and env.get('GH_HOST'):
        return env['GH_HOST'].lower()
    return 'api.github.com'


def _gh_external_write(command: str, root: Path | None = None) -> str | None:
    """Exact resource of a gh API mutation or PR review: the grant must name this target.

    ``github-api:<METHOD> <host>/<endpoint>`` or ``github-pr-review:<owner>/<repo>#<n>``;
    a review whose PR cannot be named statically yields ``github-pr-review:<owner>/<repo>#``,
    which no grant can match.
    """
    outer = _command_env(command)
    for piece in _shell_commands(command):
        if piece is None:
            continue
        env, tokens = {**outer, **piece[0]}, piece[1]
        index = next((i for i, token in enumerate(tokens) if _executable_name(token) == 'gh'), None)
        if index is None:
            continue
        argv = ['gh', *tokens[index + 1:]]
        lowered = ['gh', *[token.lower() for token in argv[1:]]]
        positionals, indexes = _positionals(lowered, _GH_VALUE_OPTIONS, 2)
        if positionals[:1] == ['api']:
            request = _gh_api_request(argv[indexes[0] + 1:], _api_host(env))
            if request:
                return f'github-api:{request[0]} {request[1]}/{request[2]}'
        if positionals == ['pr', 'review']:
            target = _gh_pull_request(argv, indexes[1], root, env)
            return f'github-pr-review:{target or _gh_repository(argv, root, env) + "#"}'
    return None


def _git_push_targets(arguments: list[str], root: Path | None) -> list[str | None]:
    """Branches/tags a ``git push <arguments>`` updates; ``None`` when one cannot be named.

    A non-``origin`` remote prefixes the ref (``<remote> <ref>``), deletions become
    ``delete:<ref>`` and ``--all``/``--mirror``/``--tags`` stay literal, so a grant
    for one branch never matches them.
    """
    # A grant for a branch never authorizes running a server- or local-side command;
    # --receive-pack/--exec make the target unresolvable so no grant can match (S53-2).
    # git accepts any unambiguous prefix of a long option (`--receiv=`, `--ex=`), so refuse every
    # `--` option that is a prefix of either, with or without a value (review round 3).
    for token in arguments:
        name = token[2:].split('=', 1)[0] if token.startswith('--') else ''
        if name and ('receive-pack'.startswith(name) or 'exec'.startswith(name)):
            return [None]
    value_options = {'--repo', '-o', '--push-option', '--receive-pack', '--exec'}
    positionals: list[str] = []
    remote: str | None = None
    delete = False
    bulk: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in value_options:
            remote = arguments[index + 1] if token == '--repo' and index + 1 < len(arguments) else remote  # nosec B105
            index += 2
            continue
        if token.startswith('--repo='):
            remote = token.split('=', 1)[1]
        elif token in {'-d', '--delete'}:
            delete = True
        elif token in {'--all', '--branches', '--mirror', '--tags'}:
            bulk.append(token)
        elif not token.startswith('-'):
            positionals.append(token)
        index += 1
    if positionals and remote is None:
        remote, positionals = positionals[0], positionals[1:]
    current = git_output(root, 'symbolic-ref', '--quiet', '--short', 'HEAD') if root is not None else None
    targets: list[str | None] = list(bulk)
    for spec in positionals or ([] if bulk else ['HEAD']):
        source, colon, destination = spec.lstrip('+').partition(':')
        name = destination if colon else source
        if colon and not source:
            name, delete_one = destination, True
        else:
            delete_one = delete
        if name in {'HEAD', '@'}:
            name = (current or '').strip()
        name = name.removeprefix('refs/heads/').removeprefix('refs/tags/')
        if not name:
            targets.append(None)
            continue
        name = f'delete:{name}' if delete_one else name
        targets.append(name if remote in {None, 'origin'} else f'{remote} {name}')
    return targets


def production_targets(root: Path | None, command: str) -> list[tuple[str, str | None]]:
    """``(action, exact resource)`` for every production action in ``command``.

    The resource is what a production grant must name: a branch or tag for git push,
    ``owner/repo#N`` for a merge, ``owner/repo@tag`` for a release, the image for
    docker push and ``name@version`` for npm publish. ``None`` means the target cannot
    be determined statically, which no grant satisfies.
    """
    targets: list[tuple[str, str | None]] = []
    payload = _exact_outer_shell_payload(command)
    outer = {**_command_env(command), **(_command_env(payload) if payload is not None else {})}
    for piece in _shell_commands(command if payload is None else payload):
        if piece is None:
            continue
        env, tokens = {**outer, **piece[0]}, piece[1]
        index = next((i for i, token in enumerate(tokens) if _executable_name(token) in _AUTHORITY_EXECUTABLES), None)
        if index is None:
            continue
        argv = [_executable_name(tokens[index]), *tokens[index + 1:]]
        lowered = [argv[0], *[token.lower() for token in argv[1:]]]
        action = _production_action(lowered)
        if not action:
            continue
        if argv[0] == 'git':
            _, sub = _git_subcommand(lowered)
            targets.extend((action, target) for target in _git_push_targets(argv[sub + 1:], root))
            continue
        positionals, indexes = _positionals(lowered, _GH_VALUE_OPTIONS if argv[0] == 'gh' else frozenset(), 3)
        resource: str | None = None
        if action == 'pull-request-merge' and positionals[:1] == ['api']:
            request = _gh_api_request(argv[indexes[0] + 1:], _api_host(env))
            merge = _GITHUB_PULL_MERGE.search(request[2]) if request else None
            host = _gh_host(argv, env)
            repo = f'{merge.group(1).lower()}' if merge else None
            if repo is not None and host and host != 'github.com':
                repo = f'{host}/{repo}'
            resource = f'{repo}#{merge.group(2)}' if merge else None
        elif action == 'pull-request-merge':
            resource = _gh_pull_request(argv, indexes[1], root, env)
            # gh pr merge --admin bypasses branch protection; a plain merge grant must not
            # authorize it, so the target is a distinct resource that only an explicit grant names.
            if resource is not None and any(w == '--admin' or w.startswith('--admin=') for w in lowered):
                resource = f'{resource}!admin'
        elif action == 'github-release' and len(positionals) > 2:
            resource = f'{_gh_repository(argv, root, env)}@{argv[indexes[2]]}'
        elif action == 'docker-push':
            pushed = [argv[i] for p, i in zip(positionals, indexes) if p not in {'push', 'image', 'manifest'}]
            tags = [argv[i + 1] for i, token in enumerate(argv[:-1]) if token in {'-t', '--tag'}]
            resource = (pushed or tags or [None])[0]
        elif action == 'npm-publish' and root is not None:
            package = load_json(root / 'package.json', None)
            if isinstance(package, dict) and package.get('name') and package.get('version'):
                resource = f'{package["name"]}@{package["version"]}'
        targets.append((action, resource))
    return targets


_CURL_BODY_OPTIONS = frozenset({
    '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json', '-F', '--form',
    '--form-string', '-T', '--upload-file',
})
_WGET_BODY_OPTIONS = frozenset({'--post-data', '--post-file', '--body-data', '--body-file'})
# gh subcommands that only read; every other gh subcommand is an external write unless it is a
# modelled production action (pr merge, workflow run, release create/upload/edit) or gh api/pr review.
_GH_READ_COMMANDS = frozenset({
    'view', 'list', 'ls', 'status', 'diff', 'checks', 'checkout', 'clone', 'download', 'watch', 'get', 'search',
})
_GH_READ_GROUPS = frozenset({'search', 'status', 'help', 'version', 'completion', 'browse', 'api'})
_GH_TEXT_OPTIONS = frozenset({
    '-b', '--body', '-F', '--body-file', '-t', '--title', '-l', '--label', '-a', '--assignee', '-m', '--milestone',
    '-B', '--base', '-H', '--head', '-r', '--reviewer', '--add-label', '--remove-label', '--visibility', '-e', '--env',
    '-o', '--org', '-n', '--name', '-d', '--description', '-c', '--color',
})


def _http_tool_write(argv: list[str]) -> str | None:
    """URL a ``curl``/``wget`` argv writes to (non-GET method, body, form or upload), else ``None``."""
    options = _CURL_BODY_OPTIONS if argv[0] == 'curl' else _WGET_BODY_OPTIONS
    method_options = {'-X', '--request'} if argv[0] == 'curl' else {'--method'}
    write, url = False, None
    for index, word in enumerate(argv[1:], 1):
        option, _, attached = word.partition('=') if word.startswith('--') else (word, '', '')
        method = attached or (argv[index + 1] if index + 1 < len(argv) else '') if option in method_options else None
        if argv[0] == 'curl' and word.startswith('-X') and len(word) > 2:
            method = word[2:]
        if method is not None and method.strip().upper() not in {'GET', 'HEAD', ''}:
            write = True
        if option in options or (argv[0] == 'curl' and re.match(r'^-[dFT]\S', word)) or option.startswith('--data-'):
            write = True
        if url is None and re.match(r'^https?://', word, re.IGNORECASE):
            url = word
    return (url or 'direct-http-write') if write else None


def _gh_write_resource(argv: list[str], env: dict[str, str] | None = None) -> str | None:
    """Exact resource of a gh subcommand outside the read-only allowlist, e.g. ``gh:a/b pr close 1``.

    The repository is ``-R``/``--repo``, else ``GH_REPO``, else ``.`` (the current repository);
    a non-default ``GH_HOST`` qualifies it, so an env override never matches a default grant.
    """
    if any('$' in word or '`' in word for word in argv):
        return None  # a dynamic selector is ambiguous authority, not a grantable exact target
    lowered = [word.lower() for word in argv]
    positionals, indexes = _positionals(lowered, _GH_VALUE_OPTIONS, 2)
    if not positionals or positionals[0] in _GH_READ_GROUPS or (len(positionals) > 1 and positionals[1] in _GH_READ_COMMANDS):
        return None
    if len(positionals) == 1:
        return None  # `gh pr` alone prints help
    if _production_action(['gh', *lowered[1:]]) or tuple(positionals) == ('pr', 'review'):
        return None
    operands, _ = _positionals(['gh', *argv[indexes[-1] + 1:]], _GH_TEXT_OPTIONS | _GH_VALUE_OPTIONS, 8)
    repository = _gh_repo_flag(argv)
    if repository is None:
        repository = (env or {}).get('GH_REPO', '').lower() or '.'
    host = (env or {}).get('GH_HOST', '').lower()
    if host and host != 'github.com':
        repository = f'{host}/{repository}'
    return f'gh:{repository} ' + ' '.join([*positionals, *operands])


def _http_write_resource_text(command: str, root: Path | None = None) -> str | None:
    lowered = command.lower()
    mutation = False
    gh_resource = _gh_external_write(command, root)
    if gh_resource:
        return gh_resource
    gh_env = _command_env(command)
    for argv in _simple_commands(command):
        if argv is None:
            continue
        if argv[0] in {'curl', 'wget'} and _http_tool_write(argv):
            return _http_tool_write(argv)
        if argv[0] == 'gh':
            gh_resource = _gh_write_resource(argv, gh_env)
            if gh_resource:
                return gh_resource
    if re.search(r'\bcurl\b', lowered):
        mutation = bool(re.search(r'(?:-x|--request)\s*(?:post|put|patch|delete)\b|(?:-d|--data(?:-raw|-binary)?)(?:\s|=)', lowered))
    elif re.search(r'\bwget\b', lowered):
        mutation = bool(re.search(r'--method(?:\s|=)(?:post|put|patch|delete)\b|--post-data(?:\s|=)', lowered))
    elif re.search(r'\bgh\b[^\n]*\bapi\b', lowered):
        # Fallback for text shlex cannot tokenize: any explicit non-GET verb or a field.
        verbs = re.findall(r'(?:^|\s)(?:-x|--method)(?:\s*=\s*|\s*)["\']?([a-z]+)', lowered)
        mutation = any(verb not in {'get', 'head'} for verb in verbs) or bool(
            re.search(r'(?:^|\s)(?:-f|--field|--raw-field|--input)(?:\s|=)', lowered)
        )
        if mutation:
            return 'github-api:unparsed'
    elif re.search(r'\bgh\b[^\n]*\bpr\b[^\n]*\breview\b', lowered):
        return 'github-pr-review:unparsed'
    if not mutation:
        return None
    match = _HTTP_URL.search(command)
    return match.group(0) if match else 'direct-http-write'


_SECRET_PIECE_SPLIT = re.compile(r"""[\s'"`=:@,;()<>|&{}]+""")
_SCAN_SECONDS = 3.0
_SCAN_ENTRY_LIMIT = 20000
_HAS_SUBST = re.compile(r'\$\(|`|<\(')
_BRACE = re.compile(r'\{([^{}]*)\}')
_BUDGET_MARKER = 'a bounded filesystem scan did not complete'
_INERT_SECRET = frozenset({
    'echo', 'printf', 'ls', 'stat', 'test', '[', 'du', 'touch', 'mkdir', 'which', 'basename', 'dirname', 'realpath',
    'readlink',
})
_GREP_FAMILY = frozenset({'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'ack-grep'})
_ALWAYS_RECURSIVE_GREP = frozenset({'rg', 'ag', 'ack', 'ack-grep'})
_GREP_VALUE_OPTIONS = frozenset({
    '-m', '--max-count', '-A', '-B', '-C', '--before-context', '--after-context', '--context', '-d', '-D', '--devices',
    '--binary-files', '--color', '--colour', '--include', '--exclude', '--exclude-dir', '--include-dir',
})
_COPY_READERS = frozenset({'cp', 'rsync', 'scp'})
_ARCHIVE_READERS = frozenset({'tar', 'zip', '7z', '7za', 'gzip', 'bsdtar'})
_GIT_TEXT_OPTIONS = frozenset({
    '-m', '--message', '--grep', '--author', '--committer', '-S', '-G', '--format', '--pretty', '--since', '--until',
    '--date', '-F', '--file',
})


class _BudgetExceeded(Exception):
    """Raised when a filesystem scan exceeds its entry or time budget (fail closed)."""


class _Budget:
    def __init__(self) -> None:
        self._deadline = time.monotonic() + _SCAN_SECONDS
        self._entries = 0

    def tick(self) -> None:
        self._entries += 1
        if self._entries > _SCAN_ENTRY_LIMIT or time.monotonic() > self._deadline:
            raise _BudgetExceeded


def _brace_options(body: str) -> list[str]:
    numeric = re.fullmatch(r'(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?', body)
    if numeric:
        a, b = int(numeric.group(1)), int(numeric.group(2))
        step = abs(int(numeric.group(3) or 1)) or 1
        span = range(a, b + 1, step) if a <= b else range(a, b - 1, -step)
        return [str(x) for x in span][:64]
    alpha = re.fullmatch(r'([A-Za-z])\.\.([A-Za-z])', body)
    if alpha:
        a, b = ord(alpha.group(1)), ord(alpha.group(2))
        span = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return [chr(x) for x in span][:64]
    return body.split(',')


def _brace_expand(word: str) -> list[str]:
    """Brace expansion of comma lists and ``x..y`` ranges, capped so it cannot explode."""
    stack, results, guard = [word], [], 0
    while stack and guard < 512:
        guard += 1
        current = stack.pop()
        match = _BRACE.search(current)
        if not match:
            results.append(current)
            continue
        prefix, suffix = current[: match.start()], current[match.end():]
        for option in _brace_options(match.group(1)):
            stack.append(prefix + option + suffix)
        if len(stack) + len(results) > 256:
            break
    return (results or [word])[:64]


def _secret_path_match(path: str, patterns: list[str]) -> bool:
    normalized = path.replace('\\', '/')
    if not normalized.strip('./'):
        return False
    candidates = {normalized, normalized.lstrip('/')}
    for prefix in ('~/', '$home/', '${home}/'):
        if normalized.lower().startswith(prefix):
            candidates.add(normalized[len(prefix):])
    # Case-insensitive file systems (macOS, Windows) open '.env' for '.ENV': fold case.
    folded = [pattern.casefold() for pattern in patterns]
    for candidate in candidates:
        # 'secrets/' or 'trust-ci/runtime' names the whole protected directory.
        for spelling in (candidate, candidate.rstrip('/') + '/'):
            if _matches_any(spelling, patterns) or _matches_any(spelling.casefold(), folded):
                return True
    return False


def _secret_exception(raw: str) -> bool:
    base = os.path.basename(raw.replace('\\', '/').rstrip('/'))
    return bool(base) and any(fnmatch.fnmatch(base, exc) for exc in SECRET_READ_EXCEPTIONS)


def _bounded_glob(start: str, pattern: str, budget: _Budget) -> list[str]:
    """Filesystem matches of a glob pattern, one path segment at a time, under ``budget``."""
    normalized = pattern.replace('\\', '/')
    if normalized.startswith('/'):
        bases, segments = ['/'], [seg for seg in normalized.split('/') if seg]
    else:
        bases, segments = [start], [seg for seg in normalized.split('/') if seg]
    for segment in segments:
        nxt: list[str] = []
        if _GLOB_META.search(segment):
            for base in bases:
                try:
                    with os.scandir(base) as entries:
                        for entry in entries:
                            budget.tick()
                            if fnmatch.fnmatch(entry.name, segment):
                                nxt.append(os.path.join(base, entry.name))
                except OSError:
                    continue
        else:
            for base in bases:
                budget.tick()
                nxt.append(os.path.join(base, segment))
        bases = nxt
        if not bases:
            break
    return bases


def _secret_reference(
    root: Path, raw: str, patterns: list[str], *, expand: bool = True, budget: _Budget | None = None,
) -> bool:
    """Whether ``raw`` names secret material, inside the repository or outside it."""
    if not raw or '\x00' in raw or _secret_exception(raw):
        return False
    rel = safe_relative_path(root, raw)
    if rel is not None and _secret_path_match(rel, patterns):
        return True
    if _secret_path_match(raw, patterns):
        return True
    if expand and _GLOB_META.search(raw):
        budget = budget or _Budget()
        for match in _bounded_glob(str(root), raw, budget):
            if _secret_reference(root, match, patterns, expand=False):
                return True
    return False


def _resolve_under_root(root: Path, word: str) -> str | None:
    if not word or _GLOB_META.search(word):
        return None
    rel = safe_relative_path(root, word)
    if rel is None:
        return None
    return str(root) if rel in ('', '.') else os.path.join(str(root), rel)


def _walk_for_secret(
    root: Path, directory: str, patterns: list[str], budget: _Budget, glob_filter: str | None = None,
) -> str | None:
    """First secret file in ``directory`` (recursively, skipping ``.git``), under ``budget``."""
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.tick()
                    if entry.name == '.git':
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif (not glob_filter or fnmatch.fnmatch(entry.name, glob_filter)) and _secret_reference(
                        root, entry.path, patterns, expand=False,
                    ):
                        return entry.path
        except OSError:
            continue
    return None


def _consume_options(rest: list[str], value_options: frozenset[str]) -> list[str]:
    """Positional operands of ``rest``, dropping options and the values of ``value_options``."""
    positionals: list[str] = []
    index = 0
    while index < len(rest):
        token = rest[index]
        if token == '--':  # nosec B105
            positionals.extend(rest[index + 1:])
            break
        if token in value_options:
            index += 2
            continue
        if token.startswith('-') and len(token) > 1:
            index += 1
            continue
        positionals.append(token)
        index += 1
    return positionals


def _git_path_words(rest: list[str]) -> list[str]:
    words: list[str] = []
    index = 0
    while index < len(rest):
        token = rest[index]
        option = token.split('=', 1)[0]
        if '=' in token and option in _GIT_TEXT_OPTIONS:
            index += 1
            continue
        if token in _GIT_TEXT_OPTIONS:
            index += 2
            continue
        if token.startswith('-') and len(token) > 1:
            index += 1
            continue
        words.append(token)
        index += 1
    return words


def _grep_path_words(rest: list[str]) -> list[str]:
    words: list[str] = []
    have_pattern = False
    index = 0
    while index < len(rest):
        token = rest[index]
        if token == '--':  # nosec B105
            tail = rest[index + 1:]
            if not have_pattern and tail:
                tail = tail[1:]
            words.extend(tail)
            break
        if token in {'-e', '--regexp'}:  # the regexp is data, not a path
            have_pattern = True
            index += 2
            continue
        if token.startswith('--regexp='):
            have_pattern = True
            index += 1
            continue
        if token in {'-f', '--file'}:  # a pattern file is itself a path to read
            if index + 1 < len(rest):
                words.append(rest[index + 1])
            have_pattern = True
            index += 2
            continue
        if token.startswith('--file='):
            words.append(token.split('=', 1)[1])
            have_pattern = True
            index += 1
            continue
        if token in _GREP_VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith('-') and len(token) > 1:
            index += 1
            continue
        if not have_pattern:
            have_pattern = True  # the first bare operand is the pattern
        else:
            words.append(token)
        index += 1
    return words


def _skip_first_positional(rest: list[str], value_options: frozenset[str]) -> list[str]:
    positionals = _consume_options(rest, value_options)
    return positionals[1:]  # first positional is a filter/script/program, not a path


def _find_path_words(rest: list[str]) -> list[str]:
    words: list[str] = []
    for token in rest:
        if token.startswith('-') or token in {'(', ')', '!', ';', '+'}:
            break
        words.append(token)
    return words


def _secret_path_words(argv: list[str]) -> list[str] | None:
    """Path operands worth checking for secrets; ``None`` for an inert command (``echo``, ``ls``)."""
    name, rest = argv[0], argv[1:]
    if name in _INERT_SECRET and not any(_HAS_SUBST.search(token) for token in argv):
        return None
    if name == 'git':
        return _git_path_words(rest)
    if name in _GREP_FAMILY:
        return _grep_path_words(rest)
    if name in {'jq', 'yq'}:
        return _skip_first_positional(rest, frozenset({'--arg', '--argjson', '--slurpfile', '--rawfile', '-L'}))
    if name == 'awk':
        return _skip_first_positional(rest, frozenset({'-v', '-F'}))
    if name == 'sed':
        return _skip_first_positional(rest, frozenset({'-e', '--expression', '-f', '--file', '-l', '-i'}))
    if name == 'find':
        return _find_path_words(rest)
    if name in _COPY_READERS or name in _ARCHIVE_READERS:
        return [token for token in rest if not (token.startswith('-') and len(token) > 1)]
    return [token for token in rest if token]


def _is_recursive_reader(argv: list[str]) -> bool:
    name, rest = argv[0], argv[1:]
    if name in _ALWAYS_RECURSIVE_GREP:
        return True
    if name in _GREP_FAMILY:
        return any(
            token in {'--recursive', '--dereference-recursive', '-r', '-R'}
            or (token.startswith('-') and not token.startswith('--') and ('r' in token[1:] or 'R' in token[1:]))
            for token in rest
        )
    if name in _COPY_READERS:
        return any(
            token in {'-r', '-R', '-a', '--recursive', '--archive'}
            or (token.startswith('-') and not token.startswith('--') and ('r' in token[1:].lower() or 'a' in token[1:]))
            for token in rest
        )
    if name in _ARCHIVE_READERS:
        return True
    if name == 'find':
        return any(token in {'-exec', '-execdir', '-ok', '-okdir'} for token in rest)
    return False


def _argv_secret_reference(root: Path, argv: list[str], patterns: list[str], budget: _Budget) -> str | None:
    if not argv:
        return None
    words = _secret_path_words(argv)
    if words is None:
        return None
    recursive = _is_recursive_reader(argv)
    for word in words:
        for variant in _brace_expand(word):
            if recursive:
                full = _resolve_under_root(root, variant)
                if full and os.path.isdir(full):
                    hit = _walk_for_secret(root, full, patterns, budget)
                    if hit is not None:
                        rel = safe_relative_path(root, hit)
                        return rel if rel is not None else hit
            for piece in _SECRET_PIECE_SPLIT.split(_HTTP_URL.sub(' ', variant)):
                if piece and _secret_reference(root, piece, patterns, budget=budget):
                    return piece
    return None


def _raw_secret_reference(root: Path, command: str, patterns: list[str], budget: _Budget) -> str | None:
    """Fallback for untokenizable text: scan every quoted/fragmented piece."""
    unquoted = command.replace('"', '').replace("'", '')
    seen: set[str] = set()
    for variant in (command, unquoted, unquoted.replace('\\', '')):
        for piece in _SECRET_PIECE_SPLIT.split(_HTTP_URL.sub(' ', variant)):
            if not piece or piece in seen:
                continue
            seen.add(piece)
            if _secret_reference(root, piece, patterns, budget=budget):
                return piece
    return None


def shell_secret_reference(root: Path, command: str, patterns: list[str]) -> str | None:
    """First secret path a shell command names, under any quoting, nesting or option form.

    The command is tokenized (never executed); per-command path operands are checked,
    interpreter text (commit messages, grep/jq/awk/sed programs) is skipped, recursive
    readers of a directory holding secrets are walked, and brace/ANSI-C expansions are
    resolved. A bounded, fail-closed marker is returned if the scan exceeds its budget.
    """
    budget = _Budget()
    try:
        for argv in _simple_commands(command):
            hit = (
                _raw_secret_reference(root, command, patterns, budget)
                if argv is None
                else _argv_secret_reference(root, argv, patterns, budget)
            )
            if hit is not None:
                return hit
    except _BudgetExceeded:
        return _BUDGET_MARKER
    return None


def _agent_type(tool_input: Any) -> str | None:
    if not isinstance(tool_input, dict):
        return None
    for key in ('agent_type', 'type', 'name', 'role'):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def evaluate_pre_tool(
    root: Path,
    event: dict[str, Any],
    *,
    _skip_substring_control_plane_guard: bool = False,
) -> tuple[bool, str | None]:
    tool = str(event.get('tool_name', ''))
    tool_input = event.get('tool_input') or {}
    route = get_active_route(root)
    config = load_json(root / '.getzilla/config/policy.json', {}) or {}
    if not isinstance(config, dict):
        config = {}
    control_plane = _configured_patterns(config, 'control_plane_paths', DEFAULT_CONTROL_PLANE)
    protected = _configured_patterns(config, 'protected_paths', DEFAULT_PROTECTED)
    secret_read = _configured_patterns(config, 'secret_read_paths', DEFAULT_SECRET_READ)

    if tool == 'Bash':
        command = str(tool_input.get('command', '')) if isinstance(tool_input, dict) else str(tool_input)
        if (
            not _skip_substring_control_plane_guard
            and _is_control_plane_shell_mutation(command, control_plane)
        ):
            return False, 'Blocked control-plane shell mutation; use a structured write with an exact protected-path grant.'
        secret = shell_secret_reference(root, command, secret_read)
        if secret is not None:
            return False, f'Reading secret material is blocked: the shell command references {secret}'
        pattern = _destructive_pattern(
            command,
            _configured_patterns(config, 'destructive_command_patterns', DESTRUCTIVE_COMMANDS),
        )
        if pattern is not None:
            return False, f'Blocked destructive command by repository policy: {pattern}'
        authority = analyze_command_authority(command)
        if authority.ambiguous or (authority.actions and not authority.context_proven):
            return False, (
                'Ambiguous production authority (alias definition, nested or dynamic command): spell the git/gh/'
                'docker/npm operation literally at the top level so it can be matched to an exact grant.'
            )
        for action in authority.actions:
            if action == 'workflow-dispatch':
                return False, 'GitHub Actions workflow dispatch is forbidden for this repository.'
            from .human_gates import gate_block_reason

            for target_action, resource in production_targets(root, command) or [(action, None)]:
                gate_reason = gate_block_reason(root, 'production', target_action)
                if gate_reason:
                    return False, gate_reason
                ref = (resource or '').removeprefix('delete:')
                if target_action.startswith('git-push') and (ref in PROTECTED_BRANCHES or ref in {'--all', '--branches', '--mirror'}):
                    return False, f'Push to protected branch {resource} is forbidden for agents, with or without a grant.'
                if resource is None:
                    return False, (
                        f'Production action {target_action} requires an exact delegated local grant bound to the current SHA '
                        'for a named target (branch, tag, owner/repo#N, image or package); none could be determined.'
                    )
                if not has_valid_approval(root, 'production', action=target_action, resource=resource):
                    return False, (
                        f'Production action {target_action} on {resource} requires an exact delegated local grant '
                        'bound to the current SHA.'
                    )
        http_resource = _http_write_resource(command, root)
        if http_resource:
            from .human_gates import gate_block_reason

            gate_reason = gate_block_reason(root, 'external-write', 'external-write', http_resource)
            if gate_reason:
                return False, gate_reason
            if not has_valid_approval(root, 'external-write', action='external-write', resource=http_resource):
                return False, f'Direct external write requires an exact delegated grant for resource {http_resource}.'

    candidate_paths = _extract_paths(tool_input)
    if tool == 'apply_patch' and isinstance(tool_input, dict):
        candidate_paths.extend(_extract_patch_paths(str(tool_input.get('command', ''))))

    lowered_tool = tool.lower()
    is_read = (
        lowered_tool in {'read', 'read_file', 'open_file', 'fs_read', 'grep', 'notebookread', 'search'}
        or ('read' in lowered_tool and tool.startswith('mcp__'))
    )
    is_write = tool in {'apply_patch', 'Edit', 'Write'} or any(word in lowered_tool for word in ('write_file', 'edit_file', 'delete_file'))

    normalized: list[str] = []
    for raw in candidate_paths:
        rel = safe_relative_path(root, raw)
        if rel is None:
            if is_write:
                return False, f'Write outside repository root is blocked: {raw}'
            continue
        normalized.append(rel)

    if is_read:
        budget = _Budget()
        glob_filter = tool_input.get('glob') if isinstance(tool_input, dict) and lowered_tool == 'grep' else None
        try:
            for raw in candidate_paths:
                if _secret_reference(root, raw, secret_read, budget=budget):
                    rel = safe_relative_path(root, raw)
                    return False, f'Reading secret material is blocked: {rel if rel is not None else raw}'
                directory = _resolve_under_root(root, raw)
                if directory and os.path.isdir(directory):
                    hit = _walk_for_secret(root, directory, secret_read, budget, glob_filter)
                    if hit is not None:
                        rel = safe_relative_path(root, hit)
                        return False, f'Reading secret material is blocked: {rel if rel is not None else hit}'
        except _BudgetExceeded:
            return False, f'Reading secret material is blocked: {_BUDGET_MARKER}'

    if is_write:
        for rel in normalized:
            if _matches_any(rel, protected):
                if not has_valid_approval(root, 'protected-path', action='protected-path-write', resource=rel):
                    return False, f'Protected path edit requires an exact delegated grant for {rel}.'

    if tool == 'Agent' or lowered_tool in {'spawn_agent', 'agent'}:
        agent_type = _agent_type(tool_input)
        if route and agent_type:
            allowed = set(route.get('allowed_agents', []))
            if agent_type not in allowed:
                return False, f'Agent {agent_type} is outside active route {route.get("route_id")}; allowed: {sorted(allowed)}'
            roles = write_roles(root)
            if agent_type in roles:
                expected = route.get('write_agent')
                if expected != agent_type:
                    return False, f'Route permits only write owner {expected}, not {agent_type}'
                active = active_write_agents(root, roles)
                if active:
                    return False, f'Another write agent is already active: {active}'

    if tool.startswith('mcp__') and SIDE_EFFECT_TOOL.search(tool):
        from .human_gates import gate_block_reason

        gate_reason = gate_block_reason(root, 'external-write', 'external-write', tool)
        if gate_reason:
            return False, gate_reason
        if not has_valid_approval(root, 'external-write', action='external-write', resource=tool):
            return False, f'MCP side-effect tool {tool} requires an exact delegated external-write grant.'

    return True, None
