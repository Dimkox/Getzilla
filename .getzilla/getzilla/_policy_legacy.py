from __future__ import annotations

import codecs
import contextlib
import contextvars
import fnmatch
import itertools
import json
import os
import posixpath
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
    '.agents/**', '.grok/**', '.qwen/**', '.claude/**', '.codex/**', '.gemini/**', '.cursor/**', '.getzilla/**', '.github/**',
    'trust-ci/**', '**/.grok/**', '**/.qwen/**', '**/.claude/**', '**/.codex/**', '**/.gemini/**', '**/.cursor/**', '_lib.py',
    '.gitignore', 'AGENTS.md', 'README.md', 'CHANGELOG.md', 'VERSION',
    'decisions.md', 'mistakes.md', 'Makefile', 'ruff.toml', 'bandit.yaml', '.coveragerc',
    'scripts/getzilla_*.py', 'scripts/install_into.py', 'scripts/package_stack.py',
    'user_prompt_submit.py', 'pre_tool_use.py', 'post_tool_use.py', 'pre_compact.py',
    'session_start.py', 'session_end.py', 'stop_gate.py', 'subagent_start.py', 'subagent_stop.py',
    'tests/_support.py', 'tests/test_*.py', 'engineering/runbooks/publish-v*.md',
]
AGENT_SCRATCH = '.getzilla/runtime/scratch'
SCRATCH_HINT = ('Agent working files belong in .getzilla/runtime/scratch/, which needs no grant; '
                'receipts, routes, grants and other runtime state stay protected.')


def agent_scratch(root: Path, rel: str) -> bool:
    """A repository path inside the agent scratch area, also after resolving symlinks."""
    norm = posixpath.normpath(str(rel).replace('\\', '/'))
    if norm.startswith('../') or not norm.startswith(AGENT_SCRATCH + '/'):
        return False
    base = os.path.realpath(os.path.join(str(root), AGENT_SCRATCH))
    target = os.path.realpath(os.path.join(str(root), norm))
    if not (target == base or target.startswith(base + os.sep)):
        return False
    try:
        # A second name for an inode may be a protected file outside scratch (#102).
        return not (os.path.isfile(target) and os.stat(target).st_nlink > 1)
    except OSError:
        return True


def creates_hardlink(command: str) -> bool:
    """``ln`` without -s, ``link`` or ``cp -l``: the new name shares the source inode (#102)."""
    for argv in _simple_commands(command):
        if argv is None:
            return True
        name, rest = argv[0], argv[1:]
        options = [arg for arg in rest if arg.startswith('-') and arg != '-']
        if name == 'link':
            return True
        if name == 'ln' and not any(arg in {'--symbolic', '-s'} or (not arg.startswith('--') and 's' in arg[1:])
                                    for arg in options):
            return True
        if name == 'cp' and any(arg == '--link' or (not arg.startswith('--') and 'l' in arg[1:]) for arg in options):
            return True
    return False


DEFAULT_PROTECTED = [
    '.git/**', '.env', '.env.*', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
    *DEFAULT_CONTROL_PLANE, 'bitrix/**',
]
DEFAULT_SECRET_READ = [
    '.env', '.env.*', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.p12', '**/*.pfx',
    '**/id_rsa', '**/id_ed25519', '**/credentials*', '**/secrets/**', 'trust-ci/env/*.env', 'trust-ci/runtime/**',
    '**/id_ecdsa', '**/id_dsa', '**/.ssh/**', '**/.git-credentials', '**/.netrc', '**/_netrc', '**/.npmrc', '**/.pypirc',
    '**/.pgpass', '**/.config/gh/hosts.yml', '**/.config/gh/**', '**/.docker/config.json', '**/.kube/config', '**/.aws/**',
    # Agent-harness and cloud/package credential stores (review S59-4).
    '**/.claude/.credentials.json', '**/.codex/auth.json', '**/.vault-token',
    '**/.composer/auth.json', '**/.config/composer/auth.json', '**/.config/gcloud/**',
    '**/.azure/**', '**/.terraform.d/credentials.tfrc.json', '**/.cargo/credentials*',
    '**/.gem/credentials',
]
# Names that match a secret glob but are templates or public halves; never secret.
SECRET_READ_EXCEPTIONS = (
    '*.pub', '.env.example', '.env.sample', '.env.template', '.env.dist',
    'known_hosts', 'known_hosts.old', 'authorized_keys', 'authorized_keys2',
)
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
    r'\brobocopy\b[^\n]*\s/mir\b',
    r'''(?:^|[\s;&|\\/"'])format(?:\.com|\.exe)?["']?\s+(?:/\S+\s+)*[a-z]:''',
    r'\bformat-volume\b',
    r'\bclear-disk\b',
]
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
# Every MCP server fails closed (#195): a tool is a write unless its name reads as a read. A read
# starts or ends with a read verb (get_issue, searchConfluence, issue_read) and has no write verb
# anywhere in it, so get_or_create_x and mark_all_notifications_read stay writes. Any other name,
# including a verb that is not on a list (modify_x, pay_x, bulkCreate), needs an external-write grant.
# query and fetch are not reads by default: a database query or an HTTP fetch can write.
_READ_VERBS = frozenset({'get', 'list', 'search', 'read', 'lookup', 'describe', 'download'})
# Words that are nouns inside reads (get_check_run, pull_request_read) but writes as the first word
# (run_query, request_download).
_LEADING_WRITE_VERBS = frozenset({'run', 'request'})
_CHAIN_WORDS = frozenset({'and', 'or', 'then'})
_WRITE_VERBS = frozenset({
    'create', 'update', 'delete', 'remove', 'write', 'modify', 'patch', 'put', 'replace', 'insert', 'upsert',
    'append', 'upload', 'send', 'publish', 'merge', 'revoke', 'grant', 'trash', 'archive', 'close', 'reopen',
    'cancel', 'trigger', 'execute', 'mark', 'set', 'add', 'edit', 'post', 'submit', 'approve', 'transfer',
    'move', 'rename', 'import', 'invite', 'pay', 'refund', 'clear', 'destroy', 'purge', 'drop', 'reset',
    'restore', 'assign', 'enable', 'disable', 'start', 'stop', 'accept', 'decline', 'lock', 'unlock',
    'deploy', 'push', 'apply', 'save', 'star', 'unstar', 'fork', 'resolve', 'unresolve', 'dismiss',
    'manage', 'transition', 'comment', 'reply', 'label', 'unlabel', 'share', 'forward', 'respond',
    'rerun', 'untrash', 'fire', 'copy', 'batch', 'generate', 'reprioritize',
})
# Exact read tools whose names do not read as reads. A project adds its own per server in
# .getzilla/config/policy.json under "mcp_read_tools" ({"Server": ["tool", ...]}).
_MCP_READ_TOOLS = {
    'github': frozenset({'run_secret_scanning'}),
    'Atlassian_MCP': frozenset({'atlassianUserInfo', 'executeRead'}),
}
_NAME_TOKEN = re.compile(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+')
_ASCII_NAME = re.compile(r'[A-Za-z0-9_.-]+')
_GITHUB_NAME = re.compile(r'[A-Za-z0-9._-]+')


def _mcp_server_action(tool: str) -> tuple[str, str]:
    # The action is every segment after the server: a verb may sit before the last `__` (delete__file).
    parts = tool.split('__')
    return (parts[1], '__'.join(parts[2:])) if len(parts) > 2 else ('', parts[-1])


def _mcp_github(tool: str) -> bool:
    """Any server whose name holds github, also behind a prefix segment: its writes name owner/repo (#184)."""
    parts = tool.split('__')
    return any('github' in part.lower() for part in parts[1:-1])


def _mcp_github_reads(tool: str) -> bool:
    """Only a server named github (or ..._github, as plugin_github_github) gets the GitHub read list (#215)."""
    parts = tool.split('__')
    return any(part.lower() == 'github' or part.lower().endswith('_github') for part in parts[1:-1])


def _configured_mcp_reads(root: Path | None, server: str) -> frozenset[str]:
    if root is None:
        return frozenset()
    config = load_json(root / '.getzilla/config/policy.json', {}) or {}
    reads = config.get('mcp_read_tools') if isinstance(config, dict) else None
    names = reads.get(server) if isinstance(reads, dict) else None
    return frozenset(name for name in names if isinstance(name, str)) if isinstance(names, list) else frozenset()


def mcp_side_effect(tool: str, root: Path | None = None) -> bool:
    """Whether an MCP tool may write and so needs an exact external-write grant."""
    if not tool.startswith('mcp__'):
        return False
    server, action = _mcp_server_action(tool)
    # A host can put namespaces before the tool name (mcp__codex_apps__github__search_issues): the read
    # verb belongs to the last segment, while a write verb anywhere still makes a write (delete__file).
    name = action.rsplit('__', 1)[-1]
    namespace = {token.lower() for token in _NAME_TOKEN.findall(action[:-len(name)])}
    known = _MCP_READ_TOOLS.get('github' if _mcp_github_reads(tool) else server, frozenset())
    # An exact read name counts behind a namespace only when no namespace word is a write verb
    # (delete_repo__run_secret_scanning stays a write).
    plain_namespace = not namespace & (_WRITE_VERBS | _LEADING_WRITE_VERBS)
    if action in known or (name in known and plain_namespace) or action in _configured_mcp_reads(root, server):
        return False
    if not _ASCII_NAME.fullmatch(action):
        return True  # a look-alike letter must not split a write verb (get_dеlete)
    tokens = [token.lower() for token in _NAME_TOKEN.findall(action)]
    if not tokens or tokens[0] in _LEADING_WRITE_VERBS or any(token in _WRITE_VERBS for token in tokens):
        return True
    # run/request lead a hyphen segment too (get_x-run); a second action after and/or/then
    # (list_and_kill, getAndRun) is a write unless it is a read verb (#215).
    segments = [_NAME_TOKEN.findall(part) for part in action.split('-')[1:]]
    if any(words and words[0].lower() in _LEADING_WRITE_VERBS for words in segments):
        return True
    if any(word in _CHAIN_WORDS and following not in _READ_VERBS for word, following in zip(tokens, tokens[1:])):
        return True
    words = [token.lower() for token in _NAME_TOKEN.findall(name)] or tokens
    if words[0] in _LEADING_WRITE_VERBS:
        return True
    return not (words[0] in _READ_VERBS or words[-1] in _READ_VERBS)


def _mcp_repository_problem(root: Path, tool_input: Any) -> str | None:
    """A GitHub write names its target in owner/repo; it must be the repository grants bind to (#184)."""
    if not isinstance(tool_input, dict) or 'owner' not in tool_input and 'repo' not in tool_input:
        return None
    owner, repo = tool_input.get('owner'), tool_input.get('repo')
    if not isinstance(owner, str) or not isinstance(repo, str) \
            or not _GITHUB_NAME.fullmatch(owner) or not _GITHUB_NAME.fullmatch(repo):
        return 'it names an incomplete or invalid owner/repo target'
    from .state import _repository_identity
    try:
        bound = _repository_identity(root)
    except RuntimeError:
        return 'the local repository has no GitHub origin to bind grants to'
    if f'{owner}/{repo}'.lower() != bound.lower():
        return f'it targets {owner}/{repo}, but grants here bind only {bound}'
    return None

# Set while a command is read as a POSIX shell reads it on Windows: Claude Code runs Git Bash
# there, where `\n` is an escaped `n`, while cmd.exe and PowerShell read `\` as a separator.
_POSIX_READING: contextvars.ContextVar[bool] = contextvars.ContextVar('getzilla_posix_reading', default=False)


def _windows_reading() -> bool:
    """Read commands as cmd.exe/PowerShell do: native Windows, unless a POSIX reading is requested."""
    return fsx.WINDOWS and not _POSIX_READING.get()


@contextlib.contextmanager
def posix_reading():
    """Evaluate a command as Git Bash reads it; the filesystem stays NTFS."""
    token = _POSIX_READING.set(True)
    try:
        yield
    finally:
        _POSIX_READING.reset(token)


# Native Windows only (``_windows_reading``); POSIX parsing below is unchanged.
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
    if not _windows_reading():
        return Path(token).name.lower()
    name = PureWindowsPath(token).name.lower()
    for suffix in _WINDOWS_LAUNCHER_SUFFIXES:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return name


def _strip_windows_carets(text: str) -> str:
    """Remove cmd.exe ``^`` escapes outside quotes: ``g^it``/``git^ push`` -> ``git``/``git push``."""
    result: list[str] = []
    quote = ''
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = ''
            result.append(char)
        elif char in {'"', "'"}:
            quote = char
            result.append(char)
        elif char == '^':
            following = text[index + 1:index + 2]
            if following:
                result.append(following)
                index += 1
            # a trailing '^' is line continuation; drop it
        else:
            result.append(char)
        index += 1
    return ''.join(result)


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
    if _windows_reading():
        text = _windows_literal_backslashes(_strip_windows_carets(text))
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
    folded = _strip_windows_carets(command).replace('\\', '/').replace('"', '').replace("'", '')
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

    Windows also checks the folded spelling from ``_windows_command_variant`` against the
    substring patterns. The recursive-delete check reads argv, so it gets separators,
    carets and launcher suffixes folded but keeps quotes: text quoted as an argument (a
    commit message naming ``rm -rf /``) is an argument in cmd.exe, PowerShell and Git Bash.
    """
    candidates = [command]
    argv_candidates = [command]
    if _windows_reading():
        variant = _windows_command_variant(command)
        if variant != command:
            candidates.append(variant)
        separators = _WINDOWS_LAUNCHER.sub('', _strip_windows_carets(command).replace('\\', '/'))
        if separators != command:
            argv_candidates.append(separators)
    for pattern in patterns:
        if any(re.search(pattern, candidate, flags=re.IGNORECASE) for candidate in candidates):
            return pattern
    if any(_recursive_remove_of_root(candidate) for candidate in argv_candidates):
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
        tokens = _shell_tokens(_ANSI_C_QUOTE.sub(_ansi_c, command))
    except ValueError:
        return env
    current: list[str] = []
    for token in [*tokens, _ShellToken(';', 0, 0, operator=True)]:
        if token.operator:
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
        current.append(token.value)
    return env


@dataclass(frozen=True)
class _ShellToken:
    value: str
    start: int
    end: int
    operator: bool = False
    expansion: bool = False
    substitution: bool = False
    opaque: bool = False


_SHELL_OPERATORS = (
    ';;&', '<<<', '<<-', '&>>', '&&', '||', ';;', ';&', '|&',
    '<<', '>>', '<&', '>&', '<>', '>|', '&>',
)


def _shell_tokens(text: str) -> list[_ShellToken]:
    """Scan literal words and operators once, retaining quote/escape provenance.

    This is a bounded lexical grammar, not a shell interpreter. Active expansion
    is marked, never evaluated. Offsets refer to the original command so callers
    can split commands without splitting quoted argument data.
    """
    tokens: list[_ShellToken] = []
    index = 0
    while index < len(text):
        if text[index] in ' \t\r':
            index += 1
            continue
        start = index
        if text[index] in _PUNCTUATION:
            operator = next((op for op in _SHELL_OPERATORS if text.startswith(op, index)), text[index])
            index += len(operator)
            tokens.append(_ShellToken(operator, start, index, operator=True))
            continue
        quote = ''
        expansion = substitution = opaque = False
        while index < len(text):
            char = text[index]
            if quote == "'":
                if char == "'":
                    quote = ''
                index += 1
                continue
            if char == '\\' or (_windows_reading() and char == '^' and not quote):
                following = text[index + 1:index + 2]
                if not following:
                    raise ValueError('unfinished shell escape')
                if following == '\n':
                    raise ValueError('shell line continuation is unsupported')
                if not quote or following in {'$', '`', '"', '\\'}:
                    index += 2
                    continue
            if quote:
                if char == quote:
                    quote = ''
            elif char in {'"', "'"}:
                quote = char
            elif char in ' \t\r' or char in _PUNCTUATION:
                break
            elif char in '*?[{' or (char == '~' and (
                index == start or (_ASSIGNMENT.match(text[start:index]) and text[index - 1] in '=:')
            )):
                # Same closed literal-word boundary used by root admission: shell glob,
                # brace and tilde syntax is opaque only outside quotes and escapes.
                opaque = True
            if char in {'$', '`'}:
                expansion = True
                substitution = substitution or char == '`' or text.startswith('$(', index)
            index += 1
        if quote:
            raise ValueError('unfinished shell quote')
        values = _split_words(text[start:index])
        if len(values) != 1:
            raise ValueError('unsupported shell word')
        tokens.append(_ShellToken(values[0], start, index, expansion=expansion,
                                  substitution=substitution, opaque=opaque or expansion))
    return tokens


def _words(text: str) -> list[str]:
    """Compatibility view; consumers that split commands retain token provenance."""
    return [token.value for token in _shell_tokens(_ANSI_C_QUOTE.sub(_ansi_c, text))]


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


_POWERSHELL_EXECUTABLES = frozenset({'powershell', 'pwsh', 'powershell.exe', 'pwsh.exe'})


def _is_encoded_flag(word: str) -> bool:
    """Any spelling of -EncodedCommand: a prefix (`-e`, `-en`, `-enc`), `-ec`, `/enc`, `-enc:X` (#64)."""
    if not word.startswith(('-', '/')):
        return False
    name = word.lstrip('-/').split(':', 1)[0].lower()
    return name == 'ec' or (bool(name) and 'encodedcommand'.startswith(name))


def _nested_commands(argv: list[str]) -> list[str | list[str] | None]:
    """Command strings (``str``) or argv lists that ``argv`` itself runs.

    ``sh -c``, ``cmd /c``, ``powershell -Command``, ``git submodule foreach``,
    ``git rebase -x``, ``git bisect run``, ``git filter-branch --*-filter``,
    ``git -c alias.x=!cmd`` and ``find -exec``; ``None`` for an opaque payload
    (``powershell -EncodedCommand``).
    """
    name, lowered = argv[0], [word.lower() for word in argv]
    if name in _SHELL_EXECUTABLES:
        # Short (`-c`, `-qc`) and long (`--command X`, `--command=X`) spellings (#64).
        for i, word in enumerate(argv[1:], 1):
            if word.startswith('--command='):
                return [word.split('=', 1)[1]]
            if (_SHELL_COMMAND_OPTION.fullmatch(word) or word == '--command') and i + 1 < len(argv):
                return [argv[i + 1]]
        return []
    if name == 'cmd':
        index = next((i for i, word in enumerate(lowered) if word in {'/c', '/k'}), None)
        return [' '.join(argv[index + 1:])] if index else []
    if name in _POWERSHELL_EXECUTABLES:
        if any(_is_encoded_flag(word) for word in lowered[1:]):
            return [None]
        index = next(
            (i for i, word in enumerate(lowered[1:], 1) if word == '-c' or (len(word) > 3 and '-command'.startswith(word))),
            None,
        )
        return [' '.join(argv[index + 1:])] if index else []
    if name in {'start-process', 'saps', 'start'} and _windows_reading():
        rest = argv[1:]
        filepath: str | None = None
        launched: list[str] = []
        positionals: list[str] = []
        have_arglist = False
        pos = 0
        while pos < len(rest):
            low = rest[pos].lower()
            if low in {'-filepath', '-path'} and pos + 1 < len(rest):
                filepath = rest[pos + 1]
                pos += 2
                continue
            option, colon, value = low.partition(':')
            if colon and option in {'-argumentlist', '-args', '-argument'}:
                # `-ArgumentList:X` is the same parameter; split it into option and value (#64).
                rest = [*rest[:pos], rest[pos][:len(option)], rest[pos][len(option) + 1:], *rest[pos + 1:]]
                low = option
            if low in {'-argumentlist', '-args', '-argument'} and pos + 1 < len(rest):
                if rest[pos + 1].startswith(('@', '(')):
                    # An array/paren expression is split off by the tokenizer: opaque, fail closed (#64).
                    return [None]
                # A comma-separated array spans several words (`'pr', 'merge', '1'`): take all of it (#64).
                pos += 1
                items = [rest[pos]]
                while pos + 1 < len(rest) and (rest[pos].endswith(',') or rest[pos + 1].startswith(',')):
                    pos += 1
                    items.append(rest[pos])
                launched = [item for chunk in items for item in chunk.replace(',', ' ').split() if item]
                have_arglist = True
                pos += 1
                continue
            if rest[pos].startswith('-'):
                pos += 1
                continue
            positionals.append(rest[pos])
            pos += 1
        if filepath is None and positionals:
            filepath, positionals = positionals[0], positionals[1:]
        # Without -ArgumentList, the next positional carries the arguments (`saps git 'push origin main'`).
        if not have_arglist and positionals:
            launched = [item for chunk in positionals for item in chunk.replace(',', ' ').split() if item]
        return [[_executable_name(filepath), *launched]] if filepath else []
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
        tokens = _shell_tokens(_ANSI_C_QUOTE.sub(_ansi_c, command))
    except ValueError:
        return [None]
    commands: list[list[str] | None] = []
    current: list[str] = []
    for token in [*tokens, _ShellToken(';', 0, 0, operator=True)]:
        if token.operator:
            if '<' not in token.value and '>' not in token.value and current:
                commands.extend(_expand_command(current, depth))
                current = []
            continue
        current.append(token.value)
    return commands


def _expand_command(argv: list[str], depth: int) -> list[list[str] | None]:
    argv = _strip_wrappers(argv)
    if not argv:
        return []
    name = _executable_name(argv[0])
    argv = ['git', name[4:], *argv[1:]] if name.startswith('git-') and len(name) > 4 else [name, *argv[1:]]
    result: list[list[str] | None] = [argv]
    nested_commands = _nested_commands(argv)
    if not nested_commands and name not in _DATA_ARGUMENT_EXECUTABLES:
        nested_commands = _wrapped_payloads(argv, depth)
    for nested in nested_commands:
        if nested is None or depth >= 4:
            result.append(None)
        elif isinstance(nested, str):
            result.extend(_simple_commands(nested, depth + 1))
        elif nested:
            result.extend(_expand_command(nested, depth + 1))
    return result


# Executables whose quoted arguments are data (messages, patterns, programs), never a command.
_DATA_ARGUMENT_EXECUTABLES = frozenset({
    'echo', 'printf', 'git', 'gh', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'ack-grep',
    'findstr', 'select-string', 'sls', 'jq', 'yq', 'awk', 'sed',
})


def _wrapped_payloads(argv: list[str], depth: int) -> list[str]:
    """Quoted arguments of an unknown wrapper that parse as a risky command (fail closed, #64).

    ``flock LOCK -c 'CMD'``, ``su -c 'CMD'``, ``watch 'CMD'`` and wrappers not modelled
    at all hand one argument to a shell. Any multi-word argument (or ``--opt=value``)
    whose own parse runs a delete verb, an authority client or a shell is inspected.
    """
    risky = _REMOVE_VERBS | _AUTHORITY_EXECUTABLES | _SHELL_EXECUTABLES | _WINDOWS_SHELL_EXECUTABLES | {'find', 'rsync'}
    payloads: list[str] = []
    for word in argv[1:]:
        text = word.split('=', 1)[1] if word.startswith('--') and '=' in word else word
        if not re.search(r'\s', text.strip()) or depth >= 4:
            continue
        if any(inner and inner[0] in risky for inner in _simple_commands(text, depth + 1)):
            payloads.append(text)
    return payloads


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
    if name == 'find' and '-delete' in words:
        # `find <paths> … -delete` removes every match under its start paths (review round 3).
        paths = []
        for word in words:
            if word.startswith(('-', '(', '!')):
                break
            paths.append(word)
        return paths or ['.']
    if name == 'rsync' and any(w.startswith('--del') for w in words):
        # `rsync --delete* src… dest` deletes extraneous files under the destination.
        # Options may follow the destination (`… x/ /etc --exclude foo`), so every operand gets
        # the full dangerous-target check, as for rm: fail closed (review rounds 4-5).
        positionals = [w for w in words if not w.startswith('-')]
        return positionals or None
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


_REMOVE_VERBS = frozenset({'rm', 'del', 'erase', 'rd', 'rmdir', 'remove-item', 'ri'})


def _recursive_remove_of_root(command: str) -> bool:
    """A recursive delete (any spelling, nested or wrapped) of a root-like or expansion-dependent target.

    The delete verb is matched at the head of the argv and, to cover arbitrary exec
    wrappers (``ionice``/``chrt``/``flock``/``watch``/``unbuffer`` and multiplexers
    like ``busybox``/``toybox``) without a fixed allowlist, anywhere in the argv when
    the command itself is not inert. ``flock /lock rm -rf /`` and ``busybox rm -rf /``
    are therefore blocked just as ``rm -rf /`` is (review S59-2).
    """
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
        if _executable_name(argv[0]) in _INERT_EXECUTABLES:
            continue
        for index in range(1, len(argv)):
            if _executable_name(argv[index]) in _REMOVE_VERBS | {'find', 'rsync'}:
                wrapped = [_executable_name(argv[index]), *argv[index + 1:]]
                operands = _remove_operands(wrapped)
                if operands and any(_dangerous_remove_target(operand) for operand in operands):
                    return True
                # No early break: a wrapper argument named like a verb (`flock /tmp/find rm -rf /`)
                # must not hide a later delete, so every match is checked (review round 5).
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
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        # Preserve malformed source for the existing fail-closed callers.
        return [command] if command.strip() else []
    chunks: list[str] = []
    start = 0
    for token in tokens:
        if token.operator and token.value in {'&&', '||', ';', ';;', ';&', ';;&', '|', '|&', '&', '\n'}:
            if command[start:token.start].strip():
                chunks.append(command[start:token.start])
            start = token.end
    if command[start:].strip():
        chunks.append(command[start:])
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
        # Any option may take the next word as its value, so the verb anywhere is a publish (#64).
        return 'npm-publish' if 'publish' in argv[1:] else None
    if executable in {'pnpm', 'yarn'}:
        return 'npm-publish' if 'publish' in argv[1:] else None
    if executable in _PACKAGE_PUBLISH_CLIENTS:
        # Global options come before the verb (`cargo +toolchain --config K=V publish`,
        # `gem -C DIR push`); no positional counting: the verb anywhere is a publish (#64).
        return 'package-publish' if _PACKAGE_PUBLISH_CLIENTS[executable] & set(argv[1:]) else None
    return None


@dataclass(frozen=True)
class AuthorityAnalysis:
    actions: tuple[str, ...]
    ambiguous: bool
    context_proven: bool


# Package/registry publish clients that upload artifacts to a remote index; deny by default
# so an unreviewed `twine upload`/`cargo publish` cannot ship without a production grant (S59-7).
_PACKAGE_PUBLISH_CLIENTS = {
    'twine': {'upload'}, 'cargo': {'publish'}, 'gem': {'push'}, 'poetry': {'publish'},
    'bun': {'publish'}, 'helm': {'push'}, 'crane': {'push'}, 'oras': {'push'},
    'skopeo': {'copy'}, 'nerdctl': {'push'}, 'flit': {'publish'}, 'maturin': {'publish', 'upload'},
}
_AUTHORITY_EXECUTABLES = {
    'git', 'gh', 'docker', 'npm', 'pnpm', 'yarn', 'podman', 'buildah', *_PACKAGE_PUBLISH_CLIENTS,
}
_AUTHORITY_WORDS = re.compile(
    r'\b(?:git|gh|docker|npm|pnpm|yarn|podman|buildah|' + '|'.join(sorted(_PACKAGE_PUBLISH_CLIENTS)) + r')\b',
    re.IGNORECASE,
)
_AUTHORITY_META = re.compile(r'[$`*?\[\]{}()]')
_INERT_EXECUTABLES = {'echo', 'printf'}
_SHELL_EXECUTABLES = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'fish', 'tcsh', 'csh', 'mksh', 'ash', 'script'}


def _is_authority(token: str) -> bool:
    name = _executable_name(token)
    return name in _AUTHORITY_EXECUTABLES or (name.startswith('git-') and len(name) > 4)


_GIT_CONFIG_RUNS_CODE = re.compile(
    r'(?:alias|include|includeif|filter)\..*'
    r'|core\.(?:hookspath|fsmonitor|sshcommand|worktree|editor|pager|askpass|gitproxy)'
    r'|(?:sequence\.editor|diff\.external|credential\.helper|gpg\.program|gpg\.\w+\.program)'
    r'|(?:diff|merge)\..+\.(?:textconv|command|driver)'
    r'|credential\..*helper|core\.alternaterefscommand|remote\..+\.(?:uploadpack|receivepack)'
    r'|gpg\.ssh\.defaultkeycommand|(?:mergetool|difftool)\..+\.cmd|pager\..+|sendemail\.sendmailcmd'
)
_GIT_CONFIG_VALUE_OPTIONS = frozenset({'-f', '--file', '--blob', '--type', '--default', '--comment', '--value'})
_GIT_CONFIG_READS = frozenset({'get', 'list', 'get-regexp', 'get-urlmatch', 'get-color', 'get-colorbool',
                               'unset', 'unset-all', 'remove-section', 'rename-section'})
_GIT_CONFIG_READ_OPTIONS = frozenset({'--get', '--get-all', '--get-regexp', '-l', '--list', '--unset',
                                      '--unset-all', '--remove-section', '--get-urlmatch'})


def _git_config_defines_command(argv: list[str]) -> bool:
    """``git config`` writing a key that later runs code or moves the work tree (#214).

    ``alias.*``/``include*`` make a later bare ``git <alias>`` run anything; hooks, filters, editors,
    fsmonitor and friends run a program inside an innocent-looking ``git commit`` or ``git status``.
    """
    words = [word.lower() for word in argv[_git_subcommand(argv)[1] + 1:]]
    if not any(_GIT_CONFIG_RUNS_CODE.fullmatch(word.split('=', 1)[0]) for word in words):
        return False
    if any(word.split('=', 1)[0] in _GIT_CONFIG_READ_OPTIONS for word in words):
        return False  # a read, or a removal that takes the program away
    positional, skip = [], False
    for word in words:
        if skip:
            skip = False
        elif word in _GIT_CONFIG_VALUE_OPTIONS:
            skip = True
        elif not word.startswith('-'):
            positional.append(word)
    if positional[:1] and positional[0] in _GIT_CONFIG_READS:
        return False
    if positional[:1] == ['set']:
        return True
    return len(positional) >= 2 or any(word in {'--add', '--replace-all', '-e', '--edit'} for word in words)


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
    if executable == 'gh':
        if _gh_ambiguous_command_prefix(argv):
            return action, True
        if _gh_argument_context(argv) is not None:
            parsed = _gh_arguments(argv)
            # The command-text pass checks active expansion before argv roles are trusted.
            # Dollar/backtick characters in literal text values are data, including on merge.
            return action, parsed is None
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
        if _windows_reading() and outer in _WINDOWS_SHELL_EXECUTABLES:
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


# $IFS glued to a word; `$IFSx` is another variable and does not split (#64).
_IFS_OBFUSCATION = re.compile(r'\S\$\{?IFS(?![A-Za-z0-9_])|\$(?:IFS(?![A-Za-z0-9_])|\{IFS\})\S')
_ENCODED_POWERSHELL = re.compile(r'\b(?:powershell|pwsh)\b[^\n]*\s[-/]e(?:c|n[a-z]*)?(?![a-z])', re.IGNORECASE)
_SINGLE_QUOTED = re.compile(r"'[^']*'")


def _standalone(text: str, match: re.Match[str]) -> bool:
    """A quoted span that is a whole word; ``'git'$IFS'push'`` concatenates into executable text (#64)."""
    before = text[match.start() - 1] if match.start() else ' '
    after = text[match.end()] if match.end() < len(text) else ' '
    return (before.isspace() or before in ';&|(') and (after.isspace() or after in ';&|)')


def _executable_text(raw_command: str) -> str:
    """Command text that can expand: inert ``echo``/``printf`` chunks and standalone single-quoted words dropped."""
    pieces: list[str] = []
    for chunk in _command_chunks(raw_command):
        tokens = _command_tokens(chunk)
        if tokens and not _HAS_SUBST.search(chunk):
            bounded, _ = _bounded_command(tokens)
            if bounded and _executable_name(bounded[0]) in _INERT_EXECUTABLES:
                continue
        pieces.append(_SINGLE_QUOTED.sub(lambda m: ' ' if _standalone(chunk, m) else m.group(0), chunk))
    return '\n'.join(pieces)


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
    ambiguous = ambiguous or _gh_has_opaque_shell_words(raw_command)
    executable_text = _executable_text(raw_command)
    if _IFS_OBFUSCATION.search(executable_text):
        # `git$IFS'push'`/`git${IFS}push`: $IFS word-splits into `git push` at runtime but
        # tokenizes as one opaque word here, so treat it as ambiguous authority (review S59-5).
        ambiguous = True
    simple = _simple_commands(raw_command)
    if any(argv is None for argv in simple) and _ENCODED_POWERSHELL.search(executable_text):
        # powershell -EncodedCommand carries an opaque base64 payload the parser cannot read;
        # fail closed as ambiguous instead of silently allowing it (review S59-6). Parsed text
        # is checked per command below, so a commit message mentioning it stays allowed (#64).
        ambiguous = True
    for argv in simple:
        if argv is None or argv[0] in _INERT_EXECUTABLES:
            continue
        if None in _nested_commands(argv):
            # An opaque payload (`pwsh -EncodedCommand`, a Start-Process argument expression) (#64).
            ambiguous = True
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
    if resource is None and _windows_reading():
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
_GITHUB_PULL_URL = re.compile(
    r'https?://github\.com/([A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+)/pull/([0-9]+)(?:[/?#][^\s]*)?',
    re.IGNORECASE | re.ASCII,
)
PROTECTED_BRANCHES = frozenset({'main', 'master'})


def _gh_has_opaque_shell_words(command: str, depth: int = 0) -> bool:
    """Reject unresolved gh argv before assigning text, file or resource roles.

    Reuse the shell lexer and bounded command/wrapper model. A word may expand
    into several argv entries, even in a text option. Quoted/escaped literals
    remain literal; nested command strings are checked in their own shell context.
    """
    if depth > 4:
        return True
    for chunk in _command_chunks(command):
        try:
            words = _shell_tokens(chunk)
        except ValueError:
            return re.search(r'\bgh(?:\.exe)?\b', chunk, re.IGNORECASE) is not None
        commands = _simple_commands(chunk)
        if not any(argv and argv[0] == 'gh' for argv in commands):
            continue
        if any(word.opaque or (word.operator and word.value in {'(', ')'}) for word in words):
            # Unquoted parentheses include process substitution and extglob syntax.
            return True
        for argv in commands:
            if argv is None:
                return True
            nested = _nested_commands(argv)
            if not nested and argv[0] not in _DATA_ARGUMENT_EXECUTABLES:
                nested = _wrapped_payloads(argv, depth)
            if any(isinstance(payload, str) and _gh_has_opaque_shell_words(payload, depth + 1)
                   for payload in nested):
                return True
    return False


_GH_CASE_GLOBAL_VALUES = frozenset({'-R', '--repo', '--hostname'})
_GH_BODY_VALUES = frozenset({'-b', '--body', '-F', '--body-file'})
_GH_CREATE_VALUES = _GH_BODY_VALUES | frozenset({
    '-t', '--title', '-a', '--assignee', '-l', '--label', '-m', '--milestone', '-p', '--project', '-T', '--template',
})
_GH_EDIT_VALUES = _GH_BODY_VALUES | frozenset({
    '-t', '--title', '-m', '--milestone', '--add-assignee', '--remove-assignee', '--add-label', '--remove-label',
    '--add-project', '--remove-project',
})
# A bounded set of documented mutation contexts. Other gh commands keep their existing policy.
# Values are case-sensitive: review -r and merge -m are flags, but create -r/-m consume data.
_GH_ARGUMENT_SCHEMAS = {
    ('pr', 'create'): (_GH_CREATE_VALUES | {'-B', '--base', '-H', '--head', '-r', '--reviewer'},
                       frozenset({'-d', '--draft', '-f', '--fill', '--fill-first', '--fill-verbose',
                                  '-e', '--editor', '-w', '--web', '--dry-run', '--no-maintainer-edit'}), 0),
    ('issue', 'create'): (_GH_CREATE_VALUES, frozenset({'-e', '--editor', '-w', '--web'}), 0),
    ('pr', 'edit'): (_GH_EDIT_VALUES | {'-B', '--base', '--add-reviewer', '--remove-reviewer'},
                    frozenset({'--remove-milestone'}), 1),
    ('issue', 'edit'): (_GH_EDIT_VALUES, frozenset({'--remove-milestone'}), 1),
    ('pr', 'comment'): (_GH_BODY_VALUES, frozenset({'-e', '--editor', '-w', '--web', '--edit-last',
                                                 '--create-if-none', '--delete-last', '--yes'}), 1),
    ('issue', 'comment'): (_GH_BODY_VALUES, frozenset({'-e', '--editor', '-w', '--web', '--edit-last',
                                                    '--create-if-none', '--delete-last', '--yes'}), 1),
    ('pr', 'review'): (_GH_BODY_VALUES, frozenset({'-a', '--approve', '-c', '--comment', '-r', '--request-changes'}), 1),
    ('pr', 'merge'): (_GH_BODY_VALUES | {'-A', '--author-email', '-t', '--subject', '--match-head-commit'},
                     frozenset({'--admin', '--auto', '--disable-auto', '-d', '--delete-branch',
                                '-m', '--merge', '-r', '--rebase', '-s', '--squash'}), 1),
    ('api',): (_GH_API_VALUE_OPTIONS, frozenset({'--allow-escape-sequences', '-i', '--include', '--paginate',
                                               '--silent', '--slurp', '--verbose'}), 1),
}


@dataclass(frozen=True)
class _GhArguments:
    command: tuple[str, ...]
    operands: tuple[str, ...]
    options: tuple[tuple[str, str], ...]
    flags: frozenset[str]


def _gh_argument_context(argv: list[str]) -> tuple[tuple[str, ...], tuple[int, ...]] | None:
    words, indexes = _positionals(argv, _GH_CASE_GLOBAL_VALUES, 2)
    command = tuple(word.lower() for word in words)
    if command[:1] == ('api',):
        command, indexes = ('api',), indexes[:1]
    elif command in {('pr', 'new'), ('issue', 'new')}:
        command = (command[0], 'create')
    if command in _GH_ARGUMENT_SCHEMAS:
        return command, tuple(indexes)
    return None


def _gh_ambiguous_command_prefix(argv: list[str]) -> bool:
    """Only known global options may precede the command words we classify."""
    words, indexes = _positionals(argv, _GH_CASE_GLOBAL_VALUES, 2)
    boundary = indexes[0] if words[:1] == ['api'] else indexes[-1] if indexes else len(argv)
    index = 1
    while index < boundary:
        token = argv[index]
        if token in _GH_CASE_GLOBAL_VALUES:
            if index + 1 >= len(argv):
                return True
            index += 2
            continue
        if (token.startswith('--repo=') or token.startswith('--hostname=')
                or (token.startswith('-R') and len(token) > 2)):
            index += 1
            continue
        if token.startswith('-') and token not in {'-h', '--help', '--version'}:
            return True
        index += 1
    return False


def _gh_arguments(argv: list[str]) -> _GhArguments | None:
    """Consume known gh option values once; ``None`` means unmodelled or ambiguous.

    This consumes argv from the existing shell lexer. Short clusters and unknown
    flags stay unsupported, and a hyphen-leading option value is always data.
    """
    context = _gh_argument_context(argv)
    if context is None:
        return None
    command, command_indexes = context
    values, switches, maximum = _GH_ARGUMENT_SCHEMAS[command]
    values = values | _GH_CASE_GLOBAL_VALUES
    options: list[tuple[str, str]] = []
    flags: set[str] = set()
    operands: list[str] = []
    index = 1
    while index < len(argv):
        argument = argv[index]
        if index in command_indexes:
            index += 1
            continue
        if argument == '--':
            operands.extend(argv[index + 1:])
            break
        if not argument.startswith('-') or argument == '-':
            operands.append(argument)
            index += 1
            continue
        name, separator, value = argument.partition('=')
        if name not in values and name not in switches and argument[:2] in values:
            name, separator, value = argument[:2], '=', argument[2:].removeprefix('=')
        if name in values:
            if not separator:
                index += 1
                if index >= len(argv) or index in command_indexes:
                    return None
                value = argv[index]
            if command == ('api',):
                name = {'-R': '--repo', '-F': '--field', '-f': '--raw-field'}.get(name, name)
            else:
                name = {'-R': '--repo', '-b': '--body', '-F': '--body-file'}.get(name, name)
            if name in {'--repo', '--hostname', '--body', '--body-file', '--input'} and any(
                seen == name for seen, _ in options
            ):
                return None
            options.append((name, value))
        elif name in switches or name in {'-h', '--help'}:
            if separator and value.lower() not in {'true', 'false', 't', 'f', '1', '0'}:
                return None
            flags.add(name)
        else:
            return None
        index += 1
    dynamic_operand = any(
        ('$' in word or '`' in word) if command == ('api',) else (
            _authority_token_is_dynamic(word)
            and not (command == ('pr', 'review') and _github_pull_url_target(word) is not None)
        )
        for word in operands
    )
    if len(operands) > maximum or dynamic_operand:
        return None
    selected = dict(options)
    if '--body' in selected and '--body-file' in selected:
        return None
    if '--repo' in selected and not re.fullmatch(r'(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+', selected['--repo']):
        return None
    if '--hostname' in selected and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?', selected['--hostname']):
        return None
    parsed = _GhArguments(command, tuple(operands), tuple(options), frozenset(flags))
    if any(not path or _authority_token_is_dynamic(path) for path in _gh_file_operands(parsed)):
        return None
    return parsed


def _gh_file_operands(parsed: _GhArguments) -> list[str]:
    """Actual file consumers; API typed fields and literal text have different roles."""
    paths: list[str] = []
    for name, value in parsed.options:
        if name in {'--body-file', '--input'} or (
            parsed.command == ('pr', 'create') and name in {'-T', '--template'}
        ):
            paths.append(value)
        elif parsed.command == ('api',) and name == '--field':
            _, separator, field = value.partition('=')
            if separator and field.startswith('@'):
                paths.append(field[1:])
    return paths


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
    if _gh_argument_context(argv) is not None:
        parsed = _gh_arguments(argv)
        selected = dict(parsed.options).get('--hostname') if parsed else None
        return (selected or (env or {}).get('GH_HOST', '')).lower() or None
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
    if _gh_argument_context(argv) is not None:
        parsed = _gh_arguments(argv)
        selected = dict(parsed.options).get('--repo') if parsed else ''
        return selected.lower() if selected is not None else None
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


def _github_pull_url_target(selector: str) -> str | None:
    """The complete supported URL shape; shell literal provenance is checked before argv admission."""
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 or char in '%\\' for char in selector):
        return None
    url = _GITHUB_PULL_URL.fullmatch(selector)
    if url is None or url.group(1).rsplit('/', 1)[-1] in {'.', '..'}:
        return None
    return f'{url.group(1).lower()}#{url.group(2)}'


def _gh_pull_request(argv: list[str], index: int, root: Path | None, env: dict[str, str] | None = None) -> str | None:
    """Exact PR target; URL selectors require literal github.com authority or stay unresolved."""
    if _gh_argument_context(argv) is not None:
        parsed = _gh_arguments(argv)
        selectors = list(parsed.operands) if parsed else []
    else:
        selectors, _ = _positionals(['gh', *argv[index + 1:]], frozenset({
            '-R', '--repo', '-b', '--body', '-F', '--body-file', '-t', '--subject', '--match-head-commit', '-A', '--author-email',
        }), 1)
    if not selectors:
        return None
    selector = selectors[0]
    if '://' in selector or selector.lstrip().lower().startswith(('http:', 'https:', '//')):
        # The URL resource has no host component. Never alias another authority,
        # userinfo/port, encoded URL or malformed URL-shaped selector to this grant.
        return _github_pull_url_target(selector)
    return f'{_gh_repository(argv, root, env)}#{selector}'


def _api_host(env: dict[str, str] | None) -> str:
    """Default host for a ``gh api`` call: ``GH_HOST`` from the prefix, else api.github.com."""
    if env and env.get('GH_HOST'):
        return env['GH_HOST'].lower()
    return 'api.github.com'


def _gh_external_write_argv(argv: list[str], root: Path | None, env: dict[str, str]) -> str | None:
    """API/review authority of one invocation, never a first match across commands."""
    lowered = ['gh', *[word.lower() for word in argv[1:]]]
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
    analysis = _mutation_analysis(command, root)
    targets = [target for invocation in analysis.invocations for target in invocation.production]
    if analysis.reason:
        return [(action, None) for action, _ in targets]
    return targets


def _production_argv_targets(root: Path | None, argv: list[str], env: dict[str, str]) -> tuple[tuple[str, str | None], ...]:
    """All production targets of one already bounded invocation."""
    lowered = [argv[0], *[word.lower() for word in argv[1:]]]
    action = _production_action(lowered)
    if not action:
        return ()
    if argv[0] == 'git':
        _, sub = _git_subcommand(lowered)
        return tuple((action, target) for target in _git_push_targets(argv[sub + 1:], root))
    positionals, indexes = _positionals(lowered, _GH_VALUE_OPTIONS if argv[0] == 'gh' else frozenset(), 3)
    resource: str | None = None
    if action == 'pull-request-merge' and positionals[:1] == ['api']:
        request = _gh_api_request(argv[indexes[0] + 1:], _api_host(env))
        merge = _GITHUB_PULL_MERGE.search(request[2]) if request else None
        host = request[1] if request else None
        repo = merge.group(1).lower() if merge else None
        if repo is not None and host and host not in {'github.com', 'api.github.com'}:
            repo = f'{host}/{repo}'
        resource = f'{repo}#{merge.group(2)}' if merge else None
    elif action == 'pull-request-merge':
        resource = _gh_pull_request(argv, indexes[1], root, env)
        parsed = _gh_arguments(argv)
        if resource is not None and parsed is not None and '--admin' in parsed.flags:
            resource = f'{resource}!admin'
    elif action == 'github-release' and len(positionals) > 2:
        resource = f'{_gh_repository(argv, root, env)}@{argv[indexes[2]]}'
    elif action == 'docker-push':
        pushed = [argv[i] for p, i in zip(positionals, indexes) if p not in {'push', 'image', 'manifest'}]
        tags = [argv[i + 1] for i, word in enumerate(argv[:-1]) if word in {'-t', '--tag'}]
        resource = (pushed or tags or [None])[0]
    elif action == 'npm-publish' and root is not None:
        package = load_json(root / 'package.json', None)
        if isinstance(package, dict) and package.get('name') and package.get('version'):
            resource = f'{package["name"]}@{package["version"]}'
    return ((action, resource),)


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


_HTTP_CLIENTS = frozenset({'curl', 'wget', 'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm'})
_CURL_VALUES = _CURL_BODY_OPTIONS | frozenset({
    '-X', '--request', '-H', '--header', '-o', '--output', '-D', '--dump-header', '-w', '--write-out',
    '-A', '--user-agent', '-e', '--referer', '-u', '--user', '-x', '--proxy', '-m', '--max-time',
    '--connect-timeout', '--retry', '--retry-delay', '--cacert', '--capath', '--cert', '--key', '--url', '--noproxy',
})
_CURL_SWITCHES = frozenset({
    '-f', '-s', '-S', '-L', '-I', '-G', '-i', '-k', '-v', '-4', '-6', '-q', '-g', '-N',
    '--fail', '--fail-with-body', '--silent', '--show-error', '--location', '--head', '--get', '--include',
    '--insecure', '--verbose', '--ipv4', '--ipv6', '--disable', '--globoff', '--no-buffer', '--compressed',
    '--no-progress-meter', '--http1.1', '--http2', '--help', '--version',
})
_WGET_VALUES = _WGET_BODY_OPTIONS | frozenset({
    '--method', '--header', '-O', '--output-document', '-o', '--output-file', '-U', '--user-agent',
    '--user', '--password', '--timeout', '--tries', '--ca-certificate', '--certificate', '--private-key',
})
_WGET_SWITCHES = frozenset({
    '-q', '-S', '-c', '-nv', '--quiet', '--server-response', '--continue', '--no-verbose',
    '--no-check-certificate', '--spider', '--help', '--version',
})
_PS_HTTP_BODY = frozenset({'-body', '-infile', '-form', '-contenttype'})
_PS_HTTP_VALUES = _PS_HTTP_BODY | frozenset({
    '-uri', '-method', '-custommethod', '-headers', '-outfile', '-useragent', '-timeoutsec',
    '-maximumredirection', '-authentication', '-credential', '-proxy', '-proxycredential',
})
_PS_HTTP_SWITCHES = frozenset({
    '-usebasicparsing', '-skipcertificatecheck', '-skiphttperrorcheck', '-disablekeepalive',
    '-noproxy', '-passthru', '-verbose',
})


def _http_tool_write(argv: list[str]) -> str | None:
    """One explicit HTTP endpoint, a read, or an ungrantable unresolved request.

    Consume option values by role. Body/header URLs are data. Unknown options,
    target files, client URL expansion and multiple targets never select a first URL.
    """
    client = argv[0]
    powershell = client not in {'curl', 'wget'}
    values = _PS_HTTP_VALUES if powershell else _CURL_VALUES if client == 'curl' else _WGET_VALUES
    switches = _PS_HTTP_SWITCHES if powershell else _CURL_SWITCHES if client == 'curl' else _WGET_SWITCHES
    body_options = _PS_HTTP_BODY if powershell else _CURL_BODY_OPTIONS if client == 'curl' else _WGET_BODY_OPTIONS
    methods = {'-method', '-custommethod'} if powershell else {'-X', '--request'} if client == 'curl' else {'--method'}
    reads = _PS_READ_METHODS if powershell else {'get', 'head'}
    endpoints: list[str] = []
    write = uncertain = options_done = False
    index = 1
    while index < len(argv):
        word = argv[index]
        if not options_done and word == '--':
            options_done = True
            index += 1
            continue
        if options_done or not word.startswith('-'):
            if powershell and word.startswith('@'):
                uncertain = True  # splatting can supply an otherwise invisible method or target
            endpoints.append(word)
            index += 1
            continue
        option, separator, value = word.partition('=')
        if powershell:
            option, colon, attached = option.partition(':')
            if colon:
                separator, value = colon, attached
            option = option.lower()
            if len(option) >= 3:
                matches = [name for name in values | switches if name.startswith(option)]
                if len(matches) == 1:
                    option = matches[0]
        elif not word.startswith('--') and len(word) > 2 and word[:2] in values:
            option, separator, value = word[:2], '=', word[2:].removeprefix('=')
        if option in {'--config', '-K', '--next', '-:', '--input-file', '-i', '-e', '--execute'} and (
            client == 'wget' or option not in {'-i', '-e'}
        ):
            uncertain = True
        elif option in values:
            if not separator:
                index += 1
                if index >= len(argv):
                    uncertain = True
                    break
                value = argv[index]
            if option in methods:
                write = write or value.strip().lower() not in reads
            elif option in body_options:
                write = True
            elif option in {'--url', '-uri'}:
                endpoints.append(value)
        elif option in switches and not separator:
            pass
        elif client == 'curl' and not word.startswith('--') and all('-' + flag in switches for flag in word[1:]):
            pass
        else:
            uncertain = True
        index += 1
    if uncertain:
        return 'direct-http-write'
    if not write:
        return None
    if len(endpoints) != 1 or not re.fullmatch(r'https?://[^\s]+', endpoints[0], re.IGNORECASE):
        return 'direct-http-write'
    if any(char in endpoints[0] for char in '*[]{}'):
        return 'direct-http-write'
    return endpoints[0]


def _gh_write_resource(argv: list[str], env: dict[str, str] | None = None) -> str | None:
    """Exact resource of a gh subcommand outside the read-only allowlist, e.g. ``gh:a/b pr close 1``.

    The repository is ``-R``/``--repo``, else ``GH_REPO``, else ``.`` (the current repository);
    a non-default ``GH_HOST`` qualifies it, so an env override never matches a default grant.
    """
    if _gh_ambiguous_command_prefix(argv):
        return 'gh:'
    context = _gh_argument_context(argv)
    parsed = _gh_arguments(argv) if context is not None else None
    if context is not None and parsed is None:
        return 'gh:'  # existing grant normalization forbids category-only resources
    if parsed is None and any('$' in word or '`' in word for word in argv):
        return 'gh:'
    lowered = [word.lower() for word in argv]
    positionals, indexes = _positionals(lowered, _GH_VALUE_OPTIONS, 2)
    if not positionals or positionals[0] in _GH_READ_GROUPS or (len(positionals) > 1 and positionals[1] in _GH_READ_COMMANDS):
        return None
    if len(positionals) == 1:
        return None  # `gh pr` alone prints help
    if _production_action(['gh', *lowered[1:]]) or tuple(positionals) == ('pr', 'review'):
        return None
    if parsed is not None:
        operands = list(parsed.operands)
    else:
        operands, _ = _positionals(['gh', *argv[indexes[-1] + 1:]], _GH_TEXT_OPTIONS | _GH_VALUE_OPTIONS | {'-R'}, 8)
    repository = _gh_repo_flag(argv)
    if repository is None:
        repository = (env or {}).get('GH_REPO', '').lower() or '.'
    host = _gh_host(argv, env) if parsed is not None else (env or {}).get('GH_HOST', '').lower()
    if host and host != 'github.com':
        repository = f'{host}/{repository}'
    return f'gh:{repository} ' + ' '.join([*positionals, *operands])


_PS_READ_METHODS = frozenset({'get', 'head', 'options', 'default'})


@dataclass(frozen=True)
class _MutationInvocation:
    production: tuple[tuple[str, str | None], ...] = ()
    external: str | None = None


@dataclass(frozen=True)
class _MutationAnalysis:
    invocations: tuple[_MutationInvocation, ...]
    reason: str | None = None
    external_unresolved: bool = False
    context_proven: bool = True


_TARGET_ENV = frozenset({'GH_REPO', 'GH_HOST'})
_MUTATION_WORDS = re.compile(r'\b(?:gh|curl|wget|invoke-webrequest|iwr|invoke-restmethod|irm)\b', re.IGNORECASE)
_MUTATION_SHELLS = frozenset({'bash', 'sh', 'zsh', 'dash', 'ksh'})
_UNBOUNDED_SHELL_COMMANDS = frozenset({
    'if', 'then', 'elif', 'else', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'select',
    'function', 'coproc', '!', 'eval', 'source', '.', 'alias', 'unalias', 'trap',
})
_UNRESOLVED_MUTATION = 'External write context is unresolved; use one literal command with an explicit target.'
_MULTIPLE_MUTATIONS = 'Multiple external write commands require separate tool calls, each with its exact grant.'


def _neutral_options(
    arguments: list[str], *, values: frozenset[str] = frozenset(), flags: frozenset[str] = frozenset(),
    attached_values: frozenset[str] = frozenset(),
    maximum: int | None = None,
) -> bool:
    """Closed option roles; attached-only values never consume a following word.

    An optional attached value also has its bare spelling in flags. Required
    attached values omit that spelling, so unsupported bare forms fail closed.
    """
    operands = index = 0
    while index < len(arguments):
        word = arguments[index]
        if word == '--':
            operands += len(arguments) - index - 1
            break
        if not word.startswith('-') or word == '-':
            operands += 1
        elif word not in flags:
            option, separator, _value = word.partition('=')
            if not word.startswith('--') and len(word) > 2 and word[:2] in values:
                option, separator = word[:2], '='
            if option in attached_values:
                if not separator:
                    return False
            elif option not in values:
                return False
            elif not separator:
                index += 1
                if index >= len(arguments):
                    return False
        index += 1
    return maximum is None or operands <= maximum


def _neutral_printf(arguments: list[str]) -> bool:
    """Printf operands are data only under a literal text, %% or %s format.

    Other formats can assign variables or evaluate arithmetic in supported
    shells. Variable destinations and escape-generated formats are unmodelled.
    """
    if arguments[:1] == ['--']:
        arguments = arguments[1:]
    elif arguments and arguments[0].startswith('-'):
        return False
    if not arguments:
        return False
    format_text = arguments[0]
    index = 0
    while index < len(format_text):
        char = format_text[index]
        if char in {'%', '\\'}:
            index += 1
            allowed = '%s' if char == '%' else 'abefnrtvE\\'
            if index >= len(format_text) or format_text[index] not in allowed:
                return False
        index += 1
    return True


_NEUTRAL_GIT_OPTIONS = {
    'status': (frozenset(), frozenset({'--short', '-s', '--branch', '-b', '--porcelain', '--porcelain=v1',
                                     '--porcelain=v2', '--long', '--show-stash', '--no-ahead-behind'}), frozenset()),
    'log': (frozenset({'-n', '--max-count', '--since', '--until', '--author', '--grep'}),
            frozenset({'--oneline', '--no-patch', '--stat', '--name-only', '--name-status', '--all', '--decorate',
                       '--no-decorate', '--no-ext-diff', '--no-textconv', '--pretty'}),
            frozenset({'--format', '--pretty'})),
    'diff': (frozenset(), frozenset({'--stat', '--shortstat', '--numstat', '--name-only', '--name-status', '--check',
                                   '--cached', '--staged', '--quiet', '--exit-code', '--no-ext-diff', '--no-textconv'}),
             frozenset()),
    'show': (frozenset(), frozenset({'--no-patch', '-s', '--stat', '--name-only', '--name-status',
                                    '--no-ext-diff', '--no-textconv', '--pretty'}), frozenset({'--format', '--pretty'})),
    'rev-parse': (frozenset(), frozenset({'--show-toplevel', '--show-prefix', '--git-dir', '--git-common-dir',
                                        '--is-inside-work-tree', '--verify', '--abbrev-ref', '--short'}), frozenset()),
}
_NEUTRAL_GH_OPTIONS = {
    ('pr', 'view'): (frozenset({'--json'}), frozenset({'--comments', '-c'}), 1),
    ('issue', 'view'): (frozenset({'--json'}), frozenset({'--comments', '-c'}), 1),
    ('repo', 'view'): (frozenset({'--json'}), frozenset(), 1),
    ('pr', 'list'): (frozenset({'--json', '--limit', '-L', '--state', '-s', '--base', '-B', '--head', '-H',
                              '--author', '-A', '--label', '-l', '--search', '-S'}), frozenset(), 0),
    ('issue', 'list'): (frozenset({'--json', '--limit', '-L', '--state', '-s', '--assignee', '-a',
                                 '--author', '-A', '--label', '-l', '--search', '-S'}), frozenset(), 0),
    ('pr', 'status'): (frozenset({'--json'}), frozenset(), 0),
    ('issue', 'status'): (frozenset(), frozenset(), 0),
    ('pr', 'checks'): (frozenset({'--json'}), frozenset({'--required'}), 1),
    ('pr', 'diff'): (frozenset(), frozenset({'--stat', '--name-only', '--patch'}), 1),
}


def _neutral_git(argv: list[str]) -> bool:
    arguments = argv[1:]
    while arguments and arguments[0] == '--no-pager':
        arguments = arguments[1:]
    if not arguments:
        return False
    name, arguments = arguments[0], arguments[1:]
    if name in _NEUTRAL_GIT_OPTIONS:
        values, flags, attached_values = _NEUTRAL_GIT_OPTIONS[name]
        return _neutral_options(arguments, values=values, flags=flags, attached_values=attached_values)
    # These families also write. Only the exact read subcommands are neutral.
    if name == 'config':
        return (len(arguments) == 2 and arguments[0] in {'--get', '--get-all', '--get-regexp'}
                and not arguments[1].startswith('-')) or arguments in [['--list'], ['-l']]
    if name == 'remote':
        return arguments in [[], ['-v'], ['--verbose']] or (
            len(arguments) == 2 and arguments[0] == 'get-url' and not arguments[1].startswith('-')
        )
    if name == 'branch':
        return arguments in [['--show-current'], ['--list']]
    return False


def _neutral_gh(argv: list[str]) -> bool:
    words, indexes = _positionals(argv, _GH_CASE_GLOBAL_VALUES, 2)
    if words[:1] == ['api']:
        return _gh_arguments(argv) is not None and _neutral_options(
            [word for index, word in enumerate(argv[1:], 1) if index != indexes[0]],
            values=_GH_CASE_GLOBAL_VALUES | frozenset({'-X', '--method', '-H', '--header'}),
            flags=frozenset({'-i', '--include', '--paginate', '--silent', '--slurp', '--verbose'}), maximum=1,
        )
    schema = _NEUTRAL_GH_OPTIONS.get(tuple(words))
    if schema is None or _gh_ambiguous_command_prefix(argv):
        return False
    values, flags, maximum = schema
    return _neutral_options(
        [word for index, word in enumerate(argv[1:], 1) if index not in indexes],
        values=values | _GH_CASE_GLOBAL_VALUES, flags=flags, maximum=maximum,
    )


def _neutral_command(argv: list[str], root: Path | None) -> bool:
    """Prove a bounded non-mutation command; a data argument family is not proof.

    Unknown builtins, dispatchers and read-family options can change persistent
    variables, executable resolution or repository configuration. Refuse them
    around a mutation instead of trying to enumerate all state-writing names.
    """
    name, arguments = argv[0], argv[1:]
    if name == 'printf':
        return _neutral_printf(arguments)
    if name in {'echo', 'true', 'false'}:
        return True
    if name == 'pwd':
        return arguments in [[], ['-L'], ['-P']]
    if name == 'cat':
        return _neutral_options(arguments, flags=frozenset({'-A', '-b', '-e', '-E', '-n', '-s', '-t', '-T', '-u', '-v',
                                                          '--show-all', '--number', '--number-nonblank',
                                                          '--show-ends', '--show-tabs', '--squeeze-blank'}))
    if name == 'git':
        return _neutral_git(argv)
    if name == 'gh':
        return _neutral_gh(argv)
    if name in {'cd', 'pushd'}:
        if arguments[:1] == ['--']:
            arguments = arguments[1:]
        if root is None or len(arguments) != 1 or not arguments[0] or arguments[0].startswith('-'):
            return False
        if name == 'pushd' and arguments[0].startswith('+'):
            return False  # directory-stack selection is not a literal path
        # This exception does not grant a second root. The existing root guard
        # still resolves the complete original command, including symlinks.
        try:
            return (root / arguments[0]).resolve().is_relative_to(root.resolve())
        except (OSError, RuntimeError, ValueError):
            return False
    return False


def _argv_mutation(argv: list[str], root: Path | None, env: dict[str, str]) -> _MutationInvocation | None:
    production = _production_argv_targets(root, argv, env)
    external = None
    if argv[0] == 'gh':
        external = _gh_external_write_argv(argv, root, env) or _gh_write_resource(argv, env)
    elif argv[0] in _HTTP_CLIENTS:
        external = _http_tool_write(argv)
    return _MutationInvocation(production, external) if production or external else None


def _unproven_mutations(chunk: str) -> list[_MutationInvocation]:
    """The broad legacy scanner is detection only; it can never supply grantable authority."""
    found: list[_MutationInvocation] = []
    for argv in _simple_commands(chunk):
        if not argv or argv[0] in _INERT_EXECUTABLES:
            continue
        mutation = _argv_mutation(argv, None, {})
        if mutation is not None:
            found.append(mutation)
        if argv[0] not in _DATA_ARGUMENT_EXECUTABLES:
            for index, word in enumerate(argv[1:], 1):
                name = _executable_name(word)
                if name in _AUTHORITY_EXECUTABLES | _HTTP_CLIENTS:
                    mutation = _argv_mutation([name, *argv[index + 1:]], None, {})
                    if mutation is not None:
                        found.append(mutation)
    return found


def _mutation_words(words: list[_ShellToken]) -> tuple[list[str], bool]:
    """Literal argv excluding actual redirections; quoted operator words remain data."""
    argv: list[str] = []
    uncertain = False
    index = 0
    while index < len(words):
        word = words[index]
        if word.operator:
            if word.value in {'<<', '<<-', '<<<'}:
                uncertain = True
            if '<' not in word.value and '>' not in word.value:
                uncertain = True
                index += 1
                continue
            if index and words[index - 1].end == word.start and words[index - 1].value.isdigit() and argv:
                argv.pop()
            index += 1
            if index >= len(words) or words[index].operator:
                uncertain = True
            index += 1
            continue
        argv.append(word.value)
        index += 1
    return argv, uncertain


def _mutation_analysis(
    command: str, root: Path | None = None, *, depth: int = 0, inherited: dict[str, str] | None = None,
) -> _MutationAnalysis:
    """Collect every mutating invocation from original source, with bounded execution context.

    Only literal linear composition and one supported shell payload are admitted.
    Read commands do not export assignments into later writes. Cross-command target
    environment effects are unsupported, so their presence makes mutation authority
    unresolved. No argv is converted back into shell source for admission.
    """
    try:
        words = _shell_tokens(command)
    except ValueError:
        external = bool(_MUTATION_WORDS.search(command))
        risky = external or _AUTHORITY_WORDS.search(command)
        return _MutationAnalysis((), _UNRESOLVED_MUTATION if risky else None, external, False)
    uncertain = any(word.operator and word.value not in {'&&', ';', '\n'}
                    and '<' not in word.value and '>' not in word.value for word in words)
    invocations: list[_MutationInvocation] = []
    unresolved = external_unresolved = False
    context_proven = not uncertain
    inherited = inherited if inherited is not None else {key: os.environ[key] for key in _TARGET_ENV if key in os.environ}
    for chunk in _command_chunks(command):
        lexical = _shell_tokens(chunk)
        raw_argv, ambiguous_redirect = _mutation_words(lexical)
        assignments, raw_argv = _leading_env(raw_argv)
        env = {**inherited, **assignments}
        if not raw_argv:
            context_proven = False  # assignment-only commands can write through inherited attributes
            continue
        argv, bounded = _bounded_command(raw_argv)
        if _executable_name(raw_argv[0]) == 'env':
            wrapper_env, _ = _leading_env(raw_argv[1:])
            env.update(wrapper_env)
        if not argv:
            context_proven = False
            found = _unproven_mutations(chunk)
            unresolved = unresolved or bool(found)
            external_unresolved = external_unresolved or any(item.external for item in found)
            continue
        name = _executable_name(argv[0])
        uncertain = uncertain or name in _UNBOUNDED_SHELL_COMMANDS
        argv = ['git', name[4:], *argv[1:]] if name.startswith('git-') and len(name) > 4 else [name, *argv[1:]]
        payload = _literal_shell_payload(argv) if name in _MUTATION_SHELLS else None
        if payload is not None and bounded and depth == 0:
            nested = _mutation_analysis(payload, root, depth=depth + 1, inherited=env)
            invocations.extend(nested.invocations)
            unresolved = unresolved or nested.reason is not None
            external_unresolved = external_unresolved or nested.external_unresolved
            context_proven = context_proven and nested.context_proven
            context_proven = context_proven and not any(word.operator or word.opaque for word in lexical)
            if nested.invocations and (ambiguous_redirect or any(word.opaque for word in lexical)):
                unresolved = True
            continue
        mutation = _argv_mutation(argv, root, env)
        if mutation is not None:
            invocations.append(mutation)
            unresolved = unresolved or not bounded or ambiguous_redirect or any(word.opaque for word in lexical)
            unresolved = unresolved or mutation.external == 'direct-http-write'
        else:
            context_proven = context_proven and bounded and _neutral_command(argv, root)
            context_proven = context_proven and not any(word.operator or word.opaque for word in lexical)
            found = _unproven_mutations(chunk)
            unresolved = unresolved or bool(found)
            external_unresolved = external_unresolved or any(item.external for item in found)
    if unresolved or (invocations and (uncertain or not context_proven)):
        return _MutationAnalysis(tuple(invocations), _UNRESOLVED_MUTATION, external_unresolved, False)
    if len(invocations) > 1:
        return _MutationAnalysis(tuple(invocations), _MULTIPLE_MUTATIONS)
    return _MutationAnalysis(tuple(invocations), context_proven=context_proven)


def _http_write_resource_text(command: str, root: Path | None = None) -> str | None:
    """Compatibility view: only one fully bounded write can expose an exact resource."""
    if _gh_has_opaque_shell_words(command):
        return 'gh:'
    analysis = _mutation_analysis(command, root)
    if analysis.reason:
        return 'direct-http-write' if analysis.external_unresolved or any(
            item.external for item in analysis.invocations
        ) else None
    return analysis.invocations[0].external if analysis.invocations else None


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
_WINDOWS_COPY_READERS = frozenset({'robocopy', 'xcopy', 'copy-item', 'copy', 'cpi'})
_WINDOWS_ARCHIVE_READERS = frozenset({'compress-archive'})
_WINDOWS_GREP_READERS = frozenset({'findstr', 'select-string', 'sls'})
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
        # islice so a huge range (`{1..100000000}`) never materializes as a full list.
        return [str(x) for x in itertools.islice(span, 64)]
    alpha = re.fullmatch(r'([A-Za-z])\.\.([A-Za-z])', body)
    if alpha:
        a, b = ord(alpha.group(1)), ord(alpha.group(2))
        span = range(a, b + 1) if a <= b else range(a, b - 1, -1)
        return [chr(x) for x in itertools.islice(span, 64)]
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
            raise _BudgetExceeded  # over the cap: deny rather than check a truncated list (#64)
    if stack or len(results) > 64:
        raise _BudgetExceeded
    return results or [word]


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


def _secret_exception(raw: str, patterns: list[str]) -> bool:
    # Collapse `//`, `.` and `..` first so `trust-ci//runtime/...` still names the protected tree (#64).
    normalized = posixpath.normpath(raw.replace('\\', '/')).rstrip('/')
    # The ssh client config and host-key caches are routinely read and carry no key
    # material; only files like .ssh/id_* stay secret (via their own patterns).
    base = os.path.basename(normalized)
    if normalized.lower().endswith('.ssh/config'):
        enclosing = normalized[:-len('.ssh/config')]
    elif base and any(fnmatch.fnmatch(base, exc) for exc in SECRET_READ_EXCEPTIONS):
        enclosing = os.path.dirname(normalized)
        if os.path.basename(enclosing).lower() == '.ssh':
            enclosing = os.path.dirname(enclosing)
    else:
        return False
    # A public name never overrides a protected enclosing tree (`trust-ci/runtime/**`,
    # `**/secrets/**`); only the ordinary SSH store pattern is waived (#64).
    enclosing = enclosing.rstrip('/')
    stronger = [pattern for pattern in patterns if '.ssh' not in pattern.lower()]
    return not (enclosing.strip('./~') and _secret_path_match(enclosing + '/', stronger))


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
    if budget is not None:
        # Count every literal word checked, not only filesystem globbing, so the overall
        # wall-clock/entry budget bounds the word x pattern scan and fails closed (review S59-1).
        budget.tick()
    if not raw or '\x00' in raw:
        return False
    rel = safe_relative_path(root, raw)
    if _secret_exception(raw, patterns) and (rel is None or _secret_exception(rel, patterns)):
        return False
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
    *, skip_hidden: bool = False,
) -> str | None:
    """First secret file in ``directory`` (recursively, skipping ``.git``), under ``budget``.

    ``skip_hidden`` models ripgrep's default of not descending into dotfiles/dot-dirs,
    so a plain ``Grep`` of the tree is not flagged for a hidden ``.env`` it would never
    open (review S59-8); an explicit glob clears it so a glob targeting secrets still hits.
    """
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    budget.tick()
                    if entry.name == '.git':
                        continue
                    if skip_hidden and entry.name.startswith('.'):
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif (not glob_filter or any(fnmatch.fnmatch(entry.name, g) for g in _brace_expand(glob_filter))) and _secret_reference(
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


# curl options whose values are hosts, headers, methods or numbers, never files (`--noproxy '*'`).
# Options that read files (`-d @file`, `-T`, `-K`, `-w @file`, `--cacert`) stay checked.
_CURL_NON_PATH_VALUES = frozenset({
    '--noproxy', '-H', '--header', '-X', '--request', '-A', '--user-agent', '-m', '--max-time',
    '--connect-timeout', '--retry', '--retry-delay', '--retry-max-time', '--resolve', '--limit-rate',
})
PROJECT_POLICY = '.getzilla/config/project-policy.json'


def project_policy(root: Path) -> dict[str, Any]:
    """Owner opt-ins kept by the project itself: never shipped or overwritten by a Getzilla sync, and a
    protected path agents cannot write without a grant."""
    try:
        data = json.loads((root / PROJECT_POLICY).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


_CURL_HEADER_OPTIONS = frozenset({'-H', '--header', '--proxy-header'})


def _curl_path_words(rest: list[str]) -> list[str]:
    words: list[str] = []
    option: str | None = None
    for arg in rest:
        if option is not None:
            # `-H @file` / `--header @file` read the headers from that file (#99).
            if option in _CURL_HEADER_OPTIONS and arg.startswith('@'):
                words.append(arg[1:])
            option = None
            continue
        if arg in _CURL_NON_PATH_VALUES or arg == '--proxy-header':
            option = arg
            continue
        name, equals, value = arg.partition('=')
        if arg.startswith('--') and equals and (name in _CURL_NON_PATH_VALUES or name == '--proxy-header'):
            if name in _CURL_HEADER_OPTIONS and value.startswith('@'):
                words.append(value[1:])
            continue
        if arg.startswith('-H') and len(arg) > 2 and not arg.startswith('--'):
            if arg[2:].startswith('@'):
                words.append(arg[3:])
            continue
        words.append(arg)
    return words


_CONSUMER_INTERPRETER = re.compile(r'python(?:3(?:\.\d+)?)?(?:\.exe)?')
_DIRECTORY_CHANGERS = frozenset({'cd', 'pushd', 'popd', 'chdir', 'set-location', 'sl'})


def _same_file(root: Path, word: str, rel: str) -> bool:
    if not word or word.startswith('-'):
        return False
    target = os.path.realpath(os.path.join(str(root), rel))
    return os.path.isfile(target) and os.path.realpath(os.path.join(str(root), word)) == target


def _consumer_handoffs(root: Path, command: str) -> dict[tuple[str, ...], frozenset[str]]:
    """Secret paths the owner lets an exact script receive (project policy ``secret_consumers``).

    The exception belongs to one top-level simple command: a real Python interpreter (or the script
    itself) as its first word, the script resolved to the listed file, no wrapper, no nested shell and
    no directory change anywhere in the command (#100). A redirection or ``tee`` aimed at a handed
    secret voids the exception: reading it is allowed, writing it never is (#101).
    """
    consumers = project_policy(root).get('secret_consumers')
    if not isinstance(consumers, list):
        return {}
    commands = _simple_commands(command)
    if any(argv is None or argv[0] in _DIRECTORY_CHANGERS for argv in commands):
        return {}
    try:
        tokens = _shell_tokens(_ANSI_C_QUOTE.sub(_ansi_c, command))
    except ValueError:
        return {}
    segments: list[tuple[list[str], list[str]]] = []
    words: list[str] = []
    targets: list[str] = []
    expect_target = False
    for token in [*tokens, _ShellToken(';', 0, 0, operator=True)]:
        if token.operator:
            if '>' in token.value and token.value != '>&':
                expect_target = True
                continue
            if '<' in token.value or token.value == '>&':
                continue
            if words:
                segments.append((words, targets))
            words, targets, expect_target = [], [], False
            continue
        if expect_target:
            targets.append(token.value)
            expect_target = False
        words.append(token.value)
    written = {word for argv in commands if argv and argv[0] == 'tee' for word in argv[1:] if not word.startswith('-')}
    handoffs: dict[tuple[str, ...], frozenset[str]] = {}
    for raw, redirected in segments:
        first = _executable_name(raw[0])
        interpreter = _CONSUMER_INTERPRETER.fullmatch(first) is not None
        script = raw[1] if interpreter and len(raw) > 1 else raw[0]
        allowed: set[str] = set()
        for item in consumers:
            if (isinstance(item, dict) and isinstance(item.get('script'), str) and isinstance(item.get('secrets'), list)
                    and _same_file(root, script, item['script'])):
                allowed.update(secret for secret in item['secrets'] if isinstance(secret, str) and secret)
        if not allowed:
            continue
        sinks = {*redirected, *written}
        if any(os.path.realpath(sink) == os.path.realpath(secret) or sink == secret for sink in sinks for secret in allowed):
            continue
        argv = ['git', first[4:], *raw[1:]] if first.startswith('git-') and len(first) > 4 else [first, *raw[1:]]
        handoffs[tuple(argv)] = frozenset(allowed)
    return handoffs


def _secret_path_words(argv: list[str]) -> list[str] | None:
    """Path operands worth checking for secrets; ``None`` for an inert command (``echo``, ``ls``)."""
    name, rest = argv[0], argv[1:]
    if name in _INERT_SECRET and not any(_HAS_SUBST.search(token) for token in argv):
        return None
    if name == 'curl':
        return _curl_path_words(rest)
    if name == 'gh':
        parsed = _gh_arguments(argv)
        if parsed is not None:
            return _gh_file_operands(parsed)
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
    if name in _WINDOWS_COPY_READERS or name in _WINDOWS_ARCHIVE_READERS:
        # Windows copy/archive readers: path operands are bare tokens; '/switch' and '-Option' drop out.
        # `\\` is a separator there, not an escape: split `pub\\ C:\\out`, drop a trailing `\\` (#64).
        return [
            word.replace('\\', '/').rstrip('/') or word
            for token in rest for word in token.split() if not word.startswith(('-', '/'))
        ]
    if name in {'select-string', 'sls'}:
        # Named parameters (`-Pattern X`, `-Path:X`, `-LiteralPath X`): every bare word and colon value
        # may be a path; only a purely positional first word is the pattern (#64).
        words: list[str] = []
        named = False
        index = 0
        while index < len(rest):
            low = rest[index].lower()
            option, colon, value = low.partition(':')
            if option.startswith('-'):
                name = option.lstrip('-')
                if len(name) >= 2 and any(full.startswith(name) for full in ('pattern', 'path', 'literalpath', 'pspath', 'lp')):
                    named = True
                    if colon and value:
                        words.append(rest[index].split(':', 1)[1])
                    elif name.startswith('patt') and not colon:
                        index += 1
                index += 1
                continue
            words.append(rest[index])
            index += 1
        return words if named else words[1:]
    if name in _WINDOWS_GREP_READERS:
        # findstr/Select-String: the first bare operand is the pattern, the rest are paths.
        paths = [token for token in rest if not token.startswith(('-', '/'))]
        return paths[1:]
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
    if name in _WINDOWS_ARCHIVE_READERS:
        return True
    if name in {'robocopy', 'xcopy'}:
        # Without /S they still copy every file directly in the source directory (#64).
        return True
    if name in _WINDOWS_COPY_READERS:
        return any(
            token.lower() in {'/s', '/e', '/mir'} or (len(token) > 1 and '-recurse'.startswith(token.lower()))
            for token in rest
        )
    if name in _WINDOWS_GREP_READERS:
        return any(token.lower() == '/s' or (len(token) > 1 and '-recurse'.startswith(token.lower())) for token in rest)
    return False


def _argv_secret_reference(
    root: Path, argv: list[str], patterns: list[str], budget: _Budget,
    handoffs: dict[tuple[str, ...], frozenset[str]] | None = None,
) -> str | None:
    if not argv:
        return None
    words = _secret_path_words(argv)
    if words is None:
        return None
    handed = (handoffs or {}).get(tuple(argv), frozenset())
    if handed:
        # The owner lets this script read these secrets itself; the agent still never names them elsewhere.
        words = [word for word in words if word not in handed and word.split('=', 1)[-1] not in handed]
    recursive = _is_recursive_reader(argv)
    for word in words:
        for variant in _brace_expand(word):
            if recursive:
                full = _resolve_under_root(root, variant)
                if full is None and _GLOB_META.search(variant):
                    # `findstr /s PAT deploy\*` / `grep -r PAT deploy/*`: walk the literal prefix dir.
                    prefix = _literal_pattern_prefix(variant)
                    full = _resolve_under_root(root, prefix) if prefix else None
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


_COMMAND_SCAN_BYTE_LIMIT = 131072
_SECRET_SCAN_CACHE: dict[tuple[str, str, tuple[str, ...], bool, bytes], str | None] = {}
_GH_OPAQUE_MARKER = 'unresolved GitHub CLI shell expansion'


def shell_secret_reference(root: Path, command: str, patterns: list[str]) -> str | None:
    """First secret path a shell command names, under any quoting, nesting or option form.

    The command is tokenized (never executed); per-command path operands are checked,
    interpreter text (commit messages, grep/jq/awk/sed programs) is skipped, recursive
    readers of a directory holding secrets are walked, and brace/ANSI-C expansions are
    resolved. The scan is bounded by a wall-clock and entry budget and by a hard command
    size cap, and fails closed with a marker rather than letting the hook exceed its
    PreToolUse timeout (review S59-1). The result is memoized for the life of the process
    so the hook never pays for the same scan twice (sensitive_action + evaluate_pre_tool).
    """
    # The reading is part of the key: Windows and Git Bash read the same text differently.
    # Owner opt-ins change the verdict, so the project policy is part of the key too.
    try:
        owner = (root / PROJECT_POLICY).read_bytes()
    except OSError:
        owner = b''
    key = (str(root), command, tuple(patterns), _windows_reading(), owner)
    if key in _SECRET_SCAN_CACHE:
        return _SECRET_SCAN_CACHE[key]
    if len(command) > _COMMAND_SCAN_BYTE_LIMIT:
        _SECRET_SCAN_CACHE[key] = _BUDGET_MARKER
        return _BUDGET_MARKER
    if _gh_has_opaque_shell_words(command):
        # A text role cannot hide a file option introduced by shell expansion.
        return _GH_OPAQUE_MARKER
    budget = _Budget()
    result: str | None = None
    try:
        handoffs = _consumer_handoffs(root, command)
        for argv in _simple_commands(command):
            hit = (
                _raw_secret_reference(root, command, patterns, budget)
                if argv is None
                else _argv_secret_reference(root, argv, patterns, budget, handoffs)
            )
            if hit is not None:
                result = hit
                break
    except _BudgetExceeded:
        result = _BUDGET_MARKER
    if len(_SECRET_SCAN_CACHE) < 256:
        _SECRET_SCAN_CACHE[key] = result
    return result


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
        pattern = _destructive_pattern(
            command,
            _configured_patterns(config, 'destructive_command_patterns', DESTRUCTIVE_COMMANDS),
        )
        if pattern is not None:
            return False, f'Blocked destructive command by repository policy: {pattern}'
        secret = shell_secret_reference(root, command, secret_read)
        if secret == _GH_OPAQUE_MARKER:
            return False, 'GitHub CLI arguments must be literal; quote or escape data and use explicit option values.'
        if secret is not None:
            return False, f'Reading secret material is blocked: the shell command references {secret}'
        authority = analyze_command_authority(command)
        if authority.ambiguous or (authority.actions and not authority.context_proven):
            return False, (
                'Ambiguous production authority (alias or code-running git config, nested or dynamic command): spell the git/gh/'
                'docker/npm operation literally at the top level so it can be matched to an exact grant.'
            )
        mutations = _mutation_analysis(command, root)
        if mutations.reason:
            return False, mutations.reason
        for action in authority.actions:
            if action == 'workflow-dispatch':
                return False, 'GitHub Actions workflow dispatch is forbidden for this repository.'
        production_checks = [target for invocation in mutations.invocations for target in invocation.production]
        resolved_actions = {action for action, _ in production_checks}
        production_checks.extend((action, None) for action in authority.actions if action not in resolved_actions)
        for target_action, resource in production_checks:
            from .human_gates import gate_block_reason

            gate_reason = gate_block_reason(root, 'production', target_action)
            if gate_reason:
                return False, gate_reason
            ref = (resource or '').removeprefix('delete:')
            owner_branches = project_policy(root).get('agent_push_branches')
            owner_branches = set(owner_branches) if isinstance(owner_branches, list) else set()
            if target_action.startswith('git-push') and ((ref in PROTECTED_BRANCHES and ref not in owner_branches)
                                                        or ref in {'--all', '--branches', '--mirror'}):
                return False, f'Push to protected branch {resource} is forbidden for agents, with or without a grant.'
            if resource is None:
                return False, (
                    f'Production action {target_action} requires an exact delegated local grant bound to the current SHA '
                    'for a named target (branch, tag, owner/repo#N, image or package); none could be determined.'
                )
            if not has_valid_approval(root, 'production', action=target_action, resource=resource):
                from .state import approval_mismatch
                return False, (
                    f'Production action {target_action} on {resource} requires an exact delegated local grant '
                    'bound to the current SHA.'
                    + approval_mismatch(root, 'production', action=target_action, resource=resource)
                )
        from .cost_guard import paid_run_resource
        from .util import runtime_dir

        try:
            paid_resource = paid_run_resource(command, runtime_dir(root))
        except (OSError, ValueError):
            paid_resource = None
        if paid_resource:
            from .human_gates import gate_block_reason

            gate_reason = gate_block_reason(root, 'paid-run', 'paid-run', paid_resource)
            if gate_reason:
                return False, f'Live paid run of {paid_resource} is blocked: {gate_reason}'
        http_resource = mutations.invocations[0].external if mutations.invocations else None
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
        is_grep = isinstance(tool_input, dict) and lowered_tool == 'grep'
        glob_filter = tool_input.get('glob') if is_grep else None
        glob_filter = glob_filter if isinstance(glob_filter, str) and glob_filter else None
        search_inputs = list(candidate_paths)
        try:
            if is_grep and glob_filter:
                # A grep glob names the files ripgrep opens even with no path given; a glob that
                # targets secret material (`glob='.env'`, `'**/server.key'`) is a read (review S59-3).
                # ripgrep globs take `{a,b}` alternatives: check every alternative (#64).
                search_inputs.extend(_brace_expand(glob_filter))
            for raw in search_inputs:
                if not isinstance(raw, str) or not raw:
                    continue
                if _secret_reference(root, raw, secret_read, budget=budget):
                    rel = safe_relative_path(root, raw)
                    return False, f'Reading secret material is blocked: {rel if rel is not None else raw}'
                directory = _resolve_under_root(root, raw)
                if directory and os.path.isdir(directory):
                    hit = _walk_for_secret(
                        root, directory, secret_read, budget, glob_filter,
                        skip_hidden=is_grep and glob_filter is None,
                    )
                    if hit is not None:
                        rel = safe_relative_path(root, hit)
                        return False, f'Reading secret material is blocked: {rel if rel is not None else hit}'
        except _BudgetExceeded:
            return False, f'Reading secret material is blocked: {_BUDGET_MARKER}'

    if is_write:
        for rel in normalized:
            if _matches_any(rel, protected) and not agent_scratch(root, rel):
                if not has_valid_approval(root, 'protected-path', action='protected-path-write', resource=rel):
                    hint = f' {SCRATCH_HINT}' if rel.startswith('.getzilla/runtime/') else ''
                    return False, f'Protected path edit requires an exact delegated grant for {rel}.{hint}'

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

    if mcp_side_effect(tool, root):
        from .human_gates import gate_block_reason

        gate_reason = gate_block_reason(root, 'external-write', 'external-write', tool)
        if gate_reason:
            return False, gate_reason
        if _mcp_github(tool):
            problem = _mcp_repository_problem(root, tool_input)
            if problem:
                return False, f'MCP side-effect tool {tool} is refused: {problem}.'
        if not has_valid_approval(root, 'external-write', action='external-write', resource=tool):
            from .state import approval_mismatch
            return False, (f'MCP side-effect tool {tool} requires an exact delegated external-write grant.'
                           + approval_mismatch(root, 'external-write', action='external-write', resource=tool))

    return True, None
