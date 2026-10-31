from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
import os
import stat
from pathlib import Path

from ._policy_legacy import (
    _Budget,
    _BudgetExceeded,
    _command_chunks,
    _configured_patterns,
    _secret_reference,
    _simple_commands,
    _shell_tokens,
    _GLOB_META,
    _SHELL_MUTATION_SIGNAL,
    _SHELL_REDIRECTION,
    _UNWRAP_SHELL,
    _WRAPPERS,
    DEFAULT_SECRET_READ,
)
from .util import load_json, safe_relative_path

def _normalize_repo_path(value: str) -> str:
    normalized = value.replace('\\', '/')
    while normalized.startswith('./'):
        normalized = normalized[2:]
    return normalized


def _glob_match(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(_normalize_repo_path(path), _normalize_repo_path(pattern))


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(_glob_match(path, pattern) for pattern in patterns)


def _literal_pattern_prefix(pattern: str) -> str:
    normalized = _normalize_repo_path(pattern)
    match = _GLOB_META.search(normalized)
    return normalized[:match.start()] if match else normalized


def _shell_argv(chunk: str) -> list[str]:
    stripped = chunk.split('#', 1)[0].strip()
    try:
        tokens = shlex.split(stripped)
    except ValueError:
        tokens = stripped.split()
    # A group, subshell or compound keyword runs the command after it: `(rm x)`, `then rm x`.
    while tokens and (tokens[0] in _SHELL_KEYWORDS or tokens[0][:1] in {'(', '{'}):
        first = tokens[0].lstrip('({') if tokens[0] not in _SHELL_KEYWORDS else ''
        tokens = ([first] if first else []) + tokens[1:]
    if tokens:
        last = tokens[-1].rstrip(')}')
        tokens = tokens[:-1] + ([last] if last else [])
    while tokens and re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', tokens[0]):
        tokens = tokens[1:]
    while tokens and tokens[0].lower() in _WRAPPERS:
        tokens = tokens[1:]
    return tokens


_SHELL_KEYWORDS = frozenset({'if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', 'builtin', 'exec'})


def _option_values(
    argv: list[str],
    short: str,
    long: str,
    *,
    grouped_prefixes: set[str] | None = None,
) -> list[str]:
    values: list[str] = []
    index = 1
    short_name = short.removeprefix('-')
    while index < len(argv):
        token = argv[index]
        if token in {short, long}:
            if index + 1 < len(argv):
                values.append(argv[index + 1])
                index += 2
                continue
        if token.startswith(long + '='):
            values.append(token.split('=', 1)[1])
        elif token.startswith(short) and token != short and not token.startswith('--'):
            values.append(token[len(short):])
        elif grouped_prefixes and token.startswith('-') and not token.startswith('--'):
            cluster = token[1:]
            prefix = cluster[:-len(short_name)] if short_name and cluster.endswith(short_name) else ''
            if prefix and all(char in grouped_prefixes for char in prefix) and index + 1 < len(argv):
                values.append(argv[index + 1])
                index += 2
                continue
        index += 1
    return values


def _has_option(argv: list[str], names: set[str]) -> bool:
    for token in argv[1:]:
        for name in names:
            if token == name:
                return True
            if name.startswith('--') and token.startswith(name + '='):
                return True
            if name.startswith('-') and not name.startswith('--') and token.startswith(name) and token != '-':  # nosec B105
                return True
    return False


def _operands(argv: list[str], value_options: set[str] | None = None) -> list[str]:
    result: list[str] = []
    options_with_values = value_options or set()
    after_separator = False
    index = 1
    while index < len(argv):
        token = argv[index]
        if token == '--':  # nosec B105
            after_separator = True
            index += 1
            continue
        if not after_separator and token.startswith('-'):
            if token in options_with_values and index + 1 < len(argv):
                index += 2
                continue
            if any(token.startswith(option + '=') for option in options_with_values if option.startswith('--')):
                index += 1
                continue
            index += 1
            continue
        result.append(token)
        index += 1
    return result


def _command_name(argv: list[str]) -> str:
    if not argv:
        return ''
    command = argv[0].replace('\\', '/').rsplit('/', 1)[-1].lower()
    return command[:-4] if command.endswith('.exe') else command


def _python_module_arguments(argv: list[str]) -> tuple[str, list[str], bool] | None:
    """Separate a literal module selector from interpreter options; never parse program flags as Python flags."""
    if not re.fullmatch(r'python(?:3(?:\.\d+)?)?', _command_name(argv)):
        return None
    index = 1
    unresolved = False
    while index < len(argv):
        argument = argv[index]
        if argument.split('=', 1)[0] == '--check-hash-based-pycs':
            if '=' not in argument:
                index += 1
            if index >= len(argv) or argv[index].split('=', 1)[-1] not in {'always', 'default', 'never'}:
                return None
        elif argument.startswith('--') or argument == '-' or not argument.startswith('-'):
            return None
        else:
            flags = argument[1:]
            for position, flag in enumerate(flags):
                if flag == 'm':
                    module = flags[position + 1:]
                    if not module:
                        index += 1
                        module = argv[index] if index < len(argv) else ''
                    return (module, argv[index + 1:], unresolved) if module and not module.startswith('-') else None
                if flag in 'WX':
                    value = flags[position + 1:]
                    if not value:
                        index += 1
                        if index >= len(argv):
                            return None
                        value = argv[index]
                    # Other values can import code or redirect bytecode writes; only these diagnostics are proven.
                    if value != ('ignore' if flag == 'W' else 'dev'):
                        unresolved = True
                    break
                # Inline/interactive, diagnostics and unknown selectors do not select a proven module.
                if flag not in 'bBdEIOPqRsSuvx':
                    return None
        index += 1
    return None


def _bandit_shell_targets(
    root: Path, command: str, *, bases: set[str], unknown_base: bool,
) -> tuple[list[str], bool] | None:
    """Account for the bounded Bandit CLI used by verification, not arbitrary Python program arguments.

    Config/source operands are inputs; -o/--output opens a report. Unknown options,
    expansions and shell syntax remain unresolved. Native inline and secret guards still apply.
    """
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        return None
    selected = _python_module_arguments([token.value for token in tokens])
    if selected is None or selected[0] != 'bandit':
        # Existing normalization discovers literal wrappers; it grants no scanner exception to them.
        for argv in _simple_commands(command):
            wrapped = _python_module_arguments(argv) if argv else None
            if wrapped is not None and wrapped[0] == 'bandit':
                return [], True
        return None
    unresolved = unknown_base or selected[2] or '\\' in command or any(
        token.operator or token.expansion or re.search(r'[$`~*?\[\]{}%\^#\x00]', token.value)
        for token in tokens
    )
    targets: list[str] = []
    paths: list[str] = []
    has_attached_path = False
    arguments = selected[1]
    value_options = {'-c': 'input', '--configfile': 'input', '-f': 'format', '--format': 'format',
                     '-o': 'output', '--output': 'output'}
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument == '--':
            paths.extend(arguments[index:])
            break  # Every later operand is a source path, even one spelled like an output option.
        if argument in {'-q', '--quiet', '--silent', '-r', '--recursive'}:
            continue
        if not argument.startswith('-') or argument == '-':
            paths.append(argument)
            continue
        option, separator, value = argument.partition('=')
        if option in value_options:
            if not separator:
                if index >= len(arguments) or (arguments[index].startswith('-') and arguments[index] != '-'):
                    unresolved = True
                    continue
                value = arguments[index]
                index += 1
        elif argument[:2] in {'-c', '-f', '-o'} and not argument.startswith('--'):
            option, value = argument[:2], argument[2:]
            if option in {'-c', '-o'}:
                has_attached_path = True
        else:
            unresolved = True
            continue
        if not value:
            unresolved = True
        elif value_options[option] == 'output' and value != '-':
            targets.append(value)
            paths.append(value)
        elif value_options[option] == 'input':
            paths.append(value)
        elif value_options[option] == 'format' and value != 'json':
            unresolved = True
    if paths and not unresolved and (has_attached_path or bases != {''}):
        # Raw root-relative operands retain the generic secret guard. Decoded short options and
        # directory changes need their actual paths checked against the repository's policy.
        config = load_json(root / '.getzilla/config/policy.json', {}) or {}
        patterns = _configured_patterns(
            config if isinstance(config, dict) else {}, 'secret_read_paths', DEFAULT_SECRET_READ,
        )
        try:
            budget = _Budget()
            unresolved = any(
                _secret_reference(root, posixpath.join(base, path), patterns, expand=False, budget=budget)
                for path in paths for base in sorted(bases)
            )
        except _BudgetExceeded:
            unresolved = True
    return targets, bool(unresolved)


def _directory_target(root: Path, raw: str, *, explicit: bool) -> bool:
    if explicit or raw.endswith(('/', '\\')):
        return True
    if any(marker in raw for marker in ('$(', '${', '$', '`', '*', '?', '[')):
        return False
    path = Path(raw)
    absolute = path if path.is_absolute() else root / path
    try:
        return absolute.resolve().is_dir()
    except OSError:
        return False


def _joined_target(directory: str, source: str) -> str | None:
    normalized_source = source.replace('\\', '/').rstrip('/')
    basename = normalized_source.rsplit('/', 1)[-1]
    if not basename or basename in {'.', '..'} or any(marker in basename for marker in ('$', '`', '*', '?', '[')):
        return None
    normalized_directory = directory.replace('\\', '/').rstrip('/')
    if normalized_directory in {'', '.'}:
        return basename
    return f'{normalized_directory}/{basename}'


def _copy_like_targets(root: Path, command: str, argv: list[str]) -> list[str]:
    value_options = {'-t', '--target-directory', '-S', '--suffix'}
    if command == 'install':
        value_options.update({'-m', '--mode', '-o', '--owner', '-g', '--group'})
    configured = _option_values(argv, '-t', '--target-directory')
    operands = _operands(argv, value_options)
    if configured:
        destinations = configured
        sources = operands
        explicit_directory = True
    elif operands:
        destinations = operands[-1:]
        sources = operands[:-1]
        explicit_directory = False
    else:
        return []

    targets = list(destinations)
    if command == 'mv':
        # A move removes its source, so a protected source is a protected mutation.
        targets.extend(sources)
    for destination in destinations:
        if not _directory_target(root, destination, explicit=explicit_directory):
            continue
        for source in sources:
            joined = _joined_target(destination, source)
            if joined:
                targets.append(joined)
    return list(dict.fromkeys(targets))


def _script_file_targets(
    argv: list[str],
    *,
    script_options: set[str],
    value_options: set[str],
) -> list[str]:
    operands = _operands(argv, value_options)
    if _has_option(argv, script_options):
        return operands
    return operands[1:] if len(operands) > 1 else []


def _argv_mutation_targets(root: Path, argv: list[str]) -> list[str] | None:
    command = _command_name(argv)
    if not command:
        return None
    if command == 'curl':
        targets = _option_values(
            argv,
            '-o',
            '--output',
            grouped_prefixes=set('sSfLkIiVv'),
        )
        return targets if targets else None
    if command == 'wget':
        targets = _option_values(
            argv,
            '-O',
            '--output-document',
            grouped_prefixes=set('qNc'),
        )
        return targets if targets else None
    if command == 'dd':
        targets = [token.split('=', 1)[1] for token in argv[1:] if token.startswith('of=')]
        return targets if targets else None
    if command == 'tee':
        return _operands(argv)
    if command == 'touch':
        return _operands(argv, {'-d', '--date', '-r', '--reference', '-t', '--time'})
    if command == 'mkdir':
        return _operands(argv, {'-m', '--mode', '-Z', '--context'})
    if command in {'rmdir', 'rm', 'rename'}:
        return _operands(argv)
    if command == 'link':
        # `link FILE NEW`: NEW becomes a second name for FILE's inode.
        operands = _operands(argv)
        return operands[1:] if len(operands) > 1 else operands
    if command == 'truncate':
        return _operands(argv, {'-s', '--size', '-r', '--reference'})
    if command in {'chmod', 'chown', 'chgrp'}:
        operands = _operands(argv, {'--reference', '--from'})
        if _has_option(argv, {'--reference'}):
            return operands
        return operands[1:] if len(operands) > 1 else []
    if command in {'cp', 'mv', 'ln', 'install'}:
        return _copy_like_targets(root, command, argv)
    if command == 'rsync':
        operands = _operands(argv)
        return operands[-1:] if operands else []
    if command == 'sed' and any(token == '-i' or token.startswith('-i') for token in argv[1:]):  # nosec B105
        return _script_file_targets(
            argv,
            script_options={'-e', '--expression', '-f', '--file'},
            value_options={'-e', '--expression', '-f', '--file'},
        )
    if command == 'perl' and any(token.startswith('-') and 'i' in token[1:] for token in argv[1:]):
        return _script_file_targets(
            argv,
            script_options={'-e', '-E'},
            value_options={'-e', '-E', '-M', '-m'},
        )
    if command == 'ruff' and '--fix' in argv:
        operands = _operands(argv)
        if operands and operands[0] in {'check', 'format'}:
            operands = operands[1:]
        return operands
    return None


_CD = frozenset({'cd', 'pushd'})
_DIRECTORY_WORDS = frozenset({'cd', 'pushd', 'popd', 'chdir'})
_CODE_CD = re.compile(r'(?:^|[\s;&|(){}])(?:cd|pushd|popd|chdir)(?=$|[\s;&|)}])')


def _moves_directory(argv: list[str]) -> bool:
    """A command in command position that changes directory: cd/pushd/popd, `env -C`, or eval of one (#214)."""
    if not argv:
        return False
    name = argv[0]
    # Also after a case pattern `a)`, a function body `f() {`, `function f {` or `command -p`.
    for index, word in enumerate(argv):
        if word in _DIRECTORY_WORDS and (index == 0 or argv[index - 1].endswith((')', '{'))
                                         or argv[index - 1] in {'command', '-p', 'builtin'}):
            return True
    if name == 'env':
        return any(arg in {'-C', '--chdir'} or arg.startswith(('--chdir=', '-C')) for arg in argv[1:])
    if name == 'eval':
        text = ' '.join(argv[1:])
        return _CODE_CD.search(text) is not None or '$' in text or '`' in text
    return False


def _chunks_with_operators(command: str) -> list[tuple[str, str]]:
    """(chunk, operator before it); the first chunk has ''. Malformed text is one chunk."""
    try:
        tokens = _shell_tokens(command)
    except ValueError:
        return [(command, '')] if command.strip() else []
    chunks: list[tuple[str, str]] = []
    start, operator = 0, ''
    for token in tokens:
        if token.operator and token.value in {'&&', '||', ';', ';;', ';&', ';;&', '|', '|&', '&', '\n'}:
            if command[start:token.start].strip():
                chunks.append((command[start:token.start], operator))
            start, operator = token.end, token.value
    if command[start:].strip():
        chunks.append((command[start:], operator))
    return chunks


def _cd_target(argv: list[str]) -> tuple[bool, str | None]:
    """(is a cd, its literal directory or None when the shell decides it: no argument, -, ~, $, globs)."""
    if not argv or argv[0] not in _CD:
        return False, None
    args = [arg for arg in argv[1:] if arg not in {'-P', '-L', '--'}]
    # `-`, `pushd +1`/`-1` (a stack rotation), `~`, `$X` and globs: the shell picks the directory.
    if len(args) != 1 or args[0][:1] in {'-', '+'} or re.search(r'[$`~*?\[{]', args[0]):
        return True, None
    return True, args[0]


def _shell_mutation_targets(
    root: Path, command: str, *, initial_base: str = '', initial_unknown: bool = False,
) -> tuple[list[str], bool, bool, bool]:
    """Mutation targets, each read from every directory the command can be in at that point (#214).

    `cd X && cmd` runs cmd in X; `cd X; cmd` runs it in X or, if cd failed, where it was; `cd X || cmd`
    runs it only where it was. A cd whose directory the shell decides makes later relative targets unknown,
    reported as the fourth value (blind). Unsupported scanner arguments also make destinations blind.
    """
    targets: list[str] = []
    mutation = False
    unresolved = False
    blind = False
    bases: set[str] = {initial_base}
    unknown_base = initial_unknown
    pending: tuple[set[str], bool] | None = None
    for chunk, operator in _chunks_with_operators(command):
        if pending is not None:
            moved, moved_unknown = pending
            if operator == '&&':
                bases, unknown_base = moved, moved_unknown
            elif operator != '||':
                bases, unknown_base = bases | moved, unknown_base or moved_unknown
            pending = None
        inner = _unwrap_shell(chunk)
        # Only a top-level cd (also quoted, 'cd' or \\cd) is followed; `(cd x)`, `{ cd x; }`, `if cd x` or
        # a nested shell end or branch elsewhere, so they make later relative targets unknown.
        try:
            first = shlex.split(chunk.strip())[:1]
        except ValueError:
            first = []
        plain = inner == chunk and first and first[0] in _CD and not re.search(r'[(){}]', chunk)
        is_cd, directory = _cd_target(_shell_argv(inner)) if plain else (False, None)
        if is_cd and len(_command_chunks(inner)) == 1:
            # `cd . > AGENTS.md` still truncates the file: the shell opens a redirection in the
            # directory it is in before cd runs.
            for match in _SHELL_REDIRECTION.finditer(chunk):
                raw = match.group('target').strip('"\'')
                mutation = True
                if not raw or raw.startswith('/') or any(marker in raw for marker in ('$', '`')):
                    targets.append(raw)
                elif unknown_base:
                    unresolved = blind = True
                else:
                    targets.extend(posixpath.join(base, raw) if base else raw for base in sorted(bases))
            is_cd, directory = _cd_target(_shell_argv(_SHELL_REDIRECTION.sub(' ', inner)))
            if directory is None:
                pending = (set(bases), True)
            elif posixpath.isabs(directory):
                pending = ({directory}, False)
            else:
                pending = ({posixpath.join(base, directory) if base else directory for base in bases}, unknown_base)
            continue
        for piece in _command_chunks(inner):
            if _moves_directory(_shell_argv(piece)):
                unknown_base = True
            found: list[str] = []
            redirections = [
                match.group('target').strip('"\'')
                for match in _SHELL_REDIRECTION.finditer(piece)
            ]
            if redirections:
                mutation = True
                found.extend(redirections)
            scanner = _bandit_shell_targets(root, piece, bases=bases, unknown_base=unknown_base)
            if scanner is not None:
                scanner_targets, scanner_unresolved = scanner
                scanner_unresolved = scanner_unresolved or inner != chunk
                found.extend(scanner_targets)
                mutation = mutation or bool(scanner_targets) or scanner_unresolved
                unresolved = unresolved or scanner_unresolved
                # Unknown scanner options can conceal an attached output path from lexical matching.
                blind = blind or scanner_unresolved
            else:
                signal = _SHELL_MUTATION_SIGNAL.search(piece) is not None
                argv_targets = _argv_mutation_targets(root, _shell_argv(piece))
                if argv_targets is not None:
                    mutation = True
                    found.extend(argv_targets)
                elif signal:
                    mutation = True
                    unresolved = True
                    blind = blind or unknown_base
            for raw in found:
                if not raw or raw.startswith('/') or any(marker in raw for marker in ('$', '`')):
                    targets.append(raw)
                elif unknown_base:
                    unresolved = blind = True
                else:
                    targets.extend(posixpath.join(base, raw) if base else raw for base in sorted(bases))
    return list(dict.fromkeys(targets)), mutation, unresolved, blind


def _control_plane_target(path: str, patterns: list[str]) -> bool:
    if _matches_any(path, patterns):
        return True
    normalized = _normalize_repo_path(path).rstrip('/')
    for pattern in patterns:
        candidate = _normalize_repo_path(pattern)
        if candidate.endswith('/**') and normalized == candidate[:-3].rstrip('/'):
            return True
    return False


def _dynamic_target_mentions_control_plane(raw: str, patterns: list[str]) -> bool:
    normalized = raw.replace('\\', '/')
    if not normalized.startswith(('/', '$', '`')) and _control_plane_target(normalized, patterns):
        return True
    expansion = re.compile(
        r'(?:\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]+\}|\$\([^)]*\)|`[^`]*`)/(?P<suffix>[^\s]+)'
    )
    for match in expansion.finditer(normalized):
        suffix = match.group('suffix').strip('"\'')
        if _control_plane_target(suffix, patterns):
            return True
    return False


def _opaque_control_plane_reference(root: Path, command: str, patterns: list[str]) -> bool:
    normalized = command.replace('\\', '/')
    absolute_root = root.resolve().as_posix().rstrip('/')
    for pattern in patterns:
        prefix = _literal_pattern_prefix(pattern)
        if not prefix:
            continue
        exact_pattern = _GLOB_META.search(_normalize_repo_path(pattern)) is None
        suffix = r'(?=$|[\s\'"),;:&|])' if exact_pattern else ''
        relative = re.compile(
            r'(?:^|[\s\'"=(:,>])(?:\./)?' + re.escape(prefix) + suffix,
            re.IGNORECASE,
        )
        absolute = re.compile(
            re.escape(absolute_root + '/' + prefix) + suffix,
            re.IGNORECASE,
        )
        if relative.search(normalized) or absolute.search(normalized):
            return True
    return False


def _git_code_path(rel: str) -> bool:
    """A Git file that makes a later plain git command run a program (#214)."""
    norm = posixpath.normpath(rel).lower()
    return (norm in {'.git/config', '.git/config.worktree', '.git/info/attributes', '.git/hooks'}
            or norm.startswith('.git/hooks/'))


_PIP_REQUIREMENTS = frozenset({
    '.getzilla/config/python-test-requirements.txt',
    '.getzilla/config/python-quality-requirements.txt',
})
_PIP_FLAGS = ['-I', '-m', 'pip', '--isolated', 'install', '--only-binary=:all:',
              '--no-cache-dir', '--disable-pip-version-check', '--ignore-installed']
PIP_INSTALL_HINT = (
    ' Supported pip form: PIP_CONFIG_FILE=/dev/null .getzilla/runtime/scratch/<venv>/bin/python '
    '-I -m pip --isolated install --only-binary=:all: --no-cache-dir --disable-pip-version-check '
    '--ignore-installed -r .getzilla/config/python-test-requirements.txt '
    '(optionally also -r .getzilla/config/python-quality-requirements.txt). '
    'Use an existing owner-only (0700) POSIX venv under non-shared owned directories, '
    'with no system site packages, only plain pinned requirements, '
    'and no extra options or shell commands.'
)


def is_pip_install(command: str) -> bool:
    # UV recognition selects a refusal and its hint, never admission to the closed pip grammar.
    invocations = [_shell_argv(_unwrap_shell(chunk)) for chunk in _command_chunks(command)]
    return any('install' in argv and (re.fullmatch(r'pip(?:3(?:\.\d+)?)?', _command_name(argv)) or
               (_command_name(argv) == 'uv' and _operands(argv, {
                   '--directory', '--project', '--config-file', '--cache-dir', '--color', '--allow-insecure-host',
               })[:2] == ['pip', 'install']) or
               (re.fullmatch(r'python(?:3(?:\.\d+)?)?', _command_name(argv)) and
                any(argv[index:index + 2] == ['-m', 'pip'] for index in range(len(argv)))))
               for argv in invocations)


def _plain_file(path: Path, limit: int) -> str:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > limit:
        raise ValueError('not a bounded regular file')
    return path.read_text(encoding='utf-8')


def _scratch_pip_targets(root: Path, command: str) -> tuple[list[str], bool] | None:
    """A closed POSIX install form: requirements are reads, the existing venv is the write target.

    This is target accounting, not a package sandbox. Wheels and their installed code still need
    normal dependency trust. Config files, source builds and destination overrides are excluded.
    """
    if not is_pip_install(command):
        return None
    denied: tuple[list[str], bool] = ([], True)
    # No expansions, redirections, wrappers, extra commands or environment overrides.
    if os.name == 'nt' or not re.fullmatch(r'[A-Za-z0-9_./:= -]+', command):
        return denied
    argv = command.split()
    if len(argv) < 13 or argv[0] != 'PIP_CONFIG_FILE=/dev/null' or argv[2:11] != _PIP_FLAGS:
        return denied
    interpreter = argv[1]
    if not re.fullmatch(r'\.getzilla/runtime/scratch/[A-Za-z0-9_-]+/bin/python(?:3(?:\.\d+)?)?', interpreter):
        return denied
    tail = argv[11:]
    if len(tail) % 2 or not tail or len(tail) > 4:
        return denied
    requirements = tail[1::2]
    if (any(flag != '-r' for flag in tail[::2]) or len(set(requirements)) != len(requirements)
            or not set(requirements) <= _PIP_REQUIREMENTS):
        return denied
    venv = (root / interpreter).parent.parent
    try:
        # Do not treat a scratch-directory symlink as an isolated destination.
        for path in [venv, *venv.parents]:
            if path.is_symlink() or not path.is_dir():
                return denied
            metadata = path.stat()
            if metadata.st_uid != os.getuid() or metadata.st_mode & (0o077 if path == venv else 0o022):
                return denied
            if path == root:
                break
        if (venv / 'bin').is_symlink() or not (venv / 'bin').is_dir():
            return denied
        fields = dict(line.split('=', 1) for line in _plain_file(venv / 'pyvenv.cfg', 16384).splitlines()
                      if '=' in line)
        fields = {key.strip(): value.strip() for key, value in fields.items()}
        executable = fields.get('executable', '')
        if (fields.get('include-system-site-packages') != 'false'
                or not re.fullmatch(r'/usr/(?:local/)?bin/python(?:3(?:\.\d+)?)?', executable)
                or fields.get('home') != str(Path(executable).parent)
                or (root / interpreter).resolve(strict=True) != Path(executable).resolve(strict=True)
                or not os.access(executable, os.X_OK)):
            return denied
        # Existing package directories can redirect pip's writes too. Bound the scan and reject
        # external links/hardlinks, except the ordinary venv interpreter links to its base Python.
        visited = 0
        def fail_walk(error: OSError) -> None:
            raise error

        for directory, dirs, files in os.walk(venv, followlinks=False, onerror=fail_walk):
            for name in dirs + files:
                visited += 1
                if visited > 20000:
                    return denied
                path = Path(directory) / name
                metadata = path.lstat()
                if path.is_symlink():
                    destination = path.resolve(strict=True)
                    python_link = path.parent == venv / 'bin' and (
                        re.fullmatch(r'python(?:3(?:\.\d+)?)?', name) or name == '\U0001d70bthon')
                    if not destination.is_relative_to(venv) and not (
                            python_link and destination == Path(executable).resolve(strict=True)):
                        return denied
                elif stat.S_ISREG(metadata.st_mode):
                    if metadata.st_nlink != 1:
                        return denied
                elif not stat.S_ISDIR(metadata.st_mode):
                    return denied
        for relative in requirements:
            path = root / relative
            if path.parent.is_symlink() or (root / '.getzilla').is_symlink():
                return denied
            pins = [line.strip() for line in _plain_file(path, 16384).splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
            if not pins or not all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*==[0-9][A-Za-z0-9.]*', pin)
                                   for pin in pins):
                return denied
    except (OSError, ValueError, UnicodeError, RuntimeError):
        return denied
    return [venv.relative_to(root).as_posix()], False


def _control_plane_shell_mutation(
    root: Path,
    command: str,
    patterns: list[str],
    *, initial_base: str = '', initial_unknown: bool = False,
) -> tuple[list[str], bool]:
    pip = _scratch_pip_targets(root, command)
    if pip is not None:
        return pip
    raw_targets, mutation, unresolved, blind = _shell_mutation_targets(
        root, command, initial_base=initial_base, initial_unknown=initial_unknown,
    )
    protected_targets: list[str] = []
    dynamic_protected = False
    for raw in raw_targets:
        if not raw:
            continue
        if any(marker in raw for marker in ('$(', '${', '$', '`', '*', '?', '[')):
            dynamic_protected = dynamic_protected or _dynamic_target_mentions_control_plane(raw, patterns)
            continue
        rel = safe_relative_path(root, raw)
        if rel is not None and (_control_plane_target(rel, patterns) or _git_code_path(rel)):
            protected_targets.append(rel)
    if protected_targets:
        return list(dict.fromkeys(protected_targets)), False
    if dynamic_protected or blind:
        # Unknown directories or scanner options can conceal a protected destination.
        return [], True
    return [], mutation and unresolved and _opaque_control_plane_reference(root, command, patterns)



def _leading_argv(chunk: str) -> list[str]:
    return [token.lower() for token in _shell_argv(chunk)]


def _unwrap_shell(chunk: str) -> str:
    match = _UNWRAP_SHELL.match(chunk)
    if not match:
        return chunk
    rest = match.group('rest')
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in {'"', "'"}:
        return rest[1:-1]
    return rest




_PROTECTED_REFS = frozenset({'main', 'master', 'refs/heads/main', 'refs/heads/master', 'heads/main', 'heads/master'})
_BRANCH_REWRITE = frozenset({'-f', '--force', '-m', '-M', '--move', '-d', '-D', '--delete'})
_BRANCH_COPY = frozenset({'-c', '-C', '--copy'})
_CREATE_RESET = frozenset({'-B', '-C', '--force-create'})
_GIT_GLOBAL_VALUE = frozenset({'-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path', '--config-env'})


def _protected(name: str) -> bool:
    # Case-folded: on a case-insensitive filesystem Main is main.
    return name.lstrip('+').lower() in _PROTECTED_REFS


def _git_words(argv: list[str]) -> tuple[str | None, list[str]]:
    if not argv or Path(argv[0]).name.lower() not in {'git', 'git.exe'}:
        return None, []
    index = 1
    while index < len(argv) and argv[index].startswith('-'):
        index += 2 if argv[index] in _GIT_GLOBAL_VALUE else 1
    return (argv[index].lower(), argv[index + 1:]) if index < len(argv) else (None, [])


def _split_options(rest: list[str], fused: str) -> list[tuple[str, str | None]]:
    """(option, attached value) pairs and ('', positional); `-Bmain` and `--move=main` carry their value."""
    words: list[tuple[str, str | None]] = []
    for word in rest:
        if word.startswith('--') and '=' in word:
            option, value = word.split('=', 1)
            words.append((option, value))
        elif word.startswith('-') and not word.startswith('--') and len(word) > 2 and word[1] in fused:
            words.append((word[:2], word[2:]))
        elif word.startswith('-'):
            words.append((word, None))
        else:
            words.append(('', word))
    return words


def _ref_move(sub: str, rest: list[str]) -> str | None:
    words = _split_options(rest, 'BCcfmMdD')
    options = {option for option, _ in words if option}
    names = [value for option, value in words if not option and value is not None]
    attached = [value for option, value in words if option and value]
    if sub == 'update-ref':
        if '--stdin' in options:
            return 'main'
        skipped, positional = False, []
        for option, value in words:
            if option == '-m' and value is None:
                skipped = True
            elif not option and value is not None:
                if skipped:
                    skipped = False
                    continue
                positional.append(value)
        return next((n for n in positional[:1] if _protected(n)), None)
    if sub == 'branch':
        targets = names + attached
        if options & _BRANCH_REWRITE:
            return next((n for n in targets if _protected(n)), None)
        if options & _BRANCH_COPY:
            return next((n for n in targets[1:2] if _protected(n)), None)
        return None
    if sub in {'checkout', 'switch'} or (sub == 'worktree' and names[:1] == ['add']):
        for index, (option, value) in enumerate(words):
            if option in _CREATE_RESET or (sub == 'switch' and option in {'-c', '--create'}):
                value = value if value is not None else (words[index + 1][1] if index + 1 < len(words) else None)
                if value and _protected(value):
                    return value
        return None
    if sub in {'fetch', 'pull'}:
        remote = names[0] if names else ''
        local = remote in {'', '.'} or '/' in remote or remote.startswith('file:')
        for spec in names[1:]:
            source, _, destination = spec.partition(':')
            forced = spec.startswith('+') or bool(options & {'-f', '--force'})
            covered = _protected(destination) or (
                '*' in destination and fnmatch.fnmatch('refs/heads/main', destination.lstrip('+')))
            same = source.lstrip('+').lower().removeprefix('refs/heads/') == destination.lower().removeprefix('refs/heads/')
            if destination and covered and (forced or local or not same):
                return destination
        return None
    if sub == 'symbolic-ref' and len(names) >= 2 and _protected(names[0]):
        return names[0]
    return None


def protected_ref_move(command: str) -> str | None:
    """The protected branch a git command moves, renames or deletes locally (#214), else None.

    A moved local main changes the base every diff, review and verification compares against.
    Commits and merges while main is checked out are not covered here.
    """
    for chunk, _ in _chunks_with_operators(command):
        for piece in _command_chunks(_unwrap_shell(chunk)):
            sub, rest = _git_words(_shell_argv(piece))
            hit = _ref_move(sub, rest) if sub else None
            if hit:
                return hit
    return None


control_plane_shell_mutation = _control_plane_shell_mutation
