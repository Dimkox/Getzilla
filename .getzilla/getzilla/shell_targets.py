from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from pathlib import Path

from ._policy_legacy import (
    _command_chunks,
    _shell_tokens,
    _GLOB_META,
    _SHELL_MUTATION_SIGNAL,
    _SHELL_REDIRECTION,
    _UNWRAP_SHELL,
    _WRAPPERS,
)
from .util import safe_relative_path

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
    if name in _DIRECTORY_WORDS:
        return True
    if name == 'env':
        return any(arg in {'-C', '--chdir'} or arg.startswith(('--chdir=', '-C')) for arg in argv[1:])
    if name == 'eval':
        return _CODE_CD.search(' '.join(argv[1:])) is not None
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


def _shell_mutation_targets(root: Path, command: str) -> tuple[list[str], bool, bool, bool]:
    """Mutation targets, each read from every directory the command can be in at that point (#214).

    `cd X && cmd` runs cmd in X; `cd X; cmd` runs it in X or, if cd failed, where it was; `cd X || cmd`
    runs it only where it was. A cd whose directory the shell decides makes later relative targets unknown,
    reported as the fourth value (blind).
    """
    targets: list[str] = []
    mutation = False
    unresolved = False
    blind = False
    bases: set[str] = {''}
    unknown_base = False
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
            if directory is None:
                pending = (set(bases), True)
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


def _control_plane_shell_mutation(
    root: Path,
    command: str,
    patterns: list[str],
) -> tuple[list[str], bool]:
    raw_targets, mutation, unresolved, blind = _shell_mutation_targets(root, command)
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
        # A write after a cd into a directory the shell decides could land anywhere (#214).
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
