"""Path hints: a read or search command that names a missing path gets the closest real paths.

Agents guess file names ("TechnicalSheet.php" for "TechnicalSheetController.php") or search
from the wrong directory. Each miss costs a full model call over the whole context, and the
search that usually follows costs more. Only the explicit path arguments of read-only
commands (cat, head, tail, sed without -i, rg, grep, ls, find, wc, nl, stat, file, awk) are
checked; writes, redirections to files and anything with shell expansion are never inspected.

- :func:`refusal` (PreToolUse): every path the command names is missing, so it could read
  nothing; refuse it and list the closest existing paths instead of running it.
- :func:`hint` (PostToolUse): some named paths are missing; add the same list beside the output.
"""
from __future__ import annotations

import difflib
import glob as _glob
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

MAX_SUGGESTIONS = 5
MIN_SCORE = 0.45
MAX_CANDIDATES = 3000
LOCATE = 'Locate before reading: `rg --files | rg -i <name>`.'
STATS = '.getzilla/runtime/path-hints.json'

_EXPANSION = re.compile(r'[$`]')
_OPERATORS = {'&&', '||', ';', '|'}
_HARMLESS_TARGETS = {'/dev/null', '&1', '&2'}
_GLOB = re.compile(r'[*?\[]')
_WORDS = re.compile(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+')

# program -> (options that take a value, first positional is a pattern/script, pattern options)
_SPECS: dict[str, tuple[frozenset[str], bool, frozenset[str]]] = {
    'cat': (frozenset(), False, frozenset()),
    'nl': (frozenset({'-b', '-n', '-s', '-v', '-w', '-i'}), False, frozenset()),
    'wc': (frozenset(), False, frozenset()),
    'stat': (frozenset({'-c', '--format', '--printf', '-f'}), False, frozenset()),
    'file': (frozenset({'-m', '-F', '-e'}), False, frozenset()),
    'head': (frozenset({'-n', '-c', '--lines', '--bytes'}), False, frozenset()),
    'tail': (frozenset({'-n', '-c', '--lines', '--bytes', '-s', '--sleep-interval', '--pid'}), False, frozenset()),
    'ls': (frozenset({'-I', '--ignore', '-w', '--width', '-T', '--tabsize', '--hide'}), False, frozenset()),
    'sed': (frozenset({'-e', '--expression', '-f', '--file', '-l', '--line-length'}), True,
            frozenset({'-e', '--expression', '-f', '--file'})),
    'awk': (frozenset({'-f', '--file', '-v', '--assign', '-F', '--field-separator'}), True, frozenset({'-f', '--file'})),
    'grep': (frozenset({'-e', '--regexp', '-f', '--file', '-m', '--max-count', '-A', '--after-context', '-B',
                        '--before-context', '-C', '--context', '-d', '--directories', '-D', '--devices', '--label',
                        '--include', '--exclude', '--exclude-dir', '--exclude-from'}), True,
             frozenset({'-e', '--regexp', '-f', '--file'})),
    'rg': (frozenset({'-e', '--regexp', '-f', '--file', '-g', '--glob', '--iglob', '-t', '--type', '-T', '--type-not',
                      '-m', '--max-count', '-A', '--after-context', '-B', '--before-context', '-C', '--context', '-M',
                      '--max-columns', '-j', '--threads', '--type-add', '--type-clear', '--sort', '--sortr', '-r',
                      '--replace', '-E', '--encoding', '-d', '--max-depth', '--max-filesize', '--colors', '--pre',
                      '--pre-glob', '--engine', '--path-separator', '--context-separator', '--ignore-file'}), True,
           frozenset({'-e', '--regexp', '-f', '--file'})),
}
_NO_PATTERN_FLAGS = {'rg': frozenset({'--files', '--type-list'})}


@dataclass
class Segment:
    program: str
    paths: list[str]
    missing: list[str] = field(default_factory=list)
    reads_stdin: bool = False


@dataclass
class Inspection:
    segments: list[Segment]
    has_fallback: bool

    @property
    def missing(self) -> list[str]:
        return [path for segment in self.segments for path in segment.missing]

    @property
    def nothing_readable(self) -> bool:
        """Every path the command names is missing and nothing else could produce output."""
        named = [segment for segment in self.segments if segment.paths]
        if self.has_fallback or not named or not self.missing:
            return False
        return all(segment.paths and len(segment.missing) == len(segment.paths) or segment.reads_stdin
                   for segment in self.segments)


def _tokens(command: str) -> list[str] | None:
    if _EXPANSION.search(command) or '<<' in command or '<(' in command or '>(' in command:
        return None
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        raw = list(lexer)
    except ValueError:
        return None
    words: list[str] = []
    index = 0
    while index < len(raw):
        piece = raw[index]
        if piece in {'>', '>>', '>&', '&>'}:
            target = raw[index + 1] if index + 1 < len(raw) else ''
            if target not in _HARMLESS_TARGETS and not (piece == '>&' and target in {'1', '2'}):
                return None  # writes somewhere: not a read-only command
            if words and words[-1] in {'1', '2'}:
                words.pop()
            index += 2
            continue
        if piece and set(piece) <= set('();<>|&') and piece not in _OPERATORS:
            return None  # subshells, input redirection, background jobs: do not guess
        words.append(piece)
        index += 1
    return words


def _positional(program: str, args: list[str]) -> tuple[list[str], bool] | None:
    takes_value, has_pattern, pattern_options = _SPECS[program]
    if program == 'sed' and any(arg == '-i' or arg.startswith(('-i', '--in-place')) for arg in args):
        return None
    positional: list[str] = []
    pattern_given = False
    literal = False
    index = 0
    while index < len(args):
        arg = args[index]
        if not literal and arg == '--':
            literal = True
        elif not literal and arg.startswith('-') and arg != '-':
            name = arg.split('=', 1)[0]
            if name in pattern_options:
                pattern_given = True
            if name in _NO_PATTERN_FLAGS.get(program, ()):
                pattern_given = True
            if arg in takes_value:
                index += 1
        else:
            positional.append(arg)
        index += 1
    if has_pattern and not pattern_given and positional:
        positional = positional[1:]
    return positional, not positional


def _find_paths(args: list[str]) -> list[str]:
    paths = []
    for arg in args:
        if arg.startswith('-') or arg in {'(', '!', ','}:
            break
        paths.append(arg)
    return paths


def _exists(path: str, cwd: Path) -> bool:
    full = Path(path) if os.path.isabs(path) else cwd / path
    if _GLOB.search(path):
        return bool(_glob.glob(str(full)))
    return os.path.lexists(full)


def inspect(command: str, cwd: Path) -> Inspection | None:
    """Explicit paths of a read-only command and which of them are missing; None when unsure."""
    tokens = _tokens(command)
    if not tokens:
        return None
    segments: list[Segment] = []
    has_fallback = '||' in tokens
    current: list[str] = []
    previous = None
    for token in [*tokens, ';']:
        if token not in _OPERATORS:
            current.append(token)
            continue
        words = [word for word in current if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', word)] if current else []
        current, operator, previous = [], previous, token
        if not words:
            return None
        program = PurePosixPath(words[0]).name
        if program == 'cd' and len(words) == 2:
            cwd = Path(words[1]) if os.path.isabs(words[1]) else cwd / words[1]
            continue
        downstream = operator == '|'
        if program == 'find':
            paths = _find_paths(words[1:])
        elif program in _SPECS:
            parsed = _positional(program, words[1:])
            if parsed is None:
                return None
            paths = parsed[0]
        else:
            return None  # not a read-only command we understand
        paths = [path for path in paths if path != '-' and not path.startswith('/dev/')]
        segment = Segment(program, paths, reads_stdin=downstream and not paths)
        segment.missing = [path for path in paths if not _exists(path, cwd)]
        segments.append(segment)
    return Inspection(segments, has_fallback) if segments else None


# -- suggestions ----------------------------------------------------------------------------------

def _index(root: Path) -> list[str]:
    """Tracked files (fast even in large repositories; untracked ones come from :func:`_nearby`)."""
    try:
        proc = subprocess.run(['git', 'ls-files', '-z'], cwd=root, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [path for path in proc.stdout.decode('utf-8', 'replace').split('\0') if path]


def _nearby(root: Path, relative: PurePosixPath) -> list[str]:
    """Entries of the deepest existing directory on the missing path, tracked or not."""
    directory = relative.parent
    while str(directory) not in {'', '.'} and not (root / str(directory)).is_dir():
        directory = directory.parent
    try:
        with os.scandir(root / str(directory)) as entries:
            names = [entry.name for _, entry in zip(range(2000), entries)]
    except OSError:
        return []
    prefix = '' if str(directory) in {'', '.'} else f'{directory}/'
    return [f'{prefix}{name}' for name in names if name != '.git']


def _words(name: str) -> list[str]:
    stem = name.split('.')[0] if not name.startswith('.') else name
    return [word.lower() for word in _WORDS.findall(stem) if len(word) >= 3]


def suggestions(root: Path, missing: str, cwd: Path, files: list[str] | None = None) -> list[str]:
    """Up to five existing repository paths that the missing one most likely meant."""
    files = _index(root) if files is None else files
    full = Path(missing) if os.path.isabs(missing) else cwd / missing
    try:
        relative = PurePosixPath(Path(os.path.normpath(full)).relative_to(os.path.normpath(root)).as_posix())
    except ValueError:
        return []
    files = list(dict.fromkeys([*files, *_nearby(root, relative)]))
    name = relative.name
    parent = str(relative.parent)
    suffix = relative.suffix.lower()
    words = _words(_GLOB.sub('', name))
    tokens = [token.lower() for token in re.split(r'[*?\[\]]+', name) if token] if _GLOB.search(name) else []
    lowered = name.lower()
    directories = {path.rsplit('/', 1)[0] for path in files if '/' in path}
    for directory in list(directories):  # every ancestor is a directory too
        while '/' in directory:
            directory = directory.rsplit('/', 1)[0]
            directories.add(directory)
    candidates = []
    for path in [*files, *sorted(directories)]:
        head, _, base = path.rpartition('/')
        base_lower = base.lower()
        if (base_lower == lowered or (head or '.') == parent or any(word in base_lower for word in words)
                or (tokens and all(token in base_lower for token in tokens))):
            candidates.append((path, head or '.', base_lower))
            if len(candidates) >= MAX_CANDIDATES:
                break
    scored = []
    for path, head, base_lower in candidates:
        score = difflib.SequenceMatcher(None, lowered, base_lower).ratio()
        if words:
            score += 0.5 * sum(word in base_lower for word in words) / len(words)
        if tokens and all(token in base_lower for token in tokens):
            score += 0.5
        if head == parent:
            score += 0.2
        if base_lower == lowered:
            score += 1.0
        if suffix and base_lower.endswith(suffix):
            score += 0.1
        scored.append((score, path))
    scored.sort(key=lambda item: (-item[0], len(item[1]), item[1]))
    return [path for score, path in scored if score >= MIN_SCORE][:MAX_SUGGESTIONS]


def _message(root: Path, cwd: Path, missing: list[str], lead: str) -> str:
    files = _index(root)
    lines = [lead]
    for path in dict.fromkeys(missing):
        found = suggestions(root, path, cwd, files)
        lines.append(f'- `{path}`: ' + (', '.join(f'`{item}`' for item in found) if found else 'no similar path in this repository'))
    lines.append(LOCATE)
    return '\n'.join(lines)


def _record(root: Path, kind: str) -> None:
    path = root / STATS
    try:
        data = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
        data = data if isinstance(data, dict) else {}
        data.setdefault('since', datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        data[kind] = int(data.get(kind, 0)) + 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    except (OSError, ValueError):
        return


_CWD_KEYS = ('workdir', 'cwd', 'working_directory', 'workingDirectory', 'directory')


def command_cwd(root: Path, payload: dict, tool_input: dict) -> Path:
    """Where the shell command runs: its own directory field, else the session cwd, else the root."""
    value = next((tool_input[key] for key in _CWD_KEYS if isinstance(tool_input.get(key), str) and tool_input[key]), None)
    if value is None:
        value = payload.get('cwd') if isinstance(payload.get('cwd'), str) and payload.get('cwd') else None
    if value is None:
        return root
    path = Path(value)
    return path if path.is_absolute() else root / path


def refusal(root: Path, command: str, cwd: Path) -> str | None:
    """PreToolUse: the reason to refuse a read that can only fail, with the real paths to use."""
    found = inspect(command, cwd)
    if found is None or not found.nothing_readable:
        return None
    _record(root, 'refused')
    return _message(root, cwd, found.missing, 'Getzilla: not run, none of these paths exist (closest existing paths):')


def hint(root: Path, command: str, cwd: Path) -> str | None:
    """PostToolUse: some named paths were missing; the closest existing ones, beside the output."""
    found = inspect(command, cwd)
    if found is None or not found.missing:
        return None
    _record(root, 'hinted')
    return _message(root, cwd, found.missing, 'Getzilla: these paths do not exist (closest existing paths):')
