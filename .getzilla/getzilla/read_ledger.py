"""Read before edit: which files this session has seen, so a patch never changes a file it never read.

An agent that patches a file from memory or habit edits code it has not looked at. PostToolUse records
every existing file a shell command names (generously: `cat`, `sed -n`, `nl`, `rg`, `git diff` alike)
and every file a patch wrote; PreToolUse refuses a patch that updates or deletes an existing file this
session never saw. The check runs only once the session's ledger has entries, so a harness that never
calls PostToolUse is never blocked by it. It is a nudge against blind edits, not a security control: any
command that names or prints a file counts as reading it.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
import shlex
import time
from pathlib import Path

LEDGER_DIR = '.getzilla/runtime/reads'
MAX_ENTRIES = 5000
MAX_COMMAND = 20_000
MAX_OUTPUT = 200_000
MAX_OUTPUT_WORDS = 2000
MAX_GLOB = 200
LEDGER_DAYS = 7
_OUTPUT_PATH = re.compile(r'[\w.\-/]*[/.][\w.\-/]*\w')
_OPERATORS = {'&&', '||', ';', '|', '&'}
_PATCH_TARGET = re.compile(r'^\*\*\* (Update|Delete|Add) File: (.+?)\s*$', re.MULTILINE)
_PATCH_MOVE = re.compile(r'^\*\*\* Move to: (.+?)\s*$', re.MULTILINE)


def _ledger(root: Path, session: str) -> Path | None:
    if not session or session == 'manual':
        return None
    name = hashlib.sha256(session.encode('utf-8', 'replace')).hexdigest()[:32]
    return root / LEDGER_DIR / f'{name}.json'


def _relative(root: Path, raw: str, cwd: Path) -> str | None:
    if not raw or '\0' in raw:
        return None
    path = Path(raw) if os.path.isabs(raw) else cwd / raw
    try:
        rel = Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
    except (ValueError, OSError):
        return None
    return rel.as_posix() if (root / rel).is_file() else None


def _entries(path: Path) -> list[str] | None:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    entries = data.get('seen') if isinstance(data, dict) else None
    return [item for item in entries if isinstance(item, str)] if isinstance(entries, list) else None


def seen(root: Path, session: str) -> set[str] | None:
    """Files this session saw; None when the session keeps no ledger yet."""
    path = _ledger(root, session)
    if path is None or not path.is_file():
        return None
    entries = _entries(path)
    return set(entries) if entries is not None else None


def _prune(directory: Path) -> None:
    """Drop ledgers of sessions idle for a week, so the folder does not grow forever."""
    limit = time.time() - LEDGER_DAYS * 86400
    try:
        for item in directory.glob('*.json'):
            if item.stat().st_mtime < limit:
                item.unlink()
    except OSError:
        return


def record(root: Path, session: str, paths: set[str]) -> None:
    """Add paths under a runtime lock; the newest stay when the ledger is full."""
    path = _ledger(root, session)
    if path is None or not paths:
        return
    from .state import runtime_lock
    try:
        with runtime_lock(root, 'reads'):
            new_session = not path.is_file()
            current = _entries(path) or []
            fresh = sorted(paths)
            merged = [item for item in current if item not in paths] + fresh
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f'{path.stem}.{os.getpid()}.tmp')
            tmp.write_text(json.dumps({'seen': merged[-MAX_ENTRIES:]}) + '\n', encoding='utf-8')
            os.replace(tmp, path)
        if new_session:
            _prune(path.parent)
    except (OSError, TimeoutError):
        return


def command_files(root: Path, command: str, cwd: Path) -> set[str]:
    """Every existing repository file a shell command names, as a repository-relative path.

    A `cd` moves the base for the words after it, and a glob counts the files it matches.
    """
    text = command[:MAX_COMMAND]
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=';&|')
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        words = text.split()
    found: set[str] = set()
    base = cwd
    previous = None
    for word in words:
        if previous == 'cd' and word not in _OPERATORS:
            target = Path(word) if os.path.isabs(word) else base / word
            if target.is_dir():
                base = target
        previous = word
        for part in (word, word.split('=', 1)[-1]):
            if any(char in part for char in '*?['):
                for match in glob.glob(str(part if os.path.isabs(part) else base / part))[:MAX_GLOB]:
                    rel = _relative(root, match, base)
                    if rel:
                        found.add(rel)
                continue
            rel = _relative(root, part, base)
            if rel:
                found.add(rel)
    return found


def output_files(root: Path, output: str, cwd: Path) -> set[str]:
    """Repository files a command printed (rg/grep matches, git diff headers): the agent saw them."""
    found: set[str] = set()
    words = list(dict.fromkeys(_OUTPUT_PATH.findall(output[:MAX_OUTPUT])))[:MAX_OUTPUT_WORDS]
    for word in words:
        for candidate in (word, word[2:] if word[:2] in {'a/', 'b/'} else None):
            rel = _relative(root, candidate, cwd) if candidate else None
            if rel:
                found.add(rel)
                break
    return found


def patch_targets(patch: str) -> tuple[set[str], set[str]]:
    """(paths a patch updates or deletes, paths it adds or moves to)."""
    changed, written = set(), set()
    for kind, raw in _PATCH_TARGET.findall(patch or ''):
        (written if kind == 'Add' else changed).add(raw.strip())
    written.update(raw.strip() for raw in _PATCH_MOVE.findall(patch or ''))
    return changed, written


def unread(root: Path, session: str, patch: str, cwd: Path) -> list[str]:
    """Existing files a patch would change that this session never saw (empty when not enforced)."""
    known = seen(root, session)
    if not known:
        return []
    changed, _ = patch_targets(patch)
    missing = []
    for raw in sorted(changed):
        rel = _relative(root, raw, cwd)
        if rel and rel not in known:
            missing.append(rel)
    return missing


def refusal(root: Path, session: str, patch: str, cwd: Path) -> str | None:
    missing = unread(root, session, patch, cwd)
    if not missing:
        return None
    from .path_hints import _record
    _record(root, 'edit_unread_refused')
    shown = ', '.join(f'`{path}`' for path in missing[:10])
    return (f'Getzilla: read before you change it. This session has not read {shown}. '
            f'Read the part you change (for example `sed -n 1,200p {shlex.quote(missing[0])}`), '
            'then send the same patch again.')


def observe(root: Path, session: str, tool: str, command: str | None, cwd: Path, output: str = '') -> None:
    """PostToolUse: remember what this tool call read or wrote."""
    if not isinstance(command, str) or not command:
        return
    if tool == 'apply_patch' or command.lstrip().startswith('*** Begin Patch'):
        changed, written = patch_targets(command)
        files = {rel for raw in changed | written if (rel := _relative(root, raw, cwd))}
    else:
        files = command_files(root, command, cwd) | output_files(root, output or '', cwd)
    record(root, session, files)
