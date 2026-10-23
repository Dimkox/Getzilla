"""Fail-closed admission for at most fifty changed code lines."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .diff_risk import changed_paths, load_rules, matches
from .project_ingestion import _git, IngestionError

_CODE_SUFFIXES = frozenset('.py .php .js .jsx .ts .tsx .vue .svelte .html .css .scss .sass .less .go .rs .java .kt .c .h .cpp .hpp .cs .fs .rb .sh .bash .ps1 .swift .m .mm .ex .exs .erl .clj .scala .dart .lua .r .sql'.split())
_DOC_SUFFIXES = frozenset({'.md', '.rst', '.txt'})
_SENSITIVE = ('trust-ci/**', 'factory/**/migrations/**', '**/hooks/**', 'scripts/getzilla_*.py',
              'architecture/**', 'governance/**', 'schemas/**', 'contracts/**', 'packages/**',
              '**/*.lock', '**/Dockerfile*', '**/.gitmodules')
_CONTROL_NAMES = frozenset({'agents.md', 'claude.md', 'gemini.md', 'qwen.md', 'skill.md', 'makefile', '.gitignore', '.gitattributes', 'policy.json'})


def inspect_light_diff(root: Path, bases: list[str], *, risk: str, complete: bool) -> dict[str, Any]:
    result: dict[str, Any] = {'admitted': False, 'code_lines': None, 'bases': bases, 'reason': 'incomplete_inventory'}
    if not complete or not bases:
        return result
    if risk != 'low':
        return {**result, 'reason': 'risk_requires_full_lane'}
    try:
        if _git(root, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout:
            return {**result, 'reason': 'uncommitted_inventory'}
        rules = load_rules()
        sensitive = [pattern for rule in rules['rules'] for pattern in rule['paths']] + list(_SENSITIVE) + rules['trivial'].get('deny', [])
        largest = 0
        for base in bases:
            import re
            if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', base):
                return result
            _git(root, 'merge-base', '--is-ancestor', base, 'HEAD')
            changes = changed_paths(root, base, 'HEAD')
            if not changes or any(item.status not in {'A', 'M', 'D'} for item in changes):
                return {**result, 'reason': 'unsupported_status'}
            modes: dict[str, set[str]] = {}
            for ref in (base, 'HEAD'):
                for item in _git(root, 'ls-tree', '-r', '-z', ref).stdout.split(b'\0'):
                    if item:
                        meta, name = item.split(b'\t', 1)
                        modes.setdefault(name.decode('utf-8', 'strict'), set()).add(meta.split()[0].decode())
            counts = {}
            for row in _git(root, 'diff', '--numstat', '-z', '--no-renames', '--no-ext-diff', '--no-textconv', base, 'HEAD', '--').stdout.split(b'\0'):
                if row:
                    added, removed, name = row.split(b'\t', 2)
                    if not added.isdigit() or not removed.isdigit():
                        return {**result, 'reason': 'binary_or_unknown_inventory'}
                    counts[name.decode('utf-8', 'strict')] = int(added) + int(removed)
            if set(counts) != {item.path for item in changes}:
                return result
            lines = 0
            for change in changes:
                path = change.path
                suffix = Path(path).suffix.lower()
                if matches(path, sensitive) or Path(path).name.lower() in _CONTROL_NAMES:
                    return {**result, 'reason': 'sensitive_path', 'path': path}
                if not modes.get(path) or not modes[path] <= {'100644', '100755'}:
                    return {**result, 'reason': 'unsafe_file_mode', 'path': path}
                if suffix not in _CODE_SUFFIXES | _DOC_SUFFIXES:
                    return {**result, 'reason': 'unknown_file_type', 'path': path}
                documentation = suffix in _DOC_SUFFIXES and modes[path] == {'100644'}
                test = matches(path, rules['tests'])
                if not documentation and not test:
                    lines += counts[path]
            largest = max(largest, lines)
        return {**result, 'admitted': largest <= 50, 'code_lines': largest,
                'reason': 'small_diff' if largest <= 50 else 'code_line_limit_exceeded'}
    except (OSError, ValueError, RuntimeError, IngestionError):
        return result
