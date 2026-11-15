"""Descriptive inventory of shipped context and its byte-identical adapter copies.

This preserves existing shipped installation. It is not external skill admission,
semantic approval, or an authority for running anything mentioned in the context.
"""
from __future__ import annotations

from .skill_preflight import MAX_FILE_BYTES, MAX_FILES, MAX_SKILLS, MAX_TOTAL_BYTES, canonical, digest, _path

PREFIXES = ('.agents/skills/', '.grok/skills/', '.claude/skills/', '.qwen/skills/', '.gemini/skills/')


def inspect_payload(entries) -> dict:
    seen = set()
    canonical_files = {}
    aliases = {}
    total = 0
    count = 0
    for path, content in entries:
        prefix = next((prefix for prefix in PREFIXES if path.startswith(prefix)), None)
        if prefix is None:
            continue
        short = path.removeprefix(prefix)
        _path(short)
        if path in seen or type(content) is not bytes or len(content) > MAX_FILE_BYTES:
            raise ValueError('invalid shipped skill file')
        seen.add(path)
        total += len(content)
        count += 1
        if total > MAX_TOTAL_BYTES * len(PREFIXES) or count > MAX_FILES * MAX_SKILLS:
            raise ValueError('shipped skill inventory exceeds bounds')
        if prefix == PREFIXES[0]:
            canonical_files[short] = digest(content)
        else:
            aliases[path] = (short, digest(content))
    identifiers = {path.split('/')[0] for path in canonical_files}
    if len(identifiers) > MAX_SKILLS:
        raise ValueError('shipped skill count exceeds bounds')
    for _path_name, (short, content_digest) in aliases.items():
        if canonical_files.get(short) != content_digest:
            raise ValueError('SHIPPED_SKILL_ALIAS_CONFLICT')
    return {'schema_version': 1, 'skill_count': len(identifiers), 'file_count': count,
            'input_bytes': total, 'inventory_digest': digest(canonical(canonical_files)),
            'permissions_granted': False, 'semantic_safety': 'unqualified',
            'scope': 'shipped-byte-provenance-only'}
