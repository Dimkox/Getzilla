"""Copy one optional transparency adapter with no-follow, exclusive writes."""
from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

from . import STACK_DIR, eu_ai_act, fsx
from .source_paths import path_problem

TEMPLATES = {
    'python': ('python/ai_transparency.py', 'ai_transparency.py'),
    'typescript': ('typescript/aiTransparency.ts', 'aiTransparency.ts'),
}


class ScaffoldError(ValueError):
    pass


def registry_hints(lang: str) -> dict[str, str]:
    if lang not in TEMPLATES:
        raise ScaffoldError('lang must be python or typescript')
    return {'disclosure_symbol': 'AI_DISCLOSURE',
            'marking_symbol': 'mark_generated_content' if lang == 'python' else 'markGeneratedContent',
            'publication_disclosure_symbol': 'label_published_content' if lang == 'python' else 'labelPublishedContent'}


def _template_bytes(relative: str) -> bytes:
    # STACK_DIR, not this file's parent: in a lean install this module runs from getzilla.zip.
    handles = [fsx.open_dir(STACK_DIR)]
    parts = ('templates/eu-ai-act/transparency/' + relative).split('/')
    try:
        for part in parts[:-1]:
            handles.append(fsx.open_dir_at(handles[-1], part))
        fd = fsx.open_at(handles[-1], parts[-1], os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ScaffoldError('template must be a regular file')
            content = stream.read(256 * 1024 + 1)
        if len(content) > 256 * 1024:
            raise ScaffoldError('template exceeds size limit')
        return content
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)


def scaffold(root: Path, system_id: str, lang: str) -> list[Path]:
    """The first glob must have a literal directory and own the final filename."""
    if fsx.WINDOWS or not all(call in os.supports_dir_fd for call in (os.open, os.mkdir)):
        raise ScaffoldError('scaffold requires descriptor-relative safe creation; copy templates manually on Windows')
    registry_hints(lang)
    root = Path(os.path.abspath(root))
    try:
        systems = [system for system in eu_ai_act.load_registry(root) if system.get('id') == system_id]
        if len(systems) != 1:
            raise ScaffoldError('system must name exactly one registered system')
        paths = systems[0].get('paths')
        if not isinstance(paths, list) or not paths or not isinstance(paths[0], str):
            raise ScaffoldError('system needs a paths glob')
        pattern = paths[0]
        wildcard = next((index for index, char in enumerate(pattern) if char in '*?['), -1)
        prefix = pattern[:wildcard] if wildcard >= 0 else ''
        if not prefix.endswith('/') or path_problem(prefix[:-1]):
            raise ScaffoldError('first paths glob needs an unambiguous relative directory prefix')
        if any(part in {'', '.', '..'} for part in pattern.split('/')) or '\\' in pattern:
            raise ScaffoldError('unsafe paths glob')
        template, name = TEMPLATES[lang]
        relative = prefix + name
        if path_problem(relative) or not fnmatch.fnmatchcase(relative, pattern):
            raise ScaffoldError('adapter filename does not match the declared paths glob')
        content = _template_bytes(template)
        handles = [fsx.open_dir(root)]
        try:
            for part in prefix[:-1].split('/'):
                try:
                    fsx.mkdir_at(handles[-1], part)
                except FileExistsError:
                    pass
                handles.append(fsx.open_dir_at(handles[-1], part))
            fd = fsx.open_at(handles[-1], name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
            fsx.fsync_dir(handles[-1])
        finally:
            for handle in reversed(handles):
                fsx.close_dir(handle)
        return [root / relative]
    except (OSError, ValueError) as exc:
        raise ScaffoldError(str(exc)) from exc
