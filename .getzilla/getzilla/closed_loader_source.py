"""Read actual Python source through fixed standard loaders without importing policy."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import zipimport


def module_source(module) -> bytes:
    """Read corresponding engine source through its actual closed loader; never execute it."""
    loader = getattr(module, '__loader__', None)
    if type(loader) not in {importlib.machinery.SourceFileLoader,
                            importlib.machinery.SourcelessFileLoader, zipimport.zipimporter}:
        raise ValueError('verification policy source loader is unavailable')
    try:
        filename = loader.get_filename(module.__name__)
        if filename != module.__file__:
            raise ValueError('verification policy source identity differs')
        source = filename
        if source.endswith('.pyc'):
            try:
                source = importlib.util.source_from_cache(source)
            except ValueError:
                source = source[:-1]
        if not source.endswith('.py'):
            raise ValueError('verification policy has no corresponding Python source')
        content = loader.get_data(source)
        if not isinstance(content, bytes) or not 0 < len(content) <= 4 * 1024 * 1024:
            raise ValueError('verification policy source is unavailable or excessive')
        return content
    except (AttributeError, ImportError, OSError, TypeError) as exc:
        raise ValueError('verification policy source cannot be bound') from exc

