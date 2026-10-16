"""Static Python import resolution against the files in scope; no module is ever loaded.

Module names come from the configured package roots. Without the namespace-package profile a
directory needs `__init__.py` to be a package. A module name provided by more than one file is
ambiguous and stays unresolved; a name with no file in scope is external unless its top-level
package is local (then it is an unresolved internal import). Dynamic imports are coverage gaps.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .models import GraphConfig, ImportEdge, ParsedFile


@dataclass(frozen=True)
class Binding:
    kind: str  # module, symbol, external, unresolved
    target_file: str | None
    module: str
    name: str | None = None


class ModuleIndex:
    def __init__(self, paths: Sequence[str], config: GraphConfig) -> None:
        self.config = config
        present = set(paths)
        self.modules: dict[str, set[str]] = {}
        self.file_module: dict[str, tuple[str, bool]] = {}  # path -> (module, is_package)
        self.blocked: dict[str, str] = {}  # module -> reason it is not importable under the profile
        self.local_tops: set[str] = set()
        roots = sorted(config.package_roots, key=len, reverse=True)
        self.scope_names: set[str] = set()  # every directory name and module stem anywhere in scope
        for path in paths:
            parts = path.split('/')
            self.scope_names.update(parts[:-1])
            if path.endswith('.py'):
                self.scope_names.add(parts[-1][:-3])
        for path in sorted(paths):
            if not path.endswith('.py'):
                continue
            for root in roots:
                prefix = '' if root in ('.', '') else root.rstrip('/') + '/'
                if not path.startswith(prefix):
                    continue
                parts = path[len(prefix):-3].split('/')
                is_package = parts[-1] == '__init__'
                module_parts = parts[:-1] if is_package else parts
                if not module_parts or not all(part.isidentifier() for part in module_parts):
                    break
                module = '.'.join(module_parts)
                self.local_tops.add(module_parts[0])
                package_dirs = module_parts[:-1] if not is_package else module_parts[:-1]
                missing = [i for i in range(len(package_dirs))
                           if f"{prefix}{'/'.join(module_parts[:i + 1])}/__init__.py" not in present]
                if missing and not config.namespace_packages:
                    self.blocked[module] = 'NAMESPACE_PACKAGE_PROFILE_DISABLED'
                    break
                self.modules.setdefault(module, set()).add(path)
                self.file_module[path] = (module, is_package)
                break

    def lookup(self, module: str) -> tuple[str | None, str | None]:
        """(file, None) when exactly one file provides the module, else (None, reason)."""
        files = self.modules.get(module)
        if files and len(files) == 1:
            return next(iter(files)), None
        if files:
            return None, 'AMBIGUOUS_MODULE'
        if module in self.blocked:
            return None, self.blocked[module]
        if self.config.namespace_packages and any(name.startswith(module + '.') for name in self.modules):
            return None, 'NAMESPACE_PACKAGE_HAS_NO_FILE'
        return None, 'NOT_IN_SCOPE'

    def is_local(self, module: str) -> bool:
        return module.split('.')[0] in self.local_tops

    def is_module(self, module: str) -> bool:
        return module in self.modules or module in self.blocked


def _classify(index: ModuleIndex, module: str) -> tuple[str | None, str, str | None]:
    target, reason = index.lookup(module)
    if target is not None:
        return target, 'internal', None
    if reason != 'NOT_IN_SCOPE':
        return None, 'unresolved', reason
    if index.is_local(module):
        return None, 'unresolved', 'INTERNAL_MODULE_NOT_FOUND'
    if module.split('.')[0] in index.scope_names:
        return None, 'unresolved', 'MODULE_NAME_IN_SCOPE_OUTSIDE_PACKAGE_ROOTS'
    return None, 'external', None


def _relative_base(index: ModuleIndex, path: str, level: int) -> list[str] | None:
    if path not in index.file_module:
        return None
    module, is_package = index.file_module[path]
    package = module.split('.') if is_package else module.split('.')[:-1]
    if level - 1 > len(package):
        return None
    return package[:len(package) - (level - 1)] if level > 1 else package


def resolve_file_imports(parsed: ParsedFile, index: ModuleIndex) -> tuple[list[ImportEdge], dict[str, Binding]]:
    edges: dict[str, ImportEdge] = {}
    bindings: dict[str, Binding] = {}

    def add(module: str, line: int) -> tuple[str | None, str]:
        target, resolution, reason = _classify(index, module)
        edge = ImportEdge(parsed.path, module, target, resolution, reason, line)
        edges.setdefault(edge.id, edge)
        return target, resolution

    for raw in parsed.imports:
        if not raw.is_from:
            target, resolution = add(raw.module, raw.line)
            if raw.asname:
                kind = 'module' if resolution == 'internal' else resolution
                bindings[raw.asname] = Binding(kind, target, raw.module)
            else:
                top = raw.module.split('.')[0]
                top_target, top_resolution, _ = _classify(index, top)
                bindings[top] = Binding('module' if top_resolution == 'internal' else top_resolution, top_target, top)
            continue
        if raw.level:
            base = _relative_base(index, parsed.path, raw.level)
            if base is None:
                edge = ImportEdge(parsed.path, '.' * raw.level + (raw.module or ''), None, 'unresolved',
                                  'RELATIVE_IMPORT_OUTSIDE_PACKAGE', raw.line)
                edges.setdefault(edge.id, edge)
                for name, asname in raw.names:
                    bindings[asname or name] = Binding('unresolved', None, edge.module, name)
                continue
            module = '.'.join([*base, *(raw.module.split('.') if raw.module else [])])
        else:
            module = raw.module or ''
        for name, asname in raw.names:
            local = asname or name
            if name == '*':
                add(module, raw.line)
                continue
            submodule = f'{module}.{name}' if module else name
            if index.is_module(submodule):
                target, resolution = add(submodule, raw.line)
                bindings[local] = Binding('module' if resolution == 'internal' else resolution, target, submodule)
            else:
                target, resolution = add(module, raw.line) if module else (None, 'unresolved')
                kind = 'symbol' if resolution == 'internal' else resolution
                bindings[local] = Binding(kind, target, module, name)
    return list(edges.values()), bindings


def resolve_python_imports(files: Sequence[ParsedFile], config: GraphConfig,
                           all_paths: Sequence[str] | None = None) -> list[ImportEdge]:
    index = ModuleIndex(all_paths if all_paths is not None else [f.path for f in files], config)
    edges = []
    for parsed in files:
        if parsed.status == 'complete':
            edges.extend(resolve_file_imports(parsed, index)[0])
    return edges


def import_bindings(files: Sequence[ParsedFile], index: ModuleIndex) -> Mapping[str, Mapping[str, Binding]]:
    return {parsed.path: resolve_file_imports(parsed, index)[1] for parsed in files if parsed.status == 'complete'}
