"""Bounded Python call resolution: exact only with enough static evidence, otherwise candidate or unresolved.

A call is `exact` when the name has a single def/class binding in the resolved scope (local file,
nested function, or an internal `from x import f` / `import x; x.f()` target) that nothing rebinds.
Rebinding, monkey patching, attribute dispatch, reflection and dynamic callees are never exact:
they become `candidate` (with the possible targets and the reason) or `unresolved`. `external`
marks builtins and modules outside the scope; nothing is invented for them.
"""
from __future__ import annotations

import builtins
from typing import Mapping, Sequence

from .models import CallEdge, GraphConfig, ParsedFile
from .python_resolver import Binding, ModuleIndex, import_bindings

BUILTINS = frozenset(dir(builtins))


def _single_def(parsed: ParsedFile, name: str) -> tuple[str | None, str | None, tuple[str, ...]]:
    """(exact symbol id, reason, candidates) for a module-level name of `parsed`."""
    kinds = parsed.module_bindings.get(name, ())
    defs = tuple(f'sym:{parsed.path}::{name}' for symbol in parsed.symbols if symbol.qualname == name)
    defs = tuple(dict.fromkeys(defs))
    if kinds and all(kind in ('def', 'class') for kind in kinds) and len(kinds) == 1 and defs:
        return defs[0], None, defs
    if defs:
        return None, 'REBOUND_NAME', defs
    if kinds and all(kind == 'import' for kind in kinds):
        return None, 'REEXPORT_NOT_FOLLOWED', ()
    if kinds:
        return None, 'VALUE_CALL', ()
    return None, 'NAME_NOT_DEFINED_IN_MODULE', ()


def resolve_python_calls(files: Sequence[ParsedFile], index: ModuleIndex, config: GraphConfig,
                         bindings: Mapping[str, Mapping[str, Binding]] | None = None) -> list[CallEdge]:
    del config  # resolution profile is fixed in this version; kept for the interface
    by_path = {parsed.path: parsed for parsed in files if parsed.status == 'complete'}
    bindings = bindings if bindings is not None else import_bindings(list(by_path.values()), index)
    patched: set[tuple[str, str]] = set()
    for parsed in by_path.values():
        for base, attr in parsed.patched:
            binding = bindings[parsed.path].get(base.split('.')[0])
            if binding is not None and binding.kind == 'module' and binding.target_file and '.' not in base:
                patched.add((binding.target_file, attr))
    edges: dict[str, CallEdge] = {}

    def in_module(target_file: str, name: str) -> tuple[str, tuple[str, ...], str | None]:
        target = by_path.get(target_file)
        if target is None:
            return 'unresolved', (), 'TARGET_NOT_PARSED'
        exact, reason, candidates = _single_def(target, name)
        if exact and (target_file, name) in patched:
            return 'candidate', candidates, 'MONKEY_PATCHED'
        if exact:
            return 'exact', (exact,), None
        return ('candidate', candidates, reason) if candidates else ('unresolved', (), reason)

    for parsed in by_path.values():
        file_bindings = bindings[parsed.path]
        kinds = {symbol.qualname: symbol.kind for symbol in parsed.symbols}
        qualnames = set(kinds)
        star = any(kind == 'STAR_IMPORT' for kind, _ in parsed.dynamic_gaps)
        for call in parsed.calls:
            caller = f'sym:{parsed.path}::{call.scope}' if call.scope else f'file:{parsed.path}'
            resolution, targets, reason = 'unresolved', (), None
            if call.form == 'reflection':
                reason = 'REFLECTION'
            elif call.form == 'dynamic':
                reason = 'DYNAMIC_CALLEE'
            else:
                parts = call.expression.split('.')
                head = parts[0]
                scopes = call.scope.split('.') if call.scope else []
                local_hit = None
                for depth in range(len(scopes), 0, -1):
                    scope = '.'.join(scopes[:depth])
                    if kinds.get(scope) == 'class' and depth != len(scopes):
                        continue  # class bodies do not enclose their methods
                    if head in parsed.scope_locals.get(scope, frozenset()):
                        local_hit = scope
                        break
                if local_hit is not None:
                    nested = f'{local_hit}.{head}'
                    if len(parts) == 1 and nested in qualnames:
                        resolution, targets = 'exact', (f'sym:{parsed.path}::{nested}',)
                    else:
                        reason = 'LOCAL_VALUE_CALL' if len(parts) == 1 else 'ATTRIBUTE_DISPATCH'
                elif head in file_bindings and parsed.module_bindings.get(head) == ('import',):
                    binding = file_bindings[head]
                    if binding.kind in ('external',):
                        resolution, reason = 'external', 'EXTERNAL_MODULE'
                    elif binding.kind == 'unresolved':
                        reason = 'IMPORT_UNRESOLVED'
                    elif binding.kind == 'symbol' and len(parts) == 1:
                        resolution, targets, reason = in_module(binding.target_file, binding.name)
                    elif binding.kind == 'module' and len(parts) >= 2:
                        module, rest = binding.module, parts[1:]
                        while len(rest) > 1 and index.lookup(f'{module}.{rest[0]}')[0]:
                            module, rest = f'{module}.{rest[0]}', rest[1:]
                        target_file = index.lookup(module)[0]
                        if len(rest) == 1 and target_file:
                            resolution, targets, reason = in_module(target_file, rest[0])
                        else:
                            reason = 'ATTRIBUTE_DISPATCH'
                    else:
                        reason = 'ATTRIBUTE_DISPATCH'
                elif head in parsed.module_bindings:
                    if len(parts) == 1:
                        exact, why, candidates = _single_def(parsed, head)
                        if exact and (parsed.path, head) in patched:
                            resolution, targets, reason = 'candidate', candidates, 'MONKEY_PATCHED'
                        elif exact:
                            resolution, targets = 'exact', (exact,)
                        elif candidates:
                            resolution, targets, reason = 'candidate', candidates, why
                        else:
                            reason = why
                    else:
                        reason = 'ATTRIBUTE_DISPATCH'
                elif star:
                    reason = 'STAR_IMPORT'
                elif head in BUILTINS:
                    resolution, reason = 'external', 'BUILTIN'
                else:
                    reason = 'UNBOUND_NAME'
            edge = CallEdge(caller, call.expression, targets, resolution, reason, call.line)
            edges.setdefault(edge.id, edge)
    return list(edges.values())
