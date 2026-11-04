"""Shared conservative prerequisites for source-only AST shortcuts."""
from __future__ import annotations

import ast
from typing import NamedTuple


class Binding(NamedTuple):
    name: str
    node: ast.AST


def binding_events(tree: ast.AST) -> tuple[Binding, ...]:
    """Enumerate lexical bindings, including names stored in AST string fields.

    Events retain their syntax node so callers can check lexical scope and
    distinguish one permitted import/assignment from subsequent rebinding.
    """
    events = []
    type_parameters = tuple(getattr(ast, name) for name in ('TypeVar', 'ParamSpec', 'TypeVarTuple')
                            if hasattr(ast, name))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            events.append(Binding(node.id, node))
        elif isinstance(node, ast.arg):
            events.append(Binding(node.arg, node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            events.append(Binding(node.name, node))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)
                events.append(Binding(name, node))
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            events.append(Binding(node.name, node))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            events.append(Binding(node.rest, node))
        elif type_parameters and isinstance(node, type_parameters):
            events.append(Binding(node.name, node))
    return tuple(events)


def namespace_is_closed(tree: ast.AST, *, allow_instrumentation: bool = False) -> bool:
    """Refuse declared namespace/reflection capabilities, without alias inference.

    Ordinary mock imports are compatible with member demands, but IPC projection
    admits no instrumentation. This does not constrain hidden external effects.
    """
    if any(event.name == '__builtins__' for event in binding_events(tree)):
        return False
    roots = {'builtins', '__builtin__'}
    if not allow_instrumentation:
        roots |= {'unittest', 'mock', 'pytest', '_pytest'}
    reflective = {'__dict__', '__builtins__', '__class__', '__bases__', '__mro__', '__globals__',
                  '__closure__', '__code__', '__func__', '__getattribute__', '__setattr__', '__delattr__',
                  '__import__', 'import_module', 'modules'}
    functions = {'globals', 'locals', 'vars', 'exec', 'eval', 'setattr', 'delattr', '__import__', '__builtins__'}
    functions |= {name for name in reflective if name.startswith('__')}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.split('.')[0] in roots for alias in node.names):
            return False
        if isinstance(node, ast.ImportFrom) and (
                (node.module or '').split('.')[0] in roots
                or any(alias.name == '*' or alias.name in reflective or alias.name in functions for alias in node.names)):
            return False
        if isinstance(node, ast.Attribute) and (node.attr in reflective or (
                node.attr in {'type', 'bytes', 'len', 'OSError', 'getattr'} and isinstance(node.ctx, (ast.Store, ast.Del)))):
            return False
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in functions:
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                node.value in reflective or node.value.startswith(('builtins.', '__builtin__.', '__builtins__.'))):
            return False
    return True
