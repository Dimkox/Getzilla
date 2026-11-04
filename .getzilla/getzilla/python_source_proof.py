"""Shared conservative prerequisites for source-only AST shortcuts."""
from __future__ import annotations

import ast
import keyword
from typing import AbstractSet, NamedTuple


class Binding(NamedTuple):
    name: str
    node: ast.AST


_REFLECTIVE = {'__dict__', '__builtins__', '__class__', '__bases__', '__mro__', '__globals__',
              '__closure__', '__code__', '__func__', '__getattribute__', '__setattr__', '__delattr__',
              '__import__', 'import_module', 'modules'}
_NAMESPACE_FUNCTIONS = {'globals', 'locals', 'vars', 'exec', 'eval', 'setattr', 'delattr', '__import__', '__builtins__'}
_NAMESPACE_FUNCTIONS |= {name for name in _REFLECTIVE if name.startswith('__')}


def binding_owner(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.AST | None:
    """Find a binding's lexical owner, including PEP 572 comprehension writes.

    Comprehension iteration targets are local, but a NamedExpr target skips
    enclosing comprehensions. A lambda still starts an independent scope.
    """
    named_expression = isinstance(parents.get(node), ast.NamedExpr)
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return node
        if not named_expression and isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            return node
    return None


def literal_import_reads(tree: ast.AST, *, forbidden_imports: AbstractSet[str] = frozenset()
                         ) -> dict[ast.Attribute, tuple[str, str]]:
    """Recognize only an unshadowed, literal, immediate from-import equivalent.

    Recognition is syntax proof, not provenance proof. Consumers must resolve
    each returned module/member through their normal bounded import resolver.
    """
    candidates = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                  and isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Call)
                  and isinstance(node.value.func, ast.Name) and node.value.func.id == '__import__']
    if not candidates or any(event.name == '__import__' for event in binding_events(tree)):
        return {}
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    capabilities = {'builtins', '__builtin__', 'sys', 'importlib', 'queue', 'threading',
                    'unittest', 'mock', 'pytest', '_pytest'} | set(forbidden_imports)
    reads = {}
    for member in candidates:
        call = member.value
        if (not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != '__import__'
                or len(call.args) != 1 or not isinstance(call.args[0], ast.Constant)
                or not isinstance(call.args[0].value, str)):
            continue
        module = call.args[0].value.split('.')
        if not all(part.isidentifier() and not keyword.iskeyword(part) for part in module) or module[0] in capabilities:
            continue
        keywords = {item.arg: item.value for item in call.keywords}
        if (len(keywords) != len(call.keywords) or not {'fromlist'} <= keywords.keys()
                or keywords.keys() - {'fromlist', 'level'}):
            continue
        level = keywords.get('level', ast.Constant(value=0))
        members = keywords['fromlist']
        if (not isinstance(level, ast.Constant) or type(level.value) is not int or level.value != 0
                or not isinstance(members, (ast.List, ast.Tuple)) or len(members.elts) != 1
                or not isinstance(members.elts[0], ast.Constant) or not isinstance(members.elts[0].value, str)
                or not member.attr.isidentifier() or member.attr.startswith('__')
                or member.attr in _REFLECTIVE | _NAMESPACE_FUNCTIONS
                or members.elts[0].value != member.attr
                or isinstance(parents.get(member), (ast.Attribute, ast.Subscript))):
            continue
        reads[member] = (call.args[0].value, member.attr)
    return reads


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


def namespace_is_closed(tree: ast.AST, *, allow_instrumentation: bool = False,
                        static_import_reads: bool = False, forbidden_imports: AbstractSet[str] = frozenset()) -> bool:
    """Refuse declared namespace/reflection capabilities, without alias inference.

    Ordinary mock imports are compatible with member demands, but IPC projection
    admits no instrumentation. This does not constrain hidden external effects.
    """
    bound = {event.name for event in binding_events(tree)}
    if '__builtins__' in bound:
        return False
    roots = {'builtins', '__builtin__'}
    if not allow_instrumentation:
        roots |= {'unittest', 'mock', 'pytest', '_pytest'}
    reflective = _REFLECTIVE
    functions = _NAMESPACE_FUNCTIONS
    permitted_importers = None

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
            if node.id == '__import__' and static_import_reads:
                if permitted_importers is None:
                    permitted_importers = {member.value.func for member in literal_import_reads(tree, forbidden_imports=forbidden_imports)}
                if node in permitted_importers:
                    continue
            return False
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and (
                node.value in reflective or node.value.startswith(('builtins.', '__builtin__.', '__builtins__.'))):
            return False
    return True
