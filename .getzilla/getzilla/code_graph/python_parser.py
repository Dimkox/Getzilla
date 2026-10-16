"""Static Python extraction with `ast` only: nothing is imported, compiled to bytecode or executed.

Symbols (functions, async functions, classes, nested qualified names, spans), raw imports and raw
call expressions are recorded as identifier chains. Literals and bodies are never kept. A syntax
or encoding error yields an incomplete ParsedFile with a reason, never an empty success.
"""
from __future__ import annotations

import ast
import hashlib
import io
import tokenize
import warnings

from .models import GraphConfig, ParsedFile, RawCall, RawImport, Span, SymbolNode

REFLECTION = frozenset({'getattr', 'setattr', 'delattr', 'eval', 'exec', 'compile', 'globals', 'locals', 'vars'})
DYNAMIC_IMPORT = frozenset({'__import__', 'importlib.import_module', 'import_module', 'importlib.__import__'})


def _chain(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return '.'.join(reversed(parts))
    return None


def _targets(node: ast.AST) -> list[ast.AST]:
    if isinstance(node, (ast.Tuple, ast.List)):
        return [item for element in node.elts for item in _targets(element)]
    if isinstance(node, ast.Starred):
        return _targets(node.value)
    return [node]


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.scope: list[str] = []
        self.symbols: list[SymbolNode] = []
        self.imports: list[RawImport] = []
        self.calls: list[RawCall] = []
        self.module_bindings: dict[str, list[str]] = {}
        self.locals: dict[str, set[str]] = {}
        self.patched: set[tuple[str, str]] = set()
        self.gaps: list[tuple[str, int]] = []
        self.globals_in_functions: set[str] = set()

    @property
    def qual(self) -> str:
        return '.'.join(self.scope)

    def _bind(self, name: str, kind: str) -> None:
        if not self.scope:
            self.module_bindings.setdefault(name, []).append(kind)
        else:
            self.locals.setdefault(self.qual, set()).add(name)

    def _symbol(self, node: ast.AST, kind: str) -> None:
        name = node.name  # type: ignore[attr-defined]
        self._bind(name, 'class' if kind == 'class' else 'def')
        qualname = '.'.join([*self.scope, name])
        span = Span(node.lineno, node.col_offset, node.end_lineno or node.lineno, node.end_col_offset or 0)
        self.symbols.append(SymbolNode(self.path, qualname, kind, span))
        for decorator in getattr(node, 'decorator_list', []):
            self.visit(decorator)
        for default in getattr(getattr(node, 'args', None), 'defaults', []) or []:
            self.visit(default)
        for base in getattr(node, 'bases', []):
            self.visit(base)
        self.scope.append(name)
        self.locals.setdefault(self.qual, set())
        args = getattr(node, 'args', None)
        if args is not None:
            for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                if arg is not None:
                    self.locals[self.qual].add(arg.arg)
        for statement in node.body:  # type: ignore[attr-defined]
            self.visit(statement)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._symbol(node, 'function')

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._symbol(node, 'async_function')

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._symbol(node, 'class')

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit(node.body)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(RawImport(alias.name, (), 0, alias.asname, node.lineno, False))
            self._bind(alias.asname or alias.name.split('.')[0], 'import')

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        names = tuple((alias.name, alias.asname) for alias in node.names)
        self.imports.append(RawImport(node.module, names, node.level, None, node.lineno, True))
        for name, asname in names:
            if name == '*':
                self.gaps.append(('STAR_IMPORT', node.lineno))
            else:
                self._bind(asname or name, 'import')

    def visit_Global(self, node: ast.Global) -> None:
        if self.scope:
            for name in node.names:
                self.globals_in_functions.add(name)

    def _assign_target(self, target: ast.AST) -> None:
        for item in _targets(target):
            if isinstance(item, ast.Name):
                if self.scope and item.id in self.globals_in_functions:
                    self.module_bindings.setdefault(item.id, []).append('assign')
                else:
                    self._bind(item.id, 'assign')
            elif isinstance(item, ast.Attribute):
                base = _chain(item.value)
                if base is not None:
                    self.patched.add((base, item.attr))
                self.visit(item.value)
            else:
                self.visit(item)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._assign_target(target)
        self.visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._assign_target(node.target)
        if node.value is not None:
            self.visit(node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._assign_target(node.target)
        self.visit(node.value)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._assign_target(node.target)
        self.visit(node.value)

    def visit_For(self, node: ast.For) -> None:
        self._assign_target(node.target)
        self.visit(node.iter)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign_target(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self._bind(node.name, 'assign')
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._bind(target.id, 'delete')
            elif isinstance(target, ast.Attribute) and _chain(target.value):
                self.patched.add((_chain(target.value), target.attr))  # type: ignore[arg-type]

    def visit_Call(self, node: ast.Call) -> None:
        chain = _chain(node.func)
        if chain is None:
            form, expression = 'dynamic', '<expression>'
            if isinstance(node.func, ast.Call) and _chain(node.func.func) in REFLECTION:
                form, expression = 'reflection', f'{_chain(node.func.func)}(...)'
        elif chain in DYNAMIC_IMPORT:
            form, expression = 'reflection', chain
            self.gaps.append(('DYNAMIC_IMPORT', node.lineno))
        elif chain in REFLECTION:
            form, expression = 'reflection', chain
            self.gaps.append(('REFLECTION', node.lineno))
        else:
            form, expression = ('name' if '.' not in chain else 'attribute'), chain
        self.calls.append(RawCall(self.qual, form, expression, node.lineno))
        self.generic_visit(node)


def _decode(content: bytes) -> str:
    encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
    text = content.decode(encoding)
    return text[1:] if text.startswith('﻿') else text


def parse_python(path: str, content: bytes, config: GraphConfig) -> ParsedFile:
    digest = hashlib.sha256(content).hexdigest()
    if len(content) > config.max_file_bytes:
        return ParsedFile(path, digest, 'python', 'incomplete', 'FILE_OVER_GRAPH_LIMIT')
    try:
        text = _decode(content)
    except (SyntaxError, LookupError, UnicodeDecodeError):
        return ParsedFile(path, digest, 'python', 'incomplete', 'ENCODING_ERROR')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(text, filename=path, type_comments=False)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ParsedFile(path, digest, 'python', 'incomplete', 'SYNTAX_ERROR')
    visitor = _Visitor(path)
    try:
        for statement in tree.body:
            visitor.visit(statement)
    except RecursionError:
        return ParsedFile(path, digest, 'python', 'incomplete', 'NESTING_TOO_DEEP')
    return ParsedFile(path, digest, 'python', 'complete', None, tuple(visitor.symbols), tuple(visitor.imports),
                      tuple(visitor.calls), {name: tuple(kinds) for name, kinds in visitor.module_bindings.items()},
                      {scope: frozenset(names) for scope, names in visitor.locals.items()},
                      tuple(sorted(visitor.patched)), tuple(visitor.gaps))
