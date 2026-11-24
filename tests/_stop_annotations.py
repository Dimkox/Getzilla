"""Passive stop-annotation AST normalization for preservation controls."""
import ast
import hashlib
import sys


def bind_diagnostic_imports(tree):
    """Resolve the runner's direct imports to their original module attributes."""
    owners = {}
    for item in tree.body:
        if not isinstance(item, ast.ImportFrom) or item.level != 1:
            continue
        if item.module == 'verification_actions':
            for alias in item.names:
                if alias.asname == '_action_' + alias.name:
                    owners[alias.asname] = ('diagnostics', alias.name)
        if item.module == 'fsx':
            for alias in item.names:
                if alias.asname is None and alias.name in {'owned_job', 'owned_popen', 'WINDOWS', 'kill_process_tree'}:
                    owners[alias.name] = ('fsx', alias.name)

    class Normalize(ast.NodeTransformer):
        def visit_Name(self, node):
            owner = owners.get(node.id)
            if owner is not None and isinstance(node.ctx, ast.Load):
                return ast.Attribute(ast.Name(owner[0], ast.Load()), owner[1], node.ctx)
            return node

    return Normalize().visit(tree)


def project_default_descriptors(node):
    """Check the descriptor transport added in ab63340c before projecting its default."""
    assert [arg.arg for arg in node.args.kwonlyargs[-2:]] == ['inherited_fds', 'stdin_fd']
    assert [ast.unparse(arg.annotation) for arg in node.args.kwonlyargs[-2:]] == ['tuple[int, ...]', 'int | None']
    assert [ast.unparse(value) for value in node.args.kw_defaults[-2:]] == ['()', 'None']
    starts = [i for i, stmt in enumerate(node.body) if isinstance(stmt, ast.If)
              and any(isinstance(v, ast.Name) and v.id == 'inherited_fds' for v in ast.walk(stmt.test))]
    assert len(starts) == 1
    start = starts[0]
    block = ast.Module(body=node.body[start:start + 4], type_ignores=[])
    options = {'show_empty': True} if sys.version_info >= (3, 13) else {}
    checksum = hashlib.sha256(ast.dump(block, **options).encode()).hexdigest()
    assert checksum == 'ecb0715f8c22ac5877cb02009cc4b456a908eaa8778fa2c4d315f19a7fec044f'
    dispatch = [call for call in ast.walk(node) if isinstance(call, ast.Call)
                and ast.unparse(call.func) in {'fsx.owned_popen', 'owned_popen'}]
    assert len(dispatch) == 1
    options_kw = dispatch[0].keywords[-1]
    assert options_kw.arg is None and ast.unparse(options_kw.value) == 'descriptor_options'
    del dispatch[0].keywords[-1]
    del node.args.kwonlyargs[-2:], node.args.kw_defaults[-2:], node.body[start:start + 4]


def strip_stop_annotations(node):
    def pure(value):
        allowed = {'replace', 'diagnostics.StopMetadata', 'diagnostics.child_stop', 'diagnostics.retain_stop'}
        names = {'stop_metadata', 'diagnostics', 'replace', 'original_returncode', 'retained', 'exc'}
        for part in ast.walk(value):
            if isinstance(part, ast.Call) and ast.unparse(part.func) not in allowed:
                raise AssertionError('nonmetadata call')
            if isinstance(part, ast.Name) and part.id not in names:
                raise AssertionError('nonmetadata input')
            if isinstance(part, (ast.NamedExpr, ast.Lambda, ast.Yield, ast.Await)):
                raise AssertionError('nonmetadata control')
    class Remove(ast.NodeTransformer):
        def visit_Assign(self, item):
            if len(item.targets) == 1 and ast.unparse(item.targets[0]) in {'stop_metadata', "retained['stop_metadata']"}:
                pure(item.value)
                return None
            return self.generic_visit(item)
        def visit_Expr(self, item):
            if isinstance(item.value, ast.Call) and ast.unparse(item.value.func) == 'diagnostics.retain_stop':
                pure(item.value)
                return None
            return self.generic_visit(item)
        def visit_Call(self, item):
            if isinstance(item.func, ast.Name) and item.func.id == 'ProcessResult':
                for keyword in item.keywords:
                    if keyword.arg == 'stop_metadata':
                        pure(keyword.value)
                item.keywords = [k for k in item.keywords if k.arg != 'stop_metadata']
                if len(item.args) == 9 and isinstance(item.args[-1], ast.Name) and item.args[-1].id == 'stop_metadata':
                    item.args.pop()
            return self.generic_visit(item)
    return Remove().visit(node)


def default_cleanup_contract(node):
    """Project only the exact approved optional grace API onto its old default."""
    import copy
    node = copy.deepcopy(node)
    field = {'_stop': 'grace_seconds', 'execute': 'termination_grace'}.get(node.name)
    if field is None:
        return node
    if node.name == 'execute':
        project_default_descriptors(node)
    assert node.args.kwonlyargs[-1].arg == field
    assert ast.dump(node.args.kw_defaults[-1]) == 'Constant(value=None)'
    assert ast.unparse(node.args.kwonlyargs[-1].annotation) == 'float | None'
    node.args.kwonlyargs.pop()
    node.args.kw_defaults.pop()
    if node.name == '_stop':
        values = [item for item in ast.walk(node) if isinstance(item, ast.IfExp)]
        assert len(values) == 1
        value = values[0]
        assert ast.unparse(value) == '_TERM_GRACE if grace_seconds is None else grace_seconds'
        class Default(ast.NodeTransformer):
            def visit_IfExp(self, item):
                assert item is value
                return ast.Name(id='_TERM_GRACE', ctx=ast.Load())
        return Default().visit(node)
    validation = ast.parse("if termination_grace is not None and not 0 < termination_grace <= 180:\n raise RunnerError('termination grace must be bounded by 180 seconds')").body[0]
    dispatch = ast.parse('def stop(process):\n if termination_grace is None:\n  _stop(process)\n else:\n  _stop(process, grace_seconds=termination_grace)').body[0]
    matches = [item for item in node.body if ast.dump(item) == ast.dump(validation)]
    wrappers = [item for item in node.body if isinstance(item, ast.FunctionDef) and item.name == 'stop']
    assert len(matches) == len(wrappers) == 1 and ast.dump(wrappers[0]) == ast.dump(dispatch)
    node.body = [item for item in node.body if item is not matches[0] and item is not wrappers[0]]
    calls = [item for item in ast.walk(node) if isinstance(item, ast.Name) and item.id == 'stop']
    assert len(calls) == 2
    for item in calls:
        item.id = '_stop'
    return node
