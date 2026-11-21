"""Passive stop-annotation AST normalization for preservation controls."""
import ast


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
