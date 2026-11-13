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

