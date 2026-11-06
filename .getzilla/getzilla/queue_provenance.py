from __future__ import annotations

import ast
import copy
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import AbstractSet, Literal, NamedTuple, TypeAlias

from .python_source_proof import binding_events, binding_owner, namespace_is_closed

LiteralKey: TypeAlias = tuple[str, object]
QueueState = Literal[
    "non_queue",
    "queue",
    "unknown_queue",
    "sequence",
    "mapping",
    "object",
]

_QUEUE_IMPORTS = {
    "celery",
    "confluent_kafka",
    "kafka",
    "kombu",
    "pika",
    "queue",
    "redis",
    "rq",
}

_CONTAINER_MUTATORS = {
    "add",
    "clear",
    "difference_update",
    "discard",
    "insert",
    "intersection_update",
    "pop",
    "popitem",
    "remove",
    "reverse",
    "setdefault",
    "sort",
    "symmetric_difference_update",
    "union_update",
    "update",
}
MAX_DOTTED_IMPORT_DEPTH = 256


def stdlib_exception_projection(tree: ast.AST, *, complete_module: bool = False) -> ast.AST:
    """Classify only stable stdlib Empty/Full exception uses as non-queue.

    Repository callers must first rule out a local queue module. Escapes,
    rebinding, reflection and unknown mock replacement keep ordinary policy.
    Visible selectors/addresses need canonical-use proof; this does not prove
    hidden effects of ordinary helpers.
    Special module-prefix proof requires complete source syntax; synthetic
    consumers leave complete_module false and retain ordinary governance.
    This projection never executes imports or modifies the caller's AST.
    """
    nodes = list(ast.walk(tree))
    imports = [node for node in nodes if isinstance(node, ast.ImportFrom)
               and not node.level and node.module == 'queue'
               and any(alias.name in {'Empty', 'Full'} for alias in node.names)]
    if not imports or not namespace_is_closed(tree, allow_instrumentation=True):
        return tree
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    bindings = binding_events(tree)
    counts = Counter(event.name for event in bindings)
    loads = {}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            loads.setdefault(node.id, []).append(node)
    patch_names = set()
    instrumentation_roots = set()
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module == 'unittest.mock':
            # Only this absolute capability has the member-mutation proof below.
            # Other instrumentation imports can expose the same mutation power.
            if node.level or any(alias.name != 'patch' for alias in node.names):
                return tree
            patch_names.update(alias.asname or alias.name for alias in node.names if alias.name == 'patch')
        elif isinstance(node, ast.ImportFrom) and node.module == 'unittest' and not node.level:
            patch_names.update((alias.asname or alias.name) + '.patch' for alias in node.names if alias.name == 'mock')
        elif isinstance(node, ast.Import):
            patch_names.update((alias.asname or alias.name) + '.patch' for alias in node.names if alias.name == 'unittest.mock')
            patch_names.update((alias.asname or alias.name) + '.mock.patch' for alias in node.names if alias.name == 'unittest')
            instrumentation_roots.update(alias.asname or alias.name.split('.')[0] for alias in node.names
                                         if alias.name in {'unittest', 'unittest.mock'})
    if any(counts[name.split('.')[0]] != 1 for name in patch_names):
        return tree

    def dotted(node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
            if len(parts) > MAX_DOTTED_IMPORT_DEPTH:
                return None
        return '.'.join((node.id, *reversed(parts))) if isinstance(node, ast.Name) else ''

    multiple_patches = {p + '.multiple' for p in patch_names}
    patch_calls = patch_names | multiple_patches
    object_patches = {p + '.object' for p in patch_names}
    mock_namespaces = {p.rsplit('.', 1)[0] for p in patch_names if '.' in p}
    exception_names = {alias.asname or alias.name for node in imports for alias in node.names
                       if alias.name in {'Empty', 'Full'}}
    module_name = '__name__'
    prefix_loads = {
        id(node.args[0].left)
        for node in nodes if isinstance(node, ast.Call) and dotted(node.func) in patch_calls
        and node.args and isinstance(node.args[0], ast.BinOp) and isinstance(node.args[0].op, ast.Add)
        and isinstance(node.args[0].left, ast.Name) and node.args[0].left.id == module_name
    }
    if prefix_loads and (not complete_module or not isinstance(tree, ast.Module)):
        # A flattened body/export slice cannot supply its lost scope provenance.
        return tree
    owners = {id(event.node): binding_owner(event.node, parents) for event in bindings} if prefix_loads else {}
    local_bindings = {owners[id(event.node)] for event in bindings if event.name == module_name} if prefix_loads else set()
    declarations = {binding_owner(node, parents) for node in nodes
                    if isinstance(node, (ast.Global, ast.Nonlocal)) and module_name in node.names} if prefix_loads else set()
    global_writes = {binding_owner(node, parents) for node in nodes
                     if isinstance(node, ast.Global) and module_name in node.names} if prefix_loads else set()
    if prefix_loads and any(event.name == module_name and
                            (owners[id(event.node)] is None or owners[id(event.node)] in global_writes)
                            for event in bindings):
        return tree

    def module_origin(reference):
        """True for implicit module lookup, False for local, None if unresolved.

        binding_owner indexes declarations; it does not resolve runtime loads.
        Function bodies skip class namespaces, but their headers do not.
        """
        current, function_body = reference, False
        type_scopes = tuple(getattr(ast, name) for name in ('TypeAlias', 'TypeVar', 'ParamSpec', 'TypeVarTuple')
                            if hasattr(ast, name))
        for _ in range(MAX_DOTTED_IMPORT_DEPTH):
            owner = parents.get(current)
            if owner is None:
                return None
            if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                in_body = current is owner.body if isinstance(owner, ast.Lambda) else current in owner.body
                if not in_body or owner in declarations:
                    return None
                if owner in local_bindings:
                    return False
                function_body = True
            elif isinstance(owner, ast.ClassDef):
                if not function_body or current not in owner.body:
                    return None
            elif isinstance(owner, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp, *type_scopes)):
                return None
            elif owner is tree:
                return True
            current = owner
        return None

    if prefix_loads and any(module_origin(node) is not True for node in nodes if id(node) in prefix_loads):
        return tree
    address_names = {}
    for node in imports:
        for alias in node.names:
            if alias.name in {'Empty', 'Full'}:
                local = alias.asname or alias.name
                address_names.setdefault(local, set()).add(local)
                address_names.setdefault(alias.name, set()).add(local)
    if prefix_loads:
        # This is a dependency of prefix normalization, not a name blacklist.
        # The same address and mutation proof must also protect that binding.
        address_names[module_name] = {module_name}
    approved_literals = set()

    # Match pkgutil.resolve_name's positive grammar, without resolving anything.
    # Its '$' also permits a terminal newline in the container passed by patch.
    word = r'(?!\d)\w+'
    path = rf'{word}(?:\.{word})*'
    resolver_pattern = re.compile(rf'^(?P<pkg>{path})(?P<colon>:(?P<obj>{path})?)?$')

    def address_proof(address):
        """Return known operand forms/bindings, or explicit UNKNOWN (None).

        A failed parse is never proof that an address is unrelated. Keep any
        proved container bindings even when its final member is unclassified.
        """
        if address.count('.') + address.count(':') + 1 > MAX_DOTTED_IMPORT_DEPTH:
            return None, set()

        def resolver(value):
            match = resolver_pattern.match(value)
            if match is None:
                return None
            parts = match['pkg'].split('.') + (match['obj'] or '').split('.')
            return set().union(*(address_names.get(part, ()) for part in parts))

        def absolute(value):
            forms, bindings = set(), set()
            if value.count('.') + value.count(':') + 1 > MAX_DOTTED_IMPORT_DEPTH:
                return forms, bindings
            resolved = resolver(value)
            if resolved is not None:
                forms.add('resolver')
                bindings.update(resolved)
                if ':' not in value and resolver_pattern.fullmatch(value):
                    forms.add('member')
            if '.' in value:
                container, member = value.rsplit('.', 1)
                owner = resolver(container)
                if owner is not None:
                    bindings.update(owner)
                    if member.isidentifier():
                        forms.add('target')
                        bindings.update(address_names.get(member, ()))
            return forms, bindings

        forms, bindings = absolute(address)
        # Literal suffixes can carry __name__ addresses through opaque helpers;
        # they are not absolute canonical targets or member names themselves.
        if address.startswith(('.', ':')):
            suffix_forms, suffix_bindings = absolute('__getzilla_current_module__' + address)
            if suffix_forms:
                forms.add('suffix')
            bindings.update(suffix_bindings)
        return frozenset(forms) if forms else None, bindings

    replaced = set()
    canonical_calls = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in instrumentation_roots:
            owner = parents.get(node)
            if not isinstance(owner, ast.Attribute) or owner.value is not node:
                return tree
        if isinstance(node, (ast.Name, ast.Attribute)) and dotted(node) in mock_namespaces:
            owner = parents.get(node)
            if not isinstance(owner, ast.Attribute) or owner.value is not node or owner.attr != 'patch':
                # A getter, alias or opaque consumer may recover mock.patch.
                return tree
        if isinstance(node, (ast.Name, ast.Attribute)) and dotted(node) in patch_names:
            owner = parents.get(node)
            if isinstance(owner, ast.Call) and owner.func is node:
                pass
            elif (isinstance(owner, ast.Attribute) and owner.value is node
                  and owner.attr in {'object', 'multiple'}
                  and isinstance(parents.get(owner), ast.Call) and parents[owner].func is owner):
                pass
            else:
                return tree
        if not isinstance(node, ast.Call):
            continue
        function = dotted(node.func)
        if function is None:
            return tree
        if function in object_patches:
            member = node.args[1] if len(node.args) > 1 else None
            if not isinstance(member, ast.Constant) or type(member.value) is not str:
                return tree
            forms, bindings = address_proof(member.value)
            if forms is None or 'member' not in forms:
                return tree
            replaced.add(member.value)
            replaced.update(bindings)
            approved_literals.add(id(member))
        elif function in patch_calls:
            target = node.args[0] if node.args else None
            prefix = ''
            if (isinstance(target, ast.BinOp) and isinstance(target.op, ast.Add)
                    and isinstance(target.left, ast.Name) and target.left.id == '__name__'):
                target = target.right
                prefix = '__getzilla_current_module__'
            if not isinstance(target, ast.Constant) or type(target.value) is not str:
                return tree
            if prefix and not target.value.startswith(('.', ':')):
                return tree
            forms, bindings = address_proof(prefix + target.value)
            required = 'resolver' if function in multiple_patches else 'target'
            if forms is None or required not in forms:
                return tree
            replaced.add(target.value.rsplit('.', 1)[-1])
            replaced.update(bindings)
            approved_literals.add(id(target))
        else:
            continue
        canonical_calls.add(id(node))
        for keyword in node.keywords:
            if keyword.arg is not None:
                if function in multiple_patches:
                    forms, bindings = address_proof(keyword.arg)
                    if forms is None or 'member' not in forms:
                        return tree
                    replaced.add(keyword.arg)
                    replaced.update(bindings)
                continue
            mapping = keyword.value
            if not isinstance(mapping, ast.Dict):
                return tree
            for key in mapping.keys:
                if not isinstance(key, ast.Constant) or type(key.value) is not str:
                    return tree
                if function in multiple_patches:
                    forms, bindings = address_proof(key.value)
                    if forms is None or 'member' not in forms:
                        return tree
                    replaced.add(key.value)
                    replaced.update(bindings)
                    approved_literals.add(id(key))

    canonical_operands = set()
    pending = [(tree, False)]
    while pending:
        node, inside = pending.pop()
        inside = inside or id(node) in canonical_calls
        if inside:
            canonical_operands.add(id(node))
        pending.extend((child, inside) for child in ast.iter_child_nodes(node))

    if prefix_loads:
        if module_name in replaced or any(isinstance(node, ast.Attribute) and node.attr == module_name
                                         and isinstance(node.ctx, (ast.Store, ast.Del)) for node in nodes):
            return tree
        for reference in loads.get(module_name, ()):
            if id(reference) in prefix_loads:
                continue
            origin = module_origin(reference)
            if origin is False:
                # An unrelated local gets no special-binding trust here.
                continue
            owner = parents.get(reference)
            literal_compare = False
            if (isinstance(owner, ast.Compare) and len(owner.ops) == len(owner.comparators) == 1
                    and isinstance(owner.ops[0], (ast.Eq, ast.NotEq))):
                other = owner.comparators[0] if owner.left is reference else owner.left
                literal_compare = ((owner.left is reference or owner.comparators[0] is reference)
                                   and isinstance(other, ast.Constant) and type(other.value) is str)
            passive = isinstance(owner, ast.Expr) or literal_compare
            message = (isinstance(owner, ast.Call) and reference in owner.args
                       and isinstance(owner.func, ast.Name) and owner.func.id in exception_names
                       and isinstance(parents.get(owner), ast.Raise) and parents[owner].exc is owner)
            if origin is not True or not (passive or message):
                return tree

    for node in nodes:
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id in exception_names
                and isinstance(parents.get(node), ast.Raise) and parents[node].exc is node):
            # Literal positional messages stay data, not callback operands.
            approved_literals.update(id(value) for value in node.args if isinstance(value, ast.Constant))
    canonical_roots = {name.split('.')[0] for name in patch_names}
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == 'getattr':
            call = parents.get(node)
            if not isinstance(call, ast.Call) or call.func is not node:
                return tree
            use = parents.get(call)
            # Comparison/discard does not transfer the result. Arguments,
            # callable recovery and other escapes need stronger proof.
            immediate_value = isinstance(use, (ast.Compare, ast.Expr))
            if not immediate_value:
                return tree
        bare_literal = isinstance(parents.get(node), ast.Expr) and parents[node].value is node
        unproved_selector = (
            isinstance(node, ast.Attribute) and node.attr == 'patch' and dotted(node) not in patch_names
            or isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == 'patch'
            and node.id not in canonical_roots | exception_names
            or isinstance(node, ast.ImportFrom) and any(alias.name == 'patch' for alias in node.names)
            and (node.level or node.module != 'unittest.mock')
            or isinstance(node, ast.Constant) and node.value == 'patch'
            and id(node) not in approved_literals and not bare_literal
        )
        if unproved_selector:
            return tree
        if isinstance(node, ast.Attribute):
            path = dotted(node)
            if path is None:
                return tree
            if path:
                forms, bindings = address_proof(path)
                if forms is None or bindings:
                    return tree
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in approved_literals and not bare_literal:
                forms, bindings = address_proof(node.value)
                over_limit = node.value.count('.') + node.value.count(':') + 1 > MAX_DOTTED_IMPORT_DEPTH
                if bindings or (forms is None and (id(node) in canonical_operands or over_limit)):
                    return tree
        if isinstance(node, ast.keyword) and node.arg in address_names:
            return tree

    selected = set()
    for node in imports:
        for alias in node.names:
            name = alias.asname or alias.name
            if alias.name not in {'Empty', 'Full'} or counts[name] != 1 or name in replaced:
                continue
            for reference in loads.get(name, ()):
                use = reference
                while isinstance(parents.get(use), ast.Tuple):
                    use = parents[use]
                owner = parents.get(use)
                if isinstance(owner, ast.ExceptHandler) and owner.type is use:
                    continue
                if isinstance(owner, ast.Raise) and owner.exc is use:
                    continue
                if (isinstance(owner, ast.Call) and owner.func is reference
                        and isinstance(parents.get(owner), ast.Raise) and parents[owner].exc is owner):
                    continue
                break
            else:
                selected.add(id(alias))
    if not selected:
        return tree
    memo = {}
    projected = copy.deepcopy(tree, memo)
    selected = {id(memo[identity]) for identity in selected}

    class Project(ast.NodeTransformer):
        def visit_ImportFrom(self, node):
            node.names = [alias for alias in node.names if id(alias) not in selected]
            return node if node.names else ast.copy_location(ast.Pass(), node)

    return Project().visit(projected)


def local_byte_channel_projection(tree: ast.AST) -> ast.AST:
    """Remove only proven bounded, non-escaping stdlib byte-channel operations.

    This is a source projection, not a path exception. Unknown constructors,
    payloads, capacities, aliases, closures and operations retain queue policy.
    Arguments stay in the tree so nested external dispatch is still analysed.
    Repository-aware callers must first rule out a local ``queue`` module.
    """
    imports = [node for node in getattr(tree, 'body', ())
               if isinstance(node, ast.ImportFrom) and node.module == 'queue' and not node.level]
    if len(imports) != 1 or any(item.name not in {'Queue', 'Empty', 'Full'} for item in imports[0].names):
        return tree
    factories = {item.asname or item.name for item in imports[0].names if item.name == 'Queue'}
    if not factories:
        return tree
    nodes = list(ast.walk(tree))
    if len(nodes) > 16384:
        return tree
    if not namespace_is_closed(tree):
        return tree
    parents = {child: node for node in nodes for child in ast.iter_child_nodes(node)}
    module_roots = {item.asname or item.name for node in nodes if isinstance(node, ast.Import)
                    for item in node.names if item.name in {'queue', 'threading', 'builtins'}}
    for node in nodes:
        if not isinstance(node, ast.Name) or node.id not in module_roots or not isinstance(node.ctx, ast.Load):
            continue
        access = parents.get(node)
        if not isinstance(access, ast.Attribute):
            return tree
        while isinstance(parents.get(access), ast.Attribute):
            access = parents[access]
        if (not isinstance(access.ctx, ast.Load) or not isinstance(parents.get(access), ast.Call)
                or parents[access].func is not access):
            return tree
    bindings = binding_events(tree)
    counts = Counter(event.name for event in bindings)
    rebound = {event.name for event in bindings if not isinstance(event.node, (ast.Import, ast.ImportFrom))}
    imported = []
    for node in nodes:
        if isinstance(node, ast.Import):
            imported.extend(item.asname or item.name.split('.')[0] for item in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.extend(item.asname or item.name for item in node.names)
    rebound.update(name for name in imported if imported.count(name) != 1)
    if factories & rebound or any(counts[name] != 1 for name in factories):
        return tree
    constants = {target.id: node.value for node in getattr(tree, 'body', ()) if isinstance(node, ast.Assign)
                 for target in node.targets if isinstance(target, ast.Name)}
    constants = {name: value for name, value in constants.items()
                 if counts[name] == 1}
    guard_builtins = {'type', 'bytes', 'len', 'OSError'}
    guards_unshadowed = not (guard_builtins & (rebound | set(imported)))

    def positive(node):
        if isinstance(node, ast.Name):
            node = constants.get(node.id)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float) and 0 < node.value <= 1048576:
            return node.value
        return None

    def enclosing(node):
        while node in parents:
            node = parents[node]
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                 ast.Lambda, ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
                return node
        return None

    def stable_assignment(reference):
        """Resolve one lexical assignment; unknown or replaced bytes stay governed."""
        current = enclosing(reference)
        while current is not None:
            local = [event.node for event in bindings if event.name == reference.id and binding_owner(event.node, parents) is current]
            if local:
                assignment = parents.get(local[0])
                return assignment.value if (len(local) == 1 and isinstance(local[0], ast.Name)
                                            and isinstance(assignment, ast.Assign)
                                            and len(assignment.targets) == 1 and assignment.targets[0] is local[0]) else None
            current = enclosing(current)
        return None

    def guarded_byte_size(reference, operation):
        """Recognise only consecutive rejecting guards which dominate enqueue.

        The producer is opaque. Only the exact immutable byte value admitted to
        this local channel is bounded; no producer allocation bound is inferred.
        """
        if not guards_unshadowed:
            return None
        value = stable_assignment(reference)
        assignment = parents.get(value)
        if not isinstance(assignment, ast.Assign):
            return None
        block = parents.get(assignment)
        statements = next((items for _field, items in ast.iter_fields(block)
                           if isinstance(items, list) and assignment in items), ()) if block is not None else ()
        index = statements.index(assignment) if assignment in statements else -1
        if index < 0 or index + 2 >= len(statements):
            return None
        type_guard, size_guard = statements[index + 1:index + 3]

        def rejects(statement):
            if not isinstance(statement, ast.If) or statement.orelse or len(statement.body) != 1:
                return False
            refusal = statement.body[0]
            error = refusal.exc if isinstance(refusal, ast.Raise) and refusal.cause is None else None
            return (isinstance(error, ast.Call) and isinstance(error.func, ast.Name) and error.func.id == 'OSError'
                    and len(error.args) == 1 and not error.keywords
                    and isinstance(error.args[0], ast.Constant) and isinstance(error.args[0].value, str))

        def checks(statement, builtin, comparison):
            if not rejects(statement) or not isinstance(statement.test, ast.Compare):
                return False
            test = statement.test
            return (len(test.ops) == len(test.comparators) == 1 and isinstance(test.ops[0], comparison)
                    and isinstance(test.left, ast.Call) and isinstance(test.left.func, ast.Name)
                    and test.left.func.id == builtin and not test.left.keywords and len(test.left.args) == 1
                    and isinstance(test.left.args[0], ast.Name) and test.left.args[0].id == reference.id)

        if (not checks(type_guard, 'type', ast.IsNot)
                or not isinstance(type_guard.test.comparators[0], ast.Name)
                or type_guard.test.comparators[0].id != 'bytes'
                or not checks(size_guard, 'len', ast.Gt)):
            return None
        size = positive(size_guard.test.comparators[0])
        if type(size) is not int:
            return None
        if any(isinstance(item, (ast.Global, ast.Nonlocal)) and reference.id in item.names for item in nodes):
            return None
        admitted = operation
        while admitted in parents and parents[admitted] is not block:
            admitted = parents[admitted]
        if admitted not in statements[index + 3:]:
            return None
        return size

    constructors, calls = set(), set()
    for node in nodes:
        if not isinstance(node, ast.Name) or node.id not in factories or not isinstance(node.ctx, ast.Load):
            continue
        call = parents.get(node)
        if (isinstance(call, ast.Subscript) and call.value is node
                and isinstance(parents.get(call), ast.AnnAssign) and parents[call].annotation is call):
            continue
        assignment = parents.get(call)
        if (not isinstance(call, ast.Call) or call.func is not node or call.args
                or len(call.keywords) != 1 or call.keywords[0].arg != 'maxsize'
                or not isinstance(call.keywords[0].value, ast.Constant)
                or type(call.keywords[0].value.value) is not int or not 1 <= call.keywords[0].value.value <= 65536):
            return tree
        targets = assignment.targets if isinstance(assignment, ast.Assign) else (
            [assignment.target] if isinstance(assignment, ast.AnnAssign) else [])
        owner = enclosing(assignment)
        if len(targets) != 1 or not isinstance(targets[0], ast.Name) or not isinstance(owner, ast.FunctionDef):
            return tree
        name = targets[0].id
        scope = list(ast.walk(owner))
        scope_counts = Counter(event.name for event in binding_events(owner))
        if (scope_counts[name] != 1
                or any(isinstance(item, (ast.Global, ast.Nonlocal)) and name in item.names for item in scope)
                or any(isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
                       and item.func.id in {'eval', 'exec', 'locals', 'globals', 'vars'} for item in scope)):
            return tree
        def byte_size(value, operation):
            if isinstance(value, ast.Constant) and isinstance(value.value, bytes):
                return max(1, len(value.value))
            if isinstance(value, ast.Name):
                return guarded_byte_size(value, operation)
            return None

        nested = set()
        puts = 0
        for use in scope:
            if not isinstance(use, ast.Name) or use.id != name or not isinstance(use.ctx, ast.Load):
                continue
            attribute = parents.get(use)
            operation = parents.get(attribute)
            if (not isinstance(attribute, ast.Attribute) or not isinstance(operation, ast.Call)
                    or operation.func is not attribute or attribute.attr not in {'put', 'get', 'empty', 'full', 'qsize'}):
                return tree
            if attribute.attr in {'put', 'get'}:
                if (len(operation.args) != (1 if attribute.attr == 'put' else 0)
                        or len(operation.keywords) != 1 or operation.keywords[0].arg != 'timeout'
                        or positive(operation.keywords[0].value) is None):
                    return tree
                if attribute.attr == 'put':
                    size = byte_size(operation.args[0], operation)
                    if size is None or size * call.keywords[0].value.value > 64 * 1024 * 1024:
                        return tree
                    puts += 1
            elif operation.args or operation.keywords:
                return tree
            calls.add(attribute)
            function = enclosing(use)
            while function is not owner:
                if not isinstance(function, ast.FunctionDef):
                    return tree
                nested.add(function)
                function = enclosing(function)
        if not puts:
            return tree
        # Captured channels may reach a local thread, never an exported callback.
        thread_names = {item.asname or item.name for statement in getattr(tree, 'body', ())
                        if isinstance(statement, ast.ImportFrom) and statement.module == 'threading' and not statement.level
                        for item in statement.names if item.name == 'Thread'}
        thread_names = {name for name in thread_names if counts[name] == 1 and name not in rebound}
        for item in nodes:
            if isinstance(item, ast.Name) and item.id in thread_names and isinstance(item.ctx, ast.Load):
                parent = parents.get(item)
                if not isinstance(parent, ast.Call) or parent.func is not item:
                    return tree
        for function in nested:
            if scope_counts[function.name] != 1:
                return tree
            if any(isinstance(item, (ast.Global, ast.Nonlocal)) and function.name in item.names for item in scope):
                return tree
            for use in scope:
                if not isinstance(use, ast.Name) or use.id != function.name or not isinstance(use.ctx, ast.Load):
                    continue
                parent = parents.get(use)
                if isinstance(parent, ast.Call) and parent.func is use and enclosing(use) is owner:
                    continue
                thread = parents.get(parent)
                if (isinstance(parent, ast.keyword) and parent.arg == 'target' and isinstance(thread, ast.Call)
                        and isinstance(thread.func, ast.Name) and thread.func.id in thread_names
                        and enclosing(thread) is owner):
                    allocation = parents.get(thread)
                    if (not isinstance(allocation, ast.Assign) or len(allocation.targets) != 1
                            or not isinstance(allocation.targets[0], ast.Name)):
                        return tree
                    thread_name = allocation.targets[0].id
                    if any(isinstance(item, (ast.Global, ast.Nonlocal)) and thread_name in item.names for item in scope):
                        return tree
                    if scope_counts[thread_name] != 1:
                        return tree
                    for item in scope:
                        if not isinstance(item, ast.Name) or item.id != thread_name or not isinstance(item.ctx, ast.Load):
                            continue
                        if enclosing(item) is not owner:
                            return tree
                        access = parents.get(item)
                        operation = parents.get(access)
                        if (not isinstance(access, ast.Attribute) or not isinstance(access.ctx, ast.Load)
                                or access.attr not in {'start', 'join', 'is_alive', 'ident'}):
                            return tree
                        if access.attr != 'ident' and (not isinstance(operation, ast.Call) or operation.func is not access):
                            return tree
                    continue
                return tree
        constructors.add(call)
        if len(constructors) > 32:
            return tree
    if not constructors:
        return tree
    replaced = {id(node) for node in constructors | calls}

    # The caller's AST and source inventory remain immutable.
    return _project_channel_tree(tree, imports[0], replaced)


def _project_channel_tree(tree: ast.AST, imported: ast.AST, replaced: set[int]) -> ast.AST:
    memo = {}
    result = copy.deepcopy(tree, memo)
    selected = {id(memo[value]) for value in replaced}
    selected_import = memo[id(imported)]

    class Project(ast.NodeTransformer):
        def visit_ImportFrom(self, node):
            return ast.Pass() if node is selected_import else self.generic_visit(node)

        def visit_Call(self, node):
            replace = id(node) in selected or id(node.func) in selected
            self.generic_visit(node)
            if replace:
                node.func = ast.Name(id='__getzilla_local_byte_channel', ctx=ast.Load())
            return node

    return Project().visit(result)


def literal_patch_members(tree: ast.AST) -> dict[int, tuple[str, str, ast.AST | None, bool]]:
    """Resolve only unshadowed stdlib mock.patch.object with a literal member."""
    if not namespace_is_closed(tree, allow_instrumentation=True, static_import_reads=True, forbidden_imports=_QUEUE_IMPORTS):
        return {}
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == 'unittest':
            aliases.update((alias.asname or alias.name) + '.patch.object' for alias in node.names if alias.name == 'mock')
        elif isinstance(node, ast.ImportFrom) and node.module == 'unittest.mock':
            aliases.update((alias.asname or alias.name) + '.object' for alias in node.names if alias.name == 'patch')
        elif isinstance(node, ast.Import):
            aliases.update((alias.asname or alias.name) + '.patch.object' for alias in node.names if alias.name == 'unittest.mock')
    bindings = binding_events(tree)
    counts = Counter(event.name for event in bindings)
    aliases = {name for name in aliases if counts[name.split('.')[0]] == 1}
    result = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2 or any(isinstance(arg, ast.Starred) for arg in node.args) or any(item.arg is None for item in node.keywords):
            continue
        parts = []
        value = node.func
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if not isinstance(value, ast.Name) or '.'.join((value.id, *reversed(parts))) not in aliases:
            continue
        target, member = node.args[:2]
        if not isinstance(target, ast.Name) or not isinstance(member, ast.Constant) or not isinstance(member.value, str) or not member.value.isidentifier():
            continue
        keywords = {item.arg: item.value for item in node.keywords}
        replacement = node.args[2] if len(node.args) == 3 else keywords.get('new', keywords.get('return_value', keywords.get('side_effect')))
        if len(node.args) > 3:
            continue
        result[id(node)] = (target.id, member.value, replacement, 'side_effect' in keywords)
    return result


class QueueAnalysisLimit(RuntimeError):
    """Raised when bounded queue analysis cannot safely continue."""


class AbstractValue(NamedTuple):
    state: QueueState
    entries: tuple[tuple[LiteralKey, "AbstractValue"], ...] = ()
    default: "AbstractValue | None" = None


class QueueTreeAnalysis(NamedTuple):
    signals: tuple[str, ...]
    derived_names: frozenset[str]
    uncertain: bool
    export_paths: frozenset[str] = frozenset()


@dataclass
class _AliasState:
    by_name: dict[str, int]
    groups: dict[int, set[str]]
    next_group: int = 0

    def fork(self) -> "_AliasState":
        return _AliasState(
            dict(self.by_name),
            {group: set(members) for group, members in self.groups.items()},
            self.next_group,
        )


class _Environment(NamedTuple):
    values: dict[str, AbstractValue]
    aliases: _AliasState


NON_QUEUE = AbstractValue("non_queue")
QUEUE = AbstractValue("queue")
UNKNOWN_QUEUE = AbstractValue("unknown_queue")
# Marks a sequence whose length is no longer tracked; only the element summary is kept.
# The key kind never comes from normalize_literal_key, so no subscript can select it.
_UNBOUNDED_LENGTH: LiteralKey = ("length", "unbounded")
# Loop iterations analysed exactly before growing sequences are widened to a summary.
_LOOP_WIDENING_DELAY = 2


def _entry_map(value: AbstractValue) -> dict[LiteralKey, AbstractValue]:
    return dict(value.entries)


def _structured(
    state: Literal["sequence", "mapping", "object"],
    entries: dict[LiteralKey, AbstractValue],
    default: AbstractValue = NON_QUEUE,
) -> AbstractValue:
    return AbstractValue(
        state,
        tuple(sorted(entries.items(), key=lambda item: (item[0][0], repr(item[0][1])))),
        default,
    )


def join_value(left: AbstractValue, right: AbstractValue) -> AbstractValue:
    """Return the order-independent least conservative value containing both inputs."""
    if left == right:
        return left
    if left.state == "unknown_queue" or right.state == "unknown_queue":
        return UNKNOWN_QUEUE
    if left.state in {"non_queue", "queue"} or right.state in {"non_queue", "queue"}:
        return UNKNOWN_QUEUE
    if left.state != right.state:
        return UNKNOWN_QUEUE

    left_default = left.default or NON_QUEUE
    right_default = right.default or NON_QUEUE
    default = join_value(left_default, right_default)
    left_entries = _entry_map(left)
    right_entries = _entry_map(right)
    keys = left_entries.keys() | right_entries.keys()
    entries = {
        key: join_value(
            left_entries.get(key, left_default),
            right_entries.get(key, right_default),
        )
        for key in keys
    }
    return _structured(left.state, entries, default)


def normalize_literal_key(node: ast.AST) -> LiteralKey | None:
    sign = 1
    value_node = node
    if isinstance(value_node, ast.UnaryOp) and isinstance(
        value_node.op, (ast.UAdd, ast.USub)
    ):
        sign = -1 if isinstance(value_node.op, ast.USub) else 1
        value_node = value_node.operand
    if not isinstance(value_node, ast.Constant):
        return None
    value = value_node.value
    if sign != 1:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        value *= sign
    if isinstance(value, bool):
        return "number", int(value)
    if isinstance(value, int):
        return "number", value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return ("number", int(value)) if value.is_integer() else ("number", value)
    if isinstance(value, str):
        return "string", value
    if isinstance(value, bytes):
        return "bytes", value
    if value is None:
        return "none", None
    return None


def _aggregate(value: AbstractValue) -> AbstractValue:
    if value.state not in {"sequence", "mapping", "object"}:
        return value
    values = [_aggregate(item) for _key, item in value.entries]
    if not values:
        return value.default or NON_QUEUE
    result = values[0]
    for item in values[1:]:
        result = join_value(result, item)
    if value.default not in {None, NON_QUEUE}:
        result = join_value(result, _aggregate(value.default))
    return result


def _sequence_length(value: AbstractValue) -> int | None:
    if value.state != "sequence" or value.default != NON_QUEUE:
        return None
    if any(key == _UNBOUNDED_LENGTH for key, _item in value.entries):
        return None
    indexes = sorted(
        int(key[1])
        for key, _item in value.entries
        if key[0] == "number" and isinstance(key[1], int)
    )
    return len(indexes) if indexes == list(range(len(indexes))) else None


def _unbounded_sequence(summary: AbstractValue) -> AbstractValue:
    """Return a sequence of unknown length whose every element is within ``summary``."""
    if summary == NON_QUEUE:
        return _structured("sequence", {_UNBOUNDED_LENGTH: NON_QUEUE})
    return _structured("sequence", {}, summary)


def widen_sequence(previous: AbstractValue, current: AbstractValue) -> AbstractValue:
    """Widen a sequence that gained indexes between loop iterations.

    Appending inside a loop adds one index per abstract iteration, an infinite ascending
    chain that never reaches a fixpoint. Collapsing such a sequence into an unbounded
    sequence summarised by the join of all its elements is sound: every index (and every
    unpacking or negative index, which need a known length) now answers with that summary
    or ``UNKNOWN_QUEUE``.
    """
    if previous.state != "sequence" or current.state != "sequence":
        return current
    if not set(_entry_map(current)) - set(_entry_map(previous)):
        return current
    return _unbounded_sequence(_aggregate(current))


def _select(value: AbstractValue, key: LiteralKey | None) -> AbstractValue:
    if value.state not in {"sequence", "mapping", "object"}:
        return value
    if key is None:
        return _aggregate(value)
    selected_key = key
    if value.state == "sequence" and key[0] == "number" and isinstance(key[1], int):
        index = key[1]
        if index < 0:
            length = _sequence_length(value)
            if length is None:
                return UNKNOWN_QUEUE
            index += length
        selected_key = "number", index
    return _entry_map(value).get(selected_key, value.default or NON_QUEUE)


def _import_targets(tree: ast.AST) -> set[str]:
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            targets.update(f"{node.module}.{alias.name}" for alias in node.names)
    return targets


def _called_imports(tree: ast.AST) -> set[tuple[str, str]]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    called: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        parts: list[str] = []
        value: ast.AST = node.func
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name) and value.id in aliases:
            imported = aliases[value.id]
            called.add((imported, ".".join((imported, *reversed(parts)))))
    return called


class _ScopeNames(NamedTuple):
    locals: frozenset[str]
    globals: frozenset[str]
    nonlocals: frozenset[str]


class _FunctionScope(NamedTuple):
    values: dict[str, AbstractValue]
    pending: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Environment]]


class _FunctionLocalVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(
            alias.asname or alias.name for alias in node.names if alias.name != "*"
        )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.names.add(node.name)
        for statement in node.body:
            self.visit(statement)


def _function_scope_names(
    statement: ast.FunctionDef | ast.AsyncFunctionDef,
) -> _ScopeNames:
    visitor = _FunctionLocalVisitor()
    for item in statement.body:
        visitor.visit(item)
    arguments = (
        statement.args.posonlyargs + statement.args.args + statement.args.kwonlyargs
    )
    visitor.names.update(argument.arg for argument in arguments)
    if statement.args.vararg is not None:
        visitor.names.add(statement.args.vararg.arg)
    if statement.args.kwarg is not None:
        visitor.names.add(statement.args.kwarg.arg)
    excluded = visitor.globals | visitor.nonlocals
    return _ScopeNames(
        frozenset(visitor.names - excluded),
        frozenset(visitor.globals),
        frozenset(visitor.nonlocals),
    )


class _Interpreter:
    def __init__(
        self,
        tree: ast.AST,
        adapter_names: AbstractSet[str],
        statement_limit: int,
        value_limit: int,
        loop_limit: int,
    ) -> None:
        if min(statement_limit, value_limit, loop_limit) < 1:
            raise QueueAnalysisLimit("queue analysis limits must be positive")
        self.tree = tree
        self.literal_patches = literal_patch_members(tree)
        self.statement_limit = statement_limit
        self.value_limit = value_limit
        self.loop_limit = loop_limit
        self.statement_count = 0
        self.value_count = 0
        self.alias_work = 0
        self.wildcard_queue_import = False
        self.signals: set[str] = set()
        self.uncertain = False
        self.lexical_depth = 0
        self.class_depth = 0
        self.module_values: dict[str, AbstractValue] = {}
        def insert(value: AbstractValue, parts: list[str]) -> AbstractValue:
            if not parts or value == QUEUE:
                return QUEUE
            entries = _entry_map(value) if value.state == 'object' else {}
            key = ('string', parts[0])
            entries[key] = insert(entries.get(key, NON_QUEUE), parts[1:])
            return _structured('object', entries)
        for name in sorted(adapter_names):
            parts = name.split('.')
            # The existing bound counts module suffix components, excluding
            # the top-level module and the final exported member.
            if len(parts) - 2 > MAX_DOTTED_IMPORT_DEPTH:
                raise QueueAnalysisLimit('queue dotted import depth limit exceeded')
            self.module_values[parts[0]] = insert(self.module_values.get(parts[0], NON_QUEUE), parts[1:])
        self.pending_functions: list[
            tuple[ast.FunctionDef | ast.AsyncFunctionDef, _Environment]
        ] = []
        self.scope_stack: list[_FunctionScope] = []

    def _statement(self) -> None:
        self.statement_count += 1
        if self.statement_count > self.statement_limit:
            raise QueueAnalysisLimit("queue statement limit exceeded")

    def _value(self, value: AbstractValue) -> AbstractValue:
        self.value_count += 1 + len(value.entries)
        if self.value_count > self.value_limit:
            raise QueueAnalysisLimit("queue value limit exceeded")
        return value

    def _join(self, left: AbstractValue, right: AbstractValue, augment_objects: bool = False) -> AbstractValue:
        if augment_objects and left.state == right.state == "object":
            entries = _entry_map(left)
            for key, value in right.entries:
                entries[key] = self._join(entries[key], value, True) if key in entries else value
            return self._value(_structured("object", entries))
        return self._value(join_value(left, right))

    def _alias_charge(self, amount: int = 1) -> None:
        self.alias_work += amount
        if self.alias_work > self.value_limit:
            raise QueueAnalysisLimit("queue alias limit exceeded")

    def _fork(self, environment: _Environment) -> _Environment:
        self._alias_charge(len(environment.aliases.by_name))
        return _Environment(dict(environment.values), environment.aliases.fork())

    def _alias_detach(self, name: str, aliases: _AliasState) -> None:
        group = aliases.by_name.pop(name, None)
        if group is None:
            return
        members = aliases.groups[group]
        members.remove(name)
        if not members:
            del aliases.groups[group]

    def _alias_create(self, name: str, aliases: _AliasState) -> None:
        self._alias_detach(name, aliases)
        self._alias_charge()
        group = aliases.next_group
        aliases.next_group += 1
        aliases.by_name[name] = group
        aliases.groups[group] = {name}

    def _alias_union(self, left: str, right: str, aliases: _AliasState) -> None:
        left_group = aliases.by_name.get(left)
        right_group = aliases.by_name.get(right)
        if left_group is None or right_group is None or left_group == right_group:
            return
        self._alias_charge()
        left_members = aliases.groups[left_group]
        right_members = aliases.groups[right_group]
        if len(left_members) < len(right_members):
            left_group, right_group = right_group, left_group
            left_members, right_members = right_members, left_members
        for member in right_members:
            aliases.by_name[member] = left_group
        left_members.update(right_members)
        del aliases.groups[right_group]

    @staticmethod
    def _alias_members(name: str, aliases: _AliasState) -> set[str]:
        group = aliases.by_name.get(name)
        return aliases.groups[group] if group is not None else {name}

    @staticmethod
    def _alias_contains(name: str, aliases: _AliasState) -> bool:
        return name in aliases.by_name

    def _join_envs(self, environments: list[_Environment]) -> _Environment:
        if not environments:
            return _Environment({}, _AliasState({}, {}))
        names = set().union(*(environment.values.keys() for environment in environments))
        result: dict[str, AbstractValue] = {}
        for name in names:
            value = environments[0].values.get(name, NON_QUEUE)
            for environment in environments[1:]:
                other = environment.values.get(name, NON_QUEUE)
                # A binding unchanged on every path constructs no value; charging it made
                # the value budget scale with locals x merge points instead of new values.
                # The comparison is as cheap as the uncharged dict copy in _fork.
                if other is not value and other != value:
                    value = self._join(value, other)
            result[name] = value
        aliases = _AliasState({}, {})
        mutable_names = sorted(
            name
            for name in names
            if any(self._alias_contains(name, environment.aliases) for environment in environments)
        )
        for name in mutable_names:
            self._alias_create(name, aliases)
        for environment in environments:
            for members in environment.aliases.groups.values():
                present = sorted(members & names)
                if not present:
                    continue
                first = present[0]
                for member in present[1:]:
                    self._alias_union(first, member, aliases)
        return _Environment(result, aliases)

    def _evaluate(self, node: ast.AST, environment: _Environment) -> AbstractValue:
        if isinstance(node, ast.Name):
            known = environment.values.get(node.id)
            if known is not None:
                return known
            return UNKNOWN_QUEUE if self.wildcard_queue_import else NON_QUEUE
        if isinstance(node, ast.Attribute):
            value = self._evaluate(node.value, environment)
            return _select(value, ("string", node.attr)) if value.state == "object" else _aggregate(value)
        if isinstance(node, ast.Subscript):
            return _select(
                self._evaluate(node.value, environment),
                normalize_literal_key(node.slice),
            )
        if isinstance(node, ast.Starred):
            return self._evaluate(node.value, environment)
        if isinstance(node, (ast.List, ast.Tuple)):
            entries = {
                ("number", index): self._evaluate(item, environment)
                for index, item in enumerate(node.elts)
            }
            return self._value(_structured("sequence", entries))
        if isinstance(node, ast.Set):
            if not node.elts:
                return NON_QUEUE
            value = self._evaluate(node.elts[0], environment)
            for item in node.elts[1:]:
                value = self._join(value, self._evaluate(item, environment))
            return value
        if isinstance(node, ast.Dict):
            entries: dict[LiteralKey, AbstractValue] = {}
            default = NON_QUEUE
            for key_node, value_node in zip(node.keys, node.values):
                value = self._evaluate(value_node, environment)
                key = None if key_node is None else normalize_literal_key(key_node)
                if key is None:
                    default = self._join(default, value)
                else:
                    entries[key] = value
            return self._value(_structured("mapping", entries, default))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._evaluate(node.left, environment)
            right = self._evaluate(node.right, environment)
            if left.state == right.state == "sequence":
                left_length = _sequence_length(left)
                right_length = _sequence_length(right)
                if left_length is None or right_length is None:
                    if _aggregate(left) == NON_QUEUE and _aggregate(right) == NON_QUEUE:
                        return self._value(_unbounded_sequence(NON_QUEUE))
                    return UNKNOWN_QUEUE
                entries = _entry_map(left)
                entries.update({
                    ("number", left_length + int(key[1])): value
                    for key, value in right.entries
                })
                return self._value(_structured("sequence", entries))
            if _aggregate(left) == NON_QUEUE and _aggregate(right) == NON_QUEUE:
                return NON_QUEUE
            return UNKNOWN_QUEUE
        if isinstance(node, ast.IfExp):
            return self._join(
                self._evaluate(node.body, environment),
                self._evaluate(node.orelse, environment),
            )
        if isinstance(node, ast.Call):
            function = _aggregate(self._evaluate(node.func, environment))
            if function.state in {"queue", "unknown_queue"}:
                return function
            if isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args:
                return _aggregate(self._evaluate(node.args[0], environment))
            return NON_QUEUE
        if isinstance(node, ast.NamedExpr):
            value = self._evaluate(node.value, environment)
            self._bind(node.target, value, environment)
            return value
        return NON_QUEUE

    def _record_binding(self, name: str, value: AbstractValue) -> None:
        if self.class_depth:
            return
        if self.lexical_depth == 0:
            values = self.module_values
        elif self.scope_stack:
            values = self.scope_stack[-1].values
        else:
            return
        previous = values.get(name)
        values[name] = value if previous is None else self._join(previous, value)

    def _bind(
        self,
        target: ast.AST,
        value: AbstractValue,
        environment: _Environment,
        alias_with: str | None = None,
        track_alias: bool = False,
        record_scope: bool = True,
    ) -> None:
        if isinstance(target, ast.Name):
            name = target.id
            self._alias_detach(name, environment.aliases)
            environment.values[name] = value
            if alias_with is not None and self._alias_contains(
                alias_with, environment.aliases
            ):
                self._alias_create(name, environment.aliases)
                self._alias_union(name, alias_with, environment.aliases)
            elif track_alias:
                self._alias_create(name, environment.aliases)
            if record_scope:
                self._record_binding(name, value)
            return
        if isinstance(target, ast.Starred):
            self._bind(
                target.value,
                value,
                environment,
                alias_with,
                track_alias,
                record_scope,
            )
            return
        if isinstance(target, (ast.List, ast.Tuple)):
            length = _sequence_length(value)
            star_index = next(
                (
                    index
                    for index, item in enumerate(target.elts)
                    if isinstance(item, ast.Starred)
                ),
                None,
            )
            for index, item in enumerate(target.elts):
                if isinstance(item, ast.Starred):
                    if length is None:
                        selected = UNKNOWN_QUEUE
                    else:
                        suffix = len(target.elts) - index - 1
                        entries = {
                            ("number", offset): _select(value, ("number", position))
                            for offset, position in enumerate(range(index, length - suffix))
                        }
                        selected = self._value(_structured("sequence", entries))
                else:
                    position = index
                    if star_index is not None and index > star_index and length is not None:
                        position = length - (len(target.elts) - index)
                    selected = (
                        _select(value, ("number", position))
                        if length is not None
                        else _aggregate(value)
                    )
                self._bind(item, selected, environment, record_scope=record_scope)
            return
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            name = target.value.id
            container = environment.values.get(name, NON_QUEUE)
            if container.state in {'non_queue', 'object'}:
                entries = _entry_map(container)
                entries[('string', target.attr)] = value
                self._set_alias_value(name, self._value(_structured('object', entries)), environment)
            else:
                self._set_alias_value(name, UNKNOWN_QUEUE, environment)
            return
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            container_name = target.value.id
            container = environment.values.get(container_name, UNKNOWN_QUEUE)
            key = normalize_literal_key(target.slice)
            if key is None or container.state not in {"sequence", "mapping"}:
                self._set_alias_value(container_name, UNKNOWN_QUEUE, environment)
                return
            entries = _entry_map(container)
            if container.state == "sequence":
                if key[0] != "number" or not isinstance(key[1], int):
                    self._set_alias_value(container_name, UNKNOWN_QUEUE, environment)
                    return
                index = key[1]
                length = _sequence_length(container)
                if length is None:
                    self._set_alias_value(container_name, UNKNOWN_QUEUE, environment)
                    return
                if index < 0:
                    index += length
                if index < 0 or index >= length:
                    self._set_alias_value(container_name, UNKNOWN_QUEUE, environment)
                    return
                key = "number", index
            entries[key] = value
            self._set_alias_value(
                container_name,
                self._value(
                    _structured(container.state, entries, container.default or NON_QUEUE)
                ),
                environment,
            )

    @staticmethod
    def _is_mutable_expression(node: ast.AST, environment: _Environment) -> bool:
        if isinstance(node, ast.Name):
            return node.id in environment.aliases.by_name
        if isinstance(node, (ast.List, ast.Dict)):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return _Interpreter._is_mutable_expression(node.left, environment)
        if isinstance(node, ast.IfExp):
            return _Interpreter._is_mutable_expression(
                node.body, environment
            ) or _Interpreter._is_mutable_expression(node.orelse, environment)
        return False

    def _set_alias_value(
        self,
        name: str,
        value: AbstractValue,
        environment: _Environment,
    ) -> None:
        members = self._alias_members(name, environment.aliases)
        self._alias_charge(len(members))
        for member in members:
            environment.values[member] = value
            self._record_binding(member, value)

    def _mutate_call(self, node: ast.Call, environment: _Environment) -> bool:
        if not isinstance(node.func, ast.Attribute) or not isinstance(node.func.value, ast.Name):
            return False
        name = node.func.value.id
        container = environment.values.get(name, NON_QUEUE)
        if container.state not in {"sequence", "mapping", "unknown_queue"}:
            return False
        if node.func.attr not in {"append", "extend"} | _CONTAINER_MUTATORS:
            return False
        if node.func.attr in _CONTAINER_MUTATORS:
            dependencies = [container]
            dependencies.extend(self._evaluate(item, environment) for item in node.args)
            dependencies.extend(
                self._evaluate(item.value, environment) for item in node.keywords
            )
            if all(_aggregate(item) == NON_QUEUE for item in dependencies):
                return True
            self._set_alias_value(name, UNKNOWN_QUEUE, environment)
            return True
        if container.state != "sequence" or len(node.args) != 1 or node.keywords:
            self._set_alias_value(name, UNKNOWN_QUEUE, environment)
            return True
        length = _sequence_length(container)
        if length is None:
            added = self._evaluate(node.args[0], environment)
            if _aggregate(container) == NON_QUEUE and _aggregate(added) == NON_QUEUE:
                # Length stays unknown and every element stays ordinary: nothing changes.
                return True
            self._set_alias_value(name, UNKNOWN_QUEUE, environment)
            return True
        entries = _entry_map(container)
        if node.func.attr == "append":
            entries[("number", length)] = self._evaluate(node.args[0], environment)
        else:
            extension = self._evaluate(node.args[0], environment)
            extension_length = _sequence_length(extension)
            if extension_length is None:
                self._set_alias_value(name, UNKNOWN_QUEUE, environment)
                return True
            entries.update({
                ("number", length + int(key[1])): value
                for key, value in extension.entries
            })
        self._set_alias_value(
            name,
            self._value(_structured("sequence", entries)),
            environment,
        )
        return True

    def _record_operation(
        self,
        kind: Literal["call", "decorator"],
        node: ast.AST,
        value_node: ast.AST,
        environment: _Environment,
        function_name: str = "",
    ) -> None:
        value = _aggregate(self._evaluate(value_node, environment))
        if value.state not in {"queue", "unknown_queue"}:
            return
        if value.state == "unknown_queue":
            self.uncertain = True
        dumped = ast.dump(node, annotate_fields=True, include_attributes=False)
        if kind == "call":
            self.signals.add(f"semantic-call:{dumped}")
        else:
            self.signals.add(f"semantic-decorator:{function_name}:{dumped}")

    def _record_expression(self, node: ast.AST, environment: _Environment) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._record_operation("call", child, child.func, environment)
                if child is not node:
                    # Nested mutators still execute when the outer call returns
                    # an ordinary scalar (for example str(items.append(queue))).
                    self._mutate_call(child, environment)

    def _function_body(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        environment: _Environment,
    ) -> None:
        for decorator in statement.decorator_list:
            self._record_operation(
                "decorator",
                decorator,
                decorator,
                environment,
                statement.name,
            )
            self._record_expression(decorator, environment)
        for expression in (
            *statement.args.defaults,
            *(item for item in statement.args.kw_defaults if item is not None),
        ):
            self._record_expression(expression, environment)
        self._bind(ast.Name(id=statement.name), NON_QUEUE, environment)
        captured = self._fork(environment)
        pending = (
            self.scope_stack[-1].pending
            if self.scope_stack
            else self.pending_functions
        )
        pending.append((statement, captured))

    @staticmethod
    def _nearest_scope_value(
        name: str,
        enclosing_values: tuple[dict[str, AbstractValue], ...],
    ) -> AbstractValue | None:
        for values in reversed(enclosing_values):
            if name in values:
                return values[name]
        return None

    def _analyze_function(
        self,
        statement: ast.FunctionDef | ast.AsyncFunctionDef,
        captured: _Environment,
        enclosing_values: tuple[dict[str, AbstractValue], ...],
    ) -> None:
        scope_names = _function_scope_names(statement)
        captured_names = (
            set(self.module_values)
            | set(scope_names.globals)
            | set(scope_names.nonlocals)
        )
        for values in enclosing_values:
            captured_names.update(values)
        for name in sorted(captured_names - set(scope_names.locals)):
            if name in scope_names.globals:
                value = self.module_values.get(name, NON_QUEUE)
            elif name in scope_names.nonlocals:
                value = self._nearest_scope_value(name, enclosing_values)
                if value is None:
                    value = UNKNOWN_QUEUE
            else:
                value = self._nearest_scope_value(name, enclosing_values)
                if value is None:
                    value = self.module_values.get(name)
                if value is None:
                    continue
            captured.values[name] = value
            self._alias_detach(name, captured.aliases)
        scope = _FunctionScope({}, [])
        self.lexical_depth += 1
        self.scope_stack.append(scope)
        for name in sorted(scope_names.locals):
            self._bind(
                ast.Name(id=name),
                NON_QUEUE,
                captured,
                record_scope=False,
            )
        arguments = (
            statement.args.posonlyargs + statement.args.args + statement.args.kwonlyargs
        )
        for argument in arguments:
            self._bind(ast.Name(id=argument.arg), NON_QUEUE, captured)
        if statement.args.vararg is not None:
            self._bind(ast.Name(id=statement.args.vararg.arg), NON_QUEUE, captured)
        if statement.args.kwarg is not None:
            self._bind(ast.Name(id=statement.args.kwarg.arg), NON_QUEUE, captured)
        try:
            self._block(statement.body, captured)
        finally:
            self.scope_stack.pop()
            self.lexical_depth -= 1
        nested_enclosing = (*enclosing_values, scope.values)
        for nested, nested_captured in scope.pending:
            self._analyze_function(nested, nested_captured, nested_enclosing)

    def _block(
        self,
        statements: list[ast.stmt],
        environment: _Environment,
    ) -> _Environment:
        for statement in statements:
            self._statement()
            environment = self._transfer(statement, environment)
        return environment

    def _loop(
        self,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
        environment: _Environment,
        target: ast.AST | None = None,
        iterable: AbstractValue = UNKNOWN_QUEUE,
    ) -> _Environment:
        zero = self._fork(environment)
        current = self._fork(environment)
        for iteration in range(self.loop_limit):
            one = self._fork(current)
            if target is not None:
                self._bind(target, _aggregate(iterable), one)
            one = self._block(body, one)
            joined = self._join_envs([zero, one])
            if iteration + 1 >= _LOOP_WIDENING_DELAY:
                # Widen before the stability check: the next state is current widened by
                # join(zero, body(current)), so stability proves a post-fixpoint even when
                # the pre-loop entries re-enter through ``zero``.
                for name, value in joined.values.items():
                    widened = widen_sequence(current.values.get(name, NON_QUEUE), value)
                    if widened is not value:
                        joined.values[name] = self._value(widened)
            if joined == current:
                return self._block(orelse, joined)
            current = joined
        raise QueueAnalysisLimit("queue loop analysis limit exceeded")

    def _transfer(
        self,
        statement: ast.stmt,
        environment: _Environment,
    ) -> _Environment:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                local = alias.asname or alias.name.split(".")[0]
                value = self.module_values.get(alias.asname or alias.name, QUEUE if alias.name.split(".")[0] in _QUEUE_IMPORTS else NON_QUEUE)
                if not alias.asname:
                    parts = alias.name.split(".")[1:]
                    if len(parts) > MAX_DOTTED_IMPORT_DEPTH:
                        raise QueueAnalysisLimit("queue object depth limit exceeded")
                    for part in reversed(parts):
                        value = self._value(_structured("object", {("string", part): value}))
                    current = environment.values.get(local)
                    if current is not None and current.state == value.state == "object":
                        value = self._join(current, value, augment_objects=True)
                self._bind(ast.Name(id=local), value, environment)
            return environment
        if isinstance(statement, ast.ImportFrom):
            is_queue = bool(
                statement.module
                and statement.module.split(".")[0] in _QUEUE_IMPORTS
            )
            for alias in statement.names:
                local = alias.asname or alias.name
                if is_queue and alias.name == "*":
                    self.wildcard_queue_import = True
                elif local in self.module_values or is_queue:
                    self._bind(ast.Name(id=local), self.module_values.get(local, QUEUE), environment)
                elif alias.name != "*":
                    self._bind(ast.Name(id=local), NON_QUEUE, environment)
            return environment
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._function_body(statement, environment)
            return environment
        if isinstance(statement, ast.ClassDef):
            for decorator in statement.decorator_list:
                self._record_expression(decorator, environment)
            for expression in (*statement.bases, *(item.value for item in statement.keywords)):
                self._record_expression(expression, environment)
            local = self._fork(environment)
            self.lexical_depth += 1
            self.class_depth += 1
            try:
                self._block(statement.body, local)
            finally:
                self.class_depth -= 1
                self.lexical_depth -= 1
            self._bind(ast.Name(id=statement.name), NON_QUEUE, environment)
            return environment
        if isinstance(statement, ast.Assign):
            self._record_expression(statement.value, environment)
            value = self._evaluate(statement.value, environment)
            mutable = self._is_mutable_expression(statement.value, environment)
            alias_with = (
                statement.value.id
                if isinstance(statement.value, ast.Name)
                and self._alias_contains(statement.value.id, environment.aliases)
                else None
            )
            for target in statement.targets:
                self._bind(
                    target,
                    value,
                    environment,
                    alias_with=alias_with,
                    track_alias=mutable and alias_with is None,
                )
                if alias_with is None and isinstance(target, ast.Name) and mutable:
                    alias_with = target.id
            return environment
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._record_expression(statement.value, environment)
                value = self._evaluate(statement.value, environment)
                alias_with = None
                if (
                    isinstance(statement.value, ast.Name)
                    and self._alias_contains(statement.value.id, environment.aliases)
                ):
                    alias_with = statement.value.id
                self._bind(
                    statement.target,
                    value,
                    environment,
                    alias_with=alias_with,
                    track_alias=self._is_mutable_expression(
                        statement.value, environment
                    )
                    and alias_with is None,
                )
            return environment
        if isinstance(statement, ast.AugAssign):
            self._record_expression(statement.value, environment)
            if isinstance(statement.op, ast.Add):
                value = self._evaluate(
                    ast.BinOp(left=statement.target, op=ast.Add(), right=statement.value),
                    environment,
                )
            else:
                value = UNKNOWN_QUEUE
            if (
                isinstance(statement.op, ast.Add)
                and isinstance(statement.target, ast.Name)
                and self._alias_contains(statement.target.id, environment.aliases)
            ):
                self._set_alias_value(statement.target.id, value, environment)
            else:
                self._bind(
                    statement.target,
                    value,
                    environment,
                    track_alias=isinstance(statement.op, ast.Add)
                    and self._is_mutable_expression(statement.target, environment),
                )
            return environment
        if isinstance(statement, ast.Expr):
            self._record_expression(statement.value, environment)
            if isinstance(statement.value, ast.Call):
                self._mutate_call(statement.value, environment)
            return environment
        if isinstance(statement, ast.If):
            self._record_expression(statement.test, environment)
            body = self._block(statement.body, self._fork(environment))
            orelse = self._block(statement.orelse, self._fork(environment))
            return self._join_envs([body, orelse])
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._record_expression(statement.iter, environment)
            iterable = self._evaluate(statement.iter, environment)
            return self._loop(
                statement.body,
                statement.orelse,
                environment,
                statement.target,
                iterable,
            )
        if isinstance(statement, ast.While):
            self._record_expression(statement.test, environment)
            return self._loop(statement.body, statement.orelse, environment)
        if isinstance(statement, ast.Try):
            normal = self._block(statement.body, self._fork(environment))
            normal = self._block(statement.orelse, normal)
            alternatives = [normal]
            alternatives.extend(
                self._block(handler.body, self._fork(environment))
                for handler in statement.handlers
            )
            joined = self._join_envs(alternatives)
            return self._block(statement.finalbody, joined)
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            restored = []
            for item in statement.items:
                self._record_expression(item.context_expr, environment)
                patch = self.literal_patches.get(id(item.context_expr))
                if patch:
                    name, member, replacement, _factory = patch
                    target = ast.Attribute(value=ast.Name(id=name, ctx=ast.Load()), attr=member, ctx=ast.Store())
                    original = self._evaluate(target, environment)
                    restored.append((target, original))
                    replacement_value = self._evaluate(replacement, environment) if replacement is not None else NON_QUEUE
                    self._bind(target, self._join(original, replacement_value), environment)
                if item.optional_vars is not None:
                    self._bind(
                        item.optional_vars,
                        self._evaluate(item.context_expr, environment),
                        environment,
                    )
            result = self._block(statement.body, environment)
            for target, original in reversed(restored):
                self._bind(target, original, result)
            return result
        if isinstance(statement, ast.Match):
            self._record_expression(statement.subject, environment)
            alternatives = [
                self._block(case.body, self._fork(environment))
                for case in statement.cases
            ]
            alternatives.append(self._fork(environment))
            return self._join_envs(alternatives)
        expressions: list[ast.AST] = []
        if isinstance(statement, (ast.Return, ast.Raise, ast.Assert)):
            expressions.extend(
                value
                for value in (
                    getattr(statement, "value", None),
                    getattr(statement, "exc", None),
                    getattr(statement, "cause", None),
                    getattr(statement, "test", None),
                    getattr(statement, "msg", None),
                )
                if value is not None
            )
        for expression in expressions:
            self._record_expression(expression, environment)
        return environment

    def analyze(self) -> QueueTreeAnalysis:
        queue_imports = {
            target
            for target in _import_targets(self.tree)
            if target.split(".")[0] in _QUEUE_IMPORTS
        }
        if not queue_imports and not self.module_values:
            return QueueTreeAnalysis((), frozenset(), False)
        body = self.tree.body if isinstance(self.tree, ast.Module) else []
        environment = _Environment(dict(self.module_values), _AliasState({}, {}))
        environment = self._block(body, environment)
        pending_index = 0
        while pending_index < len(self.pending_functions):
            statement, captured = self.pending_functions[pending_index]
            pending_index += 1
            self._analyze_function(statement, captured, ())
        self.signals.update(f"import:{target}" for target in queue_imports)
        for imported, call in _called_imports(self.tree):
            if imported.split(".")[0] in _QUEUE_IMPORTS:
                self.signals.add(f"call:{call}")
        derived_names = frozenset(
            name
            for name, value in environment.values.items()
            if _aggregate(value).state in {"queue", "unknown_queue"}
        )
        export_paths: set[str] = set()
        def exported(name: str, value: AbstractValue, depth: int = 0) -> None:
            if depth > MAX_DOTTED_IMPORT_DEPTH + 1:
                raise QueueAnalysisLimit('queue exported field depth limit exceeded')
            if value.state == 'object' and value.default in {None, NON_QUEUE}:
                for key, item in value.entries:
                    if key[0] == 'string':
                        exported(name + '.' + str(key[1]), item, depth + 1)
            elif _aggregate(value).state in {'queue', 'unknown_queue'}:
                export_paths.add(name)
        for name, value in environment.values.items():
            exported(name, value)
        return QueueTreeAnalysis(tuple(sorted(self.signals)), derived_names, self.uncertain, frozenset(export_paths))


def analyze_queue_tree(
    tree: ast.AST,
    adapter_names: AbstractSet[str] = frozenset(),
    *,
    statement_limit: int = 4096,
    value_limit: int = 4096,
    loop_limit: int = 8,
    allow_local_ipc: bool = True,
    complete_module: bool = False,
) -> QueueTreeAnalysis:
    """Analyze values; only full-source callers may opt into module provenance."""
    if allow_local_ipc:
        tree = stdlib_exception_projection(tree, complete_module=complete_module)
        tree = local_byte_channel_projection(tree)
    return _Interpreter(tree, adapter_names, statement_limit, value_limit, loop_limit).analyze()
