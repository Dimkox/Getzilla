"""Exact source resolution and syntax proofs; fitness owns canonical state."""
from __future__ import annotations

import ast
from pathlib import Path
from .architecture_diff import ArchitectureDiff
from .python_source_proof import queue_declaration_candidates




def _queue_return_exports_scoped(tree: ast.Module, adapters: frozenset[str],
                                 requested: frozenset[str] | None, depth: int, budget: list[int] | _QueueBudget) -> set[str]:
    """Evaluate helper dependencies first; nested scopes share one work budget."""
    from . import architecture_fitness as _fitness_owner
    if depth > _fitness_owner.MAX_QUEUE_ADAPTER_DEPTH:
        raise _fitness_owner.ArchitectureError('queue factory return depth limit exceeded', code='limit')
    marker = '__getzilla_return_projection__'
    if any(isinstance(node, _fitness_owner.ast.Name) and (node.id == marker or
           (node.id.startswith(('__getzilla_return_factory_', '__getzilla_nested_factory_')) and node.id not in adapters))
           for node in _fitness_owner.ast.walk(tree)):
        raise _fitness_owner.ArchitectureError('return projection name collision', code='fitness')
    projections = {}

    def units(nodes: int) -> int:
        return (nodes + _fitness_owner.QUEUE_PROJECTION_WORK_NODES - 1) // _fitness_owner.QUEUE_PROJECTION_WORK_NODES

    functions = dict.fromkeys(node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                              and (requested is None or node.name in requested))
    shared = scalar = None
    bounded = isinstance(budget, _fitness_owner._QueueBudget)
    if functions and bounded:
        preparation_cost = units(sum(1 for _ in ast.walk(tree)))
        budget.step(cost=preparation_cost)
        if (preparation_cost > 1 and len(functions) > 1 and _fitness_owner.namespace_is_closed(
                tree, allow_instrumentation=True, static_import_reads=True, forbidden_imports=_fitness_owner._QUEUE_IMPORTS)):
            scalar = _fitness_owner._queue_scalar_projection(tree)
            shared = queue_declaration_candidates(scalar)
    for name in functions:
        demand = frozenset({name})
        if shared is not None:
            candidate, nodes = shared(name)
            budget.step(cost=units(nodes))
            projection = _fitness_owner._queue_export_slice_prepared(candidate, demand)
        else:
            if bounded and projections:
                budget.step(cost=preparation_cost)
            projection = (_fitness_owner._queue_export_slice_prepared(scalar, demand) if scalar is not None
                          else _fitness_owner._queue_export_slice(tree, demand))
        selected = next(item for item in projection.body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name)
        projections[name] = (selected, [item for item in projection.body if item is not selected])
    dependencies = {}
    for name, (selected, prefix) in projections.items():
        names = {item.id for item in _fitness_owner.ast.walk(selected) if isinstance(item, _fitness_owner.ast.Name)}
        # Module aliases can carry a helper into a return without naming it in
        # the function. Function bodies in the prefix belong to their own scope.
        for statement in prefix:
            if not isinstance(statement, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef, _fitness_owner.ast.ClassDef)):
                names.update(item.id for item in _fitness_owner.ast.walk(statement) if isinstance(item, _fitness_owner.ast.Name))
        dependencies[name] = (names & projections.keys()) - {name}
    dependents = {name: set() for name in projections}
    for name, needed in dependencies.items():
        for dependency in needed:
            dependents[dependency].add(name)
    remaining = {name: set(needed) for name, needed in dependencies.items()}
    ready = _fitness_owner.deque(sorted(name for name, needed in remaining.items() if not needed))
    order = []
    while ready:
        name = ready.popleft()
        order.append(name)
        for dependent in sorted(dependents[name]):
            remaining[dependent].discard(name)
            if not remaining[dependent]:
                ready.append(dependent)
    order.extend(name for name in projections if name not in order)  # cycles retain bounded rechecks
    pending, queued, found = _fitness_owner.deque(order), set(order), set()
    while pending:
        name = pending.popleft()
        queued.remove(name)
        if name in found:
            continue
        if isinstance(budget, _fitness_owner._QueueBudget):
            budget.step()
        else:
            if budget[0] <= 0:
                raise _fitness_owner.ArchitectureError('queue factory return dependency limit exceeded', code='limit')
            budget[0] -= 1
        selected, prefix = projections[name]
        if _fitness_owner._queue_projected_return(selected, prefix, adapters, found, marker, depth, budget):
            found.add(name)
            for dependent in sorted(dependents[name] - found - queued):
                pending.append(dependent)
                queued.add(dependent)
    return found


def _queue_projected_return(selected: ast.FunctionDef | ast.AsyncFunctionDef, prefix: list[ast.stmt],
                             adapters: frozenset[str], known: set[str], marker: str,
                             depth: int, budget: list[int] | _QueueBudget) -> bool:
    from . import architecture_fitness as _fitness_owner
    import copy

    class Returns(_fitness_owner.ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            return node
        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Return(self, node):
            return _fitness_owner.ast.Expr(value=_fitness_owner.ast.Call(func=_fitness_owner.ast.Attribute(value=_fitness_owner.ast.Name(id=marker, ctx=_fitness_owner.ast.Load()), attr='append', ctx=_fitness_owner.ast.Load()),
                                          args=[node.value or _fitness_owner.ast.Constant(value=None)], keywords=[]))

    inherited = set()
    projected_prefix = []
    for statement in prefix:
        projected_prefix.append(statement)
        if isinstance(statement, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef)) and statement.name in known:
            alias = '__getzilla_return_factory_' + statement.name
            inherited.add(alias)
            projected_prefix.append(_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=statement.name, ctx=_fitness_owner.ast.Store())], value=_fitness_owner.ast.Name(id=alias, ctx=_fitness_owner.ast.Load())))
    adapters = adapters | inherited
    initialize = _fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=marker, ctx=_fitness_owner.ast.Store())], value=_fitness_owner.ast.List(elts=[], ctx=_fitness_owner.ast.Load()))
    arguments = [*selected.args.posonlyargs, *selected.args.args]
    parameters = [*arguments, *selected.args.kwonlyargs,
                  *([selected.args.vararg] if selected.args.vararg else []),
                  *([selected.args.kwarg] if selected.args.kwarg else [])]
    defaults = [_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=argument.arg, ctx=_fitness_owner.ast.Store())], value=_fitness_owner.ast.Constant(value=None))
                for argument in parameters]
    defaults.extend(_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=argument.arg, ctx=_fitness_owner.ast.Store())], value=copy.deepcopy(default))
                    for argument, default in zip(arguments[-len(selected.args.defaults):], selected.args.defaults))
    defaults.extend(_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=argument.arg, ctx=_fitness_owner.ast.Store())], value=copy.deepcopy(default))
                    for argument, default in zip(selected.args.kwonlyargs, selected.args.kw_defaults) if default is not None)
    nested = [item for item in selected.body if isinstance(item, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef))]
    nested_factories = set()
    if nested:
        nested_tree = _fitness_owner.ast.Module(body=[*projected_prefix, *defaults, *selected.body], type_ignores=[])
        nested_factories = _fitness_owner._queue_return_exports_scoped(nested_tree, frozenset(adapters),
            frozenset(item.name for item in nested), depth + 1, budget)
    nested_names = {'__getzilla_nested_factory_' + name for name in nested_factories}
    body = list(defaults)
    for item in selected.body:
        body.append(Returns().visit(copy.deepcopy(item)))
        if isinstance(item, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef)) and item.name in nested_factories:
            body.append(_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=item.name, ctx=_fitness_owner.ast.Store())],
                value=_fitness_owner.ast.Name(id='__getzilla_nested_factory_' + item.name, ctx=_fitness_owner.ast.Load())))
    for decorator in selected.decorator_list:
        body.append(_fitness_owner.ast.Expr(value=_fitness_owner.ast.Call(func=_fitness_owner.ast.Attribute(value=_fitness_owner.ast.Name(id=marker, ctx=_fitness_owner.ast.Load()), attr='append', ctx=_fitness_owner.ast.Load()), args=[decorator], keywords=[])))
    result = _fitness_owner.analyze_queue_tree(_fitness_owner.ast.Module(body=[*projected_prefix, initialize, *body], type_ignores=[]), frozenset(adapters) | nested_names)
    return marker in result.derived_names


def _call_use_inventory(tree: ast.AST, *, namespace_closed: bool, patches: dict) -> _CallUseInventory:
    """One complete immutable index, shared by object and result-use queries."""
    from . import architecture_fitness as _fitness_owner
    nodes = tuple(_fitness_owner.ast.walk(tree))
    parents = {child: node for node in nodes for child in _fitness_owner.ast.iter_child_nodes(node)}
    bindings = _fitness_owner.binding_events(tree)
    owners = {node: _fitness_owner.binding_owner(node, parents) for node in nodes}
    counts = _fitness_owner.Counter(event.name for event in bindings)
    scope_counts = _fitness_owner.Counter((owners[event.node], event.name) for event in bindings)
    declarations = _fitness_owner.defaultdict(set)
    reads, attributes, getters = (_fitness_owner.defaultdict(list) for _ in range(3))
    unknown_reads, structural = set(), set()
    getter_values = {}
    unknown_getter = bool(counts['getattr'])
    for node in nodes:
        if isinstance(node, (_fitness_owner.ast.Global, _fitness_owner.ast.Nonlocal)):
            declarations[owners[node]].update(node.names)
        elif isinstance(node, _fitness_owner.ast.Name) and isinstance(node.ctx, _fitness_owner.ast.Load):
            reads[node.id].append(node)
            if node.id == 'getattr':
                use = parents.get(node)
                unknown_getter |= not isinstance(use, _fitness_owner.ast.Call) or use.func is not node
        elif isinstance(node, _fitness_owner.ast.Attribute) and isinstance(node.ctx, _fitness_owner.ast.Load):
            attributes[node.attr].append(node)
        headers = []
        if isinstance(node, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef, _fitness_owner.ast.ClassDef, _fitness_owner.ast.Lambda)):
            headers = [value for field, values in _fitness_owner.ast.iter_fields(node) if field != 'body'
                       for value in (values if isinstance(values, list) else [values])]
        if isinstance(node, (_fitness_owner.ast.ListComp, _fitness_owner.ast.SetComp, _fitness_owner.ast.DictComp, _fitness_owner.ast.GeneratorExp)) and node.generators:
            headers.append(node.generators[0].iter)
        unknown_reads.update(child for header in headers if isinstance(header, _fitness_owner.ast.AST)
                             for child in _fitness_owner.ast.walk(header) if isinstance(child, _fitness_owner.ast.Name) and isinstance(child.ctx, _fitness_owner.ast.Load))
        if isinstance(node, _fitness_owner.ast.Call):
            if id(node) in patches:
                structural.add(node.args[0])
            if isinstance(node.func, _fitness_owner.ast.Name) and node.func.id == 'getattr':
                literal = (len(node.args) in (2, 3) and not node.keywords and isinstance(node.args[1], _fitness_owner.ast.Constant)
                           and isinstance(node.args[1].value, str))
                if literal:
                    getters[node.args[1].value].append(node)
                    if namespace_closed and not counts['getattr'] and isinstance(node.args[0], _fitness_owner.ast.Name) and node.args[1].value.isidentifier():
                        getter_values[node] = node.args[0].id + '.' + node.args[1].value
                        structural.add(node.args[0])
                else:
                    unknown_getter = True
    nonlocals = frozenset(name for names in declarations.values() for name in names)
    identities = _fitness_owner.defaultdict(set)
    import_ids = {node: _fitness_owner.ast.dump(node) for node in {event.node for event in bindings}
                  if isinstance(node, (_fitness_owner.ast.Import, _fitness_owner.ast.ImportFrom))}
    for event in bindings:
        identities[event.name].add(import_ids.get(event.node))
    stable_imports = frozenset(name for name, values in identities.items()
                              if namespace_closed and name not in nonlocals and len(values) == 1 and None not in values)
    frozen = [_fitness_owner.MappingProxyType({name: tuple(values) for name, values in index.items()})
              for index in (declarations, reads, attributes, getters)]
    return _fitness_owner._CallUseInventory(tree, namespace_closed, nodes, _fitness_owner.MappingProxyType(parents), bindings,
        _fitness_owner.MappingProxyType(counts), _fitness_owner.MappingProxyType(scope_counts), _fitness_owner.MappingProxyType(owners), frozen[0], nonlocals,
        frozenset(unknown_reads), *frozen[1:], unknown_getter, _fitness_owner.MappingProxyType(getter_values),
        frozenset(structural), stable_imports)


def _discarded_call_results(inventory: _CallUseInventory, *, returns: bool = False) -> frozenset[ast.Call]:
    """Prove complete local data flow to discard; unknown consumption stays live.

    Calls, statement protocols, returns and escaping closures are never data
    sinks. Plain aliases require one lexical binding and every reader. These
    facts live only in this analysis; caller AST identities are not cache keys.
    """
    from . import architecture_fitness as _fitness_owner
    nodes, parents, counts = inventory.nodes, inventory.parents, inventory.scope_counts
    owner = inventory.owners.get
    declarations = inventory.declarations
    unknown = object()

    @_fitness_owner.lru_cache(maxsize=None)
    def resolved(node):
        if node in inventory.unknown_reads:
            return unknown
        scope = owner(node)
        while True:
            if node.id in declarations.get(scope, ()):
                return unknown
            if counts[(scope, node.id)]:
                if isinstance(scope, _fitness_owner.ast.ClassDef) and owner(node) is not scope:
                    return unknown
                return scope
            if scope is None:
                return None
            scope = owner(scope)

    reads, attributes, getters = inventory.reads, inventory.attributes, inventory.getters
    memo = {}
    active = set()
    function_memo = {}
    function_active = set()
    work = 0

    def callable_use_safe(node, depth):
        parent = parents.get(node)
        if isinstance(parent, _fitness_owner.ast.Call) and parent.func is node:
            return safe(parent, depth + 1)
        if isinstance(parent, _fitness_owner.ast.Expr) and parent.value is node:
            return True
        if isinstance(parent, _fitness_owner.ast.Assign) and parent.value is node and len(parent.targets) == 1:
            return binding_safe(parent.targets[0], depth + 1, callable_value=True)
        return False

    def function_result_safe(function, depth):
        nonlocal work
        if returns:
            return False
        if function in function_memo:
            return function_memo[function]
        if function in function_active or depth > 64 or work >= _fitness_owner.MAX_QUEUE_DEPENDENCY_WORK:
            return False
        work += 1
        function_active.add(function)
        if isinstance(function, _fitness_owner.ast.Lambda):
            answer = callable_use_safe(function, depth + 1)
        else:
            scope = owner(function)
            answer = (not function.decorator_list and counts[(scope, function.name)] == 1
                      and function.name not in inventory.nonlocals)
            references = []
            for read in reads.get(function.name, ()):
                selected = resolved(read)
                if selected is unknown:
                    answer = False
                elif selected is scope:
                    references.append(read)
            if isinstance(scope, _fitness_owner.ast.ClassDef):
                class_scope = owner(scope)
                # Unknown receivers/getters or an escaping class do not prove
                # which method will run. Unused sibling methods stay separate.
                receiver_used = any(
                    resolved(read) in (unknown, method)
                    for method in scope.body if isinstance(method, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef))
                    for argument in [*method.args.posonlyargs, *method.args.args][:1]
                    for read in reads.get(argument.arg, ()))
                answer &= not (scope.bases or scope.keywords or scope.decorator_list or receiver_used
                               or any(name.startswith('__') for name in attributes))
                answer &= not inventory.unknown_getter and not any(
                    resolved(read) in (unknown, class_scope) for read in reads.get(scope.name, ()))
                references.extend(attributes.get(function.name, ()))
                references.extend(getters.get(function.name, ()))
            answer = answer and all(callable_use_safe(read, depth + 1) for read in references)
        function_active.remove(function)
        function_memo[function] = answer
        return answer

    def binding_safe(target, depth, origin=None, *, callable_value=False):
        if not isinstance(target, _fitness_owner.ast.Name):
            return False
        scope = owner(target)
        if (isinstance(scope, _fitness_owner.ast.ClassDef) or counts[(scope, target.id)] != 1
                or target.id in declarations.get(scope, ())):
            return False
        for read in reads.get(target.id, ()):
            selected = resolved(read)
            checked = (callable_use_safe(read, depth + 1) if callable_value
                       else safe(read, depth + 1, origin)) if selected is scope else True
            if selected is unknown or not checked:
                return False
        return True

    initial_origin = object()

    def safe(node, depth=0, origin=initial_origin):
        nonlocal work
        if origin is initial_origin:
            origin = owner(node)
        key = (node, origin)
        if key in memo:
            return memo[key]
        if key in active or work >= _fitness_owner.MAX_QUEUE_DEPENDENCY_WORK or depth > 64:
            return False
        work += 1
        active.add(key)
        parent = parents.get(node)
        answer = False
        if isinstance(parent, _fitness_owner.ast.Expr) and parent.value is node:
            answer = True
        elif isinstance(parent, _fitness_owner.ast.Assign) and parent.value is node:
            answer = all(binding_safe(target, depth + 1, origin) for target in parent.targets)
        elif isinstance(parent, _fitness_owner.ast.AnnAssign) and parent.value is node:
            answer = binding_safe(parent.target, depth + 1, origin)
        elif isinstance(parent, (_fitness_owner.ast.Return, _fitness_owner.ast.Yield, _fitness_owner.ast.YieldFrom)) or (
                isinstance(parent, _fitness_owner.ast.Lambda) and parent.body is node):
            function = parent if isinstance(parent, _fitness_owner.ast.Lambda) else owner(parent)
            answer = (function is origin and isinstance(function, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef, _fitness_owner.ast.Lambda))
                      and function_result_safe(function, depth + 1))
        elif isinstance(parent, (_fitness_owner.ast.List, _fitness_owner.ast.Tuple)) or isinstance(parent, _fitness_owner.ast.Dict) and node in parent.values:
            answer = not isinstance(getattr(parent, 'ctx', _fitness_owner.ast.Load()), (_fitness_owner.ast.Store, _fitness_owner.ast.Del)) and safe(parent, depth + 1, origin)
        active.remove(key)
        memo[key] = answer
        return answer

    return frozenset(node for node in nodes if isinstance(node, _fitness_owner.ast.Call) and safe(node))


def _inventory_use_proof(inventory: _CallUseInventory, *, returns: bool = False) -> _CallableUseProof:
    """Positive proof for plain callees/aliases; all other value uses are opaque.

    This is a complete syntactic use inventory, not a carrier recognizer. A
    future or unsupported expression therefore cannot make an import disappear.
    Caller-owned trees are prepared afresh; only owned immutable source bytes
    may cache the result. Whole-source binding identity is conservative across
    lexical scopes: repeated identical imports share one provider identity, but
    every other binding or namespace uncertainty refuses that shortcut.
    """
    from . import architecture_fitness as _fitness_owner
    nodes, parents, namespace_closed = inventory.nodes, inventory.parents, inventory.namespace_closed
    counts, loads, declared_nonlocal = inventory.counts, inventory.reads, inventory.nonlocals
    getter_values, structural = inventory.getter_values, inventory.structural
    discarded_results = _fitness_owner._discarded_call_results(inventory, returns=returns) if namespace_closed else frozenset()

    def reference(node):
        parts = []
        while isinstance(node, _fitness_owner.ast.Attribute) and isinstance(node.ctx, _fitness_owner.ast.Load):
            parts.append(node.attr)
            node = node.value
        if node in getter_values:
            prefix = getter_values[node]
            return '.'.join((prefix, *reversed(parts)))
        if isinstance(node, _fitness_owner.ast.Name) and isinstance(node.ctx, _fitness_owner.ast.Load):
            return '.'.join((node.id, *reversed(parts)))
        return None

    memo = {}
    alias_work = 0

    def use_kind(node, visiting=frozenset()):
        nonlocal alias_work
        # Qualifiers belong to the complete direct member expression. Literal
        # getters/patch targets use the already-validated member projection.
        if node in structural:
            holder = parents[node]
            if holder in getter_values:
                node = holder
            else:
                return 0
        while (isinstance(parents.get(node), _fitness_owner.ast.Attribute) and parents[node].value is node
               and isinstance(parents[node].ctx, _fitness_owner.ast.Load)):
            node = parents[node]
        if node in memo:
            return memo[node]
        parent = parents.get(node)
        if isinstance(parent, _fitness_owner.ast.Call) and parent.func is node:
            # Object identity does not prove that the returned value is data.
            # Every unproved result retains its full return/source demand.
            result = 0 if parent in discarded_results else 1
        elif (namespace_closed and isinstance(parent, _fitness_owner.ast.Assign) and parent.value is node
              and len(parent.targets) == 1 and isinstance(parent.targets[0], _fitness_owner.ast.Name)
              and counts.get(parent.targets[0].id) == 1 and parent.targets[0].id not in declared_nonlocal):
            alias = parent.targets[0].id
            readers = loads.get(alias, ())
            if alias in visiting:
                result = 2
            elif not readers:
                # An exhaustive zero-reader inventory proves a plain copy,
                # rather than an unsupported carrier or invocation.
                result = 0
            else:
                alias_work += 1
                if alias_work > _fitness_owner.MAX_QUEUE_DEPENDENCY_WORK or len(visiting) >= 64:
                    # Failure to finish a positive proof grants no admission.
                    # Existing dependency/source budgets still decide whether
                    # resolving the conservative demand itself is possible.
                    result = 2
                else:
                    result = max(use_kind(reader, visiting | {alias}) for reader in readers)
        else:
            result = 2
        memo[node] = result
        return result

    kinds = {}
    for node in nodes:
        if node in structural:
            continue
        parent = parents.get(node)
        if isinstance(parent, _fitness_owner.ast.Attribute) and parent.value is node and isinstance(parent.ctx, _fitness_owner.ast.Load):
            continue
        name = reference(node)
        if name:
            kinds[name] = max(kinds.get(name, 0), use_kind(node))
    return _fitness_owner._CallableUseProof(*(frozenset(name for name, kind in kinds.items() if kind == value)
                               for value in range(3)), inventory.stable_imports)


def _local_queue_resolution(
    root: Path,
    diff: ArchitectureDiff,
    module: str,
    side: str,
    cache: _QueueResolutionCache,
    resolving: set[str],
    visited: set[str],
    source_roots: tuple[str, ...],
    requested: frozenset[str] | None = None,
    callable_only: bool = False,
    budget: _QueueBudget | None = None,
) -> _QueueAdapterResolution:
    from . import architecture_fitness as _fitness_owner
    budget = budget if budget is not None else _fitness_owner._QueueBudget(side, profile=cache.profile)
    if budget.profile != cache.profile:
        raise _fitness_owner.ArchitectureError("queue source cache profile mismatch", code="fitness")
    original_key = (module, requested, callable_only) if cache.profile == _fitness_owner._CONSUMER_PROFILE else (module, requested, callable_only, cache.profile)
    prefetched = cache.values.get(module)
    source_identity = tuple((path, _fitness_owner.hashlib.sha256(value).hexdigest())
                            for path, value, _package in prefetched.sources) if prefetched else ()
    work_key = repr((side, module, tuple(sorted(requested)) if requested is not None else None,
                     callable_only, source_identity))
    diagnostic_side = side if isinstance(side, str) and side in ('head', 'base') else 'unknown'
    step = _fitness_owner._diagnostic_step('demand-' + diagnostic_side, ('module', module),
                            (tuple(sorted(requested)) if requested is not None else None, callable_only))
    source_path = prefetched.sources[0][0] if prefetched and prefetched.sources else None
    with _fitness_owner.diagnostics.span(step, stage='action', location=_fitness_owner._diagnostic_location(source_path)):
        frame = budget.enter(work_key, module=module)
        try:
            budget.step(request=True)
            cached = cache.demands.get(original_key)
            if cached is not None and cached.footprint is None:
                raise _fitness_owner.ArchitectureError('queue cached resource footprint is unavailable', code='limit')
            result = _fitness_owner._local_queue_resolution_impl(root, diff, module, side, cache, resolving, visited,
                source_roots, requested, callable_only, budget)
            budget.merge(result.footprint)
            canonical = result
            if (callable_only and resolving and module not in resolving and not result.source_modules
                    and result.reason == 'local_module_not_queue' and result.declared_exports):
                # A dependent declaration read still traverses a reexport edge.
                # Keep its topology/depth charge even though its stable function
                # body is not expanded. The canonical declaration cache stays
                # independent of whether this request has a parent.
                if len(visited | {module}) > budget.module_limit:
                    raise _fitness_owner.ArchitectureError('queue adapter module limit exceeded', code='limit')
                _fitness_owner._queue_check_depth(budget, len(resolving) + 1, site='declaration', module=module, side=side, active=resolving)
                visited.add(module)
                result = result._replace(source_modules=frozenset({module}), height=1, witness=(module,))
        except BaseException as error:
            if (isinstance(error, _fitness_owner.ArchitectureError) and error.code == 'limit'
                    and type(getattr(error, '_queue_refusal_capture', None)) is not _fitness_owner._QueueRefusalCapture):
                # Capture actual active request frames before unwinding. An inner
                # interpreter refusal with no measured counter stays explicitly unknown.
                captured = budget.refusal(str(error), 'other', None, None, site='resolver')
                error.queue_refusal = captured.queue_refusal
                error._queue_refusal_capture = captured._queue_refusal_capture._replace(owner=error)
            budget.leave(frame)
            raise
        footprint = budget.leave(frame)
        bounded = result._replace(footprint=footprint)
        if cache.demands.get(original_key) is canonical:
            cache.demands[original_key] = canonical._replace(footprint=footprint)
        return bounded


def _local_queue_resolution_impl(
    root: Path,
    diff: ArchitectureDiff,
    module: str,
    side: str,
    cache: _QueueResolutionCache,
    resolving: set[str],
    visited: set[str],
    source_roots: tuple[str, ...],
    requested: frozenset[str] | None,
    callable_only: bool,
    budget: _QueueBudget,
) -> _QueueAdapterResolution:
    from . import architecture_fitness as _fitness_owner
    if (
        not module
        or any(_fitness_owner.re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) is None for part in module.split("."))
    ):
        return _fitness_owner._QueueAdapterResolution("not_queue", "invalid_local_module")
    if module not in cache.source_modules:
        return _fitness_owner._QueueAdapterResolution("not_queue", "local_module_missing")
    prefetched = cache.values.get(module)
    demand_key = (module, requested, callable_only) if cache.profile == _fitness_owner._CONSUMER_PROFILE else (module, requested, callable_only, cache.profile)
    cached_declaration = cache.demands.get(demand_key)
    if callable_only and cached_declaration is not None and not cached_declaration.source_modules:
        return cached_declaration
    if callable_only and prefetched is not None and prefetched.sources:
        # Declaration inspection does not expand a dependency. It is bounded by
        # the prefetched module batch and AST node cap, unlike recursive returns.
        source_path, value, _package = prefetched.sources[0]
        with _fitness_owner._source_span(source_path, side, 'prepare'):
            _fitness_owner._budgeted_queue_tree(source_path, value, budget)
            prepared = _fitness_owner._queue_source_preparation(source_path, value)
        if _fitness_owner._queue_owned_callable_mutation(source_path, value, requested):
            raise _fitness_owner.ArchitectureError('aliased callable attribute mutation is unsupported', code='fitness')
        if requested and requested <= prepared.plain_callables:
            result = _fitness_owner._QueueAdapterResolution('not_queue', 'local_module_not_queue',
                declared_exports=_fitness_owner._queue_normalized_source(source_path, value).declared_exports)
            cache.demands[demand_key] = result
            return result
    if module not in visited:
        if len(visited) >= budget.module_limit:
            raise _fitness_owner.ArchitectureError("queue adapter module limit exceeded", code="limit")
        visited.add(module)
    if prefetched is not None and prefetched.state != "prefetched":
        return prefetched
    if module in resolving:
        return _fitness_owner._QueueAdapterResolution("unsupported", "cyclic_local_queue_adapter")
    _fitness_owner._queue_check_depth(budget, len(resolving) + 1, site='active', module=module, side=side, active=resolving)
    cached = cache.demands.get(demand_key)
    if cached is not None and not (cached.source_modules & resolving):
        if len(visited | cached.source_modules) > budget.module_limit:
            raise _fitness_owner.ArchitectureError('queue adapter module limit exceeded', code='limit')
        _fitness_owner._queue_check_depth(budget, len(resolving) + cached.height, site='cached', module=module, side=side, active=resolving,
                           cached=cached.witness, cached_height=cached.height, cached_modules=cached.source_modules)
        visited.update(cached.source_modules)
        return cached
    resolving.add(module)
    try:
        sources = prefetched.sources if prefetched is not None else ()
        if not sources:
            result = _fitness_owner._QueueAdapterResolution("not_queue", "local_module_missing")
            cache.values[module] = result
            return result
        source_path, value, current_package = sources[0]
        with _fitness_owner._source_span(source_path, side, 'prepare'):
            tree = _fitness_owner._budgeted_queue_tree(source_path, value, budget)
            prepared = _fitness_owner._queue_source_preparation(source_path, value)
        declared = _fitness_owner._queue_normalized_source(source_path, value).declared_exports
        requested = requested if requested is not None else frozenset(declared)
        if _fitness_owner._queue_owned_callable_mutation(source_path, value, requested):
            raise _fitness_owner.ArchitectureError('aliased callable attribute mutation is unsupported', code='fitness')
        with _fitness_owner._source_span(source_path, side, 'slice'):
            tree = _fitness_owner._queue_owned_export_slice(source_path, value, requested)
        with _fitness_owner._source_span(source_path, side, 'imports'):
            imported = _fitness_owner._queue_adapter_names(
                root, diff, tree, side, cache, resolving, visited, current_package=current_package,
                source_roots=source_roots, requested=requested or frozenset(),
                callable_only_exports=callable_only,
                source_preparation=prepared if tree is prepared.tree else None, budget=budget,
            )
        try:
            with _fitness_owner._source_span(source_path, side, 'values'):
                analysis = _fitness_owner.analyze_queue_tree(tree, imported.names, allow_local_ipc='queue' not in cache.source_modules)
        except _fitness_owner.QueueAnalysisLimit as exc:
            raise _fitness_owner.ArchitectureError(str(exc), code="limit") from exc
        if imported.unproved_queue_callback:
            raise _fitness_owner._UnsupportedQueueCallbackError('queue-bearing callback return is unsupported', code='fitness')
        # A projection with no queue imports, values or effects cannot create a
        # queue return. Avoid reslicing every ordinary helper in that case.
        try:
            with _fitness_owner._source_span(source_path, side, 'returns'):
                factories = _fitness_owner._queue_return_exports_scoped(tree, imported.names, None, 0, budget) if analysis.signals or imported.names else set()
        except _fitness_owner.QueueAnalysisLimit as exc:
            raise _fitness_owner.ArchitectureError(str(exc), code='limit') from exc
        if factories:
            # The adapter value models a callable's returned queue. Preserve the
            # selected function body for operation checks, then expose its return
            # summary before subsequent assignments such as app = make_queue().
            body = []
            aliases = {'__getzilla_factory_' + name for name in factories}
            if any(isinstance(node, _fitness_owner.ast.Name) and node.id in aliases for node in _fitness_owner.ast.walk(tree)):
                raise _fitness_owner.ArchitectureError('factory projection name collision', code='fitness')
            for node in tree.body:
                body.append(node)
                if isinstance(node, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef)) and node.name in factories:
                    alias = '__getzilla_factory_' + node.name
                    body.append(_fitness_owner.ast.Assign(targets=[_fitness_owner.ast.Name(id=node.name, ctx=_fitness_owner.ast.Store())], value=_fitness_owner.ast.Name(id=alias, ctx=_fitness_owner.ast.Load())))
            try:
                analysis = _fitness_owner.analyze_queue_tree(_fitness_owner.ast.Module(body=body, type_ignores=[]), imported.names | aliases,
                                              allow_local_ipc='queue' not in cache.source_modules)
            except _fitness_owner.QueueAnalysisLimit as exc:
                raise _fitness_owner.ArchitectureError(str(exc), code='limit') from exc
        exports = set(analysis.export_paths) - {'__getzilla_factory_' + name for name in factories}
        exports = tuple(sorted(exports))
        has_queue_provenance = bool(analysis.signals or exports)
        state = (
            "unsupported"
            if (imported.unsupported or analysis.uncertain) and has_queue_provenance
            else ("resolved" if has_queue_provenance else "not_queue")
        )
        reason = "local_queue_provenance_resolved" if has_queue_provenance else "local_module_not_queue"
        result = _fitness_owner._QueueAdapterResolution(
            state, reason, exports, analysis.signals, declared,
            source_modules=imported.source_modules | {module}, height=imported.height + 1,
            witness=(module, *imported.witness),
        )
        # Side/source bytes belong to this snapshot cache; a completed summary
        # additionally binds the export demand, transitive module cost and depth.
        if state != 'unsupported':
            cache.demands[demand_key] = result
        return result
    finally:
        resolving.remove(module)


def _queue_adapter_names(
    root: Path,
    diff: ArchitectureDiff,
    tree: ast.AST,
    side: str,
    cache: _QueueResolutionCache,
    resolving: set[str] | None = None,
    visited: set[str] | None = None,
    *, current_package: str = "",
    source_roots: tuple[str, ...],
    requested: frozenset[str] = frozenset(),
    callable_only_exports: bool = False,
    source_preparation: _QueueSourcePreparation | None = None,
    budget: _QueueBudget | None = None,
) -> _QueueAdapterNamesResult:
    from . import architecture_fitness as _fitness_owner
    budget = budget if budget is not None else _fitness_owner._QueueBudget(side, profile=cache.profile)
    proven: set[str] = set()
    unsupported = False
    modules: set[str] = set()
    height = 0
    witness: tuple[str, ...] = ()
    unproved_queue_callback = False
    active = resolving if resolving is not None else set()
    seen = visited if visited is not None else set()
    dependency_result = _fitness_owner._operation_dependencies(tree, requested=requested)
    dependencies = set(dependency_result.names)
    if source_preparation is not None and tree is not source_preparation.tree:
        raise _fitness_owner.ArchitectureError('owned queue source preparation mismatches its AST', code='fitness')
    full_fallback = source_preparation is not None and not source_preparation.namespace_closed
    patches = {} if full_fallback else _fitness_owner.literal_patch_members(tree)
    member_demands: dict[str, frozenset[str] | None] = {}
    preparation = None
    prepared = False

    def demanded_members(access_name: str) -> frozenset[str] | None:
        nonlocal preparation, prepared
        if not prepared:
            preparation = None if full_fallback else _fitness_owner._prepare_module_member_demands(tree, patches)
            prepared = True
        if access_name not in member_demands:
            member_demands[access_name] = (_fitness_owner._prepared_module_member_demand(preparation, access_name)
                                           if preparation is not None else None)
        return member_demands[access_name]

    if source_preparation is not None:
        inventory = source_preparation.inventory
        use_namespace_closed = source_preparation.namespace_closed
    else:
        preparation = _fitness_owner._prepare_module_member_demands(tree, patches)
        prepared = True
        use_namespace_closed = preparation is not None
        inventory = _fitness_owner._call_use_inventory(tree, namespace_closed=use_namespace_closed, patches=patches)
    force_returns = bool(requested) and not callable_only_exports
    use_proof = (source_preparation.callable_uses if source_preparation is not None and not force_returns
                 else _fitness_owner._inventory_use_proof(inventory, returns=force_returns))
    callback_demands = set(use_proof.opaque)
    return_demands = use_proof.returns | use_proof.opaque
    dependencies.update(name.split('.')[0] for name in return_demands)

    def complete_callable_use(prefix: str) -> bool:
        if local_name not in use_proof.stable_imports:
            return False
        relevant = {name for name in use_proof.identity | use_proof.returns | use_proof.opaque
                    if name == prefix or name.startswith(prefix + '.') or prefix.startswith(name + '.')}
        if relevant:
            return relevant <= use_proof.identity
        # An explicit, stable import reexport may forward the caller's proved
        # object-only demand. No recognized use at a root is not such a proof.
        return callable_only_exports and local_name in requested

    def callback_has_queue_export(resolution: _fitness_owner._QueueAdapterResolution) -> bool:
        for value in callback_demands:
            if wildcard:
                prefix = value
            else:
                if value == access_name or access_name.startswith(value + '.'):
                    suffix = ''
                elif value.startswith(access_name + '.'):
                    suffix = value[len(access_name):]
                else:
                    continue
                prefix = suffix.lstrip('.') if whole_module else target_name + suffix
            if not prefix and resolution.exports:
                return True
            if any(export == prefix or export.startswith(prefix + '.') for export in resolution.exports):
                return True
        return False

    def resolve_import(module: str, members: frozenset[str] | None, *, split: bool) -> _fitness_owner._QueueAdapterResolution:
        if not split or not members:
            return _fitness_owner._local_queue_resolution(root, diff, module, side, cache, active, seen,
                source_roots[:_fitness_owner.MAX_QUEUE_SOURCE_ROOTS], requested=members,
                callable_only=complete_callable_use(access_name)
                and (callable_only_exports or local_name not in requested)
                and local_name not in return_demands, budget=budget)
        results = []
        for member in sorted(members):
            prefix = access_name + '.' + member
            returned = (local_name in requested and not callable_only_exports) or local_name in return_demands or any(
                value == prefix or value.startswith(prefix + '.') for value in return_demands)
            results.append(_fitness_owner._local_queue_resolution(root, diff, module, side, cache, active, seen,
                source_roots[:_fitness_owner.MAX_QUEUE_SOURCE_ROOTS], requested=frozenset({member}),
                callable_only=not returned and complete_callable_use(prefix), budget=budget))
        if len(results) == 1:
            return results[0]
        state = ('unsupported' if any(item.state == 'unsupported' for item in results)
                 else 'resolved' if any(item.state == 'resolved' for item in results) else 'not_queue')
        missing = all(item.reason == 'local_module_missing' for item in results)
        return _fitness_owner._QueueAdapterResolution(state, 'local_module_missing' if missing else
            'local_queue_provenance_resolved' if state != 'not_queue' else 'local_module_not_queue',
            tuple(sorted({name for item in results for name in item.exports})),
            tuple(sorted({signal for item in results for signal in item.signals})),
            tuple(sorted({name for item in results for name in item.declared_exports})),
            source_modules=frozenset(name for item in results for name in item.source_modules),
            height=max(item.height for item in results),
            witness=max(results, key=lambda item: (item.height, bool(item.source_modules))).witness)

    for _target, _member, replacement, factory in patches.values():
        names = frozenset(node.id for node in _fitness_owner.ast.walk(replacement) if isinstance(node, _fitness_owner.ast.Name)) if replacement is not None else frozenset()
        dependencies.update(names)
        if factory:
            return_demands |= names
    reachable = dependencies | set(dependency_result.frontier)
    normalized: list[tuple[str, str, str, str, int, bool, bool]] = []
    for node in _fitness_owner.ast.walk(tree):
        if isinstance(node, _fitness_owner.ast.Import):
            imports = tuple((alias.name, "", alias.asname or alias.name.split(".", 1)[0], alias.asname or alias.name, 0, True, False) for alias in node.names)
        elif isinstance(node, _fitness_owner.ast.ImportFrom):
            module = _fitness_owner._resolve_import_module(current_package, node.module, node.level)
            imports = tuple((
                module,
                alias.name,
                alias.asname or alias.name,
                alias.asname or alias.name,
                node.level, False, alias.name == "*",
            ) for alias in node.names)
        else:
            continue
        normalized.extend(imports)
    for _module, _target, name, access, _level, _whole, wildcard in normalized:
        if wildcard:
            # A wildcard supplies no complete binding/use proof for a callable.
            return_demands |= {name}
            for value in use_proof.returns | use_proof.opaque:
                dependencies.add(value.split('.')[0])
                return_demands |= {value}
            callback_demands.update(use_proof.opaque)
            continue
        for value in use_proof.returns | use_proof.opaque:
            if value == access or value.startswith(access + '.') or access.startswith(value + '.'):
                dependencies.add(name)
                return_demands |= {value}
                if value == access or access.startswith(value + '.'):
                    return_demands |= {name}
                if value in use_proof.opaque:
                    callback_demands.add(value)
                    if not use_namespace_closed or access.startswith(value + '.'):
                        callback_demands.add(access)
    reachable = dependencies | set(dependency_result.frontier)
    relevant = [item for item in normalized if item[0].split(".")[0] not in _fitness_owner._QUEUE_IMPORTS and (item[6] and reachable or item[2] in dependencies or item[2] in dependency_result.frontier_imports)]
    _fitness_owner._prime_local_module_sources(root, diff, {item[0] for item in relevant}, side, cache, source_roots[:_fitness_owner.MAX_QUEUE_SOURCE_ROOTS], budget.module_limit - len(seen), budget)
    for target_module, target_name, local_name, access_name, level, whole_module, wildcard in normalized:
            if target_module.split(".")[0] in _fitness_owner._QUEUE_IMPORTS or not (wildcard and reachable or local_name in dependencies or local_name in dependency_result.frontier_imports):
                continue
            queue_adjacent = _fitness_owner._queue_adjacent_module(target_module)
            frontier_reachable = local_name in dependency_result.frontier_imports
            if len(source_roots) > _fitness_owner.MAX_QUEUE_SOURCE_ROOTS and (queue_adjacent or frontier_reachable):
                proven.add(local_name)
                unsupported = True
                continue
            bounded_source_roots = source_roots[:_fitness_owner.MAX_QUEUE_SOURCE_ROOTS]
            resolution = resolve_import(target_module,
                (frozenset({target_name}) if target_name and not wildcard else
                 frozenset(reachable) if wildcard else demanded_members(access_name)),
                split=whole_module and not wildcard)
            modules.update(resolution.source_modules)
            if resolution.source_modules and resolution.height > height:
                witness = resolution.witness
            height = max(height, resolution.height if resolution.source_modules else 0)
            if target_name and not wildcard and target_name not in resolution.declared_exports and _fitness_owner._is_local_package(cache, target_module):
                target_module, target_name, whole_module = f"{target_module}.{target_name}", "", True
                _fitness_owner._prime_local_module_sources(root, diff, {target_module}, side, cache, bounded_source_roots, budget.module_limit - len(seen), budget)
                resolution = resolve_import(target_module, demanded_members(access_name), split=True)
                modules.update(resolution.source_modules)
                if resolution.source_modules and resolution.height > height:
                    witness = resolution.witness
                height = max(height, resolution.height if resolution.source_modules else 0)
                queue_adjacent = _fitness_owner._queue_adjacent_module(target_module)
            export_resolved = (
                (target_name and any(value == target_name or value.startswith(target_name + '.') for value in resolution.exports))
                or (not target_name and bool(resolution.exports))
            )
            if callback_has_queue_export(resolution):
                if dependency_result.exhausted:
                    raise _fitness_owner.ArchitectureError('callable use dependency frontier is exhausted', code='limit')
                # Validate the unchanged interpreter bounds before reporting a
                # semantic refusal; a limit must not turn into new_queue.
                unproved_queue_callback = True
            if target_name and not wildcard:
                members = [value[len(target_name):] for value in resolution.exports if value.startswith(target_name + '.')]
                if members:
                    proven.update(local_name + member for member in members)
                    if target_name not in resolution.exports:
                        continue
            local_values = tuple(sorted(name for name in reachable & set(resolution.exports) if not name.startswith('_'))) if wildcard else (local_name,)
            if whole_module and resolution.reason in {"local_queue_provenance_resolved", "local_module_not_queue"}:
                proven.update(f"{access_name}.{export}" for export in resolution.exports)
                unsupported = unsupported or bool(resolution.exports)
                continue
            if (frontier_reachable or whole_module or wildcard) and (
                level > 0
                or resolution.reason != "local_module_missing"
                or any(name == target_module.split(".", 1)[0] or name.startswith(target_module.split(".", 1)[0] + ".") for name in cache.source_modules)
            ):
                declared = resolution.reason == "local_module_not_queue" and (
                    whole_module or wildcard or target_name in resolution.declared_exports)
                if declared or wildcard and not local_values and (
                    resolution.reason == "local_queue_provenance_resolved"
                ):
                    continue
                proven.update(local_values or reachable)
                unsupported = True
                continue
            if (
                len(source_roots) > _fitness_owner.MAX_QUEUE_SOURCE_ROOTS
                and resolution.state == "resolved"
                and export_resolved
            ):
                proven.add(local_name)
                unsupported = True
                continue
            if resolution.state == "unsupported" and export_resolved:
                proven.add(local_name)
                unsupported = True
                continue
            if (
                resolution.state == "unsupported"
                and queue_adjacent
            ):
                raise _fitness_owner.ArchitectureError(
                    f"relevant local queue adapter is unsupported: {target_module}"
                    f" ({resolution.reason})",
                    code="fitness",
                )
            if (
                not resolution.exports
                and queue_adjacent
                and (
                    level > 0
                    or any(name == target_module.split(".", 1)[0] or name.startswith(target_module.split(".", 1)[0] + ".") for name in cache.source_modules)
                )
                and resolution.reason == "local_module_missing"
            ):
                raise _fitness_owner.ArchitectureError(
                    f"relevant local queue adapter is unresolved: {target_module}",
                    code="fitness",
                )
            if (
                target_name
                and target_name not in resolution.exports
                and resolution.state == "resolved"
                and queue_adjacent
            ):
                raise _fitness_owner.ArchitectureError(
                    f"relevant local queue adapter export is unresolved: "
                    f"{target_module}.{target_name}",
                    code="fitness",
                )
            if (
                target_name and target_name in resolution.exports
            ) or (not target_name and resolution.exports):
                proven.add(local_name)
    return _fitness_owner._QueueAdapterNamesResult(frozenset(proven), unsupported, frozenset(modules), height, unproved_queue_callback, witness)

from .architecture_fitness import (  # noqa: F401 canonical annotation/result types
    _QueueBudget, _QueueSourcePreparation, _QueueAdapterNamesResult, _QueueAdapterResolution,
    _QueueResolutionCache, _CallUseInventory, _CallableUseProof, _OperationDependencies,
)
