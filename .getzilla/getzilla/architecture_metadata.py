"""Readonly exact-source metadata and syntax proofs; fitness owns shared state."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Any
from .architecture_diff import ArchitectureDiff


def _instrumentation_targets_closed(tree, parents, events, resolve, imported, protected):
    """Admit only closed instrumentor uses, never arbitrary patch factories."""
    from . import architecture_fitness as _fitness_owner
    roots = {'unittest', 'mock', 'pytest', '_pytest'}
    modules = set()
    instrumentors = []
    for event in events:
        node = event.node
        if isinstance(node, _fitness_owner.ast.Import):
            modules.update(alias.name for alias in node.names)
            if any(alias.name.split('.')[0] in roots and (alias.asname or alias.name.split('.')[0]) == event.name for alias in node.names):
                instrumentors.append(event)
        elif isinstance(node, _fitness_owner.ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module)
            if node.module.split('.')[0] in roots:
                instrumentors.append(event)

    def target_closed(node):
        if not isinstance(node, _fitness_owner.ast.Constant) or type(node.value) is not str or len(node.value) > 4096:
            return False
        parts = node.value.split('.')
        if not 2 <= len(parts) <= 32 or any(not p.isidentifier() or p.startswith('__') or p in protected | roots for p in parts):
            return False
        parent = '.'.join(parts[:-1])
        # A flat imported module member, or a declared imported-module namespace.
        if parent not in modules and not (len(parts) > 2 and '.'.join(parts[:-2]) in modules and parts[-2] in modules):
            return False
        try:
            expression = _fitness_owner.ast.parse(node.value, mode='eval')
        except SyntaxError:
            return False
        guard = _fitness_owner.ast.Module(body=[_fitness_owner.ast.Import(names=[_fitness_owner.ast.alias(name=parts[0])]), _fitness_owner.ast.Expr(value=expression.body)], type_ignores=[])
        return _fitness_owner.namespace_is_closed(guard, allow_instrumentation=True)

    for event in instrumentors:
        for node in _fitness_owner.ast.walk(tree):
            if not isinstance(node, _fitness_owner.ast.Name) or not isinstance(node.ctx, _fitness_owner.ast.Load) or node.id != event.name:
                continue
            if resolve(node) is not event.node:
                return False
            member = node
            while isinstance(parents.get(member), _fitness_owner.ast.Attribute) and parents[member].value is member:
                member = parents[member]
            canonical = imported(member)
            parent = parents.get(member)
            if canonical == 'unittest.TestCase' and isinstance(parent, _fitness_owner.ast.ClassDef) and member in parent.bases:
                continue
            if canonical in {'unittest.mock.Mock', 'unittest.mock.MagicMock'} and isinstance(parent, _fitness_owner.ast.Call) and parent.func is member:
                continue
            if canonical != 'unittest.mock.patch' or not isinstance(parent, _fitness_owner.ast.Call) or parent.func is not member:
                return False
            use = parents.get(parent)
            direct = isinstance(use, _fitness_owner.ast.withitem) and use.context_expr is parent
            decorator = isinstance(use, (_fitness_owner.ast.FunctionDef, _fitness_owner.ast.AsyncFunctionDef, _fitness_owner.ast.ClassDef)) and parent in use.decorator_list
            if (not (direct or decorator) or not parent.args or not target_closed(parent.args[0])
                    or any(keyword.arg is None or keyword.arg == 'target' for keyword in parent.keywords)):
                return False
    return True


def _byte_only_http_imports(tree: ast.AST) -> set[str]:
    """Prove response parsing only, not the behavior of arbitrary imported code."""
    from . import architecture_fitness as _fitness_owner
    if not _fitness_owner.namespace_is_closed(tree, allow_instrumentation=True):
        return set()
    parents = {child: node for node in _fitness_owner.ast.walk(tree) for child in _fitness_owner.ast.iter_child_nodes(node)}
    events = _fitness_owner.binding_events(tree)
    bindings: dict[tuple[_fitness_owner.ast.AST | None, str], list[_fitness_owner.ast.AST]] = _fitness_owner.defaultdict(list)
    for event in events:
        bindings[(_fitness_owner.binding_owner(event.node, parents), event.name)].append(event.node)

    def resolve(name: _fitness_owner.ast.Name) -> _fitness_owner.ast.AST | None:
        scope = _fitness_owner.binding_owner(name, parents)
        while True:
            found = bindings.get((scope, name.id), ())
            if found:
                return found[0] if len(found) == 1 else None
            if scope is None:
                return None
            scope = _fitness_owner.binding_owner(scope, parents)
            # A method closes over enclosing functions/globals, never class locals.
            while isinstance(scope, _fitness_owner.ast.ClassDef):
                scope = _fitness_owner.binding_owner(scope, parents)

    def imported(value: _fitness_owner.ast.AST) -> str | None:
        parts = []
        while isinstance(value, _fitness_owner.ast.Attribute):
            if not isinstance(value.ctx, _fitness_owner.ast.Load):
                return None
            parts.append(value.attr)
            value = value.value
        if not isinstance(value, _fitness_owner.ast.Name):
            return None
        event = resolve(value)
        if isinstance(event, _fitness_owner.ast.Import):
            aliases = [a for a in event.names if (a.asname or a.name.split('.')[0]) == value.id]
            prefix = aliases[0].name if aliases and aliases[0].asname else value.id
        elif isinstance(event, _fitness_owner.ast.ImportFrom) and event.level == 0:
            aliases = [a for a in event.names if (a.asname or a.name) == value.id]
            prefix = event.module + '.' + aliases[0].name if aliases else ''
        else:
            return None
        return '.'.join((prefix, *reversed(parts)))

    http_events = []
    for event in events:
        node = event.node
        if isinstance(node, _fitness_owner.ast.Import):
            for alias in node.names:
                if alias.name == 'http.client' and (alias.asname or alias.name.split('.')[0]) == event.name:
                    http_events.append((event.name, node, alias.name))
        elif isinstance(node, _fitness_owner.ast.ImportFrom) and node.module == 'http.client':
            if node.level or any(a.name != 'HTTPResponse' for a in node.names):
                return set()
            http_events.extend((a.asname or a.name, node, 'http.client.' + a.name) for a in node.names)
    if not http_events:
        return set()
    protected = {'http', 'client', 'HTTPResponse', 'io', 'BytesIO', 'makefile'}
    protected.update(name for name, _, _ in http_events)
    protected.update(node.name for node in _fitness_owner.ast.walk(tree) if isinstance(node, _fitness_owner.ast.ClassDef))
    protected.update(node.id for node in _fitness_owner.ast.walk(tree)
                     if isinstance(node, _fitness_owner.ast.Name) and imported(node) in {'io', 'io.BytesIO'})
    if not _fitness_owner._instrumentation_targets_closed(tree, parents, events, resolve, imported, protected):
        return set()
    # A module/class alias cannot escape or be mutated into another supplier.
    for node in _fitness_owner.ast.walk(tree):
        if imported(node) == 'io.BytesIO' and isinstance(node, (_fitness_owner.ast.Name, _fitness_owner.ast.Attribute)):
            parent = parents.get(node)
            if not ((isinstance(parent, _fitness_owner.ast.Call) and parent.func is node)
                    or (isinstance(parent, _fitness_owner.ast.ClassDef) and node in parent.bases)):
                return set()
        if isinstance(node, _fitness_owner.ast.Attribute) and not isinstance(node.ctx, _fitness_owner.ast.Load):
            base = node
            while isinstance(base, _fitness_owner.ast.Attribute):
                base = base.value
            if isinstance(base, _fitness_owner.ast.Name) and imported(base) in {'io', 'http', 'http.client'}:
                return set()
        if isinstance(node, _fitness_owner.ast.Name) and isinstance(node.ctx, _fitness_owner.ast.Load) and imported(node) == 'io':
            parent = parents.get(node)
            if not isinstance(parent, _fitness_owner.ast.Attribute) or parent.attr not in {'BytesIO', 'StringIO'}:
                return set()
    calls = set()
    for name, event, _ in http_events:
        for node in _fitness_owner.ast.walk(tree):
            if not isinstance(node, _fitness_owner.ast.Name) or not isinstance(node.ctx, _fitness_owner.ast.Load) or node.id != name:
                continue
            if resolve(node) is not event:
                return set()
            member = node
            while isinstance(parents.get(member), _fitness_owner.ast.Attribute) and parents[member].value is member:
                member = parents[member]
            call = parents.get(member)
            if imported(member) != 'http.client.HTTPResponse' or not isinstance(call, _fitness_owner.ast.Call) or call.func is not member:
                return set()
            statement = parents.get(call)
            if not isinstance(statement, (_fitness_owner.ast.Assign, _fitness_owner.ast.AnnAssign, _fitness_owner.ast.Return)) or statement.value is not call:
                return set()
            if len(call.args) != 1 or call.keywords:
                return set()
            supplier = call.args[0]
            if not isinstance(supplier, _fitness_owner.ast.Call) or not isinstance(supplier.func, _fitness_owner.ast.Name) or supplier.args or supplier.keywords:
                return set()
            cls = resolve(supplier.func)
            if (not isinstance(cls, _fitness_owner.ast.ClassDef) or cls.lineno >= call.lineno or cls.bases or cls.keywords or cls.decorator_list
                    or getattr(cls, 'type_params', ()) or len(cls.body) != 1):
                return set()
            method = cls.body[0]
            if (not isinstance(method, _fitness_owner.ast.FunctionDef) or method.name != 'makefile' or method.decorator_list or method.returns
                    or method.args.vararg or method.args.kwarg or method.args.kwonlyargs or method.args.defaults
                    or getattr(method, 'type_params', ())
                    or len(method.args.posonlyargs + method.args.args) != 2
                    or any(a.annotation for a in method.args.posonlyargs + method.args.args) or len(method.body) != 1
                    or not isinstance(method.body[0], _fitness_owner.ast.Return)):
                return set()
            value = method.body[0].value
            if (not isinstance(value, _fitness_owner.ast.Call) or imported(value.func) != 'io.BytesIO' or value.keywords
                    or len(value.args) != 1 or not isinstance(value.args[0], _fitness_owner.ast.Constant)
                    or type(value.args[0].value) is not bytes or len(value.args[0].value) > 65536):
                return set()
            uses = [n for n in _fitness_owner.ast.walk(tree) if isinstance(n, _fitness_owner.ast.Name) and isinstance(n.ctx, _fitness_owner.ast.Load)
                    and n.id == cls.name and resolve(n) is cls]
            if uses != [supplier.func]:
                return set()
            calls.add(call)
    return {item[2] for item in http_events} if calls else set()


def _constructor_only_urllib_imports(tree: ast.AST) -> set[str]:
    """Prove stdlib request/error data construction, never arbitrary client use."""
    from . import architecture_fitness as _fitness_owner
    if not _fitness_owner.namespace_is_closed(tree, allow_instrumentation=True):
        return set()
    nodes = tuple(_fitness_owner.ast.walk(tree))
    parents = {child: node for node in nodes for child in _fitness_owner.ast.iter_child_nodes(node)}
    events = _fitness_owner.binding_events(tree)
    bindings = _fitness_owner.defaultdict(list)
    for event in events:
        bindings[(_fitness_owner.binding_owner(event.node, parents), event.name)].append(event.node)

    def resolve(name):
        scope = _fitness_owner.binding_owner(name, parents)
        while True:
            found = bindings.get((scope, name.id), ())
            if found:
                return found[0] if len(found) == 1 else None
            if scope is None:
                return None
            scope = _fitness_owner.binding_owner(scope, parents)
            while isinstance(scope, _fitness_owner.ast.ClassDef):
                scope = _fitness_owner.binding_owner(scope, parents)

    def imported(value):
        parts = []
        while isinstance(value, _fitness_owner.ast.Attribute) and isinstance(value.ctx, _fitness_owner.ast.Load):
            parts.append(value.attr)
            value = value.value
        if not isinstance(value, _fitness_owner.ast.Name):
            return None
        declaration = resolve(value)
        if isinstance(declaration, _fitness_owner.ast.Import):
            matches = [a for a in declaration.names if (a.asname or a.name.split('.')[0]) == value.id]
            prefix = matches[0].name if matches and matches[0].asname else value.id
        elif isinstance(declaration, _fitness_owner.ast.ImportFrom) and declaration.level == 0:
            matches = [a for a in declaration.names if (a.asname or a.name) == value.id]
            prefix = declaration.module + '.' + matches[0].name if matches else ''
        else:
            return None
        return '.'.join((prefix, *reversed(parts)))

    declarations = {}
    imported_modules = set()
    for event in events:
        if isinstance(event.node, _fitness_owner.ast.Import):
            imported_modules.update(alias.name for alias in event.node.names)
        elif isinstance(event.node, _fitness_owner.ast.ImportFrom) and event.node.level == 0 and event.node.module:
            imported_modules.add(event.node.module)
    for event in events:
        declaration = event.node
        if isinstance(declaration, _fitness_owner.ast.ImportFrom) and (declaration.module or '').split('.')[0] == 'urllib':
            return set()
        if isinstance(declaration, _fitness_owner.ast.Import):
            for alias in declaration.names:
                if alias.name.split('.')[0] == 'urllib':
                    if alias.name not in {'urllib.request', 'urllib.error'} or alias.asname is not None:
                        return set()
                    declarations[declaration] = alias.name
        if event.name == 'urllib' and declaration not in declarations:
            return set()
    if not declarations:
        return set()
    used = set()
    instrumentor_names = {e.name for e in events if isinstance(e.node, (_fitness_owner.ast.Import, _fitness_owner.ast.ImportFrom))
                         and ((isinstance(e.node, _fitness_owner.ast.ImportFrom) and (e.node.module or '').split('.')[0] in {'unittest', 'mock', 'pytest', '_pytest'})
                              or (isinstance(e.node, _fitness_owner.ast.Import) and any(a.name.split('.')[0] in {'unittest', 'mock', 'pytest', '_pytest'} for a in e.node.names)))}
    for node in nodes:
        if isinstance(node, (_fitness_owner.ast.Global, _fitness_owner.ast.Nonlocal)) and 'urllib' in node.names:
            return set()
        if not isinstance(node, _fitness_owner.ast.Name) or not isinstance(node.ctx, _fitness_owner.ast.Load):
            continue
        if node.id != 'urllib' and node.id not in instrumentor_names:
            continue
        member = node
        while isinstance(parents.get(member), _fitness_owner.ast.Attribute) and parents[member].value is member:
            member = parents[member]
        call = parents.get(member)
        canonical = imported(member)
        if node.id == 'urllib':
            declaration = resolve(node)
            if (declaration not in declarations or canonical not in {'urllib.request.Request', 'urllib.error.HTTPError'}
                    or canonical.rsplit('.', 1)[0] != declarations[declaration]
                    or not isinstance(call, _fitness_owner.ast.Call) or call.func is not member):
                return set()
            used.add(declaration)
            continue
        if canonical == 'unittest.TestCase' and isinstance(call, _fitness_owner.ast.ClassDef) and member in call.bases:
            continue
        if not isinstance(call, _fitness_owner.ast.Call) or call.func is not member:
            return set()
        if canonical in {'unittest.main', 'unittest.mock.Mock', 'unittest.mock.MagicMock'}:
            continue
        if any(k.arg is None for k in call.keywords) or not call.args:
            return set()
        if canonical == 'unittest.mock.patch':
            target = call.args[0]
            if (not isinstance(target, _fitness_owner.ast.Constant) or type(target.value) is not str
                    or not _fitness_owner.re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,4095}', target.value)
                    or any(p in {'urllib', 'Request', 'HTTPError', 'builtins', 'sys', 'importlib',
                                 'namespace_is_closed', 'binding_events', 'binding_owner'} or p.startswith('__')
                           for p in target.value.split('.'))):
                return set()
            parts = target.value.split('.')
            # A declared module member, or its imported stdlib dependency member.
            # Unknown target factories and unrelated policy globals are not proof.
            direct = '.'.join(parts[:-1]) in imported_modules
            stdlib_member = (len(parts) > 2 and '.'.join(parts[:-2]) in imported_modules
                             and parts[-2] in _fitness_owner.sys.stdlib_module_names)
            if not (direct or stdlib_member):
                return set()
        elif canonical == 'unittest.mock.patch.object':
            if (len(call.args) < 2 or imported(call.args[0]) != 'sys'
                    or not isinstance(call.args[1], _fitness_owner.ast.Constant) or call.args[1].value not in {'stdin', 'stdout'}):
                return set()
        elif canonical == 'unittest.mock.patch.dict':
            if imported(call.args[0]) != 'os.environ':
                return set()
        else:
            return set()
    return set(declarations.values()) if used == set(declarations) else set()


def _component_metadata_head(diff: ArchitectureDiff, base: dict, head: dict, root: Path | None) -> tuple[dict, bool] | None:
    """Closed source declarations only; network/secret/authority checks still run."""
    from . import architecture_fitness as _fitness_owner
    old = {node['id']: node for node in base['nodes']}
    added = {node['id']: node for node in head['nodes'] if node['id'] not in old}
    if not added:
        return head, False
    if root is None or diff.head_kind == 'worktree':
        return None
    artifacts = {item.path: item for item in diff.artifacts}
    domains = {d['id']: d['kind'] for d in base['trust_domains']}
    data = {d['id'] for d in base['data_classifications'] if not d['contains_secret']}
    secrets = {s['id'] for s in base['secret_classes']}
    profiles = {}
    source_paths = tuple(path for node in added.values() for path in node['repository_paths'])
    if any(str(_fitness_owner.PurePosixPath(path)) != path or '..' in _fitness_owner.PurePosixPath(path).parts or any(c in path for c in '*?[]\\')
           or not path.startswith('trust-ci/src/adaptive_trust_ci/') or not path.endswith('.py') for path in source_paths):
        return None
    try:
        source_bytes = _fitness_owner.read_diff_files(root, diff, source_paths)
        prior_bytes = _fitness_owner.read_diff_files(root, diff, source_paths, 'base')
    except (_fitness_owner.ArchitectureError, OSError):
        return None
    for identity, node in added.items():
        runtime = node['runtime']
        if (node['type'] != 'local_component' or node['public_contracts'] or node['data_classification'] not in data
                or runtime['kind'] != 'python_process' or runtime['lifecycle'] != 'on_demand'
                or runtime['evidence'] != 'source_described' or not node['repository_paths']):
            return None
        local = domains.get(node['trust_domain']) == 'local_preflight' and not node['secrets'] and runtime['network'] == 'none'
        observer = (domains.get(node['trust_domain']) == 'trust_ci_control' and runtime['network'] == 'declared_egress'
                    and set(node['secrets']) <= secrets & {'SECRET-GITHUB-APP', 'SECRET-READ-TOKEN'})
        if not local and not observer:
            return None
        profiles[identity] = 'local' if local else 'observer'
        for path in node['repository_paths']:
            item = artifacts.get(path)
            if (str(_fitness_owner.PurePosixPath(path)) != path or '..' in _fitness_owner.PurePosixPath(path).parts or any(c in path for c in '*?[]\\')
                    or not path.startswith('trust-ci/src/adaptive_trust_ci/') or not path.endswith('.py')
                    or item is None or item.status != 'added' or item.base_digest is not None or item.base_size
                    or item.head_digest is None or item.head_size <= 0
                    or prior_bytes[path] is not None or source_bytes[path] is None
                    or len(source_bytes[path]) != item.head_size or _fitness_owner.hashlib.sha256(source_bytes[path]).hexdigest() != item.head_digest
                    or any(_fitness_owner._matches(path, n['repository_paths']) for n in base['nodes'])
                    or [n['id'] for n in head['nodes'] if _fitness_owner._matches(path, n['repository_paths'])] != [identity]):
                return None
    old_edges = {e['id'] for e in base['edges']}
    edges = [e for e in head['edges'] if e['id'] not in old_edges]
    residual = {**head, 'nodes': [n for n in head['nodes'] if n['id'] not in added],
                'edges': [e for e in head['edges'] if e['id'] in old_edges]}
    if residual != base:
        return None
    all_nodes = {n['id']: n for n in head['nodes']}
    observed = set()
    for edge in edges:
        failure = edge['failure_behavior']
        if (edge['from'] not in added or edge['direction'] != 'from_to' or edge['sync_or_async'] != 'synchronous'
                or not 1 <= len(edge['allowed_data']) <= 2 or not set(edge['allowed_data']) <= data
                or failure['mode'] != 'fail_closed' or failure['terminal_action'] != 'reject' or failure['max_retries'] != 0
                or not 0 <= failure['timeout_ms'] <= 20000
                or failure['observable_signal'] not in {s['id'] for s in base['signals']} or 'secret_classes' in edge):
            return None
        dependency = (edge['type'] == 'dependency' and edge['protocol'] == 'python'
                      and edge['network_policy'] == 'no_network' and edge['authentication'] == 'local_os'
                      and all_nodes[edge['to']]['type'] == 'local_component'
                      and all_nodes[edge['to']]['runtime']['kind'] == 'python_process'
                      and all_nodes[edge['to']]['runtime']['lifecycle'] == 'on_demand')
        endpoint = old.get(edge['to'], {})
        observation = (profiles[edge['from']] == 'observer' and edge['to'] == 'NODE-GITHUB'
                       and endpoint.get('type') == 'external_system' and domains.get(endpoint.get('trust_domain')) == 'external_platform'
                       and edge['type'] == 'data_flow' and edge['protocol'] == 'https'
                       and edge['network_policy'] == 'allowlisted_egress' and edge['authentication'] == 'github_app'
                       and failure['timeout_ms'] > 0)
        if not dependency and not observation:
            return None
        if observation:
            observed.add(edge['from'])
    if any(role == 'observer' and identity not in observed for identity, role in profiles.items()):
        return None
    return residual, True


def _trust_ci_metadata_paths(diff: ArchitectureDiff, root: Path | None = None) -> tuple[str, ...]:
    """Qualify source bindings, never runtime authority, from validated paired states."""
    from . import architecture_fitness as _fitness_owner
    if diff._base_state is None or diff._head_state is None:
        return ()
    if diff.head_kind == 'worktree' and root is not None and (
            {node['id'] for node in diff._head_state.snapshot.system['nodes']}
            - {node['id'] for node in diff._base_state.snapshot.system['nodes']}):
        equivalent = _fitness_owner._committed_worktree_diff(root, diff)
        if equivalent is None:
            return ()
        diff = equivalent
    base = diff._base_state.snapshot.system
    head = diff._head_state.snapshot.system
    before = {node["id"]: node for node in base["nodes"]}
    artifacts = {item.path: item for item in diff.artifacts}

    def changed_bytes(path: str) -> bool:
        item = artifacts.get(path)
        return bool(item is not None and item.status in {"added", "modified"}
                    and item.head_digest is not None and item.head_size > 0
                    and item.head_digest != item.base_digest)

    component = _fitness_owner._component_metadata_head(diff, base, head, root)
    if component is None:
        return ()
    head, new_components = component

    # Remove only exact newly added public descriptors and owner memberships.
    # The existing envelope comparison below then checks every surrounding field.
    old_contracts = {item["id"]: item for item in base["contracts"]}
    new_contracts = {item["id"]: item for item in head["contracts"]}
    public_paths: list[str] = []
    admitted: dict[str, str] = {}
    for name, identity, owner, kind, role, compatibility, filenames in _fitness_owner._PUBLIC_CONTRACT_BINDINGS:
        if identity in old_contracts or identity not in new_contracts:
            continue
        path = f"engineering/contracts/schemas/{name}.v1.json"
        descriptor = {"id": identity, "path": path, "version": "1", "kind": kind,
                      "role": role, "compatibility": compatibility}
        owners = [node for node in head["nodes"] if identity in node["public_contracts"]]
        if (new_contracts[identity] != descriptor or not changed_bytes(path)
                or len(owners) != 1 or owners[0]["id"] != owner or owner not in before):
            return ()
        paired = tuple(f"trust-ci/src/adaptive_trust_ci/{filename}" for filename in filenames)
        if not any(
            changed_bytes(source_path)
            and source_path in owners[0]["repository_paths"]
            and [node["id"] for node in head["nodes"] if source_path in node["repository_paths"]] == [owner]
            for source_path in paired
        ):
            return ()
        admitted[identity] = owner
        public_paths.append(path)
    if admitted:
        head = {
            **head,
            "contracts": [item for item in head["contracts"] if item["id"] not in admitted],
            "nodes": [{**node, "public_contracts": [identity for identity in node["public_contracts"]
                        if admitted.get(identity) != node["id"]]} for node in head["nodes"]],
        }
    after = {node["id"]: node for node in head["nodes"]}
    domains = {domain["id"] for domain in base["trust_domains"] if domain["kind"] == "trust_ci_control"}

    def properties(node: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in node.items() if key != "repository_paths"}

    def source(path: str) -> bool:
        return (
            str(_fitness_owner.PurePosixPath(path)) == path
            and ".." not in _fitness_owner.PurePosixPath(path).parts
            and not any(character in path for character in "*?[]\\")
            and path.startswith("trust-ci/src/adaptive_trust_ci/")
            and path.endswith(".py")
            and changed_bytes(path)
        )

    qualified: list[str] = []
    same_envelope = (
        {key: value for key, value in base.items() if key != "nodes"}
        == {key: value for key, value in head.items() if key != "nodes"}
        and before.keys() == after.keys()
        and all(properties(before[key]) == properties(after[key]) for key in before)
    )
    bindings_valid = same_envelope
    changed_bindings = False
    if same_envelope:
        old_owners: dict[str, set[str]] = {}
        new_owners: dict[str, set[str]] = {}
        for identity in before:
            old_paths = set(before[identity]["repository_paths"])
            new_paths = set(after[identity]["repository_paths"])
            if old_paths == new_paths:
                continue
            changed_bindings = True
            node = before[identity]
            worker_extension = (
                identity == "NODE-TRUST-CI-WORKER"
                and node["type"] == "worker"
                and node["trust_domain"] == "TD-TRUST-CI-EXECUTION"
                and node["owner"] == "Trust CI operators"
                and node["runtime"]["kind"] == "container"
                and old_paths <= new_paths
                and new_paths - old_paths <= _fitness_owner._PUBLIC_WORKER_SOURCES
            )
            if not worker_extension and (node["trust_domain"] not in domains
                                        or node["type"] not in {"service", "datastore", "local_component"}):
                bindings_valid = False
            for path in old_paths ^ new_paths:
                if not source(path):
                    bindings_valid = False
        for identity, node in before.items():
            for path in node["repository_paths"]:
                old_owners.setdefault(path, set()).add(identity)
        for identity, node in after.items():
            for path in node["repository_paths"]:
                new_owners.setdefault(path, set()).add(identity)
        for path in old_owners.keys() | new_owners.keys():
            old = old_owners.get(path, set())
            new = new_owners.get(path, set())
            if old == new:
                continue
            if not old and len(new) == 1:
                # A new exact source registration cannot expand an existing prefix owner.
                if any(_fitness_owner._matches(path, node["repository_paths"]) for node in before.values()):
                    bindings_valid = False
                continue
            # Approved correction: store.py is the API's existing PostgreSQL client,
            # not the PostgreSQL server. No other ownership transfer is metadata.
            api = before.get("NODE-TRUST-CI-API", {})
            postgres = before.get("NODE-TRUST-CI-POSTGRES", {})
            if not (
                path == "trust-ci/src/adaptive_trust_ci/store.py"
                and old == {"NODE-TRUST-CI-POSTGRES"}
                and new == {"NODE-TRUST-CI-API"}
                and api.get("type") == "service"
                and api.get("runtime", {}).get("kind") == "container"
                and postgres.get("type") == "datastore"
                and postgres.get("runtime", {}).get("kind") == "postgresql"
                and api.get("owner") == postgres.get("owner") == "Trust CI operators"
                and api.get("trust_domain") == postgres.get("trust_domain")
                and api.get("trust_domain") in domains
            ):
                bindings_valid = False
    if bindings_valid and (changed_bindings or new_components) and "architecture/system.yaml" in diff.changed_paths:
        qualified.append("architecture/system.yaml")
    if bindings_valid and same_envelope and admitted and "architecture/system.yaml" in diff.changed_paths:
        qualified.extend(("architecture/system.yaml", *public_paths))

    contract_path = "engineering/contracts/openapi/trust-ci.v1.json"
    old_contracts = {item["id"]: item for item in base["contracts"]}
    new_contracts = {item["id"]: item for item in head["contracts"]}
    contract = old_contracts.get("CONTRACT-TRUST-CI-OPENAPI")
    owners = {identity for identity, node in before.items() if "CONTRACT-TRUST-CI-OPENAPI" in node["public_contracts"]}
    head_owners = {identity for identity, node in after.items() if "CONTRACT-TRUST-CI-OPENAPI" in node["public_contracts"]}
    if (
        contract_path in diff.changed_paths
        and contract is not None
        and contract == new_contracts.get("CONTRACT-TRUST-CI-OPENAPI")
        and contract["path"] == contract_path
        and contract["kind"] == "openapi"
        and contract["role"] == contract["compatibility"] == "bidirectional"
        and owners == head_owners == {"NODE-TRUST-CI-API"}
        and properties(before["NODE-TRUST-CI-API"]) == properties(after["NODE-TRUST-CI-API"])
        and before["NODE-TRUST-CI-API"]["trust_domain"] in domains
        and before["NODE-TRUST-CI-API"]["type"] == "service"
    ):
        qualified.append(contract_path)
    if 'architecture/system.yaml' in qualified and (new_components or any(
            path.startswith('architecture/generated/') for path in diff.changed_paths)):
        views = _fitness_owner._paired_component_views(root, diff)
        if views is None:
            return ()
        qualified.extend(path for path in views if path in diff.changed_paths)
    return tuple(sorted(set(qualified)))
