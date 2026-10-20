"""Cost guard: paid or unbounded operations need a budget, a tested bound and a human before the first live run.

Three layers, all static (nothing is called, imported or executed):

- prompt signals (C01): a paid provider or an automation platform together with repetition
  (variants, batches, "until it works", schedules) — read with the language-pack vocabulary;
- diff findings (C02): calls into paid SDKs or provider hosts inside loops that nothing bounds,
  retries without a stop, and n8n workflow cycles through paid nodes without a counter;
- the budget contract (C03): `cost-contract.json` in the active change package with max calls,
  max spend, a stop condition, an alert and the code symbol that enforces the limit, which a test
  must reference. The first live run is behind the `paid_run_approval` human gate.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from .risk_terms import RiskVocabulary, load_vocabulary

CONFIG = Path(__file__).resolve().parents[1] / 'config' / 'cost-providers.json'
CONTRACT_NAME = 'cost-contract.json'
STATE_NAME = 'cost-guard.json'
GATE = 'paid_run_approval'
SIGNAL_PREFIX = 'COST_SIGNAL:'
BLOCKING = frozenset({'UNBOUNDED_PAID_LOOP', 'UNBOUNDED_RETRY'})
REPEAT_IDS = frozenset({'multiplicity', 'unbounded-loop', 'schedule'})
CODE_SUFFIXES = ('.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.go', '.rs', '.cs', '.java', '.kt', '.php', '.rb',
                 '.sh', '.ps1', '.swift')


@lru_cache(maxsize=4)
def load_providers(path: Path = CONFIG) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding='utf-8'))
    if data.get('schema_version') != 'cost-providers-v1':
        raise ValueError('unknown cost providers schema')
    return data


# --- C01: prompt ---------------------------------------------------------------------------------

@dataclass(frozen=True)
class CostSignal:
    ids: tuple[str, ...]

    @property
    def rationale(self) -> str:
        return (f"{SIGNAL_PREFIX}{','.join(self.ids)}: paid or unbounded operation; a budget contract "
                f"({CONTRACT_NAME}) with a tested limit and {GATE} before the first live run are required")


def prompt_cost_signals(text: str, vocabulary: RiskVocabulary | None = None) -> CostSignal | None:
    vocabulary = vocabulary or load_vocabulary()
    matched = vocabulary.matched_ids(text)
    provider = 'paid-provider' in matched
    platform = 'automation-platform' in matched
    repeat = bool(matched & REPEAT_IDS)
    generation = 'generation' in matched
    if (provider and repeat) or (platform and (provider or generation or repeat)) or \
            ('unbounded-loop' in matched and generation):
        return CostSignal(tuple(sorted(matched & (REPEAT_IDS | {'paid-provider', 'automation-platform', 'generation'}))))
    return None


def route_has_cost_signal(route: Mapping[str, Any] | None) -> bool:
    if not route:
        return False
    gates = route.get('human_gates') or []
    reasons = route.get('rationale') or []
    return GATE in gates or any(isinstance(item, str) and item.startswith(SIGNAL_PREFIX) for item in reasons)


# --- C02: diff -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class CostFinding:
    kind: str  # UNBOUNDED_PAID_LOOP, UNBOUNDED_RETRY, PAID_CALL, SCHEDULED_PAID_CALL, UNANALYSED_PAID_CALL
    path: str
    line: int
    detail: str

    @property
    def blocking(self) -> bool:
        return self.kind in BLOCKING

    def to_dict(self) -> dict[str, Any]:
        return {'kind': self.kind, 'path': self.path, 'line': self.line, 'detail': self.detail}


def _hosts_in(text: str, hosts: Iterable[str]) -> list[str]:
    lowered = text.lower()
    return [host for host in hosts if re.search(r'(?<![\w.-])' + re.escape(host) + r'(?![\w-])', lowered)]


def _chain(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Call):
        inner = _chain(node.func)
        return None if inner is None else '.'.join([inner, *reversed(parts)])
    if isinstance(node, ast.Name):
        return '.'.join([node.id, *reversed(parts)])
    return None


def _string_parts(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return ''.join(_string_parts(value) for value in node.values)
    return ''


class _PythonCost(ast.NodeVisitor):
    def __init__(self, path: str, providers: Mapping[str, Any], paid_functions: frozenset[str] = frozenset()) -> None:
        self.path = path
        self.paid_functions = paid_functions  # local functions that make a paid call (second pass)
        self.paid_function_names: set[str] = set()
        self.hosts = providers['hosts']
        self.modules = tuple(providers['python_modules'])
        self.aliases: set[str] = set()
        self.clients: set[str] = set()
        self.host_vars: set[str] = set()
        self.loops: list[tuple[ast.AST, bool]] = []
        self.functions: list[ast.AST] = []
        self.findings: list[CostFinding] = []

    def _is_paid_module(self, name: str) -> bool:
        return any(name == module or name.startswith(module + '.') for module in self.modules)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if self._is_paid_module(alias.name):
                self.aliases.add(alias.asname or alias.name.split('.')[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            # `from google import genai` imports the paid module google.genai itself (#76).
            if node.module and (self._is_paid_module(node.module) or self._is_paid_module(f'{node.module}.{alias.name}')):
                self.aliases.add(alias.asname or alias.name)

    def visit_Assign(self, node: ast.Assign) -> None:
        value_chain = _chain(node.value.func) if isinstance(node.value, ast.Call) else _chain(node.value)
        paid_value = value_chain is not None and value_chain.split('.')[0] in self.aliases | self.clients
        host_value = bool(_hosts_in(_string_parts(node.value), self.hosts))
        for target in node.targets:
            if isinstance(target, ast.Name):
                if paid_value:
                    self.clients.add(target.id)
                if host_value:
                    self.host_vars.add(target.id)
        self.generic_visit(node)

    def _loop_bounded_while(self, node: ast.While) -> bool:
        counters = {target.id for child in ast.walk(node) for target in [getattr(child, 'target', None)]
                    if isinstance(child, ast.AugAssign) and isinstance(target, ast.Name)}

        def uses_counter(test: ast.AST) -> bool:
            return isinstance(test, ast.Compare) and any(
                isinstance(part, ast.Name) and part.id in counters for part in [test.left, *test.comparators])

        if uses_counter(node.test):
            return True
        for child in ast.walk(node):
            if isinstance(child, ast.If) and uses_counter(child.test) and any(isinstance(n, ast.Break) for n in ast.walk(child)):
                return True
        return False

    def visit_While(self, node: ast.While) -> None:
        self.loops.append((node, self._loop_bounded_while(node)))
        self.generic_visit(node)
        self.loops.pop()

    def visit_For(self, node: ast.For) -> None:
        iterator = _chain(node.iter.func) if isinstance(node.iter, ast.Call) else None
        unbounded = iterator in {'itertools.count', 'count', 'itertools.cycle', 'cycle', 'itertools.repeat', 'repeat'} or (
            iterator == 'iter' and isinstance(node.iter, ast.Call) and len(node.iter.args) == 2)
        self.loops.append((node, not unbounded))
        self.generic_visit(node)
        self.loops.pop()

    visit_AsyncFor = visit_For

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node)
        outer_loops, self.loops = self.loops, []
        self.generic_visit(node)
        self.loops = outer_loops
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _unbounded_retry(self) -> str | None:
        for function in self.functions:
            for decorator in getattr(function, 'decorator_list', []):
                name = _chain(decorator.func if isinstance(decorator, ast.Call) else decorator) or ''
                keywords = {kw.arg for kw in decorator.keywords} if isinstance(decorator, ast.Call) else set()
                if name.split('.')[-1] == 'retry' and 'stop' not in keywords:
                    return f'{name} without stop='
                if name.endswith('on_exception') and not keywords & {'max_tries', 'max_time'}:
                    return f'{name} without max_tries/max_time'
        return None

    def visit_Call(self, node: ast.Call) -> None:
        chain = _chain(node.func) or ''
        root_name = chain.split('.')[0]
        hosts = [host for arg in [*node.args, *[kw.value for kw in node.keywords]] for host in _hosts_in(_string_parts(arg), self.hosts)]
        uses_host_var = any(isinstance(arg, ast.Name) and arg.id in self.host_vars for arg in node.args)
        constructor = root_name in self.aliases and len(chain.split('.')) == 1
        direct = ((root_name in self.aliases or root_name in self.clients) and not constructor) or bool(hosts) or uses_host_var
        via_function = bool(chain) and chain.split('.')[-1] in self.paid_functions and \
            (len(chain.split('.')) == 1 or root_name in {'self', 'cls'})
        if direct or via_function:
            label = chain or 'call'
            if direct:
                self.paid_function_names.update(getattr(function, 'name', '') for function in self.functions)
                self.findings.append(CostFinding('PAID_CALL', self.path, node.lineno, label))
            if any(not bounded for _, bounded in self.loops):
                self.findings.append(CostFinding('UNBOUNDED_PAID_LOOP', self.path, node.lineno,
                                                 f'{label} inside a loop with no counter or limit'))
            retry = self._unbounded_retry()
            if retry:
                self.findings.append(CostFinding('UNBOUNDED_RETRY', self.path, node.lineno, f'{label} under {retry}'))
        self.generic_visit(node)


def python_findings(path: str, content: bytes, providers: Mapping[str, Any] | None = None) -> list[CostFinding]:
    providers = providers or load_providers()
    try:
        tree = ast.parse(content.decode('utf-8', 'replace'))
    except (SyntaxError, ValueError):
        hosts = _hosts_in(content.decode('utf-8', 'replace'), providers['hosts'])
        return [CostFinding('UNANALYSED_PAID_CALL', path, 0, f'unparsable Python mentions {hosts[0]}')] if hosts else []
    first = _PythonCost(path, providers)
    first.visit(tree)
    paid_functions = frozenset(name for name in first.paid_function_names if name)
    findings = first.findings
    if paid_functions:
        second = _PythonCost(path, providers, paid_functions)  # calls to paid helpers inside loops count too
        second.visit(tree)
        findings = second.findings
    return findings + _scheduled_findings(path, tree, findings, providers)


def _scheduled_findings(path: str, tree: ast.AST, findings: list[CostFinding],
                        providers: Mapping[str, Any]) -> list[CostFinding]:
    """A paid call in a module that also schedules work repeats on every tick (#76)."""
    paid = [item for item in findings if item.kind == 'PAID_CALL']
    if not paid:
        return []
    modules = tuple(providers.get('python_scheduler_modules', ()))

    def scheduler(name: str | None) -> bool:
        return bool(name) and any(name == module or name.startswith(module + '.') for module in modules)

    for node in ast.walk(tree):
        names: list[str | None] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module]
        elif isinstance(node, ast.Attribute) and node.attr == 'beat_schedule':
            names = ['celery.schedules']
        if any(scheduler(name) for name in names):
            return [CostFinding('SCHEDULED_PAID_CALL', path, paid[0].line,
                                f'{paid[0].detail} in a module that schedules work at line {getattr(node, "lineno", 0)}')]
    return []


def _strongly_connected(graph: Mapping[str, set[str]]) -> list[set[str]]:
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    result: list[set[str]] = []
    counter = [0]

    def visit(node: str) -> None:
        work = [(node, iter(sorted(graph.get(node, ()))))]
        index[node] = low[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        while work:
            current, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter[0]
                    counter[0] += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(graph.get(child, ())))))
                    advanced = True
                    break
                if child in on_stack:
                    low[current] = min(low[current], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[current])
            if low[current] == index[current]:
                component = set()
                while True:
                    item = stack.pop()
                    on_stack.discard(item)
                    component.add(item)
                    if item == current:
                        break
                result.append(component)

    for node in sorted(graph):
        if node not in index:
            visit(node)
    return result


def n8n_findings(path: str, content: bytes, providers: Mapping[str, Any] | None = None) -> list[CostFinding]:
    providers = providers or load_providers()
    try:
        data = json.loads(content.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict) or not isinstance(data.get('nodes'), list) or not isinstance(data.get('connections'), dict):
        return []
    nodes = {node.get('name'): node for node in data['nodes'] if isinstance(node, dict) and node.get('name')}
    paid_types = set(providers['n8n_node_types'])
    paid: set[str] = set()
    findings = []
    for name, node in nodes.items():
        text = json.dumps(node.get('parameters', {}))
        hosts = _hosts_in(text, providers['hosts'])
        if node.get('type') in paid_types or hosts:
            paid.add(name)
            findings.append(CostFinding('PAID_CALL', path, 0, f"n8n node {name!r} ({node.get('type')})"))
    graph: dict[str, set[str]] = {name: set() for name in nodes}
    for source, outputs in data['connections'].items():
        for branches in (outputs or {}).values():
            for branch in branches or []:
                for link in branch or []:
                    if isinstance(link, dict) and link.get('node') in nodes and source in nodes:
                        graph[source].add(link['node'])
    markers = providers['n8n_counter_markers']
    bounded_types = set(providers['n8n_bounded_loop_types'])
    for component in _strongly_connected(graph):
        cyclic = len(component) > 1 or any(name in graph[name] for name in component)
        if not cyclic or not component & paid:
            continue
        bounded = any(nodes[name].get('type') in bounded_types for name in component) or any(
            marker in json.dumps(nodes[name].get('parameters', {})) for name in component for marker in markers)
        if not bounded:
            first = sorted(component & paid)[0]
            findings.append(CostFinding('UNBOUNDED_PAID_LOOP', path, 0,
                                        f'n8n cycle {sorted(component)} repeats paid node {first!r} without a counter'))
    return findings


def file_findings(path: str, content: bytes, providers: Mapping[str, Any] | None = None) -> list[CostFinding]:
    providers = providers or load_providers()
    if path.endswith('.py'):
        return python_findings(path, content, providers)
    if path.endswith('.json'):
        return n8n_findings(path, content, providers)
    if path.lower().endswith(CODE_SUFFIXES):
        hosts = _hosts_in(content.decode('utf-8', 'replace'), providers['hosts'])
        if hosts:
            return [CostFinding('UNANALYSED_PAID_CALL', path, 0, f'mentions {hosts[0]}; loops are not analysed for this language')]
    return []


def diff_cost_findings(root: Path, base: str | None, head: str) -> list[CostFinding]:
    from .diff_risk import changed_paths
    from .project_ingestion import _git
    findings: list[CostFinding] = []
    for change in changed_paths(root, base, head):
        if change.status == 'D':
            continue
        blob = _git(root, 'show', f'{head}:{change.path}', check=False)
        if blob.returncode == 0:
            findings.extend(file_findings(change.path, blob.stdout))
    return findings


# --- C03: contract -------------------------------------------------------------------------------

CONTRACT_FIELDS = {'schema_version', 'provider', 'max_calls', 'max_spend_usd_cents', 'stop_condition', 'alert',
                   'max_scheduled_runs_per_day',
                   'limit_symbol'}


def contract_problems(contract: Any) -> list[str]:
    if not isinstance(contract, dict):
        return ['COST_CONTRACT_INVALID: not a JSON object']
    problems = []
    if contract.get('schema_version') != 'cost-contract-v1':
        problems.append('COST_CONTRACT_INVALID: schema_version must be cost-contract-v1')
    unknown = set(contract) - CONTRACT_FIELDS
    if unknown:
        problems.append(f'COST_CONTRACT_INVALID: unknown fields {sorted(unknown)}')
    if not isinstance(contract.get('provider'), str) or not contract['provider'].strip():
        problems.append('COST_CONTRACT_INVALID: provider is required')
    if not isinstance(contract.get('max_calls'), int) or isinstance(contract.get('max_calls'), bool) or contract['max_calls'] < 1:
        problems.append('COST_CONTRACT_INVALID: max_calls must be a positive integer')
    spend = contract.get('max_spend_usd_cents')  # integer cents: records are canonical JSON, floats are refused
    if not isinstance(spend, int) or isinstance(spend, bool) or spend < 1:
        problems.append('COST_CONTRACT_INVALID: max_spend_usd_cents must be a positive integer (USD cents)')
    for name in ('stop_condition', 'alert'):
        if not isinstance(contract.get(name), str) or len(contract[name].strip()) < 10:
            problems.append(f'COST_CONTRACT_INVALID: {name} must say what happens (10+ characters)')
    if not isinstance(contract.get('limit_symbol'), str) or not contract['limit_symbol'].isidentifier():
        problems.append('COST_CONTRACT_INVALID: limit_symbol must name the code identifier that enforces the limit')
    if 'max_scheduled_runs_per_day' in contract:
        runs = contract['max_scheduled_runs_per_day']
        if not isinstance(runs, int) or isinstance(runs, bool) or runs < 1:
            problems.append('COST_CONTRACT_INVALID: max_scheduled_runs_per_day must be a positive integer')
    return problems


def bound_tested(root: Path, head: str, symbol: str, code_paths: Iterable[str], test_globs: Iterable[str]) -> bool:
    """The limit symbol appears in changed code and in at least one test at `head`."""
    from .diff_risk import matches
    from .project_ingestion import _git
    pattern = re.compile(r'(?<![\w])' + re.escape(symbol) + r'(?![\w])')

    def contains(path: str) -> bool:
        blob = _git(root, 'show', f'{head}:{path}', check=False)
        return blob.returncode == 0 and bool(pattern.search(blob.stdout.decode('utf-8', 'replace')))

    if not any(contains(path) for path in code_paths):
        return False
    listing = _git(root, 'ls-tree', '-r', '--name-only', '-z', head).stdout.decode('utf-8', 'surrogateescape').split('\0')
    return any(contains(path) for path in listing if path and matches(path, test_globs))


def write_state(runtime: Path, head: str, findings: Iterable[CostFinding]) -> None:
    """Paths and hosts the PreToolUse policy treats as a live paid run."""
    providers = load_providers()
    flagged = sorted({finding.path for finding in findings})
    runtime.mkdir(parents=True, exist_ok=True)
    (runtime / STATE_NAME).write_text(json.dumps({'schema_version': 'cost-guard-state-v1', 'head': head,
                                                  'flagged_paths': flagged, 'hosts': providers['hosts']}, indent=2) + '\n',
                                      encoding='utf-8', newline='\n')


# A command word: at the start or after a shell separator, and followed by whitespace or the end.
_WORD = r'(?:^|[\s;&|(`$])(?:[\w./\\-]*[/\\])?({})(?:\.exe)?(?=\s|$)'
NETWORK_CLIENTS = re.compile(_WORD.format('curl|wget|http|httpie|xh|invoke-webrequest|invoke-restmethod|iwr|irm'))
INTERPRETERS = re.compile(_WORD.format(
    r'python[0-9.]*|py|node|deno|bun|npx|tsx|ts-node|bash|sh|zsh|pwsh|powershell|uv|poetry'))


def paid_run_resource(command: str, runtime: Path | None = None) -> str | None:
    """The resource a shell command would spend money on: an n8n run, a provider call, or running a flagged file.

    Reading or searching code that mentions a provider is not a run: hosts count only with a
    network client in the command, flagged files only when an interpreter runs them.
    """
    providers = load_providers()
    lowered = ' '.join(command.lower().split())
    for run in providers['run_commands']:
        if run in lowered:
            return 'n8n'
    hosts = _hosts_in(lowered, providers['hosts'])
    if hosts and NETWORK_CLIENTS.search(lowered):
        return hosts[0]
    if runtime is not None and INTERPRETERS.search(lowered):
        try:
            state = json.loads((runtime / STATE_NAME).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return None
        for path in state.get('flagged_paths') or []:
            if isinstance(path, str) and path and re.search(r'(?<![\w/.-])' + re.escape(path.lower()) + r'(?![\w/-])', lowered):
                return path
    return None


@dataclass
class CostReport:
    status: str
    summary: str
    findings: list[CostFinding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    signal: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {'status': self.status, 'summary': self.summary, 'signal': self.signal,
                'findings': [item.to_dict() for item in self.findings[:100]], 'finding_count': len(self.findings),
                'problems': self.problems}


def evaluate(root: Path, route: Mapping[str, Any] | None, mode: str, bases: list[str], head: str,
             package: Path | None) -> CostReport:
    from .diff_risk import changed_paths, load_rules, matches
    strict = mode in {'pr', 'release'}
    signal = route_has_cost_signal(route)
    rules = load_rules()
    findings: list[CostFinding] = []
    changed_code: set[str] = set()
    for base in bases:
        for finding in diff_cost_findings(root, base, head):
            if finding not in findings:
                findings.append(finding)
        changed_code.update(change.path for change in changed_paths(root, base, head)
                            if change.status != 'D' and not matches(change.path, rules['tests'])
                            and not matches(change.path, rules['trivial']['allow']))
    if not signal and not findings:
        return CostReport('pass', 'no paid or unbounded operation in the prompt or the diff')
    problems = [f'{item.kind}: {item.path}:{item.line} {item.detail}' for item in findings if item.blocking]
    scheduled = [item for item in findings if item.kind == 'SCHEDULED_PAID_CALL']
    contract_path = package / CONTRACT_NAME if package is not None else None
    if contract_path is None or not contract_path.is_file():
        problems.append(f'COST_CONTRACT_MISSING: add {CONTRACT_NAME} to the active change package '
                        '(provider, max_calls, max_spend_usd_cents, stop_condition, alert, limit_symbol)')
    else:
        try:
            contract = json.loads(contract_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            contract = None
            problems.append(f'COST_CONTRACT_INVALID: {error}')
        if contract is not None:
            invalid = contract_problems(contract)
            problems.extend(invalid)
            if scheduled and not invalid and 'max_scheduled_runs_per_day' not in contract:
                # Default deny: a per-run limit does not bound a job that a scheduler repeats (#76).
                item = scheduled[0]
                problems.append(f'COST_SCHEDULE_UNBOUNDED: {item.path}:{item.line} is scheduled; '
                                'set max_scheduled_runs_per_day in the budget contract')
            if not invalid:
                code = sorted({item.path for item in findings if item.kind != 'UNANALYSED_PAID_CALL'}) or sorted(changed_code)
                if not code or not bound_tested(root, head, contract['limit_symbol'], code, rules['tests']):
                    problems.append(f"COST_BOUND_UNTESTED: {contract['limit_symbol']} must appear in the paid code and in a test")
    if problems:
        status = 'fail' if strict else 'pass'
        prefix = '' if strict else 'will fail pr/release: '
        return CostReport(status, prefix + problems[0], findings, problems, signal)
    return CostReport('pass', f'budget contract and tested bound present ({len(findings)} paid call sites)', findings, [], signal)
