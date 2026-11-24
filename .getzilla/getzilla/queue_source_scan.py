"""Changed-source queue delta scan; fitness owns canonical primitives and state."""
from __future__ import annotations

from pathlib import Path
from .architecture_diff import ArchitectureDiff


def _new_queue_sources(
    root: Path,
    diff: ArchitectureDiff,
    python: _PythonInventory,
    source_roots: tuple[str, ...],
) -> _QueueProvenanceResult:
    from . import architecture_fitness as _fitness_owner
    applicable: list[str] = []
    unsupported: list[str] = []
    changed_signals: set[str] = set()
    limits: list[tuple[str, str, str]] = []
    causes: list[tuple[str, str, str, str, str]] = []
    depth_contexts: list[tuple[str, str, _QueueDepthContext]] = []
    depth_contexts_omitted = 0
    with _fitness_owner.diagnostics.span('arch-queue-inventory-head', stage='action'):
        head_cache = _fitness_owner._queue_module_inventory(root, diff, "head", source_roots)
    with _fitness_owner.diagnostics.span('arch-queue-inventory-base', stage='action'):
        base_cache = _fitness_owner._queue_module_inventory(root, diff, "base", source_roots)
    for path in _fitness_owner._python_paths(diff):
        side = "head"
        stage = "resolve_package"
        try:
            with _fitness_owner._source_span(path, side, 'resolve'):
                current_package = _fitness_owner._module_package(path, source_roots, head_cache.paths)
            stage = 'read'
            with _fitness_owner._source_span(path, side, 'read'):
                head_value = _fitness_owner.read_diff_file(root, diff, path, 'head')
            if head_value is None:
                raise _fitness_owner.ArchitectureError('changed Python source is unavailable', code='missing')
            head_budget = _fitness_owner._QueueBudget('head', profile=head_cache.profile)
            stage = 'admit'
            with _fitness_owner._source_span(path, side, 'admit'):
                head_budget.source(path, head_value)
            # These two boundaries retain complete parsed source scopes.
            # Synthetic export/return consumers do not grant module provenance.
            stage = 'parse'
            with _fitness_owner._source_span(path, side, 'parse'):
                head_tree = python.tree(path)
            stage = 'classify'
            with _fitness_owner._source_span(path, side, 'classify'):
                head = _fitness_owner._queue_signals(
                    root, diff, head_tree, "head", head_cache, current_package, source_roots,
                    source_path=path, source=head_value, budget=head_budget, complete_module=True,
                )
            side = "base"
            stage = "read"
            with _fitness_owner._source_span(path, side, 'read'):
                base_value = _fitness_owner.read_diff_file(root, diff, path, "base")
            base = _fitness_owner._QueueProvenanceResult("not_queue", "no_base_source", ())
            if base_value is not None:
                base_budget = _fitness_owner._QueueBudget('base', profile=base_cache.profile)
                stage = 'admit'
                with _fitness_owner._source_span(path, side, 'admit'):
                    base_budget.source(path, base_value)
                stage = 'parse'
                with _fitness_owner._source_span(path, side, 'parse'):
                    base_tree = _fitness_owner.ast.parse(base_value.decode("utf-8"), filename=path)
                    if sum(1 for _ in _fitness_owner.ast.walk(base_tree)) > _fitness_owner.MAX_ANALYZED_AST_NODES:
                        raise _fitness_owner.ArchitectureError(f"Python AST node limit exceeded: {path}", code="limit")
                stage = 'classify'
                try:
                    with _fitness_owner._source_span(path, side, 'classify'):
                        base = _fitness_owner._queue_signals(
                            root, diff, base_tree, "base", base_cache, current_package, source_roots,
                            source_path=path, source=base_value, budget=base_budget, complete_module=True,
                        )
                except _fitness_owner._UnsupportedQueueCallbackError:
                    if not head.complete_empty:
                        raise
                    causes.append((path, 'base', 'classify', 'complete_empty_head', 'fitness'))
                    continue
            stage = 'compare'
            delta = set(head.signals) - set(base.signals)
            if delta:
                changed_signals.update(f"{path}:{signal}" for signal in delta)
                outcome = head.state if head.state in {"unsupported", "resolved", "not_queue"} else "unknown"
                causes.append((path, "head", "classify", "returned_queue_signal", outcome))
                if head.state == "unsupported":
                    unsupported.append(path)
                else:
                    applicable.append(path)
        except _fitness_owner.ArchitectureError as exc:
            if exc.code == "limit":
                limits.append((path, side, _fitness_owner._queue_limit_text(exc)))
                context = _fitness_owner._queue_exception_depth_context(exc, side)
                if context is not None:
                    if len(depth_contexts) < _fitness_owner._QUEUE_DEPTH_CONTEXT_LIMIT:
                        depth_contexts.append((path, side, context))
                    else:
                        depth_contexts_omitted += 1
            else:
                unsupported.append(path)
                code = _fitness_owner._queue_diagnostic_code(exc.code)
                changed_signals.add(f"{path}:unsupported:{code}")
                causes.append((path, side, stage, "architecture_error", code))
        except (SyntaxError, UnicodeDecodeError):
            value = _fitness_owner.read_diff_file(root, diff, path, "head") or b""
            if _fitness_owner.re.search(
                rb"\b(celery|rq|redis|kombu|pika|kafka|confluent_kafka|enqueue|apply_async|send_task)\b",
                value,
            ):
                unsupported.append(path)
                changed_signals.add(f"{path}:unsupported:syntax")
                causes.append((path, side, stage, "syntax_error", "syntax"))
    if unsupported or limits:
        return _fitness_owner._QueueProvenanceResult(
            "unsupported",
            "analysis_limit_exceeded" if limits else "queue_provenance_unresolved",
            tuple(sorted(changed_signals)),
            tuple(sorted(set((*applicable, *unsupported)))),
            tuple(sorted(limits)),
            tuple(sorted(causes)),
            depth_contexts=tuple(depth_contexts), depth_contexts_omitted=depth_contexts_omitted,
        )
    if applicable:
        return _fitness_owner._QueueProvenanceResult(
            "resolved",
            "new_queue_signal",
            tuple(sorted(changed_signals)),
            tuple(sorted(set(applicable))),
            causes=tuple(sorted(causes)),
        )
    return _fitness_owner._QueueProvenanceResult("not_queue", "no_queue_signal", (), causes=tuple(sorted(causes)))

from .architecture_fitness import _PythonInventory, _QueueProvenanceResult, _QueueDepthContext  # noqa: F401 canonical annotation/result types
