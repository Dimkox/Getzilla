"""Fixed issue162 producer. Public entry accepts only an actual operation ref.

No acquisition, package import, process or ranking occurs on module import. The
operator/source/resource owners remain mandatory; missing ports fail unavailable.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from dataclasses import asdict, dataclass
import time

from .budget import RetrievalError
from .contracts import sha, digest
from .study_plan import (MODELS, ARMS, EXPECTED_WINDOWS, STAGE_LIMITS,
                         original_function_mapping, map_source_documents, project_function_positions)
from .study_results import Observations, paired_ratios
from .study_metrics import ranking_metrics
from .study_inspection_manifest import assemble, worker_contract
from .study_run_artifacts import RunArtifacts, serialized_payload


@dataclass(frozen=True)
class StudyOutcome:
    status: str
    execution_id: str
    artifacts: tuple
    inspection_result: object = None


def _ports():
    try:
        from . import public_study_operation as owner
        for name in ('reviewed_public_study_inputs', 'reviewed_public_study_catalog',
                     'reviewed_public_study_functions', 'reviewed_public_study_graphs',
                     'operation_public_source_cut', 'check_public_study_source_cuts',
                     'admit_public_study_stage'):
            if not callable(getattr(owner, name, None)):
                raise RetrievalError('study_owner_port_unavailable')
        from .public_study_storage import study_storage_observation
        if not callable(study_storage_observation):
            raise RetrievalError('study_owner_port_unavailable')
        return owner
    except ImportError:
        raise RetrievalError('study_owner_port_unavailable') from None


@contextmanager
def _cuts(ports, operation, catalog):
    with ExitStack() as stack:
        captured = [stack.enter_context(ports.operation_public_source_cut(operation, batch=batch))
                    for batch in (0, 1)]
        handles = tuple((broker, handle) for broker, handle, _ in captured)
        ports.check_public_study_source_cuts(operation, handles)
        documents = tuple(document for _, _, cut in captured for document in cut.documents)
        mapped = map_source_documents(catalog, documents)
        if len(mapped) != len(catalog):
            raise RetrievalError('study_source_catalog_incomplete')
        yield handles, {(corpus, path): raw for corpus, path, raw in mapped}
        ports.check_public_study_source_cuts(operation, handles)


def _deadline(owner, start, limit):
    value = min(owner.deadline, start + limit)
    if time.monotonic() >= value:
        raise RetrievalError('study_stage_deadline')
    return value


def _storage(ports, owner, additional=0):
    if type(additional) is not int or additional < 0:
        raise RetrievalError('study_storage_budget_exceeded')
    from .public_study_storage import study_storage_observation
    observed = study_storage_observation(owner.operation_ref, owner.execution_id)
    if (type(observed.logical_bytes) is not int or observed.logical_bytes < 0
            or observed.logical_bytes + additional > 12 * 1024**3):
        raise RetrievalError('study_storage_budget_exceeded')
    return observed


def _persist(ports, owner, output, name, payload, handles=None, *, absolute_deadline=None):
    def current_deadline():
        if absolute_deadline is not None and time.monotonic() >= absolute_deadline:
            raise RetrievalError('study_query_deadline')
    current_deadline()
    raw = serialized_payload(payload)
    _storage(ports, owner, additional=len(raw))
    owner.current()
    if handles is not None:
        stage = 'inspect_release' if owner.projection.operation == 'inspect_public_artifacts' else 'rank_release'
        ports.admit_public_study_stage(owner.operation_ref, owner.reference, stage, source_cuts=handles)
    current_deadline()
    row = output.write_bytes(name, raw)
    current_deadline()
    _storage(ports, owner)
    if handles is not None:
        ports.admit_public_study_stage(owner.operation_ref, owner.reference, stage, source_cuts=handles)
    current_deadline()
    return row


def _bind_output(owner, output):
    """Existing protected execution artifact locates its own immutable output root."""
    import json
    from ..parallel import _create_log
    from ..execution_output import capture_artifact
    from .. import execution
    raw = json.dumps({'definition': 'issue162-owned-run-output-v1',
        'execution_id': owner.execution_id, 'operation_digest': owner.projection.operation_digest},
        sort_keys=True).encode() + b'\n'
    _storage(_ports(), owner, additional=len(raw))
    with _create_log(output._directory, '000.log') as stream:
        if stream.write(raw) != len(raw):
            raise RetrievalError('study_artifact_write_unavailable')
    path = (output._folder / '000.log').relative_to(owner.projection.root).as_posix()
    reference = capture_artifact(owner.projection.root, path)
    record = owner.current()
    execution.record_event(owner.projection.root, owner.admission.token, owner.execution_id,
        record['revision'], owner.admission.execution_generation, 'study-artifact-root',
        {'execution_status': 'running', 'output': {'artifact': reference,
          'preview': 'Immutable study output root.', 'complete_output': False}})
    owner.backend.artifact_anchor = reference
    owner.backend.run_artifact_context = output


def _prepare(owner, model, graphs, deadline):
    native = owner._request('inspect_native_import', {'op': 'native-import'}, query_deadline=deadline)
    tokenizer = owner._request('inspect_tokenizer', {'op': 'load-tokenizer', 'model': model},
                                query_deadline=deadline)
    loaded = owner._request('inspect_runtime', {'op': 'load-model', 'model': model,
        'contract': worker_contract(graphs[model], model)}, query_deadline=deadline)
    return native, tokenizer, loaded


def _windows(ports, owner, catalog, grouped, *, stage_deadline):
    rows = []
    for corpus, path, _, _, _ in catalog:
        _deadline(owner, stage_deadline, 0)
        with _cuts(ports, owner.operation_ref, catalog) as (handles, sources):
            result = owner._request('inspect_windows', {'op': 'windows', 'corpus': corpus,
                'path': path, 'raw': sources[corpus, path].decode('utf-8'),
                'functions': list(grouped.get((corpus, path), ()))}, source_cuts=handles,
                query_deadline=stage_deadline)
            rows.extend(result['windows'])
    actual = {corpus: sum(row['corpus'] == corpus for row in rows) for corpus in EXPECTED_WINDOWS}
    if actual != EXPECTED_WINDOWS:
        raise RetrievalError('study_historical_windows_mismatch')
    return tuple(rows)


def _inspect(ports, owner, inputs, catalog, functions, graphs, output):
    grouped, _ = original_function_mapping(inputs.dataset[0], functions)
    start = time.monotonic()
    native, first, _ = _prepare(owner, 'minilm', graphs, _deadline(owner, start, 180))
    tokenizers = {'minilm': first}
    windows = _windows(ports, owner, catalog, grouped,
                       stage_deadline=_deadline(owner, start, STAGE_LIMITS['windows']))
    probes = {'minilm': owner._request('inspect_runtime', {'op': 'probe', 'model': 'minilm'})}
    tokenizers['bge_m3'] = owner._request('inspect_tokenizer', {'op': 'load-tokenizer', 'model': 'bge_m3'})
    lengths = {}
    for row in windows:
        with _cuts(ports, owner.operation_ref, catalog) as (handles, _):
            lengths['bge_m3', row['corpus'], row['id']] = owner._request('inspect_windows',
                {'op': 'inspect-length', 'model': 'bge_m3', 'corpus': row['corpus'], 'window_id': row['id']},
                source_cuts=handles, query_deadline=start + STAGE_LIMITS['windows'])
    owner._request('inspect_runtime', {'op': 'load-model', 'model': 'bge_m3',
                                      'contract': worker_contract(graphs['bge_m3'], 'bge_m3')})
    probes['bge_m3'] = owner._request('inspect_runtime', {'op': 'probe', 'model': 'bge_m3'})
    packing = owner._request('inspect_runtime', {'op': 'packing-probe'})
    from .study_supervisor import check_live_study_resource, _capture_scientific_inspection
    with _cuts(ports, owner.operation_ref, catalog) as (handles, _):
        observed = check_live_study_resource(owner.reference, owner.projection)
        assemble(inputs, owner.projection, catalog=catalog, graphs=graphs,
            tokenizers=tokenizers, conformance=probes, windows=windows, lengths=lengths,
            packing=packing, execution_id=owner.execution_id, readback_digest=observed.readback_digest)
        _persist(ports, owner, output, 'window-mapping.json', {'windows': windows}, handles)
        _persist(ports, owner, output, 'native-inspection-facts.json',
                 {'native': native, 'tokenizers': tokenizers, 'probes': probes, 'packing': packing}, handles)
        _capture_scientific_inspection(owner, handles)
    return windows


def _judgments(dataset):
    result = {}
    for table in dataset[3]['tables']:
        for row in table['rows']:
            result[row['task_id']] = dict(zip(table['function_ids'], row['judgments'], strict=True))
    return result


def _query_metrics(result, windows, stable, judgments):
    metrics = {}
    positives = {key for key, value in judgments.items() if value == 1}
    for arm, ranking in result['rankings'].items():
        positions = project_function_positions([row[0] for row in ranking], windows, stable)
        observed = ranking_metrics(positions, judgments)
        for limit in ('2048', '8192'):
            packed = result['packing'][arm][limit]
            included = {stable[key] for key in packed['functions'] if key in stable}
            observed['context_recall_' + limit + '_ratio'] = ([len(included & positives), len(positives)]
                                                             if positives else None)
            observed['context_tokens_' + limit] = packed['tokens']
        if not positives:
            observed.update(recall_at_5_ratio=None, mrr_at_10_ratio=None,
                no_answer={'returned': len(ranking), 'top_score': ranking[0][1] if ranking else None,
                           'threshold': 'none; candidates do not establish answerability'})
        metrics[arm] = observed
    return metrics


def _primary(dataset, observations, metric_rows):
    tasks = dataset[1]['tasks']
    queries = dataset[2]['queries']
    report = []
    for corpus in ('small', 'large'):
        ids = tuple(row['task_id'] for row in tasks if row['corpus'] == corpus
                    and row['split'] == 'holdout' and row['stratum'] != 'no_answer')
        for language in ('en', 'ru', 'mixed'):
            query_ids = {row['task_id']: row['query_id'] for row in queries if row['language'] == language}
            for baseline, candidate in (('dense_minilm', 'dense_bge_m3'), ('rrf_minilm', 'rrf_bge_m3')):
                for metric in ('recall_at_5_ratio', 'mrr_at_10_ratio',
                               'context_recall_2048_ratio', 'context_recall_8192_ratio'):
                    left, right = {}, {}
                    for task in ids:
                        query = query_ids[task]
                        left[task] = metric_rows.get(('minilm', query), {}).get(baseline, {}).get(metric)
                        right[task] = metric_rows.get(('bge_m3', query), {}).get(candidate, {}).get(metric)
                    report.append({'corpus': corpus, 'language': language, 'baseline': baseline,
                        'candidate': candidate, 'metric': metric, **paired_ratios(ids, left, right)})
    coverage = observations.coverage()
    status = ('INCONCLUSIVE' if not coverage['complete'] or coverage['failed'] or coverage['nondeterministic']
              or any(row['status'] == 'INCONCLUSIVE' for row in report) else
              'FAIL' if any(row['status'] == 'FAIL' for row in report) else 'PASS')
    return {'status': status, 'slices': report, 'observations': coverage,
            'quality_pass': 0, 'warm_passes': 10, 'arm_order': ARMS,
            'timing_observations': observations.timings()}


def _check_rank_reproduction(inputs, model, graph, tokenizer, windows):
    """The rank preparation must reproduce the already witnessed experiment."""
    manifest = inputs.inspection_manifest
    ordered = sorted(windows, key=lambda row: (('small', 'large').index(row['corpus']), row['id']))
    expected = manifest['models'][model]
    if (digest(ordered) != manifest['window_manifest']['ordered_windows_digest']
            or tokenizer['tokenizer_sha256'] != expected['tokenizer_sha256']
            or graph['graph_sha256'] != expected['graph_sha256']
            or graph['report_sha256'] != expected['graph_inspection_digest']):
        raise RetrievalError('study_phase_b_reproduction_failed')


def _rank(ports, owner, inputs, catalog, functions, graphs, output):
    grouped, mapping = original_function_mapping(inputs.dataset[0], functions)
    queries = tuple(inputs.dataset[2]['queries'])
    if len(queries) != 240 or len(inputs.dataset[1]['tasks']) != 80:
        raise RetrievalError('study_frozen_query_count_mismatch')
    tasks = {row['task_id']: row for row in inputs.dataset[1]['tasks']}
    judgments = _judgments(inputs.dataset)
    observations, metrics = Observations(tuple(row['query_id'] for row in queries)), {}
    lexical_pass0 = {}
    for model_index, model in enumerate(MODELS):
        for cold in range(3):
            start = time.monotonic()
            if model_index or cold:
                reference = owner.backend.advance(owner.reference)
                owner = reference._owner
            _storage(ports, owner)
            native, tokenizer, load = _prepare(owner, model, graphs, _deadline(owner, start, 180))
            _persist(ports, owner, output, f'cold-{model}-{cold}.json',
                {'fresh_process': True, 'process_cold_not_disk_cold': True,
                 'native': native, 'tokenizer': tokenizer, 'model_load': load,
                 'seconds': time.monotonic() - start})
        if model != 'minilm':
            owner._request('inspect_tokenizer', {'op': 'load-tokenizer', 'model': 'minilm'})
        windows = _windows(ports, owner, catalog, grouped,
                           stage_deadline=time.monotonic() + STAGE_LIMITS['windows'])
        _check_rank_reproduction(inputs, model, graphs[model], tokenizer, windows)
        by_corpus = {corpus: {row['id']: row for row in windows if row['corpus'] == corpus}
                     for corpus in EXPECTED_WINDOWS}
        for corpus in ('small', 'large'):
            limit = STAGE_LIMITS['small-index' if corpus == 'small' else model + '-large-index']
            stop = _deadline(owner, time.monotonic(), limit)
            for row in by_corpus[corpus].values():
                _deadline(owner, stop, 0)
                with _cuts(ports, owner.operation_ref, catalog) as (handles, _):
                    owner._request('rank_encode', {'op': 'encode', 'kind': 'window',
                        'corpus': corpus, 'window_id': row['id']}, source_cuts=handles, query_deadline=stop)
            with _cuts(ports, owner.operation_ref, catalog) as (handles, _):
                owner._request('rank_encode', {'op': 'prepare-index', 'corpus': corpus},
                               source_cuts=handles, query_deadline=stop)
        for iteration in range(10):
            for query in queries:
                start, key = time.monotonic(), query['query_id']
                corpus = tasks[query['task_id']]['corpus']
                stop = min(owner.deadline, start + 2)
                try:
                    with _cuts(ports, owner.operation_ref, catalog) as (handles, _):
                        embedding = owner._request('rank_encode', {'op': 'encode', 'kind': 'query',
                            'corpus': corpus, 'query_id': key, 'text': query['text']},
                            source_cuts=handles, query_deadline=stop)
                        result = owner._request('rank_score', {'op': 'score', 'corpus': corpus,
                            'query_id': key}, source_cuts=handles, query_deadline=stop)
                        stable = {historical: actual for (name, historical), actual in mapping.items() if name == corpus}
                        value = _query_metrics(result, by_corpus[corpus], stable, judgments[query['task_id']])
                        if iteration == 0:
                            metrics[model, key] = value
                            common = {arm: result['rankings'][arm] for arm in ('exact_symbol', 'bm25')}
                            if key in lexical_pass0 and lexical_pass0[key] != common:
                                raise RetrievalError('study_shared_lexical_parity_failed')
                            lexical_pass0[key] = common
                        elapsed = time.monotonic() - start
                        if time.monotonic() >= stop:
                            raise RetrievalError('study_query_deadline')
                        _persist(ports, owner, output, f'rank-{model}-{iteration:02}-{sha(key.encode())}.json',
                            {'query_id': key, 'pass': iteration, 'model': model,
                             'seconds_before_artifact_release': elapsed,
                             'embedding': embedding, 'result': result, 'metrics': value if iteration == 0 else None},
                             handles, absolute_deadline=stop)
                    elapsed = time.monotonic() - start
                    if time.monotonic() >= stop:
                        raise RetrievalError('study_query_deadline')
                    observations.add(model, iteration, key, result, seconds=elapsed,
                                     absolute_deadline=stop, query_started=start)
                except Exception:
                    # A failed owner may already be retired. Never reacquire
                    # permission or repeat work merely to write a diagnostic;
                    # the existing execution owner retains failure/cleanup.
                    raise
    return _primary(inputs.dataset, observations, metrics)


def run_fixed_study(operation_ref):
    """Actual fixed producer only; no caller model, corpus, queries or flags."""
    from .study_supervisor import (_operation, owned_study_runtime, _inspection_result_after_terminal)
    ports, projection = _ports(), _operation(operation_ref)
    inputs = ports.reviewed_public_study_inputs(operation_ref)
    catalog = ports.reviewed_public_study_catalog(operation_ref)
    functions = ports.reviewed_public_study_functions(operation_ref)
    graphs = ports.reviewed_public_study_graphs(operation_ref)
    if len(catalog) != 148 or projection.operation not in {'inspect_public_artifacts', 'rank_public_study'}:
        raise RetrievalError('study_fixed_scope_unavailable')
    if projection.operation == 'rank_public_study' and inputs.inspection_manifest is None:
        raise RetrievalError('study_phase_b_unavailable')
    with RunArtifacts(projection.root, byte_limit=12 * 1024**3) as output:
        with owned_study_runtime(operation_ref) as reference:
            owner = reference._owner
            _bind_output(owner, output)
            _storage(ports, owner)
            if projection.operation == 'inspect_public_artifacts':
                _inspect(ports, owner, inputs, catalog, functions, graphs, output)
                report = {'status': 'observed-inspection', 'ranking_permitted': False}
            else:
                report = _rank(ports, owner, inputs, catalog, functions, graphs, output)
                owner = owner.backend.owner
                with _cuts(ports, operation_ref, catalog) as (handles, _):
                    _persist(ports, owner, output, 'scientific-results.json', report, handles)
            _persist(ports, owner, output, 'artifact-manifest.json',
                     {'artifacts': [asdict(row) for row in output.manifest()]})
        result = (_inspection_result_after_terminal(owner)
                  if projection.operation == 'inspect_public_artifacts' else None)
        return StudyOutcome(report['status'], owner.execution_id, output.manifest(), result)
