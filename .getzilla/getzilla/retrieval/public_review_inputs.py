"""Scientific source-review consistency only. No witness, source or model authority."""
import hashlib
import json
import math
import re
import time

from .budget import RetrievalError
from .contracts import label, sha
from .evaluation_inputs import ISSUE_162_PROFILE, audit_draft_inputs


def _require(value, reason='public_review_incomplete'):
    if not value:
        raise RetrievalError(reason)


class ScientificBudget:
    """Computational guard only; never a source/model/paid-work permission."""
    def __init__(self, deadline=None):
        now = time.monotonic()
        self.deadline = now + 30 if deadline is None else deadline
        _require(type(self.deadline) in (int, float) and math.isfinite(self.deadline)
                 and now < self.deadline <= now + 30, 'public_review_deadline')
        self.work = 0

    def check(self):
        self.work += 1
        _require(self.work <= 4000000 and time.monotonic() < self.deadline, 'public_review_deadline')


def reviewed_digest(value, budget):
    """Canonical logical-union digest; no second physical JSON decode."""
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    hasher, total = hashlib.sha256(), 0
    for index, piece in enumerate(encoder.iterencode(value)):
        if index % 1024 == 0:
            budget.check()
        raw = piece.encode()
        total += len(raw)
        _require(total <= 16 * 1048576, 'public_review_group_bytes')
        hasher.update(raw)
    budget.check()
    return hasher.hexdigest()


def _reason(value):
    return type(value) is str and 0 < len(value.encode('utf-8')) <= 8192 and '\0' not in value


def _reviewer(report):
    reviewer = report['reviewer']
    _require(type(reviewer) is dict and set(reviewer) == {
        'agent_task', 'role', 'native_session_id', 'native_generation'})
    _require(reviewer['role'] == 'data_reviewer' and label(reviewer['agent_task'])
             and label(reviewer['native_session_id'])
             and all(reviewer[name].lower() not in {'unknown', 'unavailable', 'none'}
                     for name in ('agent_task', 'native_session_id'))
             and (reviewer['native_generation'] is None
             or label(reviewer['native_generation'])))
    # These are facts witnessed by the operator, never native authentication.
    return reviewer['agent_task'], reviewer['native_session_id']


def _wave(reports, universes, tasks, input_hashes, author, budget):
    cells = {}
    for report in reports:
        budget.check()
        _require(type(report) is dict and not set(report) - {'schema_version', 'kind', 'reviewer',
            'corpus', 'slice_start', 'slice_end', 'function_ids', 'input_hashes', 'universe_digest',
            'tasks', 'source_evidence', 'limitations', 'report_path'})
        _require(type(report['schema_version']) is int and report['schema_version'] == 1
                 and report['kind'] == 'independent_partial_qrels_v1'
                 and report['input_hashes'] == input_hashes)
        reviewer = _reviewer(report)
        report_digest = reviewed_digest(report, budget)
        _require(reviewer[0] != author[0] and reviewer[1] != author[1], 'public_review_self_review')
        corpus = report['corpus']
        _require(corpus in universes)
        universe = universes[corpus]
        start, end = report['slice_start'], report['slice_end']
        _require(type(start) is int and type(end) is int and 0 <= start < end <= len(universe['functions']))
        selected = universe['functions'][start:end]
        _require(report['function_ids'] == [f['function_id'] for f in selected]
                 and report['universe_digest'] == universe['universe_digest'])
        expected_tasks = {name for name, task in tasks.items() if task['corpus'] == corpus}
        observed_tasks, local = set(), {}
        for row in report['tasks']:
            budget.check()
            _require(type(row) is dict and set(row) == {'task_id', 'judgments', 'issues'}
                     and row['task_id'] in expected_tasks and row['task_id'] not in observed_tasks
                     and type(row['judgments']) is list and len(row['judgments']) == end - start
                     and type(row['issues']) is list)
            observed_tasks.add(row['task_id'])
            issue_indices, unscoped_issue = set(), False
            for issue in row['issues']:
                budget.check()
                _require(type(issue) is str)
                scoped = re.match(r'^index ([0-9]+):', issue)
                if scoped is None:
                    unscoped_issue = True
                else:
                    location = int(scoped[1])
                    _require(start <= location < end)
                    issue_indices.add(location)
            for index, decision in enumerate(row['judgments'], start):
                budget.check()
                _require(type(decision) is int and decision in (0, 1, 2))
                key = corpus, row['task_id'], index
                _require(key not in cells)
                local[key] = (decision, reviewer, report_digest, unscoped_issue or index in issue_indices)
        _require(observed_tasks == expected_tasks)
        evidence_cells = set()
        for evidence in report['source_evidence']:
            budget.check()
            _require(type(evidence) is dict and set(evidence) == {
                'task_id', 'decision', 'function_indices', 'rationale', 'locators'}
                and _reason(evidence['rationale'])
                and type(evidence['function_indices']) is list and evidence['function_indices'])
            locators = evidence['locators']
            names = ('path', 'start', 'end', 'file_sha256', 'declaration_sha256')
            _require(type(locators) is list and all(type(locator) is dict and set(locator) == set(names) for locator in locators))
            locator_keys = {tuple(locator[name] for name in names) for locator in locators}
            for index in evidence['function_indices']:
                budget.check()
                _require(type(index) is int and start <= index < end)
                key = corpus, evidence['task_id'], index
                _require(key in local and key not in evidence_cells
                         and type(evidence['decision']) is int and local[key][0] == evidence['decision'])
                function = universe['functions'][index]
                locator = tuple(function[name] for name in names)
                _require(locator in locator_keys, 'public_review_source_evidence_missing')
                evidence_cells.add(key)
        _require(evidence_cells == set(local), 'public_review_source_evidence_missing')
        cells.update(local)
    expected = {(corpus, name, index) for corpus, universe in universes.items()
                for name, task in tasks.items() if task['corpus'] == corpus
                for index in range(len(universe['functions']))}
    _require(set(cells) == expected, 'public_review_coverage_incomplete')
    return cells


def validate_reviewed_inputs(data, predecessor_hashes, initial_reports, second_reports, query_report, *,
                             author, dispositions, no_answer_resolutions, profile=ISSUE_162_PROFILE, budget=None, query_hashes=None, adjudications=None):
    """Validate enumerated original facts. A returned mapping cannot mint a ref.

    The action owner separately binds original bytes, predecessor lineage,
    current source and actual witnessed delivery. This function grants none.
    """
    try:
        budget = ScientificBudget() if budget is None else budget
        _require(type(budget) is ScientificBudget)
        budget.check()
        audit = audit_draft_inputs(*data, profile=profile)
        _require(audit.unjudged_cells == 0, 'public_review_unjudged')
        universes = {row['corpus']: row for row in data[0]['universes']}
        tasks = {row['task_id']: row for row in data[1]['tasks']}
        _require(type(author) is tuple and len(author) == 2 and all(label(v) and
            v.lower() not in {'unknown', 'unavailable', 'none'} for v in author))
        first = _wave(initial_reports, universes, tasks, predecessor_hashes, author, budget)
        second = _wave(second_reports, universes, tasks, predecessor_hashes, author, budget)
        final = {(table['corpus'], row['task_id'], index): decision for table in data[3]['tables']
                 for row in table['rows'] for index, decision in enumerate(row['judgments'])}
        positions = {corpus: {function['function_id']: index for index, function in enumerate(universe['functions'])}
                     for corpus, universe in universes.items()}
        resolved = {}
        adjudications = {} if adjudications is None else adjudications
        for row in dispositions:
            budget.check()
            required = {'corpus', 'task_id', 'function_id', 'first', 'second', 'final',
                        'initial_report_digest', 'second_report_digest', 'reason'}
            _require(type(row) is dict and required <= set(row) <= required | {
                'adjudication_report_sha256', 'adjudication_decision_index'})
            index = positions[row['corpus']].get(row['function_id'])
            _require(index is not None and _reason(row['reason'])
                     and all(type(row[name]) is int for name in ('first', 'second', 'final')))
            key = row['corpus'], row['task_id'], index
            _require(key in first and key not in resolved and row['first'] == first[key][0]
                     and row['second'] == second[key][0] and row['final'] == final[key]
                     and row['initial_report_digest'] == first[key][2]
                     and row['second_report_digest'] == second[key][2])
            resolved[key] = row
        needed = set()
        for key, (value, reviewer, _, issues) in second.items():
            budget.check()
            old, original_reviewer, _, _ = first[key]
            third = adjudications.get(key)
            if third is None:
                _require(value in (1, 2) and value == final[key] and not issues)
            else:
                _require(third['decision'] == final[key] and all(
                    third['reviewer'][index] not in (reviewer[index], original_reviewer[index], author[index])
                    for index in (0, 1)), 'public_review_self_review')
            _require(reviewer[0] != original_reviewer[0] and reviewer[1] != original_reviewer[1], 'public_review_self_review')
            if old != value or third is not None:
                needed.add(key)
            if third is not None:
                disposition = resolved.get(key)
                _require(disposition is not None and disposition.get('adjudication_report_sha256') == third['raw_sha256']
                         and disposition.get('adjudication_decision_index') == third['decision_index'])
            elif key in resolved:
                _require(resolved[key].get('adjudication_report_sha256') is None
                         and resolved[key].get('adjudication_decision_index') is None)
        _require(set(resolved) == needed and set(adjudications) <= set(second), 'public_review_disagreement_unresolved')
        _queries(query_report, data[2], tasks, final, universes, query_hashes or predecessor_hashes, author,
                 no_answer_resolutions, budget)
        return {'cells': len(final), 'tasks': len(tasks), 'variants': len(data[2]['queries']),
                'initial_reports': sorted({row[2] for row in first.values()}),
                'second_reports': sorted({row[2] for row in second.values()}),
                'ranking_permitted': False, 'qualification': 'scientific-consistency-only'}
    except RetrievalError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, RecursionError):
        raise RetrievalError('public_review_incomplete') from None


def _queries(report, queries, tasks, final, universes, hashes, author, resolutions, budget):
    _require(type(report) is dict and not set(report) - {'schema_version', 'kind', 'reviewer', 'input_hashes',
        'clusters', 'limitations', 'report_path'} and type(report['schema_version']) is int
        and report['schema_version'] == 1 and report['kind'] == 'independent_query_review_v1'
        and report['input_hashes'] == hashes)
    reviewer = _reviewer(report)
    _require(reviewer[0] != author[0] and reviewer[1] != author[1], 'public_review_self_review')
    resolution_map = {}
    query_digest = reviewed_digest(report, budget)
    for row in resolutions:
        budget.check()
        _require(type(row) is dict and set(row) == {'task_id', 'query_report_digest', 'decision', 'reason'}
                 and row['task_id'] not in resolution_map and row['query_report_digest'] == query_digest
                 and row['decision'] == 'confirmed-no-answer-from-complete-source-reviews' and _reason(row['reason']))
        resolution_map[row['task_id']] = row
    observed, needed = set(), set()
    query_map = {row['query_id']: row for row in queries['queries']}
    for cluster in report['clusters']:
        budget.check()
        _require(type(cluster) is dict and set(cluster) == {'task_id', 'cluster_id', 'corpus', 'split',
            'declared_stratum', 'partition_grouping', 'stratum_fit', 'novelty', 'source_answerability',
            'nearest_task_ids', 'source_locators', 'rationale', 'variants'})
        task_id = cluster['task_id']
        _require(task_id in tasks and task_id not in observed)
        observed.add(task_id)
        task = tasks[task_id]
        _require(all(cluster[name] == task[name] for name in ('cluster_id', 'corpus', 'split'))
                 and cluster['declared_stratum'] == task['stratum'] and cluster['partition_grouping'] == 'supported'
                 and cluster['novelty'] == ('development_reference' if task['split'] == 'development' else 'distinct_intent_supported')
                 and _reason(cluster['rationale']))
        relevant = any(final[(task['corpus'], task_id, index)] == 1
                       for index in range(len(universes[task['corpus']]['functions'])))
        _require(relevant == (task['stratum'] != 'no_answer'), 'public_review_stratum_failure')
        known_locators = [{name: function[name] for name in
            ('path', 'start', 'end', 'file_sha256', 'declaration_sha256')}
            for function in universes[task['corpus']]['functions']]
        _require(type(cluster['source_locators']) is list
                 and (not relevant or cluster['source_locators'])
                 and all(locator in known_locators for locator in cluster['source_locators']),
                 'public_review_source_evidence_missing')
        _require(type(cluster['nearest_task_ids']) is list and all(
            name in tasks and name != task_id for name in cluster['nearest_task_ids']))
        if cluster['stratum_fit'] != 'supported' or cluster['source_answerability'] == 'declared_no_answer_not_exhaustively_certified':
            _require(task['stratum'] == 'no_answer' and cluster['stratum_fit'] in ('supported', 'ambiguous')
                     and cluster['source_answerability'] == 'declared_no_answer_not_exhaustively_certified')
            needed.add(task_id)
        else:
            _require(cluster['source_answerability'] == ('confirmed_no_answer' if not relevant else 'direct_support_observed'))
        variants = set()
        for variant in cluster['variants']:
            budget.check()
            _require(type(variant) is dict and set(variant) == {'query_id', 'language', 'text_sha256',
                'semantic_equivalence', 'mixed_language_factor', 'rationale', 'proposed_text'})
            qid = variant['query_id']
            _require(qid in query_map and qid not in variants)
            query = query_map[qid]
            _require(query['task_id'] == task_id and query['language'] == variant['language']
                     and variant['text_sha256'] == sha(query['text'].encode())
                     and variant['semantic_equivalence'] == 'supported'
                     and variant['mixed_language_factor'] == ('natural_identifier_mixed'
                         if query['language'] == 'mixed' else 'not_applicable')
                     and variant['proposed_text'] is None and _reason(variant['rationale']))
            variants.add(qid)
        _require(variants == {q['query_id'] for q in queries['queries'] if q['task_id'] == task_id})
    _require(observed == set(tasks) and set(resolution_map) == needed, 'public_review_query_unresolved')
