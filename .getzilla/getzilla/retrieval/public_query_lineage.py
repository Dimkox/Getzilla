"""Fixed pre-seal rejected-query revision consistency, not review authority."""
import json
import re

from .contracts import sha
from .evaluation_inputs_io import INPUTS
from .public_review_inputs import _require, _reason, _reviewer


def query_revision(old, new, old_raw, new_raw, old_report, tasks, *, expected_sha256, expected_changes, budget):
    budget.check()
    _require(sha(new_raw) == expected_sha256 and len(old['queries']) == len(new['queries'])
             and {k: v for k, v in old.items() if k != 'queries'} == {k: v for k, v in new.items() if k != 'queries'},
             'public_query_revision_unavailable')
    english = {q['task_id']: q for q in old['queries'] if q['language'] == 'en'}
    weak = {v['query_id'] for c in old_report['clusters'] for v in c['variants']
            if v['language'] == 'mixed' and v['mixed_language_factor'] == 'suffix_only_or_weak'}
    changed, inverse = {}, new_raw
    for index, (a, b) in enumerate(zip(old['queries'], new['queries'])):
        budget.check()
        _require({k: v for k, v in a.items() if k != 'text'} == {k: v for k, v in b.items() if k != 'text'})
        if a['text'] == b['text']:
            continue
        _require(a['language'] == 'mixed' and tasks[a['task_id']]['stratum'] == 'exact')
        en = english[a['task_id']]
        identifiers = re.fullmatch(r'Locate ([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?: in ([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*))?\.', en['text'])
        _require(identifiers is not None)
        ids = [value for value in identifiers.groups() if value]
        for identifier in ids:
            pattern = r'(?<![A-Za-z0-9_])' + re.escape(identifier) + r'(?![A-Za-z0-9_])'
            _require(re.search(pattern, a['text']) is not None and re.search(pattern, b['text']) is not None)
        old_token = json.dumps(a['text'], ensure_ascii=False).encode()
        new_token = json.dumps(b['text'], ensure_ascii=False).encode()
        _require(inverse.count(new_token) == 1)
        inverse = inverse.replace(new_token, old_token, 1)
        changed[a['query_id']] = {'task_id': a['task_id'], 'query_id': a['query_id'],
            'corpus': tasks[a['task_id']]['corpus'], 'pointer': '/queries/' + str(index) + '/text',
            'old_text_sha256': sha(a['text'].encode()), 'new_text_sha256': sha(b['text'].encode()),
            'base_en_query_id': en['query_id'], 'base_en_text_sha256': sha(en['text'].encode()),
            'code_identifiers': ids}
    _require(set(changed) == weak and len(changed) == expected_changes and inverse == old_raw,
             'public_query_revision_unavailable')
    return changed


def source_equivalence(report, original, annotation_sha256, changed, *, corpus_manifest, old_query_sha256,
                       new_query_sha256, budget):
    budget.check()
    _require(type(report) is dict and set(report) == {'schema_version', 'kind', 'reviewer', 'original_annotation_sha256',
        'original_query_sha256', 'revised_query_sha256', 'corpus', 'source_commit', 'manifest_sha256', 'universe_digest',
        'slice_start', 'slice_end', 'function_ids', 'touched_variants', 'observed_provenance', 'limitations'}
        and type(report['schema_version']) is int and report['schema_version'] == 1
        and report['kind'] == 'independent_source_query_equivalence_v1'
        and report['original_annotation_sha256'] == annotation_sha256
        and report['original_query_sha256'] == old_query_sha256
        and report['revised_query_sha256'] == new_query_sha256
        and report['reviewer'] == original['reviewer'], 'public_query_equivalence_missing')
    _reviewer(report)
    for key in ('corpus', 'universe_digest', 'slice_start', 'slice_end', 'function_ids'):
        _require(report[key] == original[key], 'public_query_equivalence_scope')
    commit, manifest_sha = corpus_manifest
    _require(report['source_commit'] == commit and report['manifest_sha256'] == manifest_sha)
    expected = {qid: row for qid, row in changed.items() if row['corpus'] == original['corpus']}
    seen = set()
    for row in report['touched_variants']:
        budget.check()
        _require(type(row) is dict and set(row) == {'task_id', 'query_id', 'old_text_sha256', 'new_text_sha256',
            'base_en_query_id', 'base_en_text_sha256', 'code_identifiers', 'inspected_meaning', 'base_en_intent',
            'label_impact', 'rationale'} and row['query_id'] in expected and row['query_id'] not in seen)
        known = expected[row['query_id']]
        _require(all(row[key] == known[key] for key in ('task_id', 'query_id', 'old_text_sha256', 'new_text_sha256',
            'base_en_query_id', 'base_en_text_sha256', 'code_identifiers'))
            and row['base_en_intent'] == 'preserved' and row['label_impact'] == 'unchanged'
            and _reason(row['inspected_meaning']) and _reason(row['rationale']), 'public_query_equivalence_unresolved')
        seen.add(row['query_id'])
    _require(seen == set(expected), 'public_query_equivalence_missing')
    return {(original['corpus'], row['task_id'], index) for row in expected.values()
            for index in range(original['slice_start'], original['slice_end'])}


def third_source(report, *, raw_sha256, universes, predecessor_hashes, queries, budget):
    """Consume actual retained third-source format; normalize identity only in memory."""
    budget.check()
    _require(type(report) is dict and set(report) == {'schema_version', 'kind', 'reviewer', 'authority', 'corpus',
        'source_commit', 'input_hashes', 'decisions', 'dependency_sources', 'inspection', 'limitations'}
        and type(report['schema_version']) is int and report['schema_version'] == 1
        and report['kind'] == 'independent_third_source_adjudication_v1')
    original = report['reviewer']
    _require(set(original) == {'task_name', 'native_session_id', 'generation', 'role'})
    identity = {'agent_task': original['task_name'], 'native_session_id': original['native_session_id'],
                'native_generation': original['generation'], 'role': original['role']}
    reviewer = _reviewer({'reviewer': identity})
    _require({name: report['input_hashes']['candidate-v3/' + name] for name in INPUTS} == predecessor_hashes)
    corpus = report['corpus']
    universe = universes[corpus]
    _require(report['source_commit'] == universe['source_commit'])
    result = {}
    for ordinal, row in enumerate(report['decisions']):
        budget.check()
        index, task = row['function_index'], row['task_id']
        _require(type(index) is int and 0 <= index < len(universe['functions'])
                 and row['function'] == universe['functions'][index]
                 and type(row['decision']) is int and row['decision'] in (1, 2)
                 and _reason(row['rationale']) and _reason(row['query_meaning']))
        _require(row['queries'] == [q for q in queries['queries'] if q['task_id'] == task])
        key = corpus, task, index
        _require(key not in result)
        result[key] = {'decision': row['decision'], 'reviewer': reviewer,
                       'raw_sha256': raw_sha256, 'decision_index': ordinal}
    return result
