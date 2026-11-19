"""Explicit current-owner witness of external public review deliveries.

This is operator-witnessed-public-only, never authenticated native delivery,
human security approval, private access or model/execution authority.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import time

from .. import state
from ..continuity import context_binding
from ..optional_modules import admit_module
from ..receipts import get_receipt, write_receipt, _exact_head
from ..util import tree_fingerprint
from ..trace_storage import native_root
from .budget import RetrievalError
from .contracts import digest, sha, label
from .evaluation_inputs import ISSUE_162_PROFILE, checked_relative, audit_draft_inputs
from .evaluation_inputs_io import INPUTS, MAX_JSON_BYTES, MAX_TOTAL_JSON_BYTES, _json
from .public_review_inputs import validate_reviewed_inputs, ScientificBudget, reviewed_digest, _require
from .public_query_lineage import query_revision, source_equivalence, third_source
from .research import CATALOGS, PUBLIC_LIMITS

ASSURANCE = 'operator-witnessed-public-only'
KIND = 'retrieval-public-witness-a'
PRODUCER_KIND = 'retrieval-public-producer-reference'
_PRODUCERS = {
    ('b1e1245b7d56570388cda4497d769cca0b8225361f8b80f27af9bf43a264e063', 12774653),
    ('2eb8d3850f59d816cbeac4bce46c9292254df274640a580540f4973f0b93aac8', 8591594),
}
MAX_GROUPS, MAX_SHARDS = 16, 4
MAX_WITNESS_BYTES, WITNESS_SECONDS = 128 * 1048576, 30
_HASH_ONLY_B = ('5971c88d285172e345a07418dd269ae63760c4e147efe01f3a3c7cd13846981c', 6967743)
_PRODUCER_SEMANTIC = {
    _HASH_ONLY_B[0]: '2d24769f3f43a0d1a9fa0cb343495b1881cd97989589bb06edd1e297726aa6fc',
    'b1e1245b7d56570388cda4497d769cca0b8225361f8b80f27af9bf43a264e063':
        '5b7d2ee6544aca3fbecdf36395daafcc26c8976c5172b06ca01a63b1f90fa6d3',
    '2eb8d3850f59d816cbeac4bce46c9292254df274640a580540f4973f0b93aac8':
        'a7e06e31b863903f869b4275c9686c16ca5e0b62f1d01ac9845911deecf1d899',
}
_ISSUER = object()


@dataclass(frozen=True)
class _Composition:
    profile: str
    audit_profile: object
    catalogs: tuple
    config_sha256: str
    predecessor_hashes: tuple
    query_revision_sha256: str | None = None
    original_language_sha256: str | None = None
    query_changes: int = 16


_PRODUCTION = _Composition('public-research162/v1', ISSUE_162_PROFILE, CATALOGS,
    'edfad980d8ddd72dfb9ec3ce9d1879e57974ccb6ad48daa5bfa66b5835ca688a', (
    'a4f490dc8199b735bfb0d2bcc4d75a98eb3f8d3cd828fe6d3abe89ba68cbfb39',
    'bc9bf68bf922aa58351377f4e42ae098b13b1f15e251d44f65cd40bec96e4979',
    'f9bfbd0bb662b097193838367c34c06f3ec13e850985cc469a2212e21511172a',
    'c712abc7dea70f6bc047dd2f9ebd6febb8e693b0874e60942d491533ad34a315'),
    'a58592fcf7e78e46145d51680bc34d602f5ff594bbb41cb94cefe3f9917f34e0',
    '125fa78acebbe6b2509f2fb1901d65bf92715f4bb443b4768e58054fa7a7ad19')


class OperatorWitnessedPublicReviewedInputs:
    __slots__ = ('_issuer', '_root', '_profile', '_receipt_digest')

    def __new__(cls, *args, **kwargs):
        raise TypeError('explicit current-owner public review witness required')

    def __setattr__(self, name, value):
        raise AttributeError('public review witness is immutable')

    def __reduce__(self):
        raise TypeError('public review witness cannot be serialized')


def _identity(info):
    return {key: getattr(info, key) for key in
            ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')}


class _Capture:
    def __init__(self, root):
        root = Path(root)
        self.root = root
        self.deadline = time.monotonic() + WITNESS_SECONDS
        self.used, self.dependencies = 0, {}
        self.group_start = None
        self.group_bytes = {}
        with native_root(root) as anchor:
            self.physical_root = anchor.identity
            self.route = state.require_route_owner(root, anchor=anchor)
            self.context = context_binding(root, self.route, anchor=anchor)
            from .policy_inputs import validate_policy
            policy = anchor.read('.getzilla/config/policy.json', source=True)
            validate_policy(policy)
            self.policy = sha(policy)
            self.manifest = sha(anchor.read('.getzilla/managed-components.json', source=True))
            _require(admit_module(root, 'retrieval-research').get('allowed'), 'public_witness_unavailable')
        self.source_binding = (_exact_head(root), tree_fingerprint(root))
        _require(self.source_binding[0] is not None, 'public_witness_source_unavailable')
        self.current()

    def check(self):
        _require(time.monotonic() < self.deadline, 'public_witness_deadline')

    def current(self):
        self.check()
        with native_root(self.root) as anchor:
            route = state.require_route_owner(self.root, anchor=anchor)
            _require(anchor.identity == self.physical_root and route['route_id'] == self.route['route_id']
                and route.get('session_id') == self.route.get('session_id')
                and context_binding(self.root, route, anchor=anchor) == self.context
                and sha(anchor.read('.getzilla/config/policy.json', source=True)) == self.policy
                and sha(anchor.read('.getzilla/managed-components.json', source=True)) == self.manifest
                and admit_module(self.root, 'retrieval-research').get('allowed'), 'public_witness_stale')
        _require((_exact_head(self.root), tree_fingerprint(self.root)) == self.source_binding, 'public_witness_stale')
        self.check()

    def read(self, path, *, limit=MAX_JSON_BYTES, source=False, expected=None, keep=True):
        self.check()
        checked_relative(path)
        _require(source or path.startswith('.getzilla/runtime/'), 'public_witness_path')
        with native_root(self.root) as anchor:
            _require(anchor.identity == self.physical_root, 'public_witness_stale')
            with anchor.file(path, source=source, limit=limit) as (descriptor, _):
                before, chunks, count, hasher = os.fstat(descriptor), [], 0, hashlib.sha256()
                while True:
                    self.check()
                    block = os.read(descriptor, min(65536, limit + 1 - count))
                    if not block:
                        break
                    count += len(block)
                    self.used += len(block)
                    _require(count <= limit and self.used <= MAX_WITNESS_BYTES, 'public_witness_bytes')
                    _require(self.group_start is None or self.used - self.group_start <= MAX_TOTAL_JSON_BYTES,
                             'public_witness_group_bytes')
                    anchor.charge(size=len(block))
                    hasher.update(block)
                    if keep:
                        chunks.append(block)
                _require(_identity(os.fstat(descriptor)) == _identity(before), 'public_witness_changed')
            snapshot = {'path': path, 'source': source, 'sha256': hasher.hexdigest(),
                        'bytes': count, 'identity': _identity(before)}
            if expected is not None:
                _require(type(expected) is dict and set(expected) == {'path', 'sha256', 'bytes'}
                         and expected['path'] == path and expected['sha256'] == snapshot['sha256']
                         and type(expected['bytes']) is int and expected['bytes'] == count, 'public_witness_changed')
            old = self.dependencies.get(path)
            _require(old is None or old == snapshot, 'public_witness_changed')
            _require(len(self.dependencies) < 512 or path in self.dependencies, 'public_witness_bytes')
            self.dependencies[path] = snapshot
            return b''.join(chunks) if keep else snapshot

    def producer_reference(self, reference, producer, supplement):
        """Consume a separate owner-observed fingerprint, never reread its body."""
        _require((reference['sha256'], reference['bytes']) in _PRODUCERS,
                 'public_witness_producer_reference_unavailable')
        receipt = get_receipt(self.root, self.route['route_id'], PRODUCER_KIND)
        _require(receipt is not None, 'public_witness_producer_reference_unavailable')
        data = receipt['details']
        _require(data['assurance'] == ASSURANCE and data['context'] == self.context
                 and data['source_binding'] == list(self.source_binding)
                 and data['physical_root'] == list(self.physical_root)
                 and data['policy_sha256'] == self.policy
                 and data['module_manifest_sha256'] == self.manifest, 'public_witness_stale')
        record = data['observations'].get(reference['sha256'])
        _require(record is not None and record['original'] == reference
                 and record['producer_identity'] == producer and record['supplement'] == supplement,
                 'public_witness_producer_reference_unavailable')
        path = checked_relative(reference['path'])
        _require(path.startswith('.getzilla/runtime/'), 'public_witness_path')
        with native_root(self.root) as anchor:
            _require(anchor.identity == self.physical_root, 'public_witness_stale')
            with anchor.file(path, limit=reference['bytes']) as (descriptor, _):
                identity = _identity(os.fstat(descriptor))
            _require(identity == record['identity'], 'public_witness_changed')
        snapshot = {**reference, 'source': False, 'identity': identity,
            'hash_observation': 'separate-operator-producer-fingerprint',
            'producer_identity': producer, 'supplement': supplement,
            'producer_receipt_sha256': digest(receipt)}
        old = self.dependencies.get(path)
        _require(old is None or old == snapshot, 'public_witness_changed')
        _require(len(self.dependencies) < 512 or path in self.dependencies, 'public_witness_bytes')
        self.dependencies[path] = snapshot
        return snapshot

    def json(self, reference):
        return _json(self.read(reference['path'], expected=reference))

    def recheck(self):
        self.current()
        for snapshot in tuple(self.dependencies.values()):
            self.check()
            with native_root(self.root) as anchor:
                _require(anchor.identity == self.physical_root and
                    _identity(anchor.stat(snapshot['path'], source=snapshot['source'])) == snapshot['identity'],
                    'public_witness_changed')
        self.current()


@state.serialized_task
def observe_public_producer(root, registration_path):
    """Explicit current owner action: separately fingerprint one exact retained A/C publication.

    The operator witnesses actual external producer delivery; the hash confirms
    retained bytes, not native delivery or lossless scientific reconstruction.
    """
    capture = _Capture(root)
    request = _json(capture.read(registration_path))
    _require(type(request) is dict and set(request) == {'schema_version', 'kind', 'original',
        'producer_identity', 'supplement'} and type(request['schema_version']) is int
        and request['schema_version'] == 1 and request['kind'] == 'operator-public-producer-reference/v1')
    original, supplement, producer = request['original'], request['supplement'], request['producer_identity']
    _require(type(original) is dict and set(original) == {'path', 'sha256', 'bytes'}
             and (original['sha256'], original['bytes']) in _PRODUCERS)
    _require(type(producer) is dict and set(producer) == {'agent_task', 'native_session_id', 'native_generation'}
             and label(producer['agent_task']) and label(producer['native_session_id'])
             and producer['native_generation'] is None)
    observed = capture.read(original['path'], limit=16 * 1048576, expected=original, keep=False)
    capture.read(supplement['path'], limit=1048576, expected=supplement, keep=False)
    record = {'original': original, 'identity': observed['identity'], 'producer_identity': producer,
              'supplement': supplement, 'hash_observation': 'separate-operator-producer-fingerprint'}
    previous = get_receipt(root, capture.route['route_id'], PRODUCER_KIND)
    details = {'assurance': ASSURANCE, 'context': capture.context,
        'source_binding': list(capture.source_binding), 'physical_root': list(capture.physical_root),
        'policy_sha256': capture.policy, 'module_manifest_sha256': capture.manifest,
        'statement': 'AUTOMATED COORDINATOR directly observed this external producer delivery; no native or human authentication.',
        'observations': {}}
    if previous is not None:
        _require({k: v for k, v in previous['details'].items() if k != 'observations'} ==
                 {k: v for k, v in details.items() if k != 'observations'}, 'public_witness_stale')
        details['observations'] = dict(previous['details']['observations'])
        old = details['observations'].get(original['sha256'])
        _require(old is None or old == record, 'public_witness_conflict')
        if old == record:
            capture.recheck()
            return {'status': 'observed', 'assurance': ASSURANCE, 'original_sha256': original['sha256'],
                    'producer_receipt_sha256': digest(previous), 'ranking_permitted': False}
    details['observations'][original['sha256']] = record
    capture.recheck()
    write_receipt(root, PRODUCER_KIND, 'observed', details=details, expected_context=capture.context,
                  interrupt_check=capture.recheck)
    receipt = get_receipt(root, capture.route['route_id'], PRODUCER_KIND)
    capture.recheck()
    return {'status': 'observed', 'assurance': ASSURANCE, 'original_sha256': original['sha256'],
            'producer_receipt_sha256': digest(receipt), 'ranking_permitted': False}


def _dataset(capture, path):
    documents, hashes, total = [], {}, 0
    for name in INPUTS:
        raw = capture.read(path + '/' + name)
        total += len(raw)
        _require(total <= MAX_TOTAL_JSON_BYTES, 'input_bytes_exceeded')
        documents.append(_json(raw))
        hashes[name] = sha(raw)
    return documents, hashes


def _sources(capture, path, composition):
    sources, total, count = {}, 0, 0
    for corpus, commit, expected in composition.catalogs:
        raw = capture.read('engineering/benchmarks/issue162/data/' + corpus + '-manifest.json', source=True)
        _require(sha(raw) == expected, 'public_catalog_changed')
        manifest = _json(raw)
        _require(manifest['corpus'] == corpus and manifest['commit'] == commit)
        for row in manifest['files']:
            if row['candidate'] is not True:
                continue
            relative = checked_relative(row['path'])
            body = capture.read(path + '/' + corpus + '/' + relative, limit=PUBLIC_LIMITS[2])
            _require(len(body) == row['bytes'] and sha(body) == row['sha256'], 'public_catalog_changed')
            total += len(body)
            count += 1
            _require(total <= PUBLIC_LIMITS[1] and count <= PUBLIC_LIMITS[0])
            sources[corpus, relative] = body
    return sources


def _supplement(group, parsed, supplement, budget=None):
    budget = ScientificBudget() if budget is None else budget
    budget.check()
    """Check exact producer-lineage objects; the operator witnesses their delivery.

    Original oversized JSON is retained/hash-bound, not silently parsed beyond
    its limit. Producer equivalence remains explicitly operator-witnessed.
    """
    original = group['original']
    identity = group['delivery_identity']
    if supplement.get('kind') == 'metadata_only_compact_equivalence_supplement':
        _require(len(parsed) == 1 and supplement['native_session_id'] == identity['native_session_id']
                 and supplement['native_generation'] == identity['native_generation']
                 and supplement['full_parsed_object_equal'] is True and supplement['semantic_changes'] is False)
        predecessor, compact = supplement['predecessor'], supplement['compact']
        _require(all(predecessor[key] == original[key] for key in ('sha256', 'bytes'))
                 and all(compact[key] == group['annotations'][0][key] for key in ('sha256', 'bytes')))
        _require(supplement['function_slice'] == [parsed[0]['slice_start'], parsed[0]['slice_end']])
        return parsed[0]
    elif supplement.get('kind') == 'independent_partial_qrels_compact_supplement_v1':
        _require(supplement['native_producer_session'] == identity['native_session_id']
                 and supplement['reviewer'] == parsed[0]['reviewer']
                 and supplement['reconstructed_object_equality'] is True
                 and all(supplement['original'][key] == original[key] for key in ('sha256', 'bytes'))
                 and len(supplement['shards']) == len(parsed))
        ordinals = []
        previous_end = None
        for shard, report, reference in zip(supplement['shards'], parsed, group['annotations']):
            budget.check()
            _require(all(shard[key] == reference[key] for key in ('sha256', 'bytes'))
                     and shard['slice_start'] == report['slice_start'] and shard['slice_end'] == report['slice_end']
                     and (previous_end is None or previous_end == report['slice_start'])
                     and len(shard['original_evidence_ordinals']) == len(report['source_evidence']))
            _require(all(type(value) is int and value >= 0 for value in shard['original_evidence_ordinals']))
            ordinals.extend(shard['original_evidence_ordinals'])
            previous_end = report['slice_end']
            _require(set(report) == set(parsed[0]))
            for key in set(report) - {'slice_start', 'slice_end', 'function_ids', 'tasks', 'source_evidence'}:
                _require(report[key] == parsed[0][key])
        _require(sorted(ordinals) == list(range(len(ordinals))), 'public_witness_lineage_missing')
        # Reconstruct the original logical object from bounded genuine shards.
        # No oversized original JSON is parsed or exempted from the file limit.
        combined = dict(parsed[0])
        combined['slice_end'] = parsed[-1]['slice_end']
        combined['function_ids'] = [identity for report in parsed for identity in report['function_ids']]
        task_ids = [row['task_id'] for row in parsed[0]['tasks']]
        _require(all([row['task_id'] for row in report['tasks']] == task_ids for report in parsed))
        combined['tasks'] = []
        for index, original_row in enumerate(parsed[0]['tasks']):
            budget.check()
            row = dict(original_row)
            _require(all({key: value for key, value in report['tasks'][index].items() if key != 'judgments'}
                         == {key: value for key, value in row.items() if key != 'judgments'} for report in parsed))
            row['judgments'] = [value for report in parsed for value in report['tasks'][index]['judgments']]
            combined['tasks'].append(row)
        restored = [None] * len(ordinals)
        for shard, report in zip(supplement['shards'], parsed):
            for ordinal, evidence in zip(shard['original_evidence_ordinals'], report['source_evidence']):
                budget.check()
                restored[ordinal] = evidence
        combined['source_evidence'] = restored
        return combined
    else:
        raise RetrievalError('public_witness_lineage_missing')


def _capture_original(capture, group):
    original = group['original']
    key = original['sha256'], original['bytes']
    _require(group['supplement'] is not None, 'public_witness_lineage_missing')
    if key in _PRODUCERS:
        capture.producer_reference(original, group['delivery_identity'], group['supplement'])
    else:
        _require(key == _HASH_ONLY_B, 'public_witness_lineage_missing')
        # The finite B original is within the physical byte cap. Its complete
        # hash read remains part of this group's original sixteen-MiB budget.
        capture.read(original['path'], limit=MAX_JSON_BYTES, expected=original, keep=False)


def _groups(capture, groups):
    budget = ScientificBudget(capture.deadline)
    _require(type(groups) is list and 3 <= len(groups) <= MAX_GROUPS)
    waves, publications, sources = {'initial': [], 'second': [], 'query': []}, [], []
    for group in groups:
        required = {'role', 'original', 'annotations', 'reports', 'delivery', 'delivery_identity', 'supplement'}
        _require(type(group) is dict and required <= set(group) <= required | {'query_equivalence'} and group['role'] in waves)
        annotations = group['annotations']
        _require(type(annotations) is list and 1 <= len(annotations) <= MAX_SHARDS)
        group_start = capture.used
        capture.group_start = group_start
        # Original body reads count toward this group's aggregate budget too.
        _require(type(group['original']['bytes']) is int and 0 < group['original']['bytes'] <= 16 * 1048576)
        if len(annotations) != 1 or annotations[0] != group['original']:
            _capture_original(capture, group)
        parsed, total = [], 0
        for reference in annotations:
            total += reference['bytes']
            _require(type(reference['bytes']) is int and 0 < reference['bytes'] <= MAX_JSON_BYTES
                     and total <= MAX_TOTAL_JSON_BYTES)
            parsed.append(capture.json(reference))
        identity = group['delivery_identity']
        _require(type(identity) is dict and set(identity) == {'agent_task', 'native_session_id', 'native_generation'})
        for report in parsed:
            reviewer = report['reviewer']
            _require({name: reviewer[name] for name in identity} == identity)
        _require(type(group['reports']) is list and 1 <= len(group['reports']) <= 4
                 and group['delivery']['bytes'] > 0)
        for report in group['reports']:
            _require(type(report['bytes']) is int and 0 < report['bytes'] <= 1048576)
            capture.read(report['path'], limit=1048576, expected=report, keep=False)
        capture.read(group['delivery']['path'], limit=1048576, expected=group['delivery'], keep=False)
        # The explicit operator witnesses actual producer delivery and supplement
        # lineage. A supplement's equality/pass boolean grants no authority.
        if group['supplement'] is not None:
            semantic = _supplement(group, parsed, capture.json(group['supplement']), budget)
            _require(reviewed_digest(semantic, budget) == _PRODUCER_SEMANTIC[group['original']['sha256']],
                     'public_witness_lineage_missing')
        else:
            _require(len(annotations) == 1 and annotations[0] == group['original'], 'public_witness_lineage_missing')
            semantic = parsed[0]
        _require(capture.used - group_start <= MAX_TOTAL_JSON_BYTES, 'public_witness_group_bytes')
        capture.group_bytes[group['original']['path']] = capture.used - group_start
        capture.group_start = None
        waves[group['role']].append(semantic)
        sources.append((group, semantic, parsed))
        publications.append(group)
    _require(len(waves['query']) == 1)
    return waves, publications, sources



def _query_lineage(capture, registration, composition, final, predecessor, old_hashes, final_hashes,
                   waves, source_groups, budget):
    revision = registration.get('query_revision')
    if final_hashes['queries.json'] == old_hashes['queries.json']:
        _require(revision is None and all(group.get('query_equivalence') is None for group, _, _ in source_groups))
        return
    _require(composition.query_revision_sha256 is not None and type(revision) is dict
        and set(revision) == {'original_query_report', 'language_supplement'}
        and revision['original_query_report']['sha256'] == composition.original_language_sha256,
        'public_query_revision_unavailable')
    old_report = capture.json(revision['original_query_report'])
    _require(old_report['input_hashes'] == old_hashes and old_report['kind'] == 'independent_query_review_v1')
    tasks = {row['task_id']: row for row in final[1]['tasks']}
    changed = query_revision(predecessor[2], final[2],
        capture.read(registration['predecessor'] + '/queries.json'),
        capture.read(registration['dataset'] + '/queries.json'), old_report, tasks,
        expected_sha256=composition.query_revision_sha256, expected_changes=composition.query_changes, budget=budget)
    language = capture.json(revision['language_supplement'])
    expected_hashes = {**old_hashes, 'queries.json': final_hashes['queries.json']}
    query_group = next(group for group, _, _ in source_groups if group['role'] == 'query')
    _require(language['kind'] == 'independent_query_revision_supplement_v1'
        and language['base_report']['sha256'] == composition.original_language_sha256
        and language['base_input_hashes'] == old_hashes and language['revised_input_hashes'] == expected_hashes
        and language['revised_full_report_sha256'] == query_group['annotations'][0]['sha256']
        and language['reviewer'] == waves['query'][0]['reviewer']
        and set(language['exact_changed_json_pointers']) == {row['pointer'] for row in changed.values()})
    manifests = {corpus: (commit, manifest) for corpus, commit, manifest in composition.catalogs}
    covered, expected = set(), set()
    for group, semantic, parsed in source_groups:
        budget.check()
        if group['role'] != 'second':
            _require(group.get('query_equivalence') is None)
            continue
        expected.update((semantic['corpus'], row['task_id'], index)
            for row in changed.values() if row['corpus'] == semantic['corpus']
            for index in range(semantic['slice_start'], semantic['slice_end']))
        capture.group_start = capture.used - capture.group_bytes[group['original']['path']]
        supplements = group.get('query_equivalence')
        _require(type(supplements) is list and 1 <= len(supplements) <= MAX_SHARDS,
                 'public_query_equivalence_missing')
        aliases = {group['original']['sha256']: semantic}
        aliases.update({reference['sha256']: report for reference, report in zip(group['annotations'], parsed)})
        for entry in supplements:
            _require(type(entry) is dict and set(entry) == {'annotation', 'delivery'})
            report = capture.json(entry['annotation'])
            capture.read(entry['delivery']['path'], limit=1048576, expected=entry['delivery'], keep=False)
            original_sha = report['original_annotation_sha256']
            _require(original_sha in aliases, 'public_query_equivalence_scope')
            cells = source_equivalence(report, aliases[original_sha], original_sha, changed,
                corpus_manifest=manifests[semantic['corpus']], old_query_sha256=old_hashes['queries.json'],
                new_query_sha256=final_hashes['queries.json'], budget=budget)
            _require(not cells & covered, 'public_query_equivalence_scope')
            covered.update(cells)
        capture.group_start = None
    _require(covered == expected, 'public_query_equivalence_missing')


def _adjudications(capture, publications, final, predecessor, old_hashes, source_groups, budget):
    _require(type(publications) is list and len(publications) <= 16)
    result = {}
    universes = {row['corpus']: row for row in final[0]['universes']}
    source_hashes = {group['original']['sha256'] for group, _, _ in source_groups if group['role'] in ('initial', 'second')}
    for publication in publications:
        budget.check()
        capture.group_start = capture.used
        _require(type(publication) is dict and set(publication) == {'annotation', 'reports', 'delivery'})
        report = capture.json(publication['annotation'])
        capture.read(publication['delivery']['path'], limit=1048576, expected=publication['delivery'], keep=False)
        _require(1 <= len(publication['reports']) <= 4)
        for reference in publication['reports']:
            capture.read(reference['path'], limit=1048576, expected=reference, keep=False)
        _require({value for key, value in report['input_hashes'].items()
                 if key.endswith('/partial-judgments.json') or key.endswith('/partial-judgments-v2.json')} <= source_hashes)
        cells = third_source(report, raw_sha256=publication['annotation']['sha256'], universes=universes,
                             predecessor_hashes=old_hashes, queries=predecessor[2], budget=budget)
        for _, task, _ in cells:
            _require([q for q in final[2]['queries'] if q['task_id'] == task] ==
                     [q for q in predecessor[2]['queries'] if q['task_id'] == task], 'public_query_equivalence_missing')
        _require(not set(cells) & set(result))
        result.update(cells)
        capture.group_start = None
    return result

def _issue(root, receipt, profile):
    reference = object.__new__(OperatorWitnessedPublicReviewedInputs)
    for key, value in (('_issuer', _ISSUER), ('_root', str(Path(root))), ('_profile', profile),
                       ('_receipt_digest', digest(receipt))):
        object.__setattr__(reference, key, value)
    return reference


@state.serialized_task
def _witness(root, registration_path, composition):
    _require(type(composition) is _Composition and (composition.profile != _PRODUCTION.profile
             or composition == _PRODUCTION), 'public_witness_unavailable')
    capture = _Capture(root)
    registration = _json(capture.read(registration_path, limit=262144))
    required = {'schema_version', 'kind', 'dataset', 'predecessor', 'public_sources',
                'config', 'author', 'groups', 'dispositions', 'no_answer_resolutions'}
    _require(required <= set(registration) <= required | {'query_revision', 'adjudications'}
        and type(registration['schema_version']) is int and registration['schema_version'] == 1
        and registration['kind'] == 'operator-public-reviews/v1')
    final, final_hashes = _dataset(capture, registration['dataset'])
    predecessor, old_hashes = _dataset(capture, registration['predecessor'])
    _require(tuple(old_hashes[name] for name in INPUTS) == composition.predecessor_hashes
             and all(final_hashes[name] == old_hashes[name] for name in INPUTS[:2]), 'public_witness_predecessor')
    config = capture.read(registration['config']['path'], expected=registration['config'])
    _require(sha(config) == composition.config_sha256, 'public_witness_config')
    source = _sources(capture, registration['public_sources'], composition)
    audit_draft_inputs(*predecessor, source, profile=composition.audit_profile)
    waves, publications, source_groups = _groups(capture, registration['groups'])
    budget = ScientificBudget(capture.deadline)
    query_hashes = dict(old_hashes)
    query_hashes['queries.json'] = final_hashes['queries.json']
    _query_lineage(capture, registration, composition, final, predecessor, old_hashes, final_hashes,
                   waves, source_groups, budget)
    dispositions = capture.json(registration['dispositions'])
    resolutions = capture.json(registration['no_answer_resolutions'])
    _require(set(dispositions) == {'dispositions'} and set(resolutions) == {'resolutions'})
    author = registration['author']
    _require(type(author) is dict and set(author) == {'agent_task', 'native_session_id'})
    adjudications = _adjudications(capture, registration.get('adjudications', []), final, predecessor,
                                   old_hashes, source_groups, budget)
    facts = validate_reviewed_inputs((*final, source), old_hashes, waves['initial'], waves['second'],
        waves['query'][0], author=(author['agent_task'], author['native_session_id']),
        dispositions=dispositions['dispositions'], no_answer_resolutions=resolutions['resolutions'],
        profile=composition.audit_profile, budget=budget, query_hashes=query_hashes, adjudications=adjudications)
    capture.recheck()
    payload = {'assurance': ASSURANCE, 'profile': composition.profile,
        'statement': 'AUTOMATED COORDINATOR directly observed the listed actual external collaboration deliveries and independence; no authenticated native bridge or human security approval is asserted.',
        'owner': {name: capture.route.get(name) for name in ('route_id', 'logical_task_id', 'session_id', 'authority_epoch')},
        'source_binding': list(capture.source_binding), 'context': capture.context, 'physical_root': list(capture.physical_root), 'policy_sha256': capture.policy,
        'module_manifest_sha256': capture.manifest, 'registration_path': registration_path,
        'dataset': final_hashes, 'predecessor': old_hashes, 'publications': publications,
        'config_sha256': composition.config_sha256, 'registration_sha256': capture.dependencies[registration_path]['sha256'],
        'public_source_root': registration['public_sources'],
        'facts': facts, 'dependencies': list(capture.dependencies.values())}
    payload['operation_digest'] = digest({'logical_task_id': capture.context['logical_task_id'],
        'authority_epoch': capture.context['authority_epoch'], 'context_digest': capture.context['digest'],
        'profile': composition.profile, 'registration_sha256': capture.dependencies[registration_path]['sha256']})
    previous = get_receipt(root, capture.route['route_id'], KIND)
    if previous is not None:
        _require(previous['details'] == payload, 'public_witness_conflict')
        capture.recheck()
        return _issue(root, previous, composition.profile)
    write_receipt(root, KIND, 'observed', details=payload, expected_context=capture.context,
                  interrupt_check=capture.recheck)
    capture.recheck()
    receipt = get_receipt(root, capture.route['route_id'], KIND)
    _require(receipt is not None and receipt['details'] == payload, 'public_witness_publication_unavailable')
    return _issue(root, receipt, composition.profile)


def witness_public_reviews(root, registration_path):
    """Explicit current task OWNER action; fixed complete public profile only."""
    return _witness(root, registration_path, _PRODUCTION)


def _consume(reference, composition):
    _require(type(reference) is OperatorWitnessedPublicReviewedInputs
             and getattr(reference, '_issuer', None) is _ISSUER and reference._profile == composition.profile,
             'public_witness_unavailable')
    capture = _Capture(reference._root)
    receipt = get_receipt(capture.root, capture.route['route_id'], KIND)
    _require(receipt is not None and digest(receipt) == reference._receipt_digest, 'public_witness_stale')
    data = receipt['details']
    _require(data['profile'] == composition.profile and data['assurance'] == ASSURANCE
             and data['source_binding'] == list(capture.source_binding) and data['context'] == capture.context and data['physical_root'] == list(capture.physical_root)
             and data['policy_sha256'] == capture.policy and data['module_manifest_sha256'] == capture.manifest,
             'public_witness_stale')
    for snapshot in data['dependencies']:
        if snapshot.get('hash_observation') == 'separate-operator-producer-fingerprint':
            actual = capture.producer_reference({key: snapshot[key] for key in ('path', 'sha256', 'bytes')},
                                                snapshot['producer_identity'], snapshot['supplement'])
        else:
            actual = capture.read(snapshot['path'], limit=MAX_JSON_BYTES,
                                  source=snapshot['source'], keep=False)
        _require(actual == snapshot, 'public_witness_changed')
    capture.recheck()
    return {'assurance': ASSURANCE, 'profile': composition.profile, 'dataset': data['dataset'],
            'config_sha256': data['config_sha256'], 'registration_sha256': data['registration_sha256'],
            'witness_sha256': reference._receipt_digest, 'operation_digest': data['operation_digest'],
            'facts': data['facts'], 'ranking_permitted': False}


def consume_public_reviews(reference):
    """Revalidate factual review scope; source/model/execution gates stay separate."""
    return _consume(reference, _PRODUCTION)


def _reviewed_dataset(reference, composition):
    facts = _consume(reference, composition)
    capture = _Capture(reference._root)
    receipt = get_receipt(capture.root, capture.route['route_id'], KIND)
    _require(receipt is not None and digest(receipt) == reference._receipt_digest, 'public_witness_stale')
    raw = capture.read(receipt['details']['registration_path'])
    _require(sha(raw) == facts['registration_sha256'], 'public_witness_changed')
    registration = _json(raw)
    documents, hashes = _dataset(capture, registration['dataset'])
    _require(hashes == facts['dataset'], 'public_witness_changed')
    capture.recheck()
    return {'facts': facts, 'inputs': tuple(documents)}


def reviewed_public_dataset(reference):
    """Return current fixed public data facts; this grants no encoder or execution access."""
    return _reviewed_dataset(reference, _PRODUCTION)


class _WitnessSourceFence:
    """Fixed current review custody at source boundaries, never a model permit."""
    __slots__ = ('_issuer', '_reference', '_capture', '_closed')

    def __new__(cls, *args, **kwargs):
        raise TypeError('owned reviewed source composition required')

    def __setattr__(self, name, value):
        raise AttributeError('review source fence is immutable')

    def __reduce__(self):
        raise TypeError('review source fence cannot be serialized')

    def check_current(self, deadline):
        _require(self._issuer is _ISSUER and not self._closed and time.monotonic() < deadline,
                 'public_witness_stale')
        receipt = get_receipt(self._capture.root, self._capture.route['route_id'], KIND)
        _require(receipt is not None and digest(receipt) == self._reference._receipt_digest,
                 'public_witness_stale')
        # Full body hashes were consumed before the fresh source lease. Immutable
        # owner-held identities/ctime are checked here without renewing that lease.
        self._capture.recheck()
        _require(time.monotonic() < deadline, 'public_witness_stale')


@contextmanager
def _reviewed_source_cut(reference, *, batch, composition):
    facts = _consume(reference, composition)
    capture = _Capture(reference._root)
    receipt = get_receipt(capture.root, capture.route['route_id'], KIND)
    _require(receipt is not None and digest(receipt) == reference._receipt_digest, 'public_witness_stale')
    raw = capture.read(receipt['details']['registration_path'])
    _require(sha(raw) == facts['registration_sha256'], 'public_witness_changed')
    registration = _json(raw)
    capture.dependencies = {snapshot['path']: snapshot for snapshot in receipt['details']['dependencies']}
    capture.recheck()
    fence = object.__new__(_WitnessSourceFence)
    for key, value in (('_issuer', _ISSUER), ('_reference', reference), ('_capture', capture), ('_closed', False)):
        object.__setattr__(fence, key, value)
    from .research import _public_source_cut
    try:
        with _public_source_cut(capture.root, capture.root / checked_relative(registration['public_sources']),
                batch=batch, review_fence=fence, catalogs=composition.catalogs) as result:
            yield result
    finally:
        object.__setattr__(fence, '_closed', True)


@contextmanager
def reviewed_public_source_cut(reference, *, batch):
    """Join current public review facts to one fresh fixed two-second source cut.

    Every held cut must remain current before encoder/output stages. This port
    neither authorizes those stages nor extends the native source deadline.
    """
    with _reviewed_source_cut(reference, batch=batch, composition=_PRODUCTION) as result:
        yield result
