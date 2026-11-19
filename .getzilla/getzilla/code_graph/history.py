"""Deterministic Git history evidence in the existing code graph, never merge authority."""
from __future__ import annotations

import hashlib
import difflib
import itertools
import json
import math
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .architecture_bindings import architecture_digest, bind_paths
from .history_git import GitReader, HistoryReadError
from .history_objects import VerifiedObjects

POLICIES = {'timestamp': 'committer_epoch_seconds', 'timezone': 'UTC',
            'windows': 'half_open_start_inclusive_end_exclusive',
            'range': 'base_exclusive_end_inclusive_all_reachable',
            'merges': 'exclude_merge_diff_include_reachable_side_commits',
            'renames': 'delete_add_no_detection', 'binary': 'NUL_in_first_8000_blob_bytes; touches_known_line_churn_unknown',
            'bulk': 'exclude_pairs_only_when_component_count_exceeds_threshold',
            'exclusions': 'explicit_relative_path_prefixes', 'working_tree': 'not_read',
            'interpretation': 'advisory_grounded_fact_selection_no_causality',
            'extractor': 'getzilla-graph-history-v1', 'root_commits': 'diff_against_empty_tree',
            'line_diff': 'python_difflib_sequence_matcher_autojunk_false_v1_LF_records_keep_terminators_prefix_suffix_anchored',
            'order': 'committer_timestamp_then_oid; component_and_pair_lexicographic'}
POLICIES['object_admission'] = 'Git_format_type_length_header_and_content_hash_before_use'
POLICIES['history_interpretation'] = 'verified_raw_commit_DAG_and_trees; no_grafts_or_replace_traversal'
POLICIES['revision_inputs'] = 'literal_refs_or_full_object_ids; verified_annotated_tag_chain'


def _memory_observation() -> dict:
    try:
        import resource
        import sys
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {'process_peak_rss_bytes': int(peak if sys.platform == 'darwin' else peak * 1024),
                'rss_scope': 'observed process-lifetime high-water mark, not isolated mining allocation'}
    except (ImportError, OSError, ValueError):
        return {'process_peak_rss_bytes': None, 'rss_scope': 'unavailable_on_this_platform'}


def _resident_bytes() -> int | None:
    try:
        # Fixed OS metadata only; no repository/config path or process arguments.
        with open('/proc/self/statm', 'rb') as handle:
            fields = handle.read(256).split()
        return int(fields[1]) * os.sysconf('SC_PAGE_SIZE')
    except (OSError, ValueError, IndexError, AttributeError):
        return None


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True)
class HistoryConfig:
    windows: tuple[tuple[int, int], ...] = ()
    exclude_prefixes: tuple[str, ...] = ()
    bulk_components: int = 5
    max_commits: int = 1000
    max_bytes: int = 8 * 1024 * 1024
    max_seconds: float = 30
    max_file_touches: int = 50000
    max_pair_observations: int = 20000
    max_line_comparisons: int = 1000000
    max_line_records: int = 50000

    def __post_init__(self):
        for value, maximum in ((self.max_commits, 10000), (self.max_bytes, 64 * 1024 * 1024),
                               (self.bulk_components, 1000), (self.max_file_touches, 100000),
                               (self.max_pair_observations, 100000), (self.max_line_comparisons, 10000000),
                               (self.max_line_records, 100000)):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('invalid history limit')
        if type(self.max_seconds) not in (int, float) or not math.isfinite(self.max_seconds) or not 0 < self.max_seconds <= 300:
            raise ValueError('invalid history deadline')
        if not isinstance(self.windows, tuple) or len(self.windows) > 24:
            raise ValueError('invalid history windows')
        previous = None
        for window in self.windows:
            if (not isinstance(window, tuple) or len(window) != 2 or any(type(v) is not int for v in window)
                    or not 0 <= window[0] < window[1] <= 253402300799
                    or previous is not None and window[0] < previous):
                raise ValueError('invalid history windows')
            previous = window[1]
        if not isinstance(self.exclude_prefixes, tuple) or len(self.exclude_prefixes) > 256:
            raise ValueError('invalid history exclusions')
        for prefix in self.exclude_prefixes:
            if (not isinstance(prefix, str) or not prefix or prefix.startswith('/') or '\\' in prefix
                    or any(part in ('', '.', '..') for part in prefix.split('/')) or '\0' in prefix):
                raise ValueError('invalid history exclusions')


def _component() -> dict:
    return {'touches': 0, 'insertions': 0, 'deletions': 0, 'binary_touches': 0,
            'line_churn_complete': True, 'file_touches': 0, 'commits': [], 'windows': []}


def _model_snapshot(architecture: Any) -> tuple[dict, dict]:
    if architecture is None:
        return {}, {}
    system = architecture.system if hasattr(architecture, 'system') else architecture['system']
    rules = architecture.rules if hasattr(architecture, 'rules') else architecture['rules']
    raw = json.dumps({'system': system, 'rules': rules}, ensure_ascii=True)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError('mapping budget')
    copied = json.loads(raw)
    system, rules = copied['system'], copied['rules']
    nodes = system.get('nodes', [])
    if not isinstance(rules, dict) or not isinstance(nodes, list) or len(nodes) > 1000:
        raise ValueError('unsupported mapping')
    ids = set()
    path_count = 0
    for node in nodes:
        identifier = node.get('id')
        paths = node.get('repository_paths', [])
        if (not isinstance(identifier, str) or not identifier or len(identifier) > 128
                or identifier in ids or not isinstance(paths, list)):
            raise ValueError('unsupported mapping')
        ids.add(identifier)
        path_count += len(paths)
        if path_count > 10000:
            raise ValueError('mapping budget')
        for path in paths:
            if (not isinstance(path, str) or not path or len(path) > 4096 or path.startswith('/')
                    or '\\' in path or '\0' in path or any(p in ('', '.', '..') for p in path.rstrip('/').split('/'))):
                raise ValueError('unsupported mapping')
    return system, rules


def _line_churn(old: bytes, new: bytes, config: HistoryConfig) -> tuple[int, int]:
    """A declared deterministic line algorithm, independent of Git diff drivers."""
    old_count = old.count(b'\n') + int(bool(old) and not old.endswith(b'\n'))
    new_count = new.count(b'\n') + int(bool(new) and not new.endswith(b'\n'))
    if not old:
        return new_count, 0
    if not new:
        return 0, old_count
    if old == new:
        return 0, 0
    if old_count + new_count > config.max_line_records:
        raise HistoryReadError('LINE_DIFF_BUDGET')

    def lines(contents):
        parts = contents.split(b'\n')
        return [part + b'\n' for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])

    old_lines, new_lines = lines(old), lines(new)
    prefix = 0
    while prefix < min(len(old_lines), len(new_lines)) and old_lines[prefix] == new_lines[prefix]:
        prefix += 1
    old_end, new_end = len(old_lines), len(new_lines)
    while old_end > prefix and new_end > prefix and old_lines[old_end - 1] == new_lines[new_end - 1]:
        old_end -= 1
        new_end -= 1
    old_lines, new_lines = old_lines[prefix:old_end], new_lines[prefix:new_end]
    if len(old_lines) * len(new_lines) > config.max_line_comparisons:
        raise HistoryReadError('LINE_DIFF_BUDGET')
    inserted = deleted = 0
    for operation, a, b, c, d in difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False).get_opcodes():
        if operation in ('insert', 'replace'):
            inserted += d - c
        if operation in ('delete', 'replace'):
            deleted += b - a
    return inserted, deleted


def mine_history(root: Path, *, architecture: Any = None, config: HistoryConfig | None = None,
                 base: str | None = None, end: str = 'HEAD') -> dict:
    """Read immutable committed history only. Observations are outside deterministic metrics."""
    started = time.monotonic()
    resident_before = _resident_bytes()
    config = config or HistoryConfig()
    reader = GitReader(Path(root).resolve(), max_bytes=config.max_bytes, max_seconds=config.max_seconds)
    reasons: set[str] = set()
    metrics: dict[str, Any] = {'commits_read': 0, 'commits_considered': 0, 'components': {}, 'pairs': [],
                               'bulk_commits': [], 'merge_commits_excluded': [], 'excluded_file_touches': 0,
                               'unmapped_file_touches': 0, 'windows': []}
    identity: dict[str, Any] = {}
    objects = None
    try:
        system, rules = _model_snapshot(architecture)
        model_digest = architecture_digest(system, rules)
    except (KeyError, TypeError, ValueError, AttributeError):
        system, rules = {}, {}
        reasons.add('UNSUPPORTED_MAPPING')
        model_digest = architecture_digest(system, rules)
    if not system.get('nodes'):
        reasons.add('MAPPING_UNAVAILABLE')
    components, pairs = metrics['components'], {}
    window_commits = [set() for _ in config.windows]
    file_touches_read = pair_observations = 0
    blob_contents: dict[str, bytes] = {}
    pair_churn: dict[tuple[str, str], tuple[int, int]] = {}
    try:
        marker = reader.root / '.git'
        if marker.is_symlink() or not (marker.is_file() or marker.is_dir()):
            raise HistoryReadError('NO_GIT_HISTORY')
        _, top = reader.read('rev-parse', '--show-toplevel')
        if not top.endswith(b'\n'):
            raise HistoryReadError('GIT_READ_INCOMPLETE')
        top_path = top[:-1]
        if os.name == 'nt' and top_path.endswith(b'\r'):
            top_path = top_path[:-1]
        if Path(top_path.decode('utf-8', 'surrogateescape')).resolve() != reader.root:
            raise HistoryReadError('NO_GIT_HISTORY')
        _, git_dir = reader.read('rev-parse', '--absolute-git-dir')
        if not git_dir.endswith(b'\n'):
            raise HistoryReadError('GIT_READ_INCOMPLETE')
        git_dir_path = git_dir[:-1]
        if os.name == 'nt' and git_dir_path.endswith(b'\r'):
            git_dir_path = git_dir_path[:-1]
        reader.git_dir = Path(git_dir_path.decode('utf-8', 'surrogateescape'))
        code, _ = reader.read('rev-parse', '--verify', 'HEAD', allowed_codes=(0, 128))
        if code:
            raise HistoryReadError('UNBORN_HISTORY')
        _, object_format = reader.read('rev-parse', '--show-object-format')
        objects = VerifiedObjects(reader, object_format.decode().strip(), config.max_commits)
        end_oid = objects.resolve(end)
        base_oid = None if base is None else objects.resolve(base)
        end_commit = objects.commit(end_oid)
        objects.tree(end_commit.tree)
        if base_oid:
            objects.tree(objects.commit(base_oid).tree)
        identity = {'end': end_oid, 'base': base_oid, 'tree': end_commit.tree,
                    'object_format': objects.format, 'repository_identity': 'verified_committed_object_ids_only'}
        _, shallow = reader.read('rev-parse', '--is-shallow-repository')
        if shallow.strip() == b'true':
            reasons.add('SHALLOW_HISTORY')
        code, partial = reader.read('config', '--local', '--get', 'extensions.partialClone', allowed_codes=(0, 1))
        if code == 0 and partial.strip():
            reasons.add('PARTIAL_HISTORY')
        _, promisor = reader.read('config', '--local', '--type=bool', '--get-regexp',
                                  r'^remote\..*\.promisor$', allowed_codes=(0, 1))
        if any(line.endswith(b' true') for line in promisor.splitlines()):
            reasons.add('PARTIAL_HISTORY')
        records, range_reasons = objects.range(end_oid, base_oid, config.max_commits)
        reasons.update(range_reasons)
        for record in sorted(records, key=lambda item: (item.timestamp, item.oid)):
            timestamp, oid, parents = record.timestamp, record.oid, record.parents
            if time.monotonic() >= reader.deadline:
                raise HistoryReadError('TIME_BUDGET')
            metrics['commits_read'] += 1
            if len(parents) > 1:
                metrics['merge_commits_excluded'].append(oid)
                continue
            window_ids = [i for i, (start, stop) in enumerate(config.windows) if start <= timestamp < stop]
            if config.windows and not window_ids:
                continue
            parent_tree = objects.commit(parents[0]).tree if parents else None
            changed_blobs = objects.changes(parent_tree, record.tree, config.max_file_touches - file_touches_read)
            object_ids = {blob for pair in changed_blobs.values() for blob in pair if set(blob) != {'0'}}
            for blob in sorted(object_ids - blob_contents.keys()):
                _, contents = objects.object(blob, 'blob')
                blob_contents[blob] = contents
            entries = []
            for path, (old, new) in sorted(changed_blobs.items()):
                old_contents, new_contents = blob_contents.get(old, b''), blob_contents.get(new, b'')
                if b'\0' in old_contents[:8000] or b'\0' in new_contents[:8000]:
                    added = removed = None
                else:
                    key = (old, new)
                    if key not in pair_churn:
                        pair_churn[key] = _line_churn(old_contents, new_contents, config)
                    added, removed = pair_churn[key]
                entries.append((path, added, removed))
            file_touches_read += len(entries)
            touched = set()
            commit_components = {}
            excluded_touches = unmapped_touches = 0
            for path, added, deleted in entries:
                if time.monotonic() >= reader.deadline:
                    raise HistoryReadError('TIME_BUDGET')
                if any(path == p or path.startswith(p + '/') for p in config.exclude_prefixes):
                    excluded_touches += 1
                    continue
                binding, ambiguous = bind_paths((path,), {'system': system, 'rules': rules})
                node = binding[path]
                if node is None:
                    unmapped_touches += 1
                    reasons.add('AMBIGUOUS_MAPPING' if path in ambiguous else 'UNMAPPED_PATHS')
                    continue
                value = commit_components.setdefault(node, _component())
                value['file_touches'] += 1
                if added is None:
                    value['binary_touches'] += 1
                    value['line_churn_complete'] = False
                else:
                    value['insertions'] += added
                    value['deletions'] += deleted
                touched.add(node)
            pair_keys = []
            if len(touched) <= config.bulk_components:
                for key in itertools.combinations(sorted(touched), 2):
                    if pair_observations + len(pair_keys) >= config.max_pair_observations:
                        raise HistoryReadError('PAIR_BUDGET')
                    pair_keys.append(key)
            # Publish only a fully parsed/analysed commit; timeout cannot fabricate
            # line counts without that commit's evidence SHA.
            if time.monotonic() >= reader.deadline:
                raise HistoryReadError('TIME_BUDGET')
            metrics['excluded_file_touches'] += excluded_touches
            metrics['unmapped_file_touches'] += unmapped_touches
            for node, delta in commit_components.items():
                value = components.setdefault(node, _component())
                if not value['windows']:
                    value['windows'] = [dict(touches=0, commits=[]) for _ in config.windows]
                for key in ('file_touches', 'insertions', 'deletions', 'binary_touches'):
                    value[key] += delta[key]
                value['line_churn_complete'] &= delta['line_churn_complete']
            metrics['commits_considered'] += 1
            for index in window_ids:
                window_commits[index].add(oid)
            for node in sorted(touched):
                value = components[node]
                value['touches'] += 1
                value['commits'].append(oid)
                for index in window_ids:
                    value['windows'][index]['touches'] += 1
                    value['windows'][index]['commits'].append(oid)
            if len(touched) > config.bulk_components:
                metrics['bulk_commits'].append(oid)
            else:
                pair_observations += len(pair_keys)
                for a, b in pair_keys:
                    pairs.setdefault((a, b), []).append(oid)
    except HistoryReadError as error:
        reasons.add(error.reason)
    except (UnicodeError, ValueError, OSError):
        reasons.add('GIT_READ_INCOMPLETE')
    metrics['components'] = dict(sorted(components.items()))
    metrics['pairs'] = [{'a': a, 'b': b, 'touches': len(commits), 'commits': commits}
                        for (a, b), commits in sorted(pairs.items())]
    metrics['pair_eligible_commits'] = metrics['commits_considered'] - len(metrics['bulk_commits'])
    metrics['pair_observations'] = pair_observations
    metrics['file_touches_read'] = file_touches_read
    metrics['pair_denominator'] = 'all considered non-bulk non-merge commits, including empty/excluded diffs'
    metrics['windows'] = [{'start': start, 'end': end, 'commits': sorted(commits), 'commits_considered': len(commits)}
                          for (start, end), commits in zip(config.windows, window_commits)]
    if config.windows and any(not commits for commits in window_commits):
        reasons.add('EMPTY_WINDOW')
    if metrics['commits_considered'] == 0:
        reasons.add('EMPTY_RANGE')
    comparable = (len(config.windows) >= 2 and len({stop - start for start, stop in config.windows}) == 1)
    if len(config.windows) >= 2 and not comparable:
        reasons.add('WINDOWS_NOT_COMPARABLE')
    coverage = {'complete': not reasons, 'reasons': sorted(reasons), 'prehistory': 'not_recorded',
                'risk_assessment': 'not_performed'}
    facts = []
    for node, value in sorted(components.items(), key=lambda item: (-item[1]['touches'], item[0])):
        facts.append({'id': 'hotspot:' + node, 'kind': 'hotspot', 'component': node,
                      'metric': 'commit_touches', 'value': value['touches'], 'commits': value['commits'],
                      'meaning': 'Observed frequency of committed component changes; not a defect diagnosis.'})
        if not reasons and comparable:
            for index in range(1, len(config.windows)):
                old, new = value['windows'][index - 1:index + 1]
                if new['touches'] > old['touches']:
                    facts.append({'id': f'increase:{node}:{index}', 'kind': 'increase', 'component': node,
                                  'metric': 'commit_touches', 'windows': [index - 1, index],
                                  'values': [old['touches'], new['touches']],
                                  'commits': old['commits'] + new['commits'],
                                  'meaning': 'Observed touch count increased in equal UTC windows; no causal claim.'})
    for pair in metrics['pairs']:
        facts.append({'id': 'cochange:' + _digest([pair['a'], pair['b']]), 'kind': 'cochange',
                      **pair, 'meaning': 'Observed joint changes, not proof of a causal dependency.'})
    for fact in facts:
        fact['coverage_complete'] = coverage['complete']
        fact['window_bounds'] = [list(window) for window in config.windows]
    return {'schema': 'getzilla-graph-history-v1', 'identity': identity, 'policies': dict(POLICIES),
            'config': asdict(config), 'config_digest': _digest(asdict(config)), 'architecture_digest': model_digest,
            'metrics': metrics, 'metrics_digest': _digest({'identity': identity, 'config': asdict(config),
                                                          'architecture': model_digest, 'metrics': metrics,
                                                          'policies': POLICIES, 'coverage': coverage}),
            'coverage': coverage, 'facts': facts,
            'observations': {'wall_seconds': time.monotonic() - started, 'git_commands': reader.commands,
                             'verified_objects_by_type': {kind: sum(actual == kind for actual, _ in objects.objects.values())
                                                          for kind in ('commit', 'tree', 'blob', 'tag')} if objects else {},
                             'git_bytes_read': reader.bytes_read, 'peak_git_buffer_bytes': reader.peak_buffer_bytes,
                             'memory_scope': 'retained Git output buffer, plus separate process-lifetime RSS observation',
                             'process_rss_before_bytes': resident_before, 'process_rss_after_bytes': _resident_bytes(),
                             'resident_scope': 'Linux current resident samples, not an isolated or peak allocation',
                             **_memory_observation(),
                             'llm_usage': {'calls': 0, 'input_tokens': 0, 'output_tokens': 0, 'usd': 0,
                                           'model_efficacy': 'not_measured', 'interpretation_execution': 'not_run'}}}


def select_interpretation(report: dict, fact_ids: list[str]) -> dict:
    """A model may select evidence IDs; arbitrary model prose cannot become grounded evidence."""
    available = {fact['id']: fact for fact in report['facts']}
    if (not isinstance(fact_ids, list) or any(not isinstance(item, str) or item not in available for item in fact_ids)
            or len(set(fact_ids)) != len(fact_ids)):
        raise ValueError('interpretation must select existing unique evidence IDs')
    return {'schema': 'getzilla-graph-history-interpretation-v1', 'authority': 'advisory_only',
            'metrics_digest': report['metrics_digest'], 'claims': [available[item] for item in fact_ids],
            'limitations': report['coverage']}


def interpretation_packet(report: dict) -> dict:
    """Freeze a bounded fact-only model input; source, messages and authors are absent."""
    body = {'schema': 'getzilla-graph-history-packet-v1', 'identity': report['identity'],
            'metrics_digest': report['metrics_digest'], 'config_digest': report['config_digest'],
            'architecture_digest': report['architecture_digest'], 'coverage': report['coverage'],
            'facts': report['facts'], 'allowed_response': {'packet_digest': 'exact digest',
                                                         'claims': [{'id': 'existing fact ID', 'commits': ['exact SHAs']}]} }
    # Copy so a caller cannot mutate the report through the model packet.
    body = json.loads(json.dumps(body, ensure_ascii=True))
    return {**body, 'packet_digest': _digest(body)}


def validate_model_selection(report: dict, response: dict) -> dict:
    """Translate a recorded adapter response into canonical claims, never accept model prose."""
    packet = interpretation_packet(report)
    if (not isinstance(response, dict) or set(response) != {'packet_digest', 'claims'}
            or response['packet_digest'] != packet['packet_digest'] or not isinstance(response['claims'], list)
            or len(response['claims']) > len(report['facts'])):
        raise ValueError('unbound interpretation')
    facts = {fact['id']: fact for fact in report['facts']}
    selected = []
    for claim in response['claims']:
        if (not isinstance(claim, dict) or set(claim) != {'id', 'commits'} or not isinstance(claim['id'], str)
                or claim['id'] not in facts or claim['commits'] != facts[claim['id']]['commits']):
            raise ValueError('unsupported interpretation claim')
        selected.append(claim['id'])
    return {**select_interpretation(report, selected), 'packet_digest': packet['packet_digest'],
            'execution': 'recorded_selection_translation_only; model provenance not attested'}
