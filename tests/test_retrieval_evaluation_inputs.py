"""Public synthetic metadata controls; no independent or human judgments are asserted."""
from __future__ import annotations

from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.retrieval.contracts import digest, sha


def fixture():
    sources, universes, tasks, queries, tables = {}, [], [], [], []
    for corpus in ('small', 'large'):
        functions = []
        for name in ('alpha', 'beta'):
            path = name + '.py'
            raw = f'def {name}():\n    return "public fixture"\n'.encode()
            sources[(corpus, path)] = raw
            item = {'corpus': corpus, 'source_commit': '1' * 40,
                'source_key': ['public-fixture', corpus, 'git-public', 'example.invalid', corpus + ':' + path],
                'path': path, 'start': 1, 'end': 2, 'symbol': name, 'file_sha256': sha(raw),
                'declaration_sha256': sha(raw), 'historical_id': path + ':1:' + name}
            functions.append({'function_id': digest(item), **item})
        universe = {'corpus': corpus, 'source_commit': '1' * 40, 'functions': functions,
            'universe_digest': digest(functions)}
        universes.append(universe)
        rows = []
        for split in ('development', 'holdout'):
            for stratum in ('exact', 'behavior', 'boundary', 'multi', 'no_answer'):
                task_id = f'{split}-{corpus}-{stratum}'
                tasks.append({'task_id': task_id, 'cluster_id': task_id, 'corpus': corpus, 'split': split,
                    'stratum': stratum, 'partition_status': 'provisional', 'novelty_independently_reviewed': False})
                for language in ('en', 'ru', 'mixed'):
                    queries.append({'task_id': task_id, 'query_id': task_id + '-' + language,
                        'language': language, 'text': 'public synthetic task', 'semantic_equivalence_review': 'unreviewed'})
                rows.append({'task_id': task_id, 'judgments': [0, 0], 'eligible_primary': False,
                    'independent_review': 'absent'})
        tables.append({'corpus': corpus, 'universe_digest': universe['universe_digest'],
            'function_ids': [f['function_id'] for f in functions], 'rows': rows})
    return ({'schema_version': 1, 'authority': 'metadata is not source permission', 'universes': universes},
        {'schema_version': 1, 'status': 'provisional', 'tasks': tasks},
        {'schema_version': 1, 'status': 'draft', 'queries': queries},
        {'schema_version': 1, 'status': 'all-unjudged-not-sealed',
         'encoding': {'0': 'unjudged', '1': 'relevant', '2': 'nonrelevant'}, 'tables': tables}, sources)


class EvaluationInputTests(unittest.TestCase):
    def audit(self, data):
        try:
            from getzilla.retrieval.evaluation_inputs import AuditProfile, audit_draft_inputs
        except ImportError:
            self.fail('source-bound draft auditing is unavailable')
        return audit_draft_inputs(*data, profile=AuditProfile((('small', 2), ('large', 2)), 1))

    def test_unknown_is_preserved_and_no_primary_or_ranking_admission_is_inferred(self):
        result = self.audit(fixture())
        self.assertEqual((result.tasks, result.variants, result.holdouts, result.judgment_cells), (20, 60, 10, 40))
        self.assertEqual(result.unjudged_cells, 40)
        self.assertEqual(result.to_dict()['primary_eligible_tasks'], 0)
        self.assertFalse(result.to_dict()['ranking_permitted'])
        with self.assertRaisesRegex(ValueError, '^independent_seals_required$'):
            result.require_rankable()

    def test_even_complete_authored_labels_are_not_independent_or_human_attestation(self):
        data = fixture()
        for table in data[3]['tables']:
            for row in table['rows']:
                row['judgments'] = [1, 2]
        result = self.audit(data)
        self.assertEqual(result.unjudged_cells, 0)
        self.assertEqual(result.to_dict()['primary_eligible_tasks'], 0)
        self.assertEqual(result.to_dict()['qualification'], 'unsealed_metadata_only')

    def test_original_development_english_and_partition_pins_are_checked(self):
        try:
            from getzilla.retrieval.evaluation_inputs import AuditProfile, audit_draft_inputs
            data = fixture()
            task_map = {t['task_id']: t for t in data[1]['tasks']}
            original_en = sorted((q['task_id'], q['text']) for q in data[2]['queries']
                if q['language'] == 'en' and task_map[q['task_id']]['split'] == 'development')
            profile = AuditProfile((('small', 2), ('large', 2)), 1,
                partition_digest=digest(data[1]), development_en_digest=digest(original_en))
        except TypeError:
            self.fail('registered development/partition pin support is unavailable')
        self.assertEqual(audit_draft_inputs(*data, profile=profile).tasks, 20)
        data[2]['queries'][0]['text'] = 'changed public development question'
        with self.assertRaisesRegex(ValueError, '^development_query_mismatch$'):
            audit_draft_inputs(*data, profile=profile)
        data = fixture()
        data[1]['tasks'][0]['cluster_id'] = 'a-different-public-cluster'
        with self.assertRaisesRegex(ValueError, '^partition_scope_mismatch$'):
            audit_draft_inputs(*data, profile=profile)

    def test_source_file_and_original_range_hashes_are_checked(self):
        data = fixture()
        data[4][('small', 'alpha.py')] += b'# public change\n'
        with self.assertRaisesRegex(ValueError, '^source_file_mismatch$'):
            self.audit(data)

    def test_bad_declaration_is_not_repaired_by_matching_function_id(self):
        data = fixture()
        universe = data[0]['universes'][0]
        function = universe['functions'][0]
        function['end'] = 1
        function['function_id'] = digest({k: v for k, v in function.items() if k != 'function_id'})
        universe['universe_digest'] = digest(universe['functions'])
        data[3]['tables'][0]['universe_digest'] = universe['universe_digest']
        data[3]['tables'][0]['function_ids'] = [f['function_id'] for f in universe['functions']]
        with self.assertRaisesRegex(ValueError, '^declaration_mismatch$'):
            self.audit(data)

    def test_full_source_key_is_part_of_function_identity(self):
        data = fixture()
        universe = data[0]['universes'][0]
        universe['functions'][0]['source_key'][3] = 'other-public-site.invalid'
        universe['universe_digest'] = digest(universe['functions'])
        data[3]['tables'][0]['universe_digest'] = universe['universe_digest']
        with self.assertRaisesRegex(ValueError, '^function_identity_mismatch$'):
            self.audit(data)

    def test_omitted_cell_is_not_nonrelevance(self):
        data = fixture()
        data[3]['tables'][0]['rows'][0]['judgments'].pop()
        with self.assertRaisesRegex(ValueError, '^judgment_scope_mismatch$'):
            self.audit(data)

    def test_bool_cannot_be_an_integer_judgment(self):
        data = fixture()
        data[3]['tables'][0]['rows'][0]['judgments'][0] = False
        with self.assertRaisesRegex(ValueError, '^invalid_judgment$'):
            self.audit(data)

    def test_table_order_and_task_membership_are_not_silently_repaired(self):
        for kind in ('function_order', 'task'):
            data = fixture()
            table = data[3]['tables'][0]
            if kind == 'function_order':
                table['function_ids'].reverse()
            else:
                table['rows'][0]['task_id'] = 'omitted-original-task'
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, '^judgment_scope_mismatch$'):
                self.audit(data)

    def test_grouped_languages_and_fixed_strata_are_required(self):
        data = fixture()
        data[2]['queries'].pop()
        with self.assertRaisesRegex(ValueError, '^query_scope_mismatch$'):
            self.audit(data)
        data = fixture()
        data[1]['tasks'][0]['stratum'] = 'behavior'
        with self.assertRaisesRegex(ValueError, '^partition_scope_mismatch$'):
            self.audit(data)

    def test_caller_review_flags_and_unknown_fields_cannot_supply_a_seal(self):
        for edit in ('eligible', 'review', 'authority'):
            data = fixture()
            if edit == 'eligible':
                data[3]['tables'][0]['rows'][0]['eligible_primary'] = True
            elif edit == 'review':
                data[3]['tables'][0]['rows'][0]['independent_review'] = 'human-approved'
            else:
                data[0]['trusted'] = True
            with self.subTest(edit=edit), self.assertRaisesRegex(ValueError, '^(unqualified_review_claim|invalid_input_shape)$'):
                self.audit(data)

    def test_malformed_types_get_fixed_refusal_without_raw_diagnostics(self):
        data = fixture()
        data[0]['universes'][0]['corpus'] = ['public-invalid']
        try:
            self.audit(data)
        except Exception as exc:
            self.assertIsInstance(exc, ValueError)
            self.assertEqual(str(exc), 'invalid_input_shape')
        else:
            self.fail('malformed input was accepted')

    def test_many_functions_in_one_file_do_not_rescan_all_source_lines(self):
        data = fixture()
        for universe in data[0]['universes']:
            corpus = universe['corpus']
            raw = b''.join(data[4].pop((corpus, f['path'])) for f in universe['functions'])
            data[4][(corpus, 'joined.py')] = raw
            for i, function in enumerate(universe['functions']):
                function.update(path='joined.py', start=2 * i + 1, end=2 * i + 2, file_sha256=sha(raw))
                function['historical_id'] = 'joined.py:' + str(function['start']) + ':' + function['symbol']
                function['function_id'] = digest({k: v for k, v in function.items() if k != 'function_id'})
            universe['universe_digest'] = digest(universe['functions'])
            table = next(t for t in data[3]['tables'] if t['corpus'] == corpus)
            table['universe_digest'] = universe['universe_digest']
            table['function_ids'] = [f['function_id'] for f in universe['functions']]
        from getzilla.retrieval import evaluation_inputs
        with mock.patch.object(evaluation_inputs, 'physical_lines', wraps=evaluation_inputs.physical_lines) as scan:
            result = self.audit(data)
        self.assertEqual(result.source_files, 2)
        self.assertEqual(scan.call_count, 2)


class EvaluationInputReaderTests(unittest.TestCase):
    def files(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        candidate, sources = root / 'candidate', root / 'public-source'
        candidate.mkdir()
        sources.mkdir()
        data = fixture()
        for name, document in zip(('function-universes.json', 'partition.json', 'queries.json', 'full-qrels.json'), data):
            (candidate / name).write_text(json.dumps(document), encoding='utf-8', newline='\n')
        for (corpus, path), raw in data[4].items():
            destination = sources / corpus / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        return candidate, sources

    def reader(self, candidate, sources):
        try:
            from getzilla.retrieval.evaluation_inputs import AuditProfile
            from getzilla.retrieval.evaluation_inputs_io import audit_directory
        except ImportError:
            self.fail('bounded draft audit consumer is unavailable')
        return audit_directory(candidate, sources, profile=AuditProfile((('small', 2), ('large', 2)), 1))

    def test_real_reader_checks_public_sources_and_keeps_unsealed_result(self):
        candidate, sources = self.files()
        result = self.reader(candidate, sources)
        self.assertEqual((result.tasks, result.source_files, result.unjudged_cells), (20, 4, 40))
        self.assertFalse(result.to_dict()['ranking_permitted'])

    def test_bad_catalog_refuses_before_any_source_file_is_opened(self):
        candidate, sources = self.files()
        value = json.loads((candidate / 'function-universes.json').read_text())
        value['universes'][0]['functions'][0]['path'] = 'missing-public.py'
        (candidate / 'function-universes.json').write_text(json.dumps(value), encoding='utf-8', newline='\n')
        from getzilla.component_state import BoundRoot
        original, reads = BoundRoot.read, []

        def observe(binding, relative, **kwargs):
            reads.append((binding.path, relative))
            return original(binding, relative, **kwargs)

        with mock.patch.object(BoundRoot, 'read', observe):
            with self.assertRaisesRegex(ValueError, '^universe_scope_mismatch$'):
                self.reader(candidate, sources)
        self.assertFalse(any(root == sources for root, _path in reads))

    def test_duplicate_json_key_is_an_explicit_fixed_refusal(self):
        candidate, sources = self.files()
        original = (candidate / 'queries.json').read_bytes()
        (candidate / 'queries.json').write_bytes(b'{"schema_version":1,' + original[1:])
        with self.assertRaisesRegex(ValueError, '^invalid_input_json$'):
            self.reader(candidate, sources)

    def test_actual_cli_missing_data_has_fixed_json_error_without_traceback(self):
        candidate, sources = self.files()
        (candidate / 'queries.json').unlink()
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_retrieval_inputs.py'),
            str(candidate), '--public-source-root', str(sources)], capture_output=True, text=True,
            encoding='utf-8', timeout=10)
        self.assertTrue(result.stdout.startswith('{'), 'validate-only CLI did not emit a structured result')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout), {'status': 'unavailable', 'reason': 'input_missing'})
        self.assertEqual(result.stderr, '')

    def test_source_replaced_after_validation_refuses_without_publishing_a_result(self):
        candidate, sources = self.files()
        try:
            from getzilla.retrieval import evaluation_inputs_io
        except ImportError:
            self.fail('bounded draft audit consumer is unavailable')
        original = evaluation_inputs_io.audit_draft_inputs

        def replace_public_fixture(*args, **kwargs):
            result = original(*args, **kwargs)
            target = sources / 'small/alpha.py'
            replacement = sources / 'small/replacement.py'
            replacement.write_bytes(target.read_bytes())
            replacement.replace(target)
            return result

        with mock.patch.object(evaluation_inputs_io, 'audit_draft_inputs', replace_public_fixture):
            with self.assertRaisesRegex(ValueError, '^source_changed$'):
                self.reader(candidate, sources)

    def test_registered_catalog_pin_is_checked_before_source_reads(self):
        candidate, sources = self.files()
        try:
            from getzilla.retrieval.evaluation_inputs import AuditProfile
            from getzilla.retrieval.evaluation_inputs_io import audit_directory
        except ImportError:
            self.fail('bounded draft audit consumer is unavailable')
        profile = AuditProfile((('small', 2), ('large', 2)), 1, (('small', '0' * 64),))
        from getzilla.component_state import BoundRoot
        original, reads = BoundRoot.read, []

        def observe(binding, relative, **kwargs):
            reads.append((binding.path, relative))
            return original(binding, relative, **kwargs)

        with mock.patch.object(BoundRoot, 'read', observe):
            with self.assertRaisesRegex(ValueError, '^universe_scope_mismatch$'):
                audit_directory(candidate, sources, profile=profile)
        self.assertFalse(any(root == sources for root, _path in reads))


if __name__ == '__main__':
    unittest.main()
