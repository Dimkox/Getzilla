"""Closed economics controls use synthetic facts, never authority or actual spend."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from getzilla import route_metrics as metrics
from tests.economics_fixtures import payloads, quantity, query, TASK


class EconomicPayloadTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(metrics, 'validate_economics_payload', None)),
                        'closed economic payload validation is absent')

    def validate(self, value):
        function = getattr(metrics, 'validate_economics_payload', None)
        self.assertTrue(callable(function), 'closed economic payload validation is absent')
        return function(value)

    def test_all17_closed_payload_variants_return_owned_snapshots(self):
        values = payloads()
        self.assertEqual(len(values), 17)
        for name, value in values.items():
            with self.subTest(variant=name):
                result = self.validate(value)
                self.assertEqual(result, value)
                self.assertIsNot(result, value)

    def test_published_payload_schema_matches_all17_runtime_closed_field_sets(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/economics-payload.v4.schema.json'
        self.assertTrue(path.is_file(), 'allocated economics payload schema is absent')
        schema = json.loads(path.read_text())
        fields = {}
        for branch in schema['oneOf']:
            definition = schema['$defs'][branch['$ref'].split('/')[-1]]
            kind = definition['properties']['candidate_kind']['const']
            self.assertIs(definition['additionalProperties'], False)
            fields[kind] = set(definition['required'])
            self.assertEqual(fields[kind], set(definition['properties']))
        self.assertEqual(fields, metrics._ECONOMIC_FIELDS)

    def test_unknown_fields_and_variants_refuse_without_payload_in_error(self):
        for value in payloads().values():
            for key in ('attrs', 'trusted_grade', 'role', 'prompt'):
                invalid = dict(value, **{key: 'synthetic-rejected-value'})
                with self.subTest(variant=value['candidate_kind'], field=key), self.assertRaises(ValueError) as caught:
                    self.validate(invalid)
                self.assertEqual(str(caught.exception), 'invalid_economics_payload')
        with self.assertRaises(ValueError):
            self.validate({'candidate_kind': 'future_kind'})

    def test_exact_builtin_types_null_reason_numeric_and_utf8_bounds(self):
        valid = payloads()['local_usage']
        for value in (True, -1, 10**18 + 1, 1.0, '1'):
            invalid = copy.deepcopy(valid)
            invalid['cpu']['value'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(invalid)
        for value, reason in ((None, None), (1, 'not_observed'), (None, 'invented')):
            invalid = copy.deepcopy(valid)
            invalid['cpu'] = quantity(value, 'cpu_ns', reason)
            with self.assertRaises(ValueError):
                self.validate(invalid)
        class DictSubclass(dict):
            pass
        with self.assertRaises(ValueError):
            self.validate(DictSubclass(valid))
        invalid = dict(valid, measurement_method='\ud800')
        with self.assertRaises(ValueError):
            self.validate(invalid)

    def test_real_calendar_ranges_currency_units_and_credit_binding(self):
        for field, replacement in (('start', '2026-02-30T00:00:00Z'),
                                   ('end_exclusive', '2026-10-01T00:00:00Z')):
            value = payloads()['charge']
            value['service_period'][field] = replacement
            with self.assertRaises(ValueError):
                self.validate(value)
        for mutate in ('currency', 'missing_currency', 'unit', 'credit'):
            value = payloads()['charge'] if mutate != 'unit' else payloads()['local_usage']
            if mutate == 'currency':
                value['amount']['currency'] = 'ZZZ'
            elif mutate == 'missing_currency':
                value['amount']['currency'] = None
            elif mutate == 'unit':
                value['cpu']['unit'] = 'elapsed_ns'
            else:
                value['direction'] = 'credit'
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate(value)

    def test_cache_and_reasoning_conservation_and_unknown_semantics(self):
        for change in ('input', 'reasoning', 'no_cache'):
            value = payloads()['model_usage']
            if change == 'input':
                value['input_total']['value'] = 99
            elif change == 'reasoning':
                value['reasoning_output']['value'] = 51
            else:
                value['cache_policy']['mode'] = 'none'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(value)
        value = payloads()['model_usage']
        value['input_semantics'] = 'unknown'
        self.assertEqual(self.validate(value), value)

    def test_allocation_unique_task_and_conservation_pair_disjoint_attempts(self):
        value = payloads()['allocation']
        value['shares'] *= 2
        with self.assertRaises(ValueError):
            self.validate(value)
        value = payloads()['allocation']
        value['shares'].append({'task': dict(TASK, task_id='task:' + '2'*32), 'weight_ppm': 500001})
        with self.assertRaises(ValueError):
            self.validate(value)
        value = payloads()['attempt_relation']
        value['to_attempt'] = value['from_attempt']
        with self.assertRaises(ValueError):
            self.validate(value)
        value = payloads()['cache_pair']
        value['long_operations'] = value['normal_operations']
        with self.assertRaises(ValueError):
            self.validate(value)

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_transport_overflow(self):
        decoder = getattr(metrics, 'decode_economics_payload', None)
        self.assertTrue(callable(decoder), 'strict economics decoder is absent')
        value = payloads()['charge']
        self.assertEqual(decoder(json.dumps(value).encode()), value)
        for raw in (b'{"candidate_kind":"charge","candidate_kind":"charge"}',
                    b'{"value":NaN}', b' ' * 8193, b'\xff'):
            with self.assertRaises(ValueError) as caught:
                decoder(raw)
            self.assertEqual(str(caught.exception), 'invalid_economics_payload')


if __name__ == '__main__':
    unittest.main()


class EconomicQueryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(metrics, 'parse_report_query', None)), 'typed report query is absent')

    def test_normalized_query_has_stable_set_order_utc_and_owned_value(self):
        first = query()
        first['scope_ids'] = ['scope-two', 'scope-one']
        second = copy.deepcopy(first)
        second['scope_ids'].reverse()
        second['views'].reverse()
        second['as_of'] = '2026-11-01T00:00:00.000000Z'
        left, right = metrics.parse_report_query(first), metrics.parse_report_query(second)
        self.assertEqual(left, right)
        self.assertIsInstance(left, metrics.ReportQuery)
        first['scope_ids'].clear()
        self.assertEqual(left.as_dict()['scope_ids'], ['scope-one', 'scope-two'])
        self.assertEqual(left.as_dict()['as_of'], '2026-11-01T00:00:00.000000Z')
        exposed = left.as_dict()
        exposed['cohort']['tasks'].clear()
        self.assertEqual(len(left.as_dict()['cohort']['tasks']), 1)

    def test_closed_query_rejects_effects_roles_bad_times_and_unbounded_dimensions(self):
        for field in ('import', 'write', 'path', 'sql', 'shell', 'url', 'destination', 'role', 'source_grade'):
            invalid = dict(query(), **{field: 'synthetic-disallowed'})
            with self.subTest(field=field), self.assertRaises(ValueError) as caught:
                metrics.parse_report_query(invalid)
            self.assertEqual(str(caught.exception), 'invalid_report_query')
        for field, value in (('scope_ids', []), ('scope_ids', ['a']*9), ('group_by', ['task']*3),
                             ('views', ['invented']), ('as_of', '2026-02-30T00:00:00Z')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                metrics.parse_report_query(dict(query(), **{field: value}))

    def test_task_and_pr_cohorts_are_exact_and_not_authority_labels(self):
        invalid = query()
        invalid['cohort']['tasks'] *= 2
        with self.assertRaises(ValueError):
            metrics.parse_report_query(invalid)
        invalid = query()
        invalid['cohort'] = {'kind': 'verified_pr_ids', 'repository_digest': 'a'*64, 'pr_numbers': [True]}
        with self.assertRaises(ValueError):
            metrics.parse_report_query(invalid)
        invalid['cohort']['pr_numbers'] = [2, 1]
        self.assertEqual(metrics.parse_report_query(invalid).as_dict()['cohort']['pr_numbers'], [1, 2])

    def test_query_decoder_rejects_duplicate_nonfinite_utf8_and_byte_limits(self):
        self.assertEqual(metrics.decode_report_query(json.dumps(query()).encode()), metrics.parse_report_query(query()))
        for raw in (b'{"scope_ids":[],"scope_ids":[]}', b'{"x":NaN}', b'\xff', b' ' * 65537):
            with self.assertRaises(ValueError) as caught:
                metrics.decode_report_query(raw)
            self.assertEqual(str(caught.exception), 'invalid_report_query')

    def test_protected_read_stays_fixed_unavailable_without_any_source_access(self):
        expected = {'definition_version': metrics.ECONOMICS_DEFINITION, 'status': 'unavailable',
                    'reason': 'protected_read_unavailable'}
        with patch.object(metrics, 'regular', side_effect=AssertionError('no source may be opened')):
            for handle in (None, object(), {'role': 'owner', 'uid': 1000}):
                result = metrics.read_report(metrics.parse_report_query(query()), handle=handle)
                self.assertIsInstance(result, metrics.ReportResult)
                self.assertEqual(result.as_dict(), expected)
                self.assertEqual(json.loads(metrics.render_report_json(result)), expected)
                self.assertEqual(metrics.render_report_text(result), 'Economics unavailable: protected_read_unavailable\n')

    def test_result_constructor_is_closed_and_strict_without_hidden_payload(self):
        for canonical in ('{"definition_version":"task-economics-v1","status":"unavailable",'
                          '"reason":"protected_read_unavailable","reason":"input_limit"}',
                          '{"definition_version":"task-economics-v1","status":"unavailable",'
                          '"reason":"protected_read_unavailable","payload":"rejected"}'):
            with self.assertRaises(ValueError) as caught:
                metrics.ReportResult(canonical)
            self.assertEqual(str(caught.exception), 'invalid_report_result')

    def test_published_query_contract_is_closed_and_complete(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/economics-query.schema.json'
        self.assertTrue(path.is_file(), 'query schema is absent')
        schema = json.loads(path.read_text())
        self.assertEqual(set(schema['properties']), metrics._QUERY_FIELDS)
        self.assertIs(schema['additionalProperties'], False)
