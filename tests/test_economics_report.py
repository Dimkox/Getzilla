"""Closed economics controls use synthetic facts, never authority or actual spend."""
import copy
import hashlib
import json
from pathlib import Path
from fractions import Fraction
import unittest
from unittest.mock import patch

from getzilla import route_metrics as metrics
from tests.economics_fixtures import payloads, quantity, query, TASK, OP, observation, binding, calculation_input


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

    def test_known_cache_buckets_cannot_exceed_total_with_unknown_uncached(self):
        value = payloads()['model_usage']
        value['uncached_input'] = quantity(None, reason='not_observed')
        value['input_total']['value'] = 1
        with self.assertRaises(ValueError):
            self.validate(value)

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
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as caught:
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

    def test_published_result_contract_is_closed_and_covers_computed_and_unavailable(self):
        path = Path(__file__).resolve().parents[1] / 'schemas/economics-result.schema.json'
        self.assertTrue(path.is_file(), 'closed result schema is absent')
        schema = json.loads(path.read_text())
        self.assertEqual(len(schema['oneOf']), 2)
        for name in ('ComputedResult', 'Unavailable', 'TaskRow', 'Money', 'Ratio', 'Usage'):
            value = schema['$defs'][name]
            self.assertIs(value['additionalProperties'], False)
            self.assertEqual(set(value['required']), set(value['properties']))


class EconomicReducerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(metrics, 'compute_economics', None)), 'pure economics reducer is absent')

    def compute(self, data, request=None):
        return metrics.compute_economics(data, metrics.parse_report_query(request or query())).as_dict()

    def money(self, values, currency='USD', basis='confirmed_billed', field='value'):
        item = next(item for item in values if item['currency'] == currency and item['basis'] == basis)
        value = item[field]
        return None if value is None else Fraction(int(value['numerator']), int(value['denominator']))

    def charge(self, value, operation=None, line='a'*64, period=None):
        result = payloads()['charge']
        result['amount']['value'] = value
        result['operation'] = copy.deepcopy(operation or OP)
        result['external_line_digest'] = line
        result['source_fact_digest'] = hashlib.sha256(json.dumps([value, operation, line], sort_keys=True).encode()).hexdigest()
        if period is not None:
            result['service_period'] = period
        return result

    def test_oldhead_preselection_attempts_count_in_lifetime_but_not_current_period(self):
        old = dict(OP, operation_id='older-operation', attempt_id='older-attempt',
                   physical_operation_digest='2'*64, claim_event_digest='3'*64)
        new_period = {'start': '2026-10-20T00:00:00Z', 'end_exclusive': '2026-10-21T00:00:00Z'}
        rows = [observation(self.charge(100, old), 'old'),
                observation(self.charge(200, line='b'*64, period=new_period), 'new'),
                observation(payloads()['task_disposition'], 'accept')]
        result = self.compute(calculation_input(rows, bindings=[binding(old, head='a'*40, outcome='failed'), binding()]))
        self.assertEqual(self.money(result['totals']['task_lifetime']), 3)
        self.assertEqual(self.money(result['totals']['cohort_period_spend']), 2)
        self.assertEqual(result['ratios']['accepted_tasks'], 1)
        self.assertEqual(self.money(result['ratios']['accepted_task_mean']), 3)
        task = result['tasks'][0]
        self.assertEqual({attempt['head'] for attempt in task['attempts']}, {'a'*40, 'd'*40})
        self.assertEqual(len(task['attempts']), 2)

    def test_exact_replay_and_input_permutation_have_identical_result_and_snapshot(self):
        row = observation(self.charge(100), 'charge')
        data = calculation_input([row, observation(payloads()['task_disposition'], 'accept')])
        expected = self.compute(data)
        data['observations'] = list(reversed(data['observations'])) + [copy.deepcopy(row)]
        self.assertEqual(self.compute(data), expected)
        request = query()
        request['snapshot_ref'] = expected['snapshot_ref']
        self.assertEqual(self.compute(data, request), expected)

    def test_bill_conflict_is_quarantined_before_task_and_accounting_filter(self):
        other = dict(OP, operation_id='outside-operation', physical_operation_digest='4'*64, claim_event_digest='5'*64)
        first = observation(self.charge(100), 'one')
        changed = self.charge(999, other)
        changed['amount']['currency'] = 'EUR'
        second = observation(changed, 'two', at='2026-10-01T00:00:00Z')
        foreign = dict(TASK, task_id='task:'+'2'*32)
        result = self.compute(calculation_input([first, second], bindings=[binding(), binding(other, foreign)]))
        self.assertEqual(result['reconciliation']['conflict_count'], 2)
        self.assertIsNone(self.money(result['totals']['task_lifetime'], currency=None))
        self.assertFalse(result['coverage']['complete'])

    def test_local_provider_usage_is_once_only_and_billed_and_estimated_never_add(self):
        local = payloads()['model_usage']
        provider = copy.deepcopy(local)
        provider.update(source_fact_digest='d'*64, source_proof_ref='e'*64, observation_origin='provider_export')
        result = self.compute(calculation_input([observation(local, 'local'), observation(provider, 'provider'),
                                                 observation(self.charge(300), 'charge')]))
        measured = {item['category']: item for item in result['tasks'][0]['usage']}
        self.assertEqual(measured['input_total']['value'], 100)
        self.assertEqual(self.money(result['totals']['task_lifetime']), 3)
        self.assertEqual(result['reconciliation']['coalesced_observations'], 1)
        self.assertNotIn('combined_money', result['totals'])

    def test_shared_allocation_conserves_exact_amount_and_exposes_remainder(self):
        allocation = payloads()['allocation']
        allocation['shares'][0]['weight_ppm'] = 333333
        result = self.compute(calculation_input([observation(self.charge(1), 'charge'),
                                                 observation(allocation, 'allocation')]))
        self.assertEqual(self.money(result['totals']['task_lifetime'], field='known_subtotal'), Fraction(333333, 100000000))
        self.assertEqual(self.money(result['reconciliation']['unallocated']), Fraction(666667, 100000000))
        self.assertEqual(self.money(result['totals']['scope_period_spend'], field='known_subtotal'), 0)

    def test_unknown_census_zero_accepted_and_missing_human_are_distinct(self):
        data = calculation_input([observation(self.charge(0), 'known-zero')])
        data['census'] = None
        request = query()
        request['views'].append('friction138')
        unknown = self.compute(data, request)
        self.assertIsNone(unknown['ratios']['accepted_tasks'])
        self.assertIsNone(unknown['friction138']['human_minutes'])
        data['census'] = [TASK]
        rejected = payloads()['task_disposition']
        rejected['decision'] = 'rejected'
        data['observations'].append(observation(rejected, 'explicit-rejection'))
        known = self.compute(data, request)
        self.assertEqual(known['ratios']['accepted_tasks'], 0)
        self.assertIsNone(self.money(known['ratios']['cohort_spend_per_accepted']))
        self.assertIn('zero_denominator', known['ratios']['reasons'])

    def test_completion_merge_acceptance_and_late_revocation_remain_independent(self):
        accepted = payloads()['task_disposition']
        revoked = copy.deepcopy(accepted)
        revoked.update(decision='revoked', decision_id='b'*64, supersedes=accepted['decision_id'])
        rows = [observation(payloads()['workflow_end'], 'ended'),
                observation(payloads()['completion'], 'completed'), observation(accepted, 'accepted'),
                observation(revoked, 'revoked', at='2026-11-02T00:00:00Z')]
        old = self.compute(calculation_input(rows))
        self.assertEqual(old['ratios']['accepted_tasks'], 1)
        self.assertEqual(old['tasks'][0]['workflow_end'], 'failed')
        self.assertEqual(old['tasks'][0]['completion'], 'completed')
        self.assertIsNone(old['tasks'][0]['merged'])
        request = query()
        request['as_of'] = '2026-11-03T00:00:00Z'
        new = self.compute(calculation_input(rows), request)
        self.assertEqual(new['ratios']['accepted_tasks'], 0)
        self.assertEqual(new['tasks'][0]['disposition'], 'revoked')
        self.assertNotEqual(old['snapshot_ref'], new['snapshot_ref'])

    def test_declared_human_decision_count_and_duration_are_separate(self):
        duration = payloads()['human_usage']
        duration['human_time']['value'] = 1200 * 10**9
        rows = [observation(duration, 'duration'), observation(payloads()['human_decision'], 'decision')]
        request = query()
        request['views'].append('friction138')
        result = self.compute(calculation_input(rows), request)
        self.assertEqual(result['friction138']['human_decision_count'], 1)
        self.assertEqual(result['friction138']['human_minutes'], {'numerator': '20', 'denominator': '1'})
        self.assertIsNone(result['friction138']['approval_count_per_commit'])

    def test_invalid_proof_or_row_bounds_never_return_complete_partial_census(self):
        data = calculation_input([observation(self.charge(100), 'charge')])
        data['observations'][0]['delivery']['row_digest'] = '0'*64
        result = self.compute(data)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(set(result), {'definition_version', 'status', 'reason'})

    def test_json_text_render_same_nullable_result_without_implicit_currency(self):
        amount = self.charge(1)
        amount['amount'].update(value=None, currency=None, unknown_reason='currency_missing')
        result = metrics.compute_economics(calculation_input([observation(amount, 'unknown')]), query())
        self.assertEqual(json.loads(metrics.render_report_json(result)), result.as_dict())
        text = metrics.render_report_text(result)
        self.assertIn('unknown', text)
        self.assertNotIn('0 USD', text)

    def tariffs(self, *, reasoning=False):
        rows = []
        rates = [('uncached_input', 1, 1), ('cache_write', 2, 1), ('cache_read', 1, 10), ('output', 3, 1)]
        if reasoning:
            rates.append(('reasoning_output', 5, 1))
        for category, numerator, denominator in rates:
            value = payloads()['tariff']
            value.update(category=category, rate_numerator=numerator, rate_denominator=denominator)
            rows.append(observation(value, 'rate-' + category, at='2026-10-01T00:00:00Z'))
        return rows

    def test_valid_time_rational_rates_do_not_double_charge_inclusive_reasoning(self):
        data = calculation_input([observation(payloads()['model_usage'], 'model'), *self.tariffs()])
        result = self.compute(data)
        self.assertEqual(self.money(result['totals']['task_lifetime'], basis='tariff_estimate'), Fraction(233, 10**6))
        data['observations'] = [observation(payloads()['model_usage'], 'model'), *self.tariffs(reasoning=True)]
        separate = self.compute(data)
        self.assertEqual(self.money(separate['totals']['task_lifetime'], basis='tariff_estimate'), Fraction(273, 10**6))

    def test_rate_boundary_spanning_unsegmented_usage_remains_unknown(self):
        rates = self.tariffs()
        for item in rates:
            payload = item['row']['payload']
            payload['validity']['end_exclusive'] = '2026-10-01T12:00:00Z'
            replacement = observation(payload, 'short-rate-' + payload['category'], at='2026-10-01T00:00:00Z')
            item.update(replacement)
        result = self.compute(calculation_input([observation(payloads()['model_usage'], 'model'), *rates]))
        self.assertIsNone(self.money(result['totals']['task_lifetime'], currency=None, basis='tariff_estimate'))

    def test_credit_and_selected_dated_fx_are_distinct_from_token_usage(self):
        debit = observation(self.charge(300), 'debit')
        credit_payload = self.charge(100, line='c'*64)
        credit_payload.update(direction='credit', adjusts_charge_event=debit['row']['event_id'])
        fx = observation(payloads()['fx'], 'fx', at='2026-10-01T00:00:00Z')
        data = calculation_input([debit, observation(credit_payload, 'credit'), fx])
        request = query()
        request['fx_refs'] = [fx['row']['event_id']]
        result = self.compute(data, request)
        self.assertEqual(self.money(result['totals']['task_lifetime']), 2)
        candidates = [row for row in result['fx_totals'] if row['view'] == 'task_lifetime'
                      and row['from_currency'] == 'USD' and row['to_currency'] == 'EUR']
        self.assertTrue(candidates, 'selected dated FX calculation is absent')
        converted = candidates[0]
        self.assertEqual(self.money(converted['amounts'], currency='EUR'), Fraction(9, 5))

    def test_ambiguous_reasoning_tariffs_cannot_use_absent_rate_fallback(self):
        request = query()
        request.update(views=['task_lifetime'], money_bases=['tariff_estimate'])
        rows = [observation(payloads()['model_usage'], 'model'),
                observation(payloads()['task_disposition'], 'accepted')]
        missing = self.compute(calculation_input(rows + self.tariffs()), request)
        single = self.compute(calculation_input(rows + self.tariffs(reasoning=True)), request)
        self.assertEqual(self.money(missing['totals']['task_lifetime'], basis='tariff_estimate'), Fraction(233, 10**6))
        self.assertEqual(self.money(single['totals']['task_lifetime'], basis='tariff_estimate'), Fraction(273, 10**6))
        self.assertEqual((missing['status'], single['status']), ('ok', 'ok'))
        second = payloads()['tariff']
        second.update(category='reasoning_output', rate_numerator=7)
        contradictory = observation(second, 'second-reasoning-rate', at='2026-10-01T00:00:00Z')
        data = calculation_input(rows + self.tariffs(reasoning=True) + [contradictory])
        before = copy.deepcopy(data)
        result = self.compute(data, request)
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['coverage']['complete'])
        self.assertTrue(all(item['value'] is None for item in result['totals']['task_lifetime']))
        self.assertTrue(any('ambiguous' in item['unknown_reasons'] for item in result['totals']['task_lifetime']))
        self.assertEqual(data, before)
        data['observations'].reverse()
        self.assertEqual(self.compute(data, request), result)

    def test_credit_parent_requires_same_account_currency_and_operation(self):
        debit = observation(self.charge(300), 'account-debit')
        credit = self.charge(100, line='d'*64)
        credit.update(direction='credit', adjusts_charge_event=debit['row']['event_id'])
        request = query()
        request.update(views=['task_lifetime'], money_bases=['confirmed_billed'])
        accepted = observation(payloads()['task_disposition'], 'accepted')
        matching = self.compute(calculation_input([debit, observation(credit, 'credit'), accepted]), request)
        self.assertEqual(matching['status'], 'ok')
        self.assertEqual(self.money(matching['totals']['task_lifetime']), 2)
        self.assertEqual(matching['reconciliation']['conflict_count'], 0)
        variants = [('provider_account_digest', 'e'*64), ('amount', dict(credit['amount'], currency='EUR')),
                    ('operation', dict(OP, operation_id='other-operation'))]
        for field, value in variants:
            changed = copy.deepcopy(credit)
            changed[field] = value
            data = calculation_input([debit, observation(changed, 'credit'), accepted])
            before = copy.deepcopy(data)
            with self.subTest(field=field):
                result = self.compute(data, request)
                self.assertEqual(result['reconciliation']['conflict_count'], 2)
                self.assertFalse(result['coverage']['complete'])
                self.assertTrue(all(item['value'] is None for item in result['totals']['task_lifetime']))
                self.assertEqual(data, before)
                data['observations'].reverse()
                self.assertEqual(self.compute(data, request), result)

    def reasoning_rate(self, identity, *, rate=5, start='2026-10-01T00:00:00Z',
                       end='2026-10-02T00:00:00Z', **changes):
        value = payloads()['tariff']
        value.update(category='reasoning_output', rate_numerator=rate,
                     validity={'start': start, 'end_exclusive': end}, **changes)
        return observation(value, identity, at='2026-10-01T00:00:00Z')

    def reasoning_prices(self, rates):
        request = query()
        request.update(views=['task_lifetime'], money_bases=['tariff_estimate'])
        data = calculation_input([observation(payloads()['model_usage'], 'model'),
                                  observation(payloads()['task_disposition'], 'accepted'),
                                  *self.tariffs(), *rates])
        before = copy.deepcopy(data)
        result = self.compute(data, request)
        self.assertEqual(data, before)
        data['observations'].reverse()
        self.assertEqual(self.compute(data, request), result)
        return result

    def test_partial_and_split_reasoning_tariffs_are_not_absent(self):
        first = self.reasoning_rate('first-half', end='2026-10-01T12:00:00Z')
        second = self.reasoning_rate('second-half', rate=7, start='2026-10-01T12:00:00Z')
        same = self.reasoning_rate('same-second-half', start='2026-10-01T12:00:00Z')
        for label, rates in [('first-only', [first]), ('second-only', [second]),
                             ('split-different', [first, second]), ('split-same', [first, same])]:
            with self.subTest(coverage=label):
                result = self.reasoning_prices(rates)
                self.assertEqual(result['status'], 'partial')
                self.assertFalse(result['coverage']['complete'])
                money = result['totals']['task_lifetime']
                self.assertTrue(all(item['value'] is None for item in money))
                self.assertTrue(any('ambiguous' in item['unknown_reasons'] for item in money))
                refs = {ref for item in money for ref in item['source_refs']}
                self.assertTrue({item['row']['event_id'] for item in rates} <= refs)

    def test_full_reasoning_tariff_cannot_hide_conflicting_partial_rate(self):
        full = self.reasoning_rate('full-rate')
        partial = self.reasoning_rate('conflicting-partial', rate=7, end='2026-10-01T12:00:00Z')
        result = self.reasoning_prices([full, partial])
        self.assertEqual(result['status'], 'partial')
        self.assertFalse(result['coverage']['complete'])
        money = result['totals']['task_lifetime']
        self.assertTrue(all(item['value'] is None for item in money))
        refs = {ref for item in money for ref in item['source_refs']}
        self.assertTrue({full['row']['event_id'], partial['row']['event_id']} <= refs)

    def test_reasoning_tariff_absence_inapplicability_and_full_equivalence_stay_known(self):
        before = self.reasoning_rate('before', start='2026-09-30T00:00:00Z', end='2026-10-01T00:00:00Z')
        after = self.reasoning_rate('after', start='2026-10-02T00:00:00Z', end='2026-10-03T00:00:00Z')
        wrong_model = self.reasoning_rate('other-model', model_id='different-model')
        wrong_policy = self.reasoning_rate('other-policy', cache_policy_digest='f'*64)
        full = self.reasoning_rate('full-rate')
        equivalent = self.reasoning_rate('equivalent-full', source_proof_ref='e'*64)
        same_partial = self.reasoning_rate('same-partial', end='2026-10-01T12:00:00Z')
        for label, rates, expected in [('absent', [], 233), ('outside', [before, after], 233),
                                       ('inapplicable', [wrong_model, wrong_policy], 233),
                                       ('single-full', [full], 273), ('equivalent-full', [full, equivalent], 273),
                                       ('matching-partial', [full, same_partial], 273),
                                       ('irrelevant-partial', [full, before, after, wrong_model, wrong_policy], 273)]:
            with self.subTest(rates=label):
                result = self.reasoning_prices(rates)
                self.assertEqual(result['status'], 'ok')
                self.assertTrue(result['coverage']['complete'])
                self.assertEqual(self.money(result['totals']['task_lifetime'], basis='tariff_estimate'),
                                 Fraction(expected, 10**6))

    def test_two_currencies_never_convert_without_selected_fx(self):
        euro = self.charge(200, line='d'*64)
        euro['amount']['currency'] = 'EUR'
        result = self.compute(calculation_input([observation(self.charge(100), 'usd'), observation(euro, 'eur')]))
        self.assertEqual(self.money(result['totals']['task_lifetime']), 1)
        self.assertEqual(self.money(result['totals']['task_lifetime'], currency='EUR'), 2)
        self.assertEqual(result['fx_totals'], [])

    def test_actual_cache_pair_requires_both_disjoint_observed_operation_sets(self):
        long_operation = dict(OP, operation_id='operation-two', physical_operation_digest='e'*64, claim_event_digest='e'*64)
        normal = payloads()['model_usage']
        long = copy.deepcopy(normal)
        long.update(operation=long_operation, source_fact_digest='d'*64)
        long['cache_policy'].update(mode='long', policy_digest='b'*64)
        pair = payloads()['cache_pair']
        pair['basis'] = 'actual_pair'
        pair_row = observation(pair, 'pair')
        request = query()
        request['cache_pair_refs'] = [pair_row['row']['event_id']]
        request['views'].append('cache_comparison')
        data = calculation_input([observation(normal, 'normal'), observation(long, 'long'), pair_row],
                                 bindings=[binding(), binding(long_operation)])
        result = self.compute(data, request)
        self.assertTrue(result['cache_comparison'], 'requested cache comparison is absent')
        self.assertEqual(result['cache_comparison'][0]['basis'], 'actual_pair')
        self.assertNotIn('not_observed', result['cache_comparison'][0]['unknown_reasons'])
        data['observations'].pop(1)
        missing = self.compute(data, request)
        self.assertIn('not_observed', missing['cache_comparison'][0]['unknown_reasons'])
        self.assertEqual(missing['cache_comparison'][0]['status'], 'partial')

    def test_requested_allowlisted_grouping_is_derived_from_same_contributions(self):
        request = query()
        request['group_by'] = ['task', 'disposition']
        request['views'] = ['task_lifetime']
        result = self.compute(calculation_input([observation(self.charge(100), 'charge'),
                                                 observation(payloads()['task_disposition'], 'accept')]), request)
        self.assertEqual(len(result['groups']), 1)
        self.assertEqual(result['groups'][0]['dimensions']['disposition'], 'accepted')
        self.assertEqual(self.money(result['groups'][0]['amounts']), 1)

    def test_changed_first_delivery_proof_does_not_silently_choose_one_version(self):
        first = observation(self.charge(100), 'charge')
        second = copy.deepcopy(first)
        second['delivery']['delivered_by'] = '2026-10-21T00:00:01.000001Z'
        result = self.compute(calculation_input([first, second]))
        self.assertEqual(result['status'], 'unavailable')

    def test_closed_result_refuses_partial_cost_relabelled_complete(self):
        result = self.compute(calculation_input([observation(self.charge(100), 'charge')]))
        self.assertEqual(result['status'], 'partial')
        result['status'] = 'ok'
        with self.assertRaises(ValueError):
            metrics.ReportResult(json.dumps(result))

    def test_missing_related_attempt_bill_and_unallocated_share_are_not_full_costs(self):
        missing = dict(OP, physical_operation_digest='d'*64, operation_id='missing-operation', attempt_id='missing-attempt',
                       claim_event_digest='d'*64)
        data = calculation_input([observation(self.charge(100), 'charge')], bindings=[binding(), binding(missing)])
        result = self.compute(data)
        self.assertIsNone(self.money(result['totals']['task_lifetime']))
        self.assertEqual(self.money(result['totals']['task_lifetime'], field='known_subtotal'), 1)
        allocation = payloads()['allocation']
        result = self.compute(calculation_input([observation(self.charge(100), 'charge'), observation(allocation, 'share')]))
        self.assertIsNone(self.money(result['totals']['task_lifetime']))
        self.assertEqual(self.money(result['totals']['task_lifetime'], field='known_subtotal'), Fraction(3, 5))

    def test_unknown_disposition_cannot_be_reported_as_zero_rejected_share(self):
        result = self.compute(calculation_input([observation(self.charge(100), 'charge')]))
        self.assertIsNone(self.money(result['ratios']['rejected_abandoned_share']))
        self.assertIn('outcome_unknown', result['ratios']['rejected_abandoned_share'][0]['unknown_reasons'])

    def test_unsuccessful_attempt_spend_inside_accepted_task_has_separate_share(self):
        old = dict(OP, operation_id='old-operation', attempt_id='old-attempt', physical_operation_digest='d'*64,
                   claim_event_digest='d'*64)
        result = self.compute(calculation_input([observation(self.charge(100, old), 'old'),
            observation(self.charge(200, line='e'*64), 'new'), observation(payloads()['task_disposition'], 'accept')],
            bindings=[binding(old, outcome='failed'), binding()]))
        self.assertIn('unsuccessful_attempt_share', result['ratios'], 'attempt waste view is absent')
        self.assertEqual(self.money(result['ratios']['unsuccessful_attempt_share']), Fraction(1, 3))

    def test_attempt_cycle_or_unseen_parent_does_not_qualify_a_complete_history(self):
        rows = [observation(self.charge(100), 'charge'), observation(payloads()['task_disposition'], 'accept')]
        left = payloads()['attempt_relation']
        right = copy.deepcopy(left)
        right.update(from_attempt=left['to_attempt'], to_attempt=left['from_attempt'])
        result = self.compute(calculation_input(rows + [observation(left, 'retry-left'), observation(right, 'retry-right')]))
        self.assertFalse(result['coverage']['complete'])
        self.assertIsNone(self.money(result['totals']['task_lifetime']))

    def test_native_selection_window_keeps_old_attempts_and_missing_selection_is_unknown(self):
        request = query()
        request['cohort'] = {'kind': 'selection_window', 'selection_interval': request['accounting_interval']}
        data = calculation_input([observation(self.charge(100), 'before-selected'),
                                  observation(payloads()['task_disposition'], 'accept')])
        self.assertEqual(self.money(self.compute(data, request)['totals']['task_lifetime']), 1)
        data['census'] = None
        result = self.compute(data, request)
        self.assertIsNone(result['ratios']['accepted_tasks'])

    def test_group_and_row_limits_fail_without_truncating_or_touching_input(self):
        data = calculation_input([observation(self.charge(100), 'charge')])
        data['observations'] *= 4097
        before = copy.deepcopy(data)
        result = self.compute(data)
        self.assertEqual(result['status'], 'unavailable')
        self.assertEqual(data, before)

    def test_group_and_fx_totals_keep_missing_related_costs_unknown(self):
        missing = dict(OP, physical_operation_digest='d'*64, operation_id='missing-operation', attempt_id='missing-attempt',
                       claim_event_digest='d'*64)
        fx = observation(payloads()['fx'], 'fx', at='2026-10-01T00:00:00Z')
        request = query()
        request['fx_refs'] = [fx['row']['event_id']]
        result = self.compute(calculation_input([observation(self.charge(100), 'charge'), fx],
                                                 bindings=[binding(), binding(missing)]), request)
        group = next(group for group in result['groups'] if group['view'] == 'task_lifetime')
        self.assertIsNone(self.money(group['amounts']))
        converted = next(row for row in result['fx_totals'] if row['view'] == 'task_lifetime')
        self.assertIsNone(self.money(converted['amounts'], currency='EUR'))

    def test_owned_result_rejects_contradictory_full_value_and_nonboolean_merge(self):
        result = self.compute(calculation_input([observation(self.charge(100), 'charge')]))
        altered = copy.deepcopy(result)
        money = next(row for row in altered['totals']['task_lifetime'] if row['currency'] == 'USD')
        money['value'] = {'numerator': '999', 'denominator': '1'}
        with self.assertRaises(ValueError):
            metrics.ReportResult(json.dumps(altered))
        altered = copy.deepcopy(result)
        altered['tasks'][0]['merged'] = 1
        with self.assertRaises(ValueError):
            metrics.ReportResult(json.dumps(altered))

    def test_wall_budget_exhaustion_returns_no_partial_totals_and_preserves_input(self):
        self.assertTrue(hasattr(metrics, 'ECONOMICS_MAX_WALL_SECONDS'), 'bounded calculation clock is absent')
        data = calculation_input([observation(self.charge(100), 'charge')])
        before = copy.deepcopy(data)
        readings = iter([0.0, 5.0])
        with patch('getzilla.route_metrics.time.monotonic', side_effect=lambda: next(readings, 5.0)):
            result = self.compute(data)
        self.assertEqual(result, {'definition_version': metrics.ECONOMICS_DEFINITION,
                                  'status': 'unavailable', 'reason': 'input_limit'})
        self.assertEqual(data, before)

    def test_original_claim_cannot_change_subject_by_changing_physical_operation(self):
        other = dict(OP, operation_id='other-operation', physical_operation_digest='d'*64)
        foreign = dict(TASK, task_id='task:'+'2'*32)
        result = self.compute(calculation_input([observation(self.charge(100), 'original'),
            observation(self.charge(200, other, line='e'*64), 'changed-subject')],
            bindings=[binding(), binding(other, foreign)]))
        self.assertEqual(result['reconciliation']['conflict_count'], 2)

    def test_native_claim_cannot_be_reused_for_two_effects_in_one_subject(self):
        other = dict(OP, operation_id='other-effect', physical_operation_digest='e'*64)
        result = self.compute(calculation_input([observation(self.charge(100), 'first'),
            observation(self.charge(200, other, line='e'*64), 'second')], bindings=[binding(), binding(other)]))
        self.assertEqual(result['reconciliation']['conflict_count'], 2)

    def test_accepted_task_mean_and_cohort_spend_per_accepted_have_distinct_numerators(self):
        other_task = dict(TASK, task_id='task:'+'2'*32)
        other = dict(OP, operation_id='other-operation', physical_operation_digest='d'*64, claim_event_digest='e'*64)
        rejected = payloads()['task_disposition']
        rejected.update(task=other_task, decision='rejected', decision_id='b'*64)
        data = calculation_input([observation(self.charge(100), 'accepted-cost'),
            observation(self.charge(200, other, line='e'*64), 'rejected-cost'),
            observation(payloads()['task_disposition'], 'accept'), observation(rejected, 'reject')],
            bindings=[binding(), binding(other, other_task)], census=[TASK, other_task])
        request = query()
        request['cohort']['tasks'].append(other_task)
        result = self.compute(data, request)
        self.assertEqual(self.money(result['ratios']['accepted_task_mean']), 1)
        self.assertEqual(self.money(result['ratios']['cohort_spend_per_accepted']), 3)
        self.assertEqual(self.money(result['ratios']['rejected_abandoned_share']), Fraction(2, 3))

    def test_as_known_uses_strict_capture_but_inclusive_six_fraction_delivery_cut(self):
        request = query()
        before = observation(self.charge(100), 'included', at='2026-10-31T23:59:59Z',
                             delivered_by='2026-11-01T00:00:00.000000Z')
        self.assertEqual(self.money(self.compute(calculation_input([before]), request)['totals']['task_lifetime']), 1)
        late = observation(self.charge(100), 'late', at='2026-10-31T23:59:59Z',
                           captured_at='2026-11-01T00:00:00Z', delivered_by='2026-11-01T00:00:00.000000Z')
        result = self.compute(calculation_input([late]), request)
        self.assertNotIn(late['row']['event_id'], result['source_refs'])
        delivered_late = observation(self.charge(100), 'delivery-late', at='2026-10-31T23:59:59Z',
                                     delivered_by='2026-11-01T00:00:00.000001Z')
        result = self.compute(calculation_input([delivered_late]), request)
        self.assertNotIn(delivered_late['row']['event_id'], result['source_refs'])

    def test_unrequested_views_do_not_populate_human_or_lifetime_sections(self):
        request = query()
        request['views'] = ['period_spend']
        data = calculation_input([observation(self.charge(100), 'charge'),
                                  observation(payloads()['human_decision'], 'decision')])
        result = self.compute(data, request)
        self.assertIsNone(result['friction138'])
        self.assertIsNone(result['ratios'])
        self.assertEqual(result['totals']['task_lifetime'], [])
        self.assertTrue(all(task['money'] == [] and task['usage'] == [] for task in result['tasks']))
        self.assertTrue(all(group.get('view') == 'cohort_period_spend' for group in result['groups']))

    def test_grouping_names_its_lifetime_or_accounting_period(self):
        result = self.compute(calculation_input([observation(self.charge(100), 'before-accounting'),
                                                 observation(payloads()['task_disposition'], 'accept')]))
        self.assertTrue(result['groups'])
        self.assertTrue(all('view' in group for group in result['groups']), 'group time basis is absent')
        lifetime = next(group for group in result['groups'] if group['view'] == 'task_lifetime')
        period = next(group for group in result['groups'] if group['view'] == 'cohort_period_spend')
        self.assertEqual(self.money(lifetime['amounts']), 1)
        self.assertEqual(self.money(period['amounts']), 0)

    def test_complete_flag_cannot_override_unknown_amounts_or_denominator(self):
        value = self.compute(calculation_input([observation(self.charge(100), 'charge')]))
        value.update(status='ok')
        value['coverage']['complete'] = True
        with self.assertRaises(ValueError):
            metrics.ReportResult(json.dumps(value))

    def test_text_includes_same_cost_denominators_and_reconciliation_as_json(self):
        result = metrics.compute_economics(calculation_input([observation(self.charge(300), 'charge'),
            observation(payloads()['task_disposition'], 'accept')]), query())
        text = metrics.render_report_text(result)
        self.assertIn('accepted_task_mean', text)
        self.assertIn('cohort_spend_per_accepted', text)
        self.assertIn('accepted_tasks=1', text)
        self.assertIn('Conflicting observations: 0', text)

    def test_maximum_row_count_retains_event_and_proof_refs_within_output_bounds(self):
        payload = self.charge(100)
        payload['service_period'] = {'start': '2026-10-20T00:00:00Z', 'end_exclusive': '2026-10-21T00:00:00Z'}
        rows = [observation(payload, 'maximum-' + str(index)) for index in range(4096)]
        request = query()
        request.update(views=['period_spend'], group_by=[], money_bases=['confirmed_billed'])
        # This isolates structural-reference ceilings. A separate fresh-process
        # benchmark exercises actual clocks/resources without this unit seam.
        with patch.object(metrics, '_economic_budget', return_value=None):
            result = self.compute(calculation_input(rows), request)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(self.money(result['totals']['cohort_period_spend']), 1)
        self.assertEqual(len(result['totals']['cohort_period_spend'][0]['source_refs']), 4097)


if __name__ == '__main__':
    unittest.main()
