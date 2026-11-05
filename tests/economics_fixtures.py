"""Synthetic public facts, never measurements, invoices or authority."""
from copy import deepcopy

H = 'a' * 64
TASK = {'domain': 'core_native', 'project_digest': H, 'task_id': 'task:' + '1' * 32}
OP = {'claim_event_digest': H, 'operation_id': 'operation-one', 'attempt_id': 'attempt-one',
      'producer_binding_digest': 'b' * 64, 'physical_operation_digest': 'c' * 64}
PERIOD = {'start': '2026-10-01T00:00:00Z', 'end_exclusive': '2026-10-02T00:00:00Z'}


def quantity(value, unit='token', reason=None):
    return {'value': value, 'unit': unit, 'unknown_reason': reason}


def query():
    return {'scope_ids': ['scope-one'], 'as_of': '2026-11-01T00:00:00Z',
            'cohort': {'kind': 'task_ids', 'tasks': [deepcopy(TASK)]},
            'accounting_interval': {'start': '2026-10-15T00:00:00Z', 'end_exclusive': '2026-11-01T00:00:00Z'},
            'views': ['task_lifetime', 'period_spend'], 'group_by': ['task'],
            'money_bases': ['confirmed_billed', 'tariff_estimate'],
            'fx_refs': [], 'cache_pair_refs': [], 'snapshot_ref': None}


def payloads():
    usage = {'source_fact_digest': H, 'source_proof_ref': H, 'operation': OP, 'service_period': PERIOD}
    state = {'task': TASK, 'effective_at': '2026-10-02T00:00:00Z', 'decision_id': H,
             'source_proof_ref': H, 'supersedes': None}
    values = [
        dict(usage, candidate_kind='model_usage', provider_id='synthetic', model_id='model-one',
             provider_account_digest=H, observation_origin='local_measurement',
             cache_policy={'mode': 'normal', 'policy_digest': H, 'ttl_seconds': 300,
                           'cache_instance_digest': H}, input_semantics='total_includes_read_and_write',
             output_semantics='includes_reasoning', input_total=quantity(100), uncached_input=quantity(60),
             cache_write=quantity(10), cache_read=quantity(30), output=quantity(50), reasoning_output=quantity(20)),
        dict(usage, candidate_kind='local_usage', measurement_method='native_direct_child',
             elapsed=quantity(100, 'elapsed_ns'), cpu=quantity(60, 'cpu_ns'),
             gpu=quantity(None, 'gpu_ns', 'not_observed'), energy=quantity(None, 'microjoule', 'not_observed'),
             peak_rss=quantity(1024, 'byte')),
        dict(usage, candidate_kind='ci_usage', job_digest=H, job_attempt=1, head='d' * 40,
             runner_kind='managed', runner_time=quantity(100, 'runner_ns')),
        dict(usage, candidate_kind='human_usage', activity='review', actor_scope_digest=H,
             basis='explicit_attestation', human_time=quantity(120, 'human_ns')),
        dict(usage, candidate_kind='charge', provider_account_digest=H, external_line_digest=H,
             direction='debit', adjusts_charge_event=None,
             amount={'value': 123, 'currency': 'USD', 'decimal_scale': 2, 'unknown_reason': None}),
        dict(candidate_kind='tariff', provider_id='synthetic', model_id='model-one', category='uncached_input',
             unit='token', cache_policy_digest=H, currency='USD', decimal_scale=6, rate_numerator=2,
             rate_denominator=1, validity=PERIOD, source_digest=H, source_published_at=PERIOD['start'], source_proof_ref=H),
        dict(candidate_kind='fx', from_currency='USD', to_currency='EUR', numerator=9, denominator=10,
             validity=PERIOD, source_digest=H, source_published_at=PERIOD['start'], source_proof_ref=H),
        dict(candidate_kind='allocation', operation=OP, shares=[{'task': TASK, 'weight_ppm': 600000}],
             supersedes=None, method='explicit_attestation', source_proof_ref=H),
        dict(state, candidate_kind='workflow_end', result='failed'),
        dict(state, candidate_kind='completion', result='completed', original_scope_digest=H,
             criteria_digest=H, evidence_digest=H),
        dict(state, candidate_kind='merge', repository_digest=H, pr_number=1, source_head='d' * 40, merge_commit='e' * 40),
        dict(state, candidate_kind='task_disposition', decision='accepted', criteria_digest=H,
             evidence_digest=H, evidence_version='synthetic-v1'),
        dict(candidate_kind='attempt_relation', task=TASK, from_attempt='attempt-one', to_attempt='attempt-two',
             relation='retry', source_proof_ref=H),
        dict(candidate_kind='review_for_push', task=TASK, push_event_digest=H, push_head='d' * 40,
             round_index=1, review_event_digest='b' * 64, source_proof_ref=H),
        dict(candidate_kind='task_pr_link', task=TASK, repository_digest=H, pr_number=1,
             mapping_evidence_digest=H, validity=PERIOD, supersedes=None, source_proof_ref=H),
        dict(candidate_kind='cache_pair', normal_operations=[OP],
             long_operations=[dict(OP, operation_id='operation-two', physical_operation_digest='e' * 64)],
             workload_source_digest=H, model_revision_digest=H, quality_criteria_digest=H,
             normal_config_digest=H, long_config_digest='b' * 64, basis='explicit_scenario', source_proof_ref=H),
        dict(candidate_kind='human_decision', task=TASK, decision_id=H, activity='approval',
             decision='approved', source_proof_ref=H, related_request_digest=None),
    ]
    return {item['candidate_kind']: deepcopy(item) for item in values}
