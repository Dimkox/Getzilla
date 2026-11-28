"""Pure semantic preflight. A ready assessment is data, never a permission."""
from __future__ import annotations

import copy

from .requirements_intake import digest, normalized, project_requirements
from .spec import definition_text_present


def question_limits(policy):
    value = policy.get('question_limits')
    if (type(value) is not dict or set(value) != {'max_questions_per_round','max_question_rounds'}
            or any(type(n) is not int or not 1 <= n <= 32 for n in value.values())):
        return None
    return value


def assess_readiness(spec: dict, provenance: dict, policy: dict) -> dict:
    # Recompute typed conflicts and D; a stored label cannot turn into readiness.
    current = project_requirements(provenance['input'],provenance)
    data = current['input']
    clean_spec = {key: value for key, value in spec.items() if key != 'intake'}
    stale = (normalized(clean_spec) != data['spec'] or
             any(policy.get(key) != data['policy'][key] for key in data['policy']))
    missing = []

    def require(ok, field, reason, locator=None):
        if not ok:
            finding = {'field': field, 'reason': reason}
            if locator is not None:
                finding['locator'] = locator
            missing.append(finding)

    objective = spec['objective']
    for key in ('statement', 'success_metric', 'target'):
        require(definition_text_present(objective[key]),
                f'objective.{key}', 'objective_unmeasurable')
    require(bool(data['scope']), 'scope', 'scope_unbounded')
    require(bool(spec['acceptance_criteria']), 'acceptance_criteria', 'criteria_missing')
    locators = {source['id']: source['locator'] for source in data['sources']}
    mapped = {}
    for row in data['requirements']:
        locator = locators[row['source_id']]
        require(row['criterion_ids'], f"requirements.{row['id']}.criterion_ids", 'requirement_unmapped', locator)
        for identifier in row['criterion_ids']:
            mapped.setdefault(identifier, locator)
    for collection, reason in (('acceptance_criteria', 'criterion_unmeasurable'), ('invariants', 'invariant_unmeasurable'),
                               ('forbidden_outcomes', 'forbidden_outcome_unmeasurable')):
        for item in spec[collection]:
            field = f"{collection}.{item['id']}"
            locator = mapped.get(item['id'])
            require(bool(item['evidence']), field + '.evidence', reason, locator)
            require(definition_text_present(item['statement']), field + '.statement', reason, locator)
            if collection == 'acceptance_criteria':
                require(item['id'] in mapped, field + '.source', 'criterion_unmapped')
    for dependency in data['dependencies']:
        require(dependency['status'] == 'satisfied', 'dependencies.' + dependency['id'], 'dependency_unresolved')
    require(bool(data['permissions']), 'permissions', 'permission_missing')
    for permission in data['permissions']:
        require(permission['status'] == 'required', 'permissions.' + permission['operation'], 'permission_unresolved')
    require(bool(data['sources']), 'sources', 'source_missing')
    for reason in current['unknown']:
        require(False, 'requirements', reason)
    assumptions = [{'requirement': row['id'], 'values': row['assumptions']} for row in data['requirements'] if row['assumptions']]
    require(not assumptions, 'assumptions', 'assumptions_unresolved')
    rounds = policy.get('rounds', 0)
    if type(rounds) is not int or not 0 <= rounds <= 4096:
        raise ValueError('invalid_question_round')
    rows = missing + [{'field': 'requirements', 'reason': row['reason']} for row in current['conflicts']]
    rows = sorted({(row['field'], row['reason']): row for row in rows}.values(), key=lambda row: (row['field'], row['reason']))
    limits = question_limits(policy)
    if rows and limits is None:
        require(False,'policy.question_limits','question_limits_unconfigured')
    exhausted = bool(rows) and limits is not None and rounds >= limits['max_question_rounds']
    questions = [] if limits is None or exhausted else [
        {'id': digest([current['draft_digest'], row], 'intake-question-v1'),
         **row}
        for row in rows[:limits['max_questions_per_round']]]
    required = 'unsupported_decision_ingress' if data['policy']['decision_required'] else False
    status = ('stale' if stale else 'conflicted' if current['conflicts'] else 'missing' if missing else
              'needs_decision' if required else 'ready')
    return {'version': 1, 'status': status, 'draft_digest': current['draft_digest'],
            'facts': {'scope_bounded': bool(data['scope']), 'source_count': len(data['sources'])},
            'missing': missing, 'conflicts': copy.deepcopy(current['conflicts']),
            'questions': questions, 'assumptions': assumptions, 'required_decision': required,
            'coverage': {'required': len(spec['acceptance_criteria']), 'mapped': len(mapped)},
            'question_budget_exhausted': exhausted,
            'authority': False, 'receipt_eligible': False}
