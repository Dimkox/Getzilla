"""Exact-source CI caller context and primary phase selection, without scan authority."""
import hashlib
import re


def selected_run_environment(environ, source_head):
    event_sha = environ.get('GETZILLA_EVENT_SHA', environ.get('GITHUB_SHA'))
    if (not isinstance(source_head, str) or not re.fullmatch('[0-9a-f]{40}', source_head)
            or not isinstance(event_sha, str) or not re.fullmatch('[0-9a-f]{40}', event_sha)
            or environ.get('GITHUB_EVENT_NAME') not in ('pull_request', 'push', 'workflow_dispatch')
            or any(not re.fullmatch('[1-9][0-9]{0,19}', environ.get(k, ''))
                   for k in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
            or environ.get('GITHUB_REPOSITORY') != 'Dimkox/Getzilla'):
        raise ValueError('Exact source and original CI event/run context required')
    selected = dict(environ, GITHUB_SHA=source_head)
    provenance = dict(event_sha=event_sha, source_head=source_head,
                      event=environ['GITHUB_EVENT_NAME'], repository=environ['GITHUB_REPOSITORY'],
                      run_id=environ['GITHUB_RUN_ID'], attempt=environ['GITHUB_RUN_ATTEMPT'])
    return selected, provenance


def primary_report(scan, declaration, preparation):
    if isinstance(scan, dict):
        return 'scan', scan
    for phase, report in (('preparation', preparation), ('declaration', declaration)):
        if isinstance(report, dict) and report.get('status') in ('fail', 'unavailable'):
            return phase, report
    return 'bootstrap', {'status': 'fail', 'reason': 'trusted checker missing or bootstrap blocked'}


def closed_phase_report(report, raw):
    """Retain a bounded primary refusal without exporting arbitrary report values."""
    gaps = report.get('gaps')
    gaps = gaps if isinstance(gaps, list) else []
    known = {'input-preparation-unavailable', 'input-worker-unavailable', 'source-changed',
             'required-source-plan-incomplete', 'source-applicability-unknown',
             'source-plan-binding-mismatch', 'source-inputs-unavailable'}
    selected = sorted({v for v in gaps if isinstance(v, str) and v in known})
    reason = report.get('reason')
    retained_reason = reason == 'selected public input/profile/source validation refused'
    return {'kind': 'public-security-input-refusal', 'status': 'fail', 'qualification': 'UNVERIFIED',
            'reason': reason if retained_reason else 'primary trusted phase refused', 'gaps': selected,
            'original_sha256': hashlib.sha256(raw).hexdigest(),
            'omitted': {'gap_values': len(gaps) - sum(isinstance(v, str) and v in known for v in gaps),
                        'reason': not retained_reason}}
