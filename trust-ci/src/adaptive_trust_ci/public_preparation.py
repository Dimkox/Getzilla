"""Ephemeral facts from one owned, reaped protected checker child.

The trusted host process is the boundary. This is not confinement against code
already executing in that process. No file/JSON/environment value can recreate
an issued capability, and a restart requires actual fresh bounded preparation.
"""
from dataclasses import fields
import weakref
from . import security_bundle as bundle
from .models import parse_datetime
from .public_process import ProducerEnvelope

_LIVE = weakref.WeakKeyDictionary()


class _Capability:
    pass


def _facts(value):
    bundle.fields(value, tuple(row.name for row in fields(bundle.ValidationFacts)))
    for key in ('source_digest', 'policy_digest', 'report_digest', 'inventory_digest', 'content_digest', 'snapshot_digest'):
        bundle.exact_digest(value[key])
    if (value['source_validated'] is not True or value['blockers'] != []
            or value['integration_validated'] is not True or value['integration_digest'] is None
            or type(value['required']) is not list or not 1 <= len(value['required']) <= bundle.MAX_CHECKS
            or type(value['sources']) is not list or len(value['sources']) > bundle.MAX_SOURCES
            or type(value['checker_source']) is not list or len(value['checker_source']) != 2):
        raise ValueError('owned-preparation-facts-refused')
    for sha in value['checker_source']:
        bundle.require_sha(sha, 'checker_source')
    parse_datetime(value['valid_until'])
    if value['integration_digest'] is not None:
        bundle.exact_digest(value['integration_digest'])
    required=[]
    for row in value['required']:
        bundle.fields(row, ('name','required','source_ids','coverage_digest'))
        if (type(row['required']) is not bool or type(row['source_ids']) is not list
                or len(row['source_ids']) > bundle.MAX_SOURCES or type(row['name']) is not str
                or bundle._NAME.fullmatch(row['name']) is None
                or any(type(item) is not str or bundle._NAME.fullmatch(item) is None for item in row['source_ids'])):
            raise ValueError('owned-preparation-requirement-refused')
        bundle.exact_digest(row['coverage_digest'])
        required.append(bundle.Requirement(row['name'],row['required'],tuple(row['source_ids']),row['coverage_digest']))
    sources=[]
    for row in value['sources']:
        bundle.fields(row, ('source_id','content_digest','acquired_at','validated'))
        if (row['validated'] is not True or type(row['source_id']) is not str
                or bundle._NAME.fullmatch(row['source_id']) is None):
            raise ValueError('owned-preparation-source-refused')
        bundle.exact_digest(row['content_digest'])
        parse_datetime(row['acquired_at'])
        sources.append(bundle.ValidatedSource(**row))
    return bundle.ValidationFacts(**{**value,'required':tuple(required),'sources':tuple(sources),
        'blockers':(),'checker_source':tuple(value['checker_source'])})


def from_owned(envelope, command, raw):
    """Called only after fixed child success, reap and whole cgroup emptiness."""
    if (type(envelope) is not ProducerEnvelope or envelope.closed is not True
            or envelope.empty_confirmed is not True or not envelope.confirms(command,raw)):
        raise ValueError('owned-preparation-lifecycle-unconfirmed')
    value=bundle.bounded_json(raw,maximum=65536)
    facts=_facts(value['facts'])
    token=_Capability()
    _LIVE[token]=facts
    return token


def consume(token, source, report, policy, *, now):
    if type(token) is not _Capability or token not in _LIVE:
        raise ValueError('live-owned-preparation-required')
    facts=_LIVE[token]
    if (facts.source_digest != bundle.digest(source) or facts.report_digest != bundle.digest(report)
            or facts.policy_digest != policy.policy_digest or facts.inventory_digest != report['inventory_sha256']
            or parse_datetime(facts.valid_until) <= now):
        raise ValueError('owned-preparation-binding-or-lifetime-changed')
    return facts
