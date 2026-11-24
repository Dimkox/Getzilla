"""Bounded issue-358 manual protocol checks; no scheduler, ledger or authority.

Inputs are supplied assertions. Existing review plans, task budgets, lifecycle and
protected economics remain authoritative. This module never runs a paid study.
"""
from __future__ import annotations

import copy
import json

from . import route_metrics

MAX_BYTES = 65536
ACTIVE = {'active', 'waiting_review', 'review', 'rework'}
TERMINAL = {'accepted', 'rejected', 'abandoned', 'revoked'}
INPUTS = {'scope', 'checks', 'tools', 'models', 'selection', 'schedule', 'randomization'}
FIELDS = {'version','task_class','procedure_version','frozen_at','starts_at','ends_at','observation_ends_at','owner','reviewer','review_minutes','wip_limit','budget_ref','budget_micros','minimum_savings_percent','max_defects','accepted_sources','expert_approval','inputs','backlog_size','pairs'}


def _require(condition):
    if not condition:
        raise ValueError('invalid-review-experiment-contract')


def _snapshot(value):
    # JSON also rejects callable/object-based evidence. Finite bounded data only.
    try:
        raw=json.dumps(value,allow_nan=False)
    except (ValueError,TypeError,RecursionError):
        raise ValueError('invalid-review-experiment-contract') from None
    _require(len(raw.encode()) <= MAX_BYTES)
    return json.loads(raw)


def _id(value):
    return type(value) is str and 1 <= len(value) <= 256 and all(ord(c)>=32 for c in value)


def _integer(value, minimum=0, maximum=10**15):
    return type(value) is int and minimum <= value <= maximum


def validate_protocol(value):
    p=_snapshot(value)
    _require(type(p) is dict and set(p)==FIELDS and type(p['version']) is int and p['version']==1)
    for key in ('task_class','procedure_version','owner','reviewer','budget_ref'):
        _require(_id(p[key]))
    for key in ('frozen_at','starts_at','ends_at','observation_ends_at','budget_micros','max_defects'):
        _require(_integer(p[key]))
    _require(p['frozen_at'] < p['starts_at'] < p['ends_at'] < p['observation_ends_at'])
    _require(_integer(p['review_minutes'],1,1440) and _integer(p['wip_limit'],1,32))
    _require(_integer(p['minimum_savings_percent'],1,99) and _integer(p['backlog_size'],8))
    _require(p['budget_micros'] > 0 and p['reviewer'] != p['owner'])
    approval=p['expert_approval']
    _require(type(approval) is dict and set(approval)=={'actor','at','procedure_version'})
    _require(_id(approval['actor']) and approval['actor'] != p['owner'] and _integer(approval['at'])
             and approval['at'] <= p['frozen_at'] and approval['procedure_version']==p['procedure_version'])
    _require(type(p['inputs']) is dict and set(p['inputs'])==INPUTS and all(_id(v) for v in p['inputs'].values()))
    _require(type(p['pairs']) is list and len(p['pairs'])==4)
    tasks=[]
    pairs=[]
    for pair in p['pairs']:
        _require(type(pair) is dict and set(pair)=={'pair','control','experiment','basis','order'})
        _require(all(_id(pair[k]) for k in ('pair','control','experiment','basis')))
        _require(type(pair['order']) is list and len(pair['order'])==2 and all(_id(v) for v in pair['order']) and set(pair['order'])=={pair['control'],pair['experiment']})
        tasks.extend((pair['control'],pair['experiment']))
        pairs.append(pair['pair'])
    _require(len(set(tasks))==8 and len(set(pairs))==4)
    _require(type(p['accepted_sources']) is list and 1 <= len(p['accepted_sources']) <= 32
             and all(_id(v) for v in p['accepted_sources']) and len(set(p['accepted_sources']))==len(p['accepted_sources'])
             and not set(tasks).intersection(p['accepted_sources']))
    return p


def review_admission(protocol, view, *, now):
    """Manual preflight only. No reservation, queue or bypass of canonical checks."""
    p=validate_protocol(protocol)
    result={'admit':False,'reason':'review_capacity_unknown','qualification':'supplied-snapshot-only'}
    try:
        v=_snapshot(view)
        _require(type(v) is dict and set(v)=={'as_of','complete','reviewer','available_minutes','tasks'})
        _require(_integer(now) and p['starts_at'] <= now < p['ends_at'] and _integer(v['as_of']) and 0 <= now-v['as_of'] <= 60)
        _require(v['complete'] is True and v['reviewer']==p['reviewer'])
        _require(_integer(v['available_minutes'],1,1440) and type(v['tasks']) is list and len(v['tasks'])<=256)
        names=[]
        wip=0
        for row in v['tasks']:
            _require(type(row) is dict and set(row)=={'task','state'} and _id(row['task']))
            _require(type(row['state']) is str and row['state'] in ACTIVE|TERMINAL)
            names.append(row['task'])
            wip+=row['state'] in ACTIVE
        _require(len(set(names))==len(names))
        result.update(wip=wip)
        if wip >= p['wip_limit'] or v['available_minutes'] < p['review_minutes']:
            result['reason']='finish_existing_review_and_rework'
        else:
            result.update(admit=True,reason='manual_capacity_preflight_only')
    except (ValueError,TypeError,KeyError):
        pass
    return result


def assess_experiment(protocol, outcomes, *, as_of, economics_queries=None, economics_handle=None):
    """Retain every assignment. Supplied decisions cannot establish human acceptance.

    Read economics through its canonical protected reader only. No caller-supplied
    cost totals or offline evaluator passes can substitute for that evidence.
    """
    p=validate_protocol(protocol)
    _require(_integer(as_of))
    rows=_snapshot(outcomes)
    _require(type(rows) is dict and len(rows)<=8)
    roster=[pair[side] for pair in p['pairs'] for side in ('control','experiment')]
    _require(set(rows)<=set(roster))
    result={'definition_version':1,'qualification':'supplied-contract-only','decision':'NOT_RUN' if not rows else 'indeterminate',
            'assigned':8,'selected_backlog_share':{'numerator':8,'denominator':p['backlog_size']},
            'outcomes':{key:0 for key in ('accepted','rejected','abandoned','revoked','unknown')},
            'cost_per_accepted':None,'gaps':[],'economics':{},'pairs':copy.deepcopy(p['pairs'])}
    if not rows:
        result['gaps']=['actual_comparative_experiment_NOT_RUN']
        return result
    stop=False
    for task in roster:
        row=rows.get(task)
        if not isinstance(row,dict) or set(row)!={'actor','decision','candidate','requirements','checks','at','defects'}:
            result['outcomes']['unknown']+=1
            result['gaps'].append('missing_or_malformed_outcome:'+task)
            continue
        known=(type(row['decision']) is str and row['decision'] in TERMINAL and _id(row['actor']) and row['actor'] != p['owner']
               and _id(row['candidate']) and row['requirements']==p['inputs']['scope']
               and row['checks'] is True and _integer(row['at']) and p['starts_at']<=row['at']<=as_of
               and _integer(row['defects']))
        result['outcomes'][row['decision'] if known else 'unknown']+=1
        if not known:
            result['gaps'].append('unverified_outcome:'+task)
        if row['checks'] is False or (_integer(row['defects']) and row['defects']>p['max_defects']):
            stop=True
    if as_of<p['observation_ends_at']:
        result['gaps'].append('observation_window_incomplete')
    # No independent human-attestation adapter exists here. Do not upgrade a
    # supplied actor name, timestamp or candidate string to verified acceptance.
    result['gaps'].append('independent_human_acceptance_unbound')
    qualified=[]
    if economics_queries is not None:
        _require(type(economics_queries) is dict and set(economics_queries)=={'control','experiment'})
        from .economics_reader import is_protected_report
        for side,query in economics_queries.items():
            read=(route_metrics.read_report(query) if economics_handle is None else
                  route_metrics.read_report(query,handle=economics_handle))
            if is_protected_report(read,handle=economics_handle,purpose='review-experiment'):
                result['economics'][side]=read.as_dict()
                qualified.append(side)
            else:
                # A supplied result/flag cannot replace canonical source admission.
                result['economics'][side]=route_metrics._unavailable_economics().as_dict()
        result['economics_qualified_sides']=sorted(qualified)
    if len(qualified)!=2:
        result['gaps'].append('economics_unavailable')
    else:
        if any(not result['economics'][side]['report']['coverage']['complete'] for side in qualified):
            result['gaps'].append('economics_incomplete')
        result['gaps'].append('economics_assignment_unbound')
    # No second subtotal. Source-qualified arithmetic is not independent human
    # acceptance or proof that supplied pair assignments match the native cohort.
    if stop:
        result['decision']='stop'
    return result
