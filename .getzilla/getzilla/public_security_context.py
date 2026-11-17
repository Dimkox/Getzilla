"""Explicit protected public execution context; no environment/file authority.

Native CLI declarations keep their original run-head=candidate contract. Only
an in-process protected entry can bind the separately observed runner context.
This is a data contract, not independent provider/execution qualification.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import hashlib
import re

_CURRENT = ContextVar('getzilla_public_security_context', default=None)
_FIELDS = {'kind', 'repository', 'repository_id', 'pr_number', 'base_sha', 'head_sha', 'tree_sha',
           'checker_sha', 'checker_tree_sha', 'runner_repository', 'runner_repository_id',
           'runner_sha', 'runner_tree_sha', 'workflow_id', 'workflow_blob_sha', 'run_id', 'run_attempt'}


def validate_context(context, source):
    if type(context) is not dict or set(context) != _FIELDS or context['kind'] != 'getzilla-public-execution-v1':
        raise ValueError('public execution context is malformed')
    for key in ('repository_id','pr_number','runner_repository_id','workflow_id','run_id','run_attempt'):
        if type(context[key]) is not int or context[key] <= 0:
            raise ValueError('public execution identity is malformed')
    for key in ('repository','runner_repository'):
        if type(context[key]) is not str or re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',context[key]) is None:
            raise ValueError('public execution repository is malformed')
    for key in ('base_sha','head_sha','tree_sha','checker_sha','checker_tree_sha','runner_sha','runner_tree_sha','workflow_blob_sha'):
        if type(context[key]) is not str or re.fullmatch('[0-9a-f]{40}',context[key]) is None:
            raise ValueError('public execution source is malformed')
    if any(source.get(key) != context[key] for key in ('head_sha','tree_sha','checker_sha','checker_tree_sha')):
        raise ValueError('public execution differs from actual candidate/checker source')
    if any(source.get(key) is not True for key in ('candidate_clean','checker_clean','same_project')):
        raise ValueError('public execution source is not clean and paired')
    return {'provider':'github-actions','repository':context['runner_repository'],
            'run_id':str(context['run_id']),'run_attempt':str(context['run_attempt']),'head_sha':context['runner_sha']}


def current_context():
    value=_CURRENT.get()
    return json.loads(value) if value is not None else None


@contextmanager
def bind_context(context, source):
    validate_context(context,source)
    token=_CURRENT.set(json.dumps(context,sort_keys=True,separators=(',',':')))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def selection_document(inventory, source, run, created_at):
    """Source declarations only, derived after validating the ORIGINAL catalog."""
    uses = []
    for row in inventory['images']:
        uses.append(dict(path=row['manifest'], line=row['line'], source_sha256=row['source_sha256'],
                         expression=row['source_reference'], reference=row['reference'], platform=row['platform']))
    return dict(schema_version=1, source=source, run=run, created_at=created_at, uses=uses)


def project_catalog(catalog, inventory_digest):
    """Keep original graph/selection identity when binding a current declaration.

    This projection is not validation. The caller must first validate the raw
    catalog against independently collected source and then validate the derived
    catalog against the full current declaration inventory.
    """
    if 'source_catalog_sha256' in catalog:
        raise ValueError('nested public catalog projection refused')
    value=json.loads(json.dumps(catalog))
    value['source_catalog_sha256']=digest(catalog)
    value['inventory_sha256']=inventory_digest
    return value
