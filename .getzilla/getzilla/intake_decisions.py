"""Bounded native-session decision bindings; never a human or receipt attestation."""
from __future__ import annotations

import re

from .requirements_intake import IntakeError, digest


def valid_event(value):
    return (type(value) is dict and set(value) == {'id','kind','decision'}
            and type(value['id']) is str and re.fullmatch('[A-Za-z0-9_.:/-]{1,128}',value['id'])
            and value['kind'] == 'native_decision' and type(value['decision']) is str and value['decision'] in {'accept','reject'})


def validate_stamp(value):
    if (type(value) is not dict or set(value) != {'version','principal','identity','D','R','P','C','cut','state','event','at'}
            or type(value['version']) is not int or value['version'] != 1
            or type(value['principal']) is not str or not re.fullmatch(r'[\w.:/-]{1,128}',value['principal'])
            or type(value['identity']) is not dict or set(value['identity']) != {'repository','logical_task_id','authority_epoch'}
            or type(value['identity']['authority_epoch']) is not int or value['identity']['authority_epoch'] < 0
            or type(value['identity']['logical_task_id']) is not str or not 1 <= len(value['identity']['logical_task_id']) <= 128
            or any(type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}',value[key]) for key in ('D','R','P','C','cut','state'))
            or not valid_event(value['event']) or type(value['at']) is not str or len(value['at']) > 64):
        raise IntakeError('invalid_native_decision')


def current_choice(route, projection, events, context_digest):
    stamp = (route.get('context',{}).get('intake') or {}).get('native_decision')
    if stamp is None:
        return None
    validate_stamp(stamp)
    data = projection['input']
    if (stamp['principal'] != route['session_id'] or stamp['identity'] != data['identity']
            or stamp['identity']['authority_epoch'] != route['authority_epoch']
            or route.get('status') in ('completed','cancelled')
            or stamp['D'] != projection['draft_digest'] or stamp['P'] != data['policy']['digest']
            or stamp['C'] != context_digest
            or not any(row['id'] == stamp['event']['id'] and row['event_digest'] == digest(stamp['event'],'intake-event-v1') for row in events)):
        return None
    # Full source bytes are rechecked by the native publisher before this helper.
    return stamp


def apply_choice(assessment, stamp):
    if stamp is None or assessment['status'] not in ('ready','needs_decision'):
        return assessment
    result = dict(assessment)
    if stamp['event']['decision'] == 'accept':
        result.update(status='ready',required_decision=False)
    else:
        result.update(status='needs_decision',required_decision='native_rejected')
    return result
