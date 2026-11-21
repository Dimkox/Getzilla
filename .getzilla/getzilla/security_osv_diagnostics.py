"""Closed alias rejection diagnostics. Raw advisory identifiers never leave this helper."""
import hashlib
import json
import re
import sys


def _shape(value):
    return {str: 'string', list: 'array', dict: 'object', int: 'integer', float: 'number',
            bool: 'boolean', type(None): 'null'}.get(type(value), 'other')


def _hash(value):
    result = hashlib.sha256()
    if type(value) is str:
        for offset in range(0, len(value), 4096):
            result.update(value[offset:offset + 4096].encode('utf-8', errors='surrogatepass'))
    else:
        result.update(_shape(value).encode('ascii'))
    return result.hexdigest()


def alias_rejection(record, index=None):
    aliases = record.get('aliases') if type(record) is dict else record
    is_array = type(aliases) is list
    value = aliases[index] if is_array and type(index) is int and 0 <= index < len(aliases) else aliases
    reason = ('field-type' if not is_array else 'item-type' if type(value) is not str
              else 'empty' if not value else 'charset')
    return {'kind': 'osv-alias-rejection', 'reason': reason, 'field_shape': _shape(aliases),
            'value_shape': _shape(value), 'count': len(aliases) if is_array else None,
            'index': index if is_array and type(index) is int and 0 <= index < len(aliases) else None,
            'value_sha256': _hash(value),
            'member_id_sha256': _hash(record.get('id')) if type(record) is dict else _hash(None)}


def bounded_alias_message(error):
    """Preserve essential closed facts within the existing 200-character log cap.

    Full hashes remain in the original raised diagnostic; this compact log
    projection explicitly declares their omission instead of truncating JSON.
    """
    seen = set()
    for _ in range(8):
        if error is None or id(error) in seen:
            break
        seen.add(id(error))
        detail = getattr(error, 'osv_alias_detail', None)
        if isinstance(detail, dict):
            reason = detail.get('reason')
            shapes = {'string', 'array', 'object', 'integer', 'number', 'boolean', 'null', 'other'}
            count, index = detail.get('count'), detail.get('index')
            if (reason in {'field-type', 'item-type', 'empty', 'charset'}
                    and detail.get('field_shape') in shapes and detail.get('value_shape') in shapes
                    and (count is None or type(count) is int and 0 <= count <= 1000000000)
                    and (index is None or type(index) is int and 0 <= index <= 1000000000)):
                value = {'kind': 'osv-alias-rejection', 'reason': reason,
                         'type': detail['field_shape'] + '/' + detail['value_shape'],
                         'count': count, 'index': index, 'omitted': ['sha256']}
                encoded = json.dumps(value, separators=(',', ':'), sort_keys=True)
                if len(encoded) <= 200:
                    return encoded
        error = error.__cause__
    return None


def snapshot_alias_message(ecosystem, error, member, identifier):
    """One valid compact refusal, including every full original identity hash.

    Keep the original400-character snapshot bound. The separate200-character
    log projection still explicitly omits hashes; neither projection admits data.
    """
    detail = getattr(error, 'osv_alias_detail', None)
    if (not isinstance(detail, dict) or ecosystem not in {'PyPI', 'npm', 'Packagist', 'Go', 'crates.io', 'RubyGems', 'Maven'}
            or not isinstance(detail.get('value_sha256'), str)
            or re.fullmatch('[0-9a-f]{64}', detail['value_sha256']) is None):
        return None
    compact = bounded_alias_message(error)
    if compact is None:
        return None
    body = json.loads(compact)
    body.pop('omitted')
    body.update(value_sha256=detail['value_sha256'], member_sha256=_hash(member), id_sha256=_hash(identifier))
    message = 'aliases: ' + json.dumps(body, separators=(',', ':'), sort_keys=True)
    if len(message) >= 400:
        # Fixed enums plus arbitrarily large counters cannot consume the hash
        # budget. Explicitly omit counters, never hashes or rejection reason.
        body.update(count=None, index=None, omitted=['count/index'])
        message = 'aliases: ' + json.dumps(body, separators=(',', ':'), sort_keys=True)
    return message if len(message) < 400 else None


def emit_alias_rejection(ecosystem, error):
    """Retain one full closed hash record in the existing captured error stream.

    The original400-byte snapshot diagnostic ceiling and enclosing command log
    rotation/output ceilings stay unchanged. This is observation, never input
    admission. Malformed mutable sidecars cannot leak content or mask refusal.
    """
    if type(ecosystem) is not str or ecosystem not in {'PyPI','npm','Packagist','Go','crates.io','RubyGems','Maven'}:
        return False
    seen=set()
    for _ in range(8):
        if error is None or id(error) in seen:
            return False
        seen.add(id(error))
        try:
            value=getattr(error,'osv_snapshot_detail',None)
        except Exception:
            return False
        if type(value) is dict:
            required={'kind','reason','type','count','index','value_sha256','member_sha256','id_sha256'}
            shapes={'string','array','object','integer','number','boolean','null','other'}
            if (set(value) not in (required,required|{'omitted'}) or type(value.get('kind')) is not str or value['kind']!='osv-alias-rejection'
                    or type(value.get('reason')) is not str or value['reason'] not in {'field-type','item-type','empty','charset'}
                    or type(value.get('type')) is not str or value['type'] not in {a+'/'+b for a in shapes for b in shapes}
                    or any(value.get(key) is not None and (type(value[key]) is not int or not 0<=value[key]<=1000000000) for key in ('count','index'))
                    or any(type(value.get(key)) is not str or re.fullmatch('[0-9a-f]{64}',value[key]) is None
                           for key in ('value_sha256','member_sha256','id_sha256'))
                    or 'omitted' in value and (type(value['omitted']) is not list or len(value['omitted'])!=1
                        or type(value['omitted'][0]) is not str or value['omitted'][0]!='count/index')):
                return False
            body={**value,'ecosystem':ecosystem}
            encoded=json.dumps(body,sort_keys=True,separators=(',',':'))+'\n'
            if len(encoded.encode('ascii'))>400:
                # Preserve every hash and reason; explicitly omit only counters.
                body.pop('count')
                body.pop('index')
                body['omitted']=['count/index']
                encoded=json.dumps(body,sort_keys=True,separators=(',',':'))+'\n'
            if len(encoded.encode('ascii'))>400:
                return False
            try:
                sys.stderr.write(encoded)
                sys.stderr.flush()
                return True
            except Exception:
                return False
        try:
            error=error.__cause__
        except Exception:
            return False
    return False
