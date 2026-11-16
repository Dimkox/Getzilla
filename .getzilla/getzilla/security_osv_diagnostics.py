"""Closed alias rejection diagnostics. Raw advisory identifiers never leave this helper."""
import hashlib
import json
import re


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
