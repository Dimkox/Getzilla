"""Closed alias rejection diagnostics. Raw advisory identifiers never leave this helper."""
import hashlib


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
