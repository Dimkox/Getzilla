"""Optional bounded local assets and explicit controlled-fixture browser observations."""
from __future__ import annotations

import hashlib
from datetime import datetime
import json
import re
import time

from getzilla.fsx import ReadOnlyBoundRoot

MAX_FILES = 16
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_TOKENS = 4096
MAX_PACK_BYTES = 1024 * 1024
MAX_SECONDS = 5
VERSION = '0.1.0'


class ReferenceError(ValueError):
    """Fixed local refusal; source content is never an error message."""


def _need(condition):
    if not condition:
        raise ReferenceError('design_reference_invalid_or_incomplete')


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8', 'strict')


def _digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


def _path(value):
    return (type(value) is str and 0 < len(value.encode('utf-8')) <= 256
            and not any(ord(c) < 32 or c in '\\?#' for c in value)
            and all(p not in ('', '.', '..') for p in value.split('/')))


def _unit(value):
    match = re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)([A-Za-z]+|%)', value)
    return match.group(1) if match else None


def _pairs(items):
    result = {}
    for key, value in items:
        _need(key not in result)
        result[key] = value
    return result


class _Number(str):
    pass


def _invalid(_value):
    raise ReferenceError('design_reference_invalid_or_incomplete')


def _json(raw):
    try:
        return json.loads(raw.decode('utf-8', 'strict'), object_pairs_hook=_pairs,
                          parse_constant=_invalid, parse_int=_Number, parse_float=_Number)
    except (ValueError, UnicodeError, RecursionError):
        raise ReferenceError('design_reference_invalid_or_incomplete') from None


def _scan(text, start, stop, delimiters):
    """Find structural punctuation outside quoted strings and balanced ()/[]."""
    quote = None
    stack = []
    index = start
    while index < stop:
        char = text[index]
        if quote:
            if char == '\\':
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char in '([':
            stack.append(char)
            _need(len(stack) <= 32)
        elif char in ')]':
            _need(bool(stack) and stack.pop() == ('(' if char == ')' else '['))
        elif not stack and char in delimiters:
            return index
        index += 1
    _need(quote is None and not stack)
    return stop


def _selector_supported(header):
    """Prove only a small ordinary selector subset; everything else is partial."""
    if len(header) > 512:
        return False
    identifier = r'[A-Za-z_][A-Za-z0-9_-]*'
    whitespace = r'[ \t\r\n\f]'
    quoted = r'''(?:"[^"\\\x00-\x1f]*"|'[^'\\\x00-\x1f]*')'''
    attribute = (r'\[' + whitespace + '*' + identifier + '(?:' + whitespace + '*[~|^$*]?='
                 + whitespace + '*(?:' + identifier + '|' + quoted + '))?' + whitespace + r'*\]')
    pseudo = r':(?:root|hover|focus|focus-visible|focus-within|active|disabled|enabled|checked|empty|first-child|last-child|only-child)'
    suffix = '(?:[.#]' + identifier + '|' + pseudo + '|' + attribute + ')'
    compound = '(?:(?:' + identifier + r'|\*)' + suffix + '*|' + suffix + '+)'
    selector = compound + '(?:(?:' + whitespace + '*[>+~]' + whitespace + '*|'
    selector += whitespace + '+)' + compound + ')*'
    start = 0
    while True:
        end = _scan(header, start, len(header), ',')
        if re.fullmatch(selector, header[start:end].strip(' \t\r\n\f')) is None:
            return False
        if end == len(header):
            return True
        start = end + 1


def _context_supported(header):
    """Prove complete headers in a small closed subset, not arbitrary CSS."""
    if len(header) > 512:
        return False
    space = r'[ \t\r\n\f]'
    identifier = r'[A-Za-z_][A-Za-z0-9_-]*'
    length = r'(?:0|[0-9]+(?:\.[0-9]+)?(?:px|em|rem))'
    feature = (r'\(' + space + r'*(?:min-|max-)?(?:width|height)' + space
               + '*:' + space + '*' + length + space + r'*\)')
    features = feature + '(?:' + space + '+and' + space + '+' + feature + ')*'
    media = '(?:(?:only|not)' + space + '+)?(?:all|screen|print)'
    media += '(?:' + space + '+and' + space + '+' + features + ')?'
    media = '(?:' + media + '|' + features + ')'
    supports = r'\(' + space + '*display' + space + '*:' + space
    supports += r'*(?:grid|flex|block)' + space + r'*\)'
    # Exclude CSS-wide keywords and reserved container/layer names.
    name = r'(?!(?ai:initial|inherit|unset|revert|revert-layer|default|none|normal|and|or|not)(?![A-Za-z0-9_-]))' + identifier
    container = '(?:' + name + space + '+)?' + features
    layer = name + r'(?:\.' + name + ')*'
    patterns = {'media': media, 'supports': supports, 'container': container, 'layer': layer}
    return any(re.fullmatch('@' + family + space + '+' + pattern, header)
               is not None for family, pattern in patterns.items())


def capture(root, files, *, capture_id, captured_at):
    started = time.monotonic()
    tokens, sources, reasons, seen = [], [], set(), set()
    snapshots = {}

    def budget():
        _need(time.monotonic() - started <= MAX_SECONDS)

    def add(kind, source, name, context, value, locator):
        budget()
        _need(len(tokens) < MAX_TOKENS and type(value) is str and len(value) <= 4096
              and len(name) <= 512 and all(len(x) <= 512 for x in context))
        origin = {'kind': kind, 'source': source, 'name': name, 'context': context}
        identity = _digest(origin)
        _need(identity not in seen)
        seen.add(identity)
        tokens.append({'id': identity, 'kind': kind, 'source': source, 'name': name,
                       'context': context, 'raw_value': value, 'unit': _unit(value),
                       'locator': locator})

    def json_tokens(value, source, pointer='', depth=0):
        budget()
        _need(depth <= 32)
        if type(value) is dict:
            if '$value' in value:
                if set(value) - {'$value', '$type', '$description'}:
                    reasons.add('unsupported-json')
                json_tokens(value['$value'], source, pointer + '/$value', depth + 1)
            else:
                for key in sorted(value):
                    escaped = key.replace('~', '~0').replace('/', '~1')
                    json_tokens(value[key], source, pointer + '/' + escaped, depth + 1)
        elif type(value) in (str, _Number):
            add('json', source, pointer, [], str(value),
                {'pointer': pointer, 'line': None, 'column': None})
        else:
            reasons.add('unsupported-json')

    def css_tokens(raw, source):
        try:
            text = raw.decode('utf-8', 'strict')
        except UnicodeError:
            raise ReferenceError('design_reference_invalid_or_incomplete') from None
        # Preserve offsets while discarding comments. Unterminated comments refuse.
        index, quote = 0, None
        characters = list(text)
        while index < len(text):
            budget()
            if quote:
                if text[index] == '\\':
                    index += 2
                    continue
                if text[index] == quote:
                    quote = None
            elif text[index] in ('"', "'"):
                quote = text[index]
            elif text[index:index + 2] == '/*':
                end = text.find('*/', index + 2)
                _need(end >= 0)
                for position in range(index, end + 2):
                    characters[position] = '\n' if text[position] == '\n' else ' '
                index = end + 2
                continue
            index += 1
        text = ''.join(characters)

        def rules(start, stop, context, depth=0):
            _need(depth <= 32)
            while start < stop:
                budget()
                at = _scan(text, start, stop, '{;}')
                header = text[start:at].strip(' \t\r\n\f')
                if at == stop:
                    _need(not header)
                    return
                _need(text[at] != '}' and bool(header))
                if text[at] == ';':
                    _need(header.startswith('@'))
                    reasons.add('unsupported-css')
                    start = at + 1
                    continue
                cursor, level = at + 1, 1
                while level:
                    closing = _scan(text, cursor, stop, '{}')
                    _need(closing < stop)
                    level += 1 if text[closing] == '{' else -1
                    cursor = closing + 1
                end = closing
                if re.match(r'@(media|supports|container|layer)(?![A-Za-z0-9_-])', header):
                    if not _context_supported(header):
                        reasons.add('unsupported-css')
                    rules(at + 1, end, context + [header], depth + 1)
                elif header.startswith('@'):
                    reasons.add('unsupported-css')
                else:
                    selector = header
                    if not _selector_supported(selector):
                        reasons.add('unsupported-css')
                    declaration = at + 1
                    while declaration < end:
                        cut = _scan(text, declaration, end, ';{}')
                        if cut < end and text[cut] in '{}':
                            reasons.add('unsupported-css')
                            break
                        value = text[declaration:cut].strip()
                        if value:
                            colon = _scan(text, declaration, cut, ':')
                            _need(colon < cut)
                            name = text[declaration:colon].strip()
                            observed = text[colon + 1:cut].strip()
                            _need(bool(observed))
                            if name.startswith('--'):
                                _need(re.fullmatch(r'--[A-Za-z_][A-Za-z0-9_-]*', name) is not None)
                                if re.search(r'\b(?:var|env|calc|url)\s*\(', observed):
                                    reasons.add('unsupported-css')
                                position = declaration + len(text[declaration:colon]) - len(text[declaration:colon].lstrip())
                                line = text.count('\n', 0, position) + 1
                                column = position - text.rfind('\n', 0, position)
                                add('css', source, name, context + [selector], observed,
                                    {'pointer': None, 'line': line, 'column': column})
                        declaration = cut + 1
                start = end + 1
        rules(0, len(text), [])

    try:
        _need(type(files) in (list, tuple) and 1 <= len(files) <= MAX_FILES
              and all(_path(p) for p in files) and len(set(files)) == len(files))
        total = 0
        with ReadOnlyBoundRoot(root) as binding:
            for source in sorted(files):
                budget()
                snapshot = binding.read(source, limit=MAX_FILE_BYTES)
                _need(snapshot is not None)
                snapshots[source] = snapshot
                total += len(snapshot.content)
                _need(total <= MAX_TOTAL_BYTES)
                sources.append({'path': source, 'sha256': snapshot.sha256})
                if source.lower().endswith('.json'):
                    json_tokens(_json(snapshot.content), source)
                elif source.lower().endswith('.css'):
                    css_tokens(snapshot.content, source)
                else:
                    reasons.add('unsupported-format')
            for source, observed in snapshots.items():
                budget()
                _need(binding.read(source, limit=MAX_FILE_BYTES) == observed)
            binding.check()
        content = {'schema_version': 1, 'extractor_version': VERSION,
                   'parameters': {'files': sorted(files)}, 'sources': sources,
                   'tokens': sorted(tokens, key=lambda token: token['id']),
                   'coverage': {'status': 'partial' if reasons else 'complete',
                                'reasons': sorted(reasons), 'files': len(sources), 'tokens': len(tokens)}}
        result = {'content': content, 'content_digest': _digest(content),
                  'capture': {'id': capture_id, 'timestamp': captured_at}}
        budget()
        validate_pack(result)
        _need(len(encode(result)) <= MAX_PACK_BYTES)
        return result
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ReferenceError('design_reference_invalid_or_incomplete') from None


def validate_pack(pack):
    try:
        if type(pack) is dict and type(pack.get('content')) is dict and pack['content'].get('schema_version') == 2:
            _validate_preview(pack)
            return
        _need(type(pack) is dict and set(pack) == {'content', 'content_digest', 'capture'})
        envelope, content = pack['capture'], pack['content']
        _need(type(envelope) is dict and set(envelope) == {'id', 'timestamp'}
              and type(envelope['id']) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', envelope['id'])
              and type(envelope['timestamp']) is str
              and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', envelope['timestamp']))
        datetime.strptime(envelope['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
        _need(type(content) is dict and set(content) == {'schema_version', 'extractor_version', 'parameters', 'sources', 'tokens', 'coverage'}
              and type(content['schema_version']) is int and content['schema_version'] == 1
              and content['extractor_version'] == VERSION and pack['content_digest'] == _digest(content))
        parameters = content['parameters']
        _need(type(parameters) is dict and set(parameters) == {'files'}
              and type(parameters['files']) is list and 1 <= len(parameters['files']) <= MAX_FILES
              and all(_path(p) for p in parameters['files'])
              and parameters['files'] == sorted(set(parameters['files'])))
        sources = content['sources']
        _need(type(sources) is list and len(sources) == len(parameters['files']))
        for row, path in zip(sources, parameters['files']):
            _need(type(row) is dict and set(row) == {'path', 'sha256'} and row['path'] == path
                  and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']))
        tokens = content['tokens']
        _need(type(tokens) is list and len(tokens) <= MAX_TOKENS)
        seen = []
        for token in tokens:
            _need(type(token) is dict and set(token) == {'id', 'kind', 'source', 'name', 'context', 'raw_value', 'unit', 'locator'}
                  and token['kind'] in ('json', 'css') and token['source'] in parameters['files']
                  and type(token['name']) is str and len(token['name']) <= 512
                  and type(token['raw_value']) is str and len(token['raw_value']) <= 4096
                  and token['unit'] == _unit(token['raw_value'])
                  and type(token['context']) is list and len(token['context']) <= 33
                  and all(type(x) is str and len(x) <= 512 for x in token['context']))
            locator = token['locator']
            _need(type(locator) is dict and set(locator) == {'pointer', 'line', 'column'})
            if token['kind'] == 'json':
                _need(locator == {'pointer': token['name'], 'line': None, 'column': None} and token['context'] == [])
            else:
                _need(locator['pointer'] is None and type(locator['line']) is int and locator['line'] >= 1
                      and type(locator['column']) is int and locator['column'] >= 1 and bool(token['context']))
            origin = {key: token[key] for key in ('kind', 'source', 'name', 'context')}
            _need(type(token['id']) is str and token['id'] == _digest(origin))
            seen.append(token['id'])
        _need(seen == sorted(set(seen)))
        coverage = content['coverage']
        _need(type(coverage) is dict and set(coverage) == {'status', 'reasons', 'files', 'tokens'}
              and type(coverage['reasons']) is list and coverage['reasons'] == sorted(set(coverage['reasons']))
              and set(coverage['reasons']) <= {'unsupported-css', 'unsupported-json', 'unsupported-format'}
              and coverage['status'] == ('partial' if coverage['reasons'] else 'complete')
              and type(coverage['files']) is int and coverage['files'] == len(sources)
              and type(coverage['tokens']) is int and coverage['tokens'] == len(tokens)
              and len(encode(pack)) <= MAX_PACK_BYTES)
    except (KeyError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ReferenceError('design_reference_invalid_or_incomplete') from None


def diff(previous, current):
    validate_pack(previous)
    validate_pack(current)
    old = {row['id']: row for row in previous['content']['tokens']}
    new = {row['id']: row for row in current['content']['tokens']}
    # Positional/file-wide provenance stays in the snapshots, separately below.
    changed = sorted(key for key in old.keys() & new.keys()
                     if any(old[key][field] != new[key][field]
                            for field in ('raw_value', 'unit', 'kind', 'source', 'name', 'context')))
    before = {row['path']: row['sha256'] for row in previous['content']['sources']}
    after = {row['path']: row['sha256'] for row in current['content']['sources']}
    return {'added': sorted(new.keys() - old.keys()), 'removed': sorted(old.keys() - new.keys()),
            'changed': changed,
            'sources_changed': sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))}

def _preview_parameters(url, resources, viewport, theme, locale):
    from urllib.parse import urlsplit
    _need(type(url) is str and type(resources) is list and 1 <= len(resources) <= 16
          and all(type(x) is str and len(x) <= 512 for x in resources)
          and resources == sorted(set(resources)) and url in resources)
    origin = None
    for value in resources:
        parts = urlsplit(value)
        _need(parts.scheme == 'http' and parts.hostname == '127.0.0.1'
              and parts.port is not None and 1024 <= parts.port <= 65535
              and parts.netloc == '127.0.0.1:' + str(parts.port)
              and not parts.fragment and parts.path.startswith('/')
              and not any(ord(c) <= 32 or ord(c) >= 127 or c == '\\' for c in value))
        _need(origin is None or origin == parts.netloc)
        origin = parts.netloc
    _need(type(viewport) is dict and set(viewport) == {'width','height'}
          and all(type(x) is int and 240 <= x <= 1920 for x in viewport.values())
          and theme in ('light', 'dark') and type(locale) is str
          and re.fullmatch('[a-z]{2}(?:-[A-Z]{2})?', locale))
    return {'url':url,'resources':resources,'viewport':viewport,'theme':theme,'locale':locale,
            'scope':'controlled-loopback-fixture', 'live_capture':'unsupported'}


def _validate_preview(pack):
    _need(type(pack) is dict and set(pack) == {'content','content_digest','capture'})
    content = pack['content']
    _need(set(content) == {'schema_version','extractor_version','parameters','sources','tokens','browser','coverage'}
          and content['schema_version'] == 2 and content['extractor_version'] == VERSION
          and pack['content_digest'] == _digest(content))
    envelope = pack['capture']
    _need(type(envelope) is dict and set(envelope) == {'id','timestamp'}
          and type(envelope['id']) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',envelope['id'])
          and type(envelope['timestamp']) is str
          and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ',envelope['timestamp']))
    datetime.strptime(envelope['timestamp'],'%Y-%m-%dT%H:%M:%SZ')
    p = content['parameters']
    _need(type(p) is dict and p == _preview_parameters(p['url'],p['resources'],p['viewport'],p['theme'],p['locale']))
    sources = content['sources']
    _need(type(sources) is list and 1 <= len(sources) <= 16)
    paths = []
    for row in sources:
        _need(type(row) is dict and set(row) == {'path','sha256'} and row['path'] in p['resources']
              and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']))
        paths.append(row['path'])
    _need(paths == sorted(set(paths)) and p['url'] in paths)
    tokens = content['tokens']
    _need(type(tokens) is list and len(tokens) <= 1536)
    ids = []
    properties = {'color','background-color','font-family','font-size','font-weight','line-height',
                  'letter-spacing','margin-top','padding-top','gap','border-radius','box-shadow'}
    for row in tokens:
        _need(type(row) is dict and set(row) == {'id','kind','source','name','context','raw_value','unit','locator'}
              and row['kind'] == 'computed' and row['source'] == p['url'] and row['name'] in properties
              and type(row['raw_value']) is str and len(row['raw_value']) <= 4096
              and row['unit'] == _unit(row['raw_value'])
              and type(row['locator']) is dict and set(row['locator']) == {'element'}
              and type(row['locator']['element']) is int and 0 <= row['locator']['element'] < 128
              and row['context'] == ['element:' + str(row['locator']['element'])]
              and row['id'] == _digest({k:row[k] for k in ('kind','source','name','context')}))
        ids.append(row['id'])
    _need(ids == sorted(set(ids)))
    b = content['browser']
    _need(type(b) is dict and set(b) == {'version','adapter','adapter_version','sandbox','loading'}
          and b['adapter'] == 'playwright' and b['sandbox'] is True
          and type(b['adapter_version']) is str and re.fullmatch(r'[0-9.]{1,64}',b['adapter_version'])
          and type(b['version']) is str and re.fullmatch(r'[0-9.]{1,64}',b['version']))
    loading = b['loading']
    _need(type(loading) is dict and set(loading) == {'fonts','fontErrors','css','ready'}
          and loading['fonts'] in ('loaded','loading') and type(loading['fontErrors']) is bool
          and type(loading['css']) is bool and loading['ready'] in ('loading','interactive','complete'))
    c = content['coverage']
    allowed = {'fixture-only','dynamic-unproven','dynamic-content','blocked-transport','request-budget',
               'resource-unavailable','response-budget','dom-budget','fonts-incomplete','loading-incomplete'}
    _need(type(c) is dict and set(c) == {'status','reasons','files','tokens'} and c['status'] == 'partial'
          and type(c['reasons']) is list and c['reasons'] == sorted(set(c['reasons']))
          and {'fixture-only','dynamic-unproven'} <= set(c['reasons']) <= allowed
          and type(c['files']) is int and c['files'] == len(sources)
          and type(c['tokens']) is int and c['tokens'] == len(tokens)
          and len(encode(pack)) <= MAX_PACK_BYTES)
