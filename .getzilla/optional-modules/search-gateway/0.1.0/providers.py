"""Independent bounded official web-search contracts. No provider SDK or page fetches."""
from __future__ import annotations

import http.client
import json
import ssl
import socket
import threading
import time
from urllib.parse import urlencode, urlsplit, urlunsplit

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_REQUEST_BYTES = 32768
PROVIDERS = ('searxng', 'serper', 'serpapi', 'brave', 'tavily', 'firecrawl', 'scrapingdog')
SUPPORTED_COUNTRIES = frozenset(('in','us','gb','ru','cn','de','fr','jp','ca','au','es'))
SUPPORTED_LANGUAGES = frozenset(('hi','en','ru','zh-cn','zh-tw','de','fr','ja','es','zh-hans'))
ENDPOINTS = {
    'serper': 'https://google.serper.dev/search',
    'serpapi': 'https://serpapi.com/search.json',
    'brave': 'https://api.search.brave.com/res/v1/web/search',
    'tavily': 'https://api.tavily.com/search',
    'firecrawl': 'https://api.firecrawl.dev/v2/search',
    'scrapingdog': 'https://api.scrapingdog.com/google',
}


class SafeRequest(dict):
    """A transport envelope whose diagnostic representation cannot expose credentials."""
    def __repr__(self):
        return '<search request provider=' + self['provider'] + '>'

    __str__ = __repr__


class TransportFailure(ValueError):
    pass


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_json_key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('invalid_json_number')))
    except RecursionError:
        raise ValueError('invalid_json_depth') from None


def eligible(provider, request):
    """An explicit engine or locale is never weakened to find a fallback."""
    name = provider['id']
    selected = request['engine']
    if name == 'brave' and (len(request['query']) > 600 or len(request['query'].split()) > 75):
        return False
    if name == 'firecrawl' and len(request['query']) > 500:
        return False
    actual = 'google' if name in ('serper', 'scrapingdog') else None
    if name == 'serpapi':
        actual = 'google' if selected == 'auto' else selected
    if selected != 'auto' and selected != actual:
        return False
    country, language = request['country'], request['language']
    if country is not None and country not in SUPPORTED_COUNTRIES:
        return False
    if language is not None and language not in SUPPORTED_LANGUAGES:
        return False
    if name == 'serpapi' and actual == 'yandex':
        return len(request['query']) <= 400 and len(request['query'].split()) <= 40 and country is None and language in (None, 'ru', 'en')
    if name == 'serpapi' and actual == 'baidu':
        return country is None and language in (None, 'zh-cn', 'zh-tw')
    if name in ('serper', 'scrapingdog') or (name == 'serpapi' and actual == 'google'):
        return True
    if name == 'searxng':
        return country is None
    if name == 'brave':
        return language in (None, 'en', 'de', 'fr', 'ru', 'zh-hans', 'ja', 'es')
    return country is None and language is None


def provider_request(provider, request):
    name, key = provider['id'], provider.get('credential', '')
    q, limit = request['query'], request['limit']
    country, language = request['country'], request['language']
    selected = request['engine']
    actual = ('google' if selected == 'auto' else selected) if name == 'serpapi' else (
        'google' if name in ('serper', 'scrapingdog') else None)
    params, body, headers = {}, None, {'Accept': 'application/json', 'User-Agent': 'Getzilla-search/0.1'}
    endpoint = provider.get('endpoint') if name == 'searxng' else ENDPOINTS[name]
    if name == 'searxng':
        params = {'q': q, 'format': 'json'}
        if language:
            params['language'] = language
    elif name == 'serper':
        headers['X-API-KEY'] = key
        body = {'q': q, 'num': limit}
        if country:
            body['gl'] = country
        if language:
            body['hl'] = language
    elif name == 'serpapi':
        params = {'engine': actual, 'api_key': key, 'text' if actual == 'yandex' else 'q': q}
        if actual == 'google':
            params['num'] = limit
            if country:
                params['gl'] = country
            if language:
                params['hl'] = language
        elif actual == 'baidu':
            params['rn'] = limit
            if language:
                params['ct'] = {'zh-cn':2, 'zh-tw':3}[language]
        elif language:
            params['lang'] = language
    elif name == 'brave':
        headers['X-Subscription-Token'] = key
        params = {'q': q, 'count': limit}
        if country:
            params['country'] = country.upper()
        if language:
            params['search_lang'] = language
    elif name == 'tavily':
        headers['Authorization'] = 'Bearer ' + key
        body = {'query': q, 'search_depth': 'basic', 'max_results': limit,
                'include_answer': False, 'include_raw_content': False, 'auto_parameters': False}
    elif name == 'firecrawl':
        headers['Authorization'] = 'Bearer ' + key
        body = {'query': q, 'limit': limit, 'sources': ['web']}
    else:
        params = {'api_key': key, 'query': q}
        if country:
            params['country'] = country
        if language:
            params['language'] = language
    if body is not None:
        headers['Content-Type'] = 'application/json'
        body = json.dumps(body, ensure_ascii=False, allow_nan=False).encode('utf-8')
    url = endpoint + ('?' + urlencode(params) if params else '')
    return SafeRequest(provider=name, url=url, headers=headers, body=body,
                       method='POST' if body is not None else 'GET', engine=actual)


def guarded_transport(request, timeout):
    """Send once, refuse redirects, and bound bytes and wall time without environment proxies."""
    parsed = urlsplit(request['url'])
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username
            or parsed.password or parsed.fragment or len(request['url'].encode()) > MAX_REQUEST_BYTES
            or len(request['body'] or b'') > MAX_REQUEST_BYTES):
        raise TransportFailure('invalid_destination')
    if request['provider'] != 'searxng' and (
            parsed.scheme != 'https' or parsed.netloc != urlsplit(ENDPOINTS[request['provider']]).netloc
            or parsed.path != urlsplit(ENDPOINTS[request['provider']]).path):
        raise TransportFailure('invalid_destination')
    deadline = time.monotonic() + timeout
    connection = (http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=timeout,
                                              context=ssl.create_default_context())
                  if parsed.scheme == 'https' else
                  http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout))
    expired = threading.Event()
    held_socket = [None]
    def expire():
        expired.set()
        active = connection.sock or held_socket[0]
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    timer = threading.Timer(timeout, expire)
    timer.daemon = True
    timer.start()
    try:
        connection.connect()
        held_socket[0] = connection.sock
        if expired.is_set() or time.monotonic() >= deadline:
            raise TimeoutError()
        connection.sock.settimeout(max(0.001, deadline-time.monotonic()))
        connection.request(request['method'], urlunsplit(('', '', parsed.path or '/', parsed.query, '')),
                           request['body'], request['headers'])
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise TransportFailure('redirect_refused')
        length = response.getheader('Content-Length')
        if length is not None and (not length.isdigit() or int(length) > MAX_RESPONSE_BYTES):
            raise TransportFailure('response_too_large')
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            # The response owns the socket after Connection: close; use its held socket too.
            sock = connection.sock or getattr(getattr(response.fp, 'raw', None), '_sock', None)
            if sock is not None:
                sock.settimeout(remaining)
            chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise TransportFailure('response_too_large')
            if not chunk:
                break
            chunks.append(chunk)
        return response.status, {'Retry-After': response.getheader('Retry-After', '')}, b''.join(chunks)
    except Exception:
        if expired.is_set() or time.monotonic() >= deadline:
            raise TimeoutError() from None
        raise
    finally:
        timer.cancel()
        connection.close()
        timer.join()


def normalize_results(name, raw, request, actual_engine, fetched_at):
    data = decode_json(raw)
    if type(data) is not dict or 'error' in data or data.get('success') is False:
        raise ValueError('provider_schema_error')
    if name in ('searxng', 'tavily'):
        rows = data.get('results')
    elif name == 'serper':
        rows = data.get('organic')
    elif name == 'brave':
        rows = data.get('web', {}).get('results') if type(data.get('web')) is dict else None
    elif name == 'firecrawl':
        rows = data.get('data', {}).get('web') if type(data.get('data')) is dict else None
    else:
        rows = data.get('organic_results')
    if type(rows) is not list or len(rows) > 1000:
        raise ValueError('provider_schema_error')
    results, seen, warnings = [], {}, []
    for rank, row in enumerate(rows, 1):
        if type(row) is not dict:
            warnings.append('invalid_result')
            continue
        url = row.get('url', row.get('link'))
        title = row.get('title')
        try:
            parsed = urlsplit(url) if type(url) is str and len(url) <= 8192 else None
            valid = (parsed is not None and parsed.scheme in ('http', 'https') and parsed.hostname
                     and not parsed.username and not parsed.password
                     and not any(ord(char) < 32 for char in url))
        except ValueError:
            valid = False
        if not valid or type(title) is not str:
            warnings.append('invalid_result')
            continue
        identity = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, ''))
        provenance = {'provider': name, 'engine': actual_engine, 'query': request['query'],
                      'fetched_at': fetched_at, 'rank': rank, 'source_url': url, 'untrusted': True}
        if identity in seen:
            if len(seen[identity]['provenance']) < 8:
                seen[identity]['provenance'].append(provenance)
            else:
                warnings.append('result_truncated')
            continue
        if len(results) >= request['limit']:
            continue
        snippet = row.get('snippet', row.get('content', row.get('description', '')))
        published = row.get('date', row.get('published_date'))
        result = {'title': title[:1024], 'url': url, 'snippet': snippet[:8192] if type(snippet) is str else '',
                  'published_at': published[:128] if type(published) is str else None, 'provenance': [provenance]}
        seen[identity] = result
        results.append(result)
    while results and len(json.dumps(results, ensure_ascii=True).encode()) > 512*1024:
        results.pop()
        warnings.append('result_truncated')
    if rows and not results:
        raise ValueError('provider_schema_error')
    return results, sorted(set(warnings))
