"""Fetch the signed runner by digest outside the rootless Docker daemon."""
import base64
import json
import os
from pathlib import Path
import re
import sys
from urllib import error, parse, request

from .policy import PolicyCatalog
from .runner_archive import INDEXES, MANIFESTS, fetch_archive, hex_digest, load_archive

ARCHIVE = Path('/var/lib/trust-ci-transfer/runner.tar')
POLICY = Path('/etc/adaptive-trust-ci/policy.json')


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Registry:
    def __init__(self, image):
        repository, pin = image.rsplit('@', 1)
        hex_digest(pin)
        first, sep, rest = repository.partition('/')
        if sep and ('.' in first or ':' in first or first == 'localhost'):
            origin, repository = first, rest
        else:
            origin = 'docker.io'
        if not re.fullmatch(r'[a-z0-9.-]+(?::[0-9]{1,5})?', origin):
            raise ValueError('invalid runner registry')
        if origin in {'docker.io', 'registry-1.docker.io'}:
            origin = 'registry-1.docker.io'
            if '/' not in repository:
                repository = 'library/' + repository
        if not re.fullmatch(r'[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*', repository):
            raise ValueError('expected immutable repository without a tag')
        self.origin = origin
        self.repo = repository
        self.opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
        self.authorization = ''
        self.basic = ''
        auth = os.environ.get('TRUST_CI_RUNNER_AUTH_FILE')
        if auth:
            encoded = json.loads(Path(auth).read_text())['auths'][origin]['auth']
            if not isinstance(encoded, str) or b':' not in base64.b64decode(encoded, validate=True):
                raise ValueError('invalid registry credentials')
            self.basic = 'Basic ' + encoded

    def open(self, kind, key):
        hex_digest(key)
        url = f'https://{self.origin}/v2/{self.repo}/{kind}/{key}'
        headers = {'Accept': ', '.join(sorted(INDEXES | MANIFESTS)) if kind == 'manifests' else 'application/octet-stream'}
        auth = self.authorization or self.basic
        if auth:
            headers['Authorization'] = auth
        try:
            return self._get(url, headers, kind)
        except error.HTTPError as exc:
            if exc.code != 401:
                raise
            challenge = exc.headers.get('WWW-Authenticate', '')
            exc.close()
        scheme, _, body = challenge.partition(' ')
        if scheme.lower() != 'bearer':
            raise ValueError('unsupported runner registry challenge')
        fields = request.parse_keqv_list(request.parse_http_list(body))
        realm = fields.get('realm', '')
        origins = {self.origin}
        if self.origin == 'registry-1.docker.io':
            origins.add('auth.docker.io')
        self._validate_url(realm, origins)
        token_url = realm + ('&' if '?' in realm else '?') + parse.urlencode({
            'scope': f'repository:{self.repo}:pull', 'service': fields.get('service', self.origin)})
        token_headers = {'Authorization': self.basic} if self.basic else {}
        with self._get(token_url, token_headers, 'token') as r:
            raw = r.read(65537)
        if len(raw) > 65536:
            raise ValueError('oversized runner registry token response')
        result = json.loads(raw)
        token = result.get('token') or result.get('access_token')
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/=-]+', token):
            raise ValueError('invalid registry token')
        self.authorization = 'Bearer ' + token
        return self._get(url, {**headers, 'Authorization': self.authorization}, kind)

    @staticmethod
    def _validate_url(url, origins):
        parsed = parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc not in origins or parsed.username or parsed.fragment:
            raise ValueError('runner registry transfer left the approved origin')

    def _get(self, url, headers, kind):
        origins = {parse.urlsplit(url).netloc}
        if kind == 'blobs' and self.origin == 'registry-1.docker.io':
            origins.add('production.cloudfront.docker.com')
        for _ in range(4):
            self._validate_url(url, origins)
            try:
                return self.opener.open(request.Request(url, headers=headers), timeout=30)
            except error.HTTPError as exc:
                if exc.code not in {301, 302, 303, 307, 308}:
                    raise
                location = exc.headers['Location']
                exc.close()
            target = parse.urljoin(url, location)
            if parse.urlsplit(target).netloc != parse.urlsplit(url).netloc:
                headers = {k: v for k, v in headers.items() if k != 'Authorization'}
            url = target
        raise ValueError('too many runner registry redirects')


def main():
    image = os.environ['TRUST_CI_RUNNER_IMAGE']
    catalog = PolicyCatalog.load(POLICY)
    pairs = {(p.sandbox.image, p.sandbox.runner_manifest_digest, p.sandbox.runner_config_digest)
             for p in catalog.profiles}
    if len(pairs) != 1:
        raise ValueError('runner policy profiles disagree')
    signed, manifest, config = pairs.pop()
    if signed != image or image.rsplit('@', 1)[-1] != manifest:
        raise ValueError('runner manifest differs from deployment policy')
    hex_digest(config)
    if sys.argv[1:] == ['fetch']:
        fetch_archive(Registry(image).open, manifest, config, ARCHIVE)
    elif sys.argv[1:] == ['load']:
        load_archive(ARCHIVE, manifest, config)
    else:
        raise ValueError('expected fetch or load')


if __name__ == '__main__':
    main()
