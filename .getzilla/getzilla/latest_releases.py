"""Fresh official release metadata, exact artifacts, and no installed-version fallback.

These observations bind upstream metadata; they are not signature attestations.
Consumers must verify the selected bytes before activation and probe the active path.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

Fetch = Callable[[str], bytes]
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_PYPI_CATALOG_BYTES = 64 * 1024 * 1024
_FINAL = re.compile(r'v?(\d+(?:\.\d+){1,3})(?:\.post(\d+))?\Z')


def stable(value: object) -> tuple[int, ...] | None:
    match = _FINAL.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return None
    parts = tuple(int(v) for v in match[1].split('.'))
    return (*parts, *((0,) * (4-len(parts))), int(match[2] or 0))


def metadata(fetch: Fetch, url: str):
    raw = fetch(url)
    parsed = urllib.parse.urlsplit(url)
    limit = MAX_PYPI_CATALOG_BYTES if parsed.netloc == 'pypi.org' and re.fullmatch(r'/pypi/[A-Za-z0-9_.-]+/json', parsed.path) else MAX_METADATA_BYTES
    if type(raw) is not bytes or not raw or len(raw) > limit:
        raise ValueError('release metadata exceeds bounds or is empty')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate official release metadata member')
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite metadata')))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError('invalid official release metadata') from exc


@dataclass(frozen=True)
class Target:
    component: str
    version: str
    url: str
    sha256: str | None = None
    integrity: str | None = None
    metadata_url: str = ''
    metadata_sha256: str = ''
    filename: str = ''
    requirements: dict = field(default_factory=dict)

    def verify(self, data: bytes) -> None:
        if self.sha256:
            valid = hashlib.sha256(data).hexdigest() == self.sha256
        elif self.integrity and self.integrity.startswith('sha512-'):
            valid = base64.b64encode(hashlib.sha512(data).digest()).decode() == self.integrity[7:]
        else:
            raise ValueError('target has no qualified expected artifact integrity')
        if not valid:
            raise ValueError(f'{self.component} {self.version}: artifact integrity mismatch')


def github_release(repository: str, fetch: Fetch, *, version_key=stable) -> dict:
    from urllib.error import HTTPError
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid official repository identity')
    url = f'https://api.github.com/repos/{repository}/releases/latest'
    raw = fetch(url)
    latest = metadata(lambda _: raw, url)
    if (type(latest) is not dict or latest.get('draft') is not False
            or latest.get('prerelease') is not False or not version_key(latest.get('tag_name'))):
        raise ValueError('official current stable release is unavailable')
    refs_url = f'https://api.github.com/repos/{repository}/git/matching-refs/tags/'
    refs_raw = fetch(refs_url)
    refs = metadata(lambda _: refs_raw, refs_url)
    if type(refs) is not list or not 0 < len(refs) <= 4096:
        raise ValueError('official complete tag index unavailable or exceeds bound')
    names = []
    for row in refs:
        ref = row.get('ref', '') if type(row) is dict else ''
        if type(ref) is not str or not ref.startswith('refs/tags/') or ref in names:
            raise ValueError('duplicate/invalid official tag reference')
        names.append(ref)
    newer = sorted((ref[10:] for ref in names if version_key(ref[10:])
                    and version_key(ref[10:]) > version_key(latest['tag_name'])), key=version_key, reverse=True)
    if len(newer) > 16:
        raise ValueError('published higher-version lookup exceeds bound')
    observations = [raw, refs_raw]
    for tag in newer:
        tagged_url = f'https://api.github.com/repos/{repository}/releases/tags/{tag}'
        try:
            tagged_raw = fetch(tagged_url)
        except HTTPError as exc:
            if exc.code == 404:
                continue  # A tag without a published release is not a stable release.
            raise
        candidate = metadata(lambda _: tagged_raw, tagged_url)
        observations.append(tagged_raw)
        if type(candidate) is not dict or candidate.get('tag_name') != tag:
            raise ValueError('higher official release identity differs')
        if candidate.get('draft') is False and candidate.get('prerelease') is False:
            latest = candidate
            break
    return {**latest, 'version': latest['tag_name'].removeprefix('v'), 'repository': repository,
            'metadata_url': url, 'metadata_sha256': hashlib.sha256(b''.join(observations)).hexdigest()}


def github_asset(release: dict, filename: str, *, component: str | None = None) -> Target:
    rows = [r for r in release.get('assets', []) if type(r) is dict and r.get('name') == filename]
    if len(rows) != 1:
        raise ValueError(f"{release['repository']} {release['version']}: required asset {filename} unavailable")
    row = rows[0]
    expected = f"https://github.com/{release['repository']}/releases/download/{release['tag_name']}/{filename}"
    digest = row.get('digest')
    if (row.get('browser_download_url') != expected or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest or '')
            or type(row.get('size')) is not int or not 0 < row['size'] <= 512*1024*1024):
        raise ValueError(f'{filename}: missing digest or unsupported official asset metadata')
    return Target(component or release['repository'], release['version'], expected, sha256=digest[7:],
                  metadata_url=release['metadata_url'], metadata_sha256=release['metadata_sha256'], filename=filename)


def npm_release(name: str, fetch: Fetch, *, version: str | None = None) -> Target:
    if not re.fullmatch(r'(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+', name):
        raise ValueError('invalid npm publication identity')
    if version is not None and not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9_.-]+)?(?:\+[A-Za-z0-9_.-]+)?', version):
        raise ValueError('invalid locked npm version')
    url = 'https://registry.npmjs.org/' + urllib.parse.quote(name, safe='@') + '/' + (version or 'latest')
    raw = fetch(url)
    row = metadata(lambda _: raw, url)
    if (type(row) is not dict or row.get('name') != name
            or (row.get('version') != version if version else not stable(row.get('version')))):
        raise ValueError('npm latest identity or final version is invalid')
    dist = row.get('dist', {})
    artifact = dist.get('tarball', '')
    origin = urllib.parse.urlsplit(artifact)
    integrity = dist.get('integrity', '')
    try:
        valid = integrity.startswith('sha512-') and len(base64.b64decode(integrity[7:], validate=True)) == 64
    except (ValueError, TypeError):
        valid = False
    if (not valid or origin.scheme != 'https' or origin.netloc != 'registry.npmjs.org'
            or origin.query or origin.fragment or not origin.path.endswith('.tgz')):
        raise ValueError('npm latest lacks fixed official tarball and SHA512 integrity')
    return Target(name, row['version'], artifact, integrity=integrity, filename=artifact.rsplit('/', 1)[-1],
                  metadata_url=url, metadata_sha256=hashlib.sha256(raw).hexdigest(),
                  requirements={**row.get('engines', {}), **{k: row[k] for k in ('os', 'cpu') if k in row}})


def pypi_version(name: str, fetch: Fetch) -> str:
    row = metadata(fetch, f'https://pypi.org/pypi/{name}/json')
    if type(row) is not dict or row.get('info', {}).get('name', '').lower().replace('_', '-') != name.lower().replace('_', '-'):
        raise ValueError('PyPI project identity differs')
    releases = row.get('releases', {})
    final = [v for v, files in releases.items() if pep440_final(v) and files
             and any(type(f) is dict and f.get('yanked') is False for f in files)]
    if not final:
        raise ValueError(f'{name}: no current final non-yanked PyPI release')
    selected = max(final, key=pep440_final)
    if any(pep440_final(v) and pep440_final(v) > pep440_final(selected) and not files for v, files in releases.items()):
        raise ValueError(f'{name}: newest final release has no artifacts; no older fallback')
    return selected


def pep440_final(value):
    """Final PEP440 ordering, including epoch/post/local; pre/dev are ineligible."""
    if type(value) is not str or len(value) > 128:
        return None
    match = re.fullmatch(r'\s*v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:(?:[-_.]?(?:post|rev|r)[-_.]?(\d+))|-(\d+))?'
                         r'(?:\+([A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*))?\s*', value, re.I)
    if not match:
        return None
    release = tuple(int(p) for p in match[2].split('.'))
    if len(release) > 32:
        raise ValueError('PEP440 release precision exceeds finite bound')
    local = tuple((1, int(p)) if p.isdigit() else (0, p.lower())
                  for p in re.split('[-_.]', match[5] or '') if p)
    return int(match[1] or 0), release+(0,)*(32-len(release)), int(match[3] or match[4] or -1), local


def node_release(fetch: Fetch, system: str, architecture: str) -> Target:
    url = 'https://nodejs.org/dist/index.json'
    raw = fetch(url)
    rows = metadata(lambda _: raw, url)
    if type(rows) is not list or not rows:
        raise ValueError('Node release index unavailable')
    final = [r for r in rows if type(r) is dict and stable(r.get('version'))]
    if not final:
        raise ValueError('Node current final release unavailable')
    row = max(final, key=lambda r: stable(r['version']))
    version = row['version'].removeprefix('v')
    platform = 'win' if system == 'windows' else system
    ext = 'zip' if platform == 'win' else 'tar.gz'
    filename = f'node-v{version}-{platform}-{architecture}.{ext}'
    # The Node index calls macOS archives osx-*-tar, while filenames use darwin.
    variant = {'darwin': f'osx-{architecture}-tar', 'win': f'win-{architecture}-zip'}.get(
        platform, f'{platform}-{architecture}')
    if variant not in row.get('files', []):
        raise ValueError(f'Node {version}: newest stable has no {variant} asset')
    checksums = fetch(f'https://nodejs.org/dist/v{version}/SHASUMS256.txt')
    if len(checksums) > MAX_METADATA_BYTES:
        raise ValueError('Node checksum file exceeds bound')
    matches = re.findall(rb'(?m)^([0-9a-f]{64})  ' + re.escape(filename.encode()) + rb'\r?$', checksums)
    if len(matches) != 1:
        raise ValueError('Node exact artifact checksum unavailable')
    return Target('node', version, f'https://nodejs.org/dist/v{version}/{filename}', sha256=matches[0].decode(),
                  filename=filename, metadata_url=url, metadata_sha256=hashlib.sha256(raw).hexdigest())


def python_windows(fetch: Fetch, architecture: str) -> Target:
    first = 'https://www.python.org/ftp/python/index-windows.json'
    url, rows, hashes, seen = first, [], [], set()
    for _ in range(16):
        if url in seen or not re.fullmatch(r'https://www\.python\.org/ftp/python/index-[A-Za-z0-9_.-]+\.json', url):
            raise ValueError('Python index pagination origin/cycle refused')
        seen.add(url)
        raw = fetch(url)
        page = metadata(lambda _: raw, url)
        if type(page) is not dict or type(page.get('versions')) is not list:
            raise ValueError('Python official runtime index is malformed')
        rows.extend(page['versions'])
        hashes.append(hashlib.sha256(raw).hexdigest())
        if not page.get('next'):
            break
        url = urllib.parse.urljoin(url, page['next'])
    else:
        raise ValueError('Python index pagination exhausted; newest stable unproved')
    final = [r for r in rows if type(r) is dict and stable(r.get('sort-version'))]
    if not final:
        raise ValueError('no final Python runtime')
    version = max(final, key=lambda r: stable(r['sort-version']))['sort-version']
    arch = {'x64': '64', 'amd64': '64', 'arm64': 'arm64', 'x86': '32'}.get(architecture)
    candidates = [r for r in final if r['sort-version'] == version
                  and re.fullmatch(r'pythoncore-\d+\.\d+-' + str(arch), str(r.get('id')))]
    if len(candidates) != 1:
        raise ValueError(f'Python {version}: no unambiguous ordinary {architecture} runtime; no old-family fallback')
    row = candidates[0]
    artifact = row.get('url', '')
    digest = row.get('hash', {}).get('sha256', '')
    if (not artifact.startswith(f'https://www.python.org/ftp/python/{version}/python-{version}-')
            or not artifact.endswith('.zip') or not re.fullmatch('[a-f0-9]{64}', digest)
            or row.get('executable') != '.\\python.exe'):
        raise ValueError('Python runtime artifact identity/integrity unsupported')
    return Target('python', version, artifact, sha256=digest, filename=artifact.rsplit('/', 1)[-1],
                  metadata_url=first, metadata_sha256=hashlib.sha256(''.join(hashes).encode()).hexdigest())


def git_windows(fetch: Fetch, architecture: str) -> Target:
    def vendor_version(value):
        match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)\.windows\.(\d+)', str(value))
        return tuple(int(p) for p in match.groups()) if match else None
    row = github_release('git-for-windows/git', fetch, version_key=vendor_version)
    match = re.fullmatch(r'v(\d+\.\d+\.\d+\.windows\.\d+)', str(row.get('tag_name', '')))
    if not match or row.get('draft') is not False or row.get('prerelease') is not False:
        raise ValueError('Git for Windows newest stable vendor build unavailable')
    version = match[1]
    base = version.split('.windows.')[0]
    suffix = {'x64': '64-bit', 'amd64': '64-bit', 'arm64': 'arm64', 'x86': '32-bit'}.get(architecture)
    release = row
    build = version.rsplit('.', 1)[-1]
    names = [a.get('name') for a in row.get('assets', []) if type(a) is dict and
             re.fullmatch(r'MinGit-'+re.escape(base)+r'(?:\.'+re.escape(build)+r')?-'+str(suffix)+r'\.zip',
                          str(a.get('name')))]
    if len(names) != 1:
        raise ValueError('Git current vendor-build native ZIP unavailable or ambiguous')
    return github_asset(release, names[0], component='git')


def composer_release(fetch: Fetch) -> Target:
    url = 'https://getcomposer.org/versions'
    raw = fetch(url)
    rows = metadata(lambda _: raw, url).get('stable', [])
    final = [r for r in rows if type(r) is dict and stable(r.get('version'))]
    if not final:
        raise ValueError('Composer latest stable metadata unavailable')
    row = max(final, key=lambda r: stable(r['version']))
    version = row['version']
    path = f'/download/{version}/composer.phar'
    if row.get('path') != path or type(row.get('min-php')) is not int:
        raise ValueError('Composer exact release artifact/runtime contract malformed')
    artifact = 'https://getcomposer.org' + path
    sums = fetch(artifact + '.sha256sum')
    if len(sums) > 4096:
        raise ValueError('Composer checksum exceeds bound')
    match = re.fullmatch(rb'([a-f0-9]{64})(?:\s+\*?composer\.phar)?\s*', sums)
    if not match:
        raise ValueError('Composer versioned SHA256 unavailable')
    return Target('composer', version, artifact, sha256=match[1].decode(), filename='composer.phar',
                  metadata_url=url, metadata_sha256=hashlib.sha256(raw).hexdigest(), requirements={'php': row['min-php']})


def php_windows(fetch: Fetch, architecture: str) -> Target:
    global_url = 'https://www.php.net/releases/?json'
    global_raw = fetch(global_url)
    releases = metadata(lambda _: global_raw, global_url)
    versions = [r['version'] for r in releases.values() if type(r) is dict and stable(r.get('version'))]
    if not versions:
        raise ValueError('PHP global stable metadata unavailable')
    version = max(versions, key=stable)
    url = 'https://downloads.php.net/~windows/releases/releases.json'
    raw = fetch(url)
    rows = metadata(lambda _: raw, url)
    candidates = []
    for row in rows.values():
        if type(row) is not dict or not re.fullmatch(re.escape(version)+r'(?:-\d+)?', str(row.get('version'))):
            continue
        for key, value in row.items():
            if re.fullmatch(r'nts-v[cs]\d+-'+re.escape(architecture), key) and type(value) is dict:
                candidates.append((key, value.get('zip', {})))
    if len(candidates) != 1:
        raise ValueError(f'PHP {version}: newest stable NTS {architecture} Windows runtime unavailable/ambiguous')
    _variant, package = candidates[0]
    filename, sha = package.get('path', ''), package.get('sha256', '')
    if not re.fullmatch(r'php-'+re.escape(version)+r'(?:-\d+)?-nts-Win32-v[cs]\d+-'+re.escape(architecture)+r'\.zip', filename) or not re.fullmatch('[a-f0-9]{64}', sha):
        raise ValueError('PHP Windows exact archive integrity unavailable')
    return Target('php', version, 'https://downloads.php.net/~windows/releases/'+filename, sha256=sha,
                  filename=filename, metadata_url=url, metadata_sha256=hashlib.sha256(global_raw+raw).hexdigest(),
                  requirements={'runtime': 'Visual C++ Redistributable 2015-2022; probe must succeed'})


class _ReleaseHTML:
    @staticmethod
    def read(raw):
        from html.parser import HTMLParser
        class Reader(HTMLParser):
            def __init__(self):
                super().__init__()
                self.text, self.rows, self.row, self.code = [], [], None, 0
            def handle_starttag(self, tag, attrs):
                if tag == 'tr':
                    self.row = {'urls': [], 'code': []}
                if self.row is not None and tag == 'a':
                    self.row['urls'].extend(v for k, v in attrs if k == 'href')
                if tag == 'code':
                    self.code += 1
            def handle_endtag(self, tag):
                if tag == 'tr' and self.row is not None:
                    self.rows.append(self.row)
                    self.row = None
                if tag == 'code':
                    self.code = max(0, self.code-1)
            def handle_data(self, data):
                self.text.append(data)
                if self.row is not None and self.code:
                    self.row['code'].append(data)
        if len(raw) > MAX_METADATA_BYTES:
            raise ValueError('official release HTML exceeds bound')
        parser = Reader()
        parser.feed(raw.decode('utf-8'))
        return ' '.join(parser.text), parser.rows


def python_source(fetch: Fetch) -> Target:
    url = 'https://www.python.org/downloads/'
    raw = fetch(url)
    text, _ = _ReleaseHTML.read(raw)
    versions = re.findall(r'Python\s+(\d+\.\d+\.\d+)(?![\w.])', text)
    if not versions:
        raise ValueError('Python global stable release unavailable')
    version = max(versions, key=stable)
    page = f'https://www.python.org/downloads/release/python-{version.replace(".", "")}/'
    detail = fetch(page)
    _, rows = _ReleaseHTML.read(detail)
    artifact = f'https://www.python.org/ftp/python/{version}/Python-{version}.tgz'
    hashes = []
    for row in rows:
        if artifact in [urllib.parse.urljoin(page, link) for link in row['urls']]:
            hashes.extend(re.findall(r'(?<![A-Za-z0-9])[a-f0-9]{64}(?![A-Za-z0-9])', ''.join(row['code']).replace(' ', '').replace('\n', '')))
    if len(hashes) != 1:
        raise ValueError('Python current source SHA256 unavailable/ambiguous')
    return Target('python', version, artifact, sha256=hashes[0], filename=f'Python-{version}.tgz',
                  metadata_url=page, metadata_sha256=hashlib.sha256(raw+detail).hexdigest(),
                  requirements={'route': 'per-user source build; compiler/OpenSSL/venv prerequisites required',
                                'signature_material': artifact+'.sigstore', 'signature_verified': False})


def git_source(fetch: Fetch) -> Target:
    url = 'https://git-scm.com/install/'
    raw = fetch(url)
    text, _ = _ReleaseHTML.read(raw)
    versions = re.findall(r'Latest version:\s*(\d+(?:\.\d+){1,3})(?![\w.])', text)
    if len(versions) != 1:
        raise ValueError('Git official global stable release unavailable/ambiguous')
    version = versions[0]
    filename = f'git-{version}.tar.gz'
    sums_url = 'https://www.kernel.org/pub/software/scm/git/sha256sums.asc'
    sums = fetch(sums_url)
    if len(sums) > MAX_METADATA_BYTES:
        raise ValueError('Git official checksum metadata exceeds bound')
    hashes = re.findall(rb'(?m)^([a-f0-9]{64})  '+re.escape(filename.encode())+rb'\r?$', sums)
    if len(hashes) != 1:
        raise ValueError('Git exact current source archive SHA256 unavailable/ambiguous')
    return Target('git', version, 'https://www.kernel.org/pub/software/scm/git/'+filename,
                  sha256=hashes[0].decode(), filename=filename, metadata_url=url,
                  metadata_sha256=hashlib.sha256(raw+sums).hexdigest(),
                  requirements={'route': 'per-user source build; compiler/make/curl/OpenSSL prerequisites required',
                                'signature_material': sums_url, 'signature_verified': False})


def claude_release(fetch: Fetch, system: str, architecture: str, *, musl=False) -> Target:
    base = 'https://downloads.claude.ai/claude-code-releases'
    raw = fetch(base+'/latest')
    if type(raw) is not bytes or len(raw) > 128:
        raise ValueError('invalid official Claude latest pointer')
    version = raw.decode('ascii').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Claude latest channel is not a final version; no lagged stable fallback')
    if architecture not in {'x64', 'arm64'} or system not in {'windows', 'linux', 'darwin'}:
        raise ValueError('unsupported native Claude platform')
    platform = ('win32' if system == 'windows' else system)+'-'+architecture+('-musl' if system == 'linux' and musl else '')
    url = base+'/'+version+'/manifest.json'
    body = fetch(url)
    manifest = metadata(lambda _: body, url)
    binary = 'claude.exe' if system == 'windows' else 'claude'
    row = manifest.get('platforms', {}).get(platform, {})
    if (manifest.get('version') != version or row.get('binary') != binary
            or not re.fullmatch('[a-f0-9]{64}', row.get('checksum', ''))
            or type(row.get('size')) is not int or not 0 < row['size'] <= 512*1024*1024):
        raise ValueError('Claude exact native platform manifest size/checksum unavailable')
    return Target('claude', version, base+'/'+version+'/'+platform+'/'+binary, sha256=row['checksum'], filename=binary,
                  metadata_url=url, metadata_sha256=hashlib.sha256(raw+body).hexdigest(), requirements={'size': row['size']})


def php_source(fetch: Fetch) -> Target:
    url = 'https://www.php.net/releases/?json'
    raw = fetch(url)
    catalog = metadata(lambda _: raw, url)
    rows = [r for r in catalog.values() if type(r) is dict and stable(r.get('version'))]
    if not rows:
        raise ValueError('PHP official current final release unavailable')
    selected = max(rows, key=lambda r: stable(r['version']))
    version = selected['version']
    filename = 'php-'+version+'.tar.gz'
    assets = [a for a in selected.get('source', []) if type(a) is dict and a.get('filename') == filename]
    if len(assets) != 1 or not re.fullmatch('[a-f0-9]{64}', assets[0].get('sha256', '')):
        raise ValueError('PHP newest exact source SHA256 unavailable; no old release fallback')
    return Target('php', version, 'https://www.php.net/distributions/'+filename, sha256=assets[0]['sha256'],
                  filename=filename, metadata_url=url, metadata_sha256=hashlib.sha256(raw).hexdigest())
