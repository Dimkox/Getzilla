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
_FINAL = re.compile(r'v?(\d+(?:\.\d+){1,3})(?:\.post(\d+))?\Z')


def stable(value: object) -> tuple[int, ...] | None:
    match = _FINAL.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return None
    parts = tuple(int(v) for v in match[1].split('.'))
    return (*parts, *((0,) * (4-len(parts))), int(match[2] or 0))


def metadata(fetch: Fetch, url: str):
    raw = fetch(url)
    if type(raw) is not bytes or not raw or len(raw) > MAX_METADATA_BYTES:
        raise ValueError('release metadata exceeds bounds or is empty')
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
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


def github_release(repository: str, fetch: Fetch) -> dict:
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid official repository identity')
    url = f'https://api.github.com/repos/{repository}/releases?per_page=100'
    raw = fetch(url)
    rows = metadata(lambda _: raw, url)
    if type(rows) is not list or not 0 < len(rows) < 100:
        raise ValueError('official release listing absent or exhausted; newest stable unproved')
    final = [r for r in rows if type(r) is dict and r.get('draft') is False
             and r.get('prerelease') is False and stable(r.get('tag_name'))]
    if not final:
        raise ValueError('no supported final upstream release')
    newest = max(stable(r['tag_name']) for r in final)
    matches = [r for r in final if stable(r['tag_name']) == newest]
    if len(matches) != 1:
        raise ValueError('ambiguous newest stable release')
    return {**matches[0], 'version': matches[0]['tag_name'].removeprefix('v'), 'repository': repository,
            'metadata_url': url, 'metadata_sha256': hashlib.sha256(raw).hexdigest()}


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


def npm_release(name: str, fetch: Fetch) -> Target:
    if not re.fullmatch(r'(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+', name):
        raise ValueError('invalid npm publication identity')
    url = 'https://registry.npmjs.org/' + urllib.parse.quote(name, safe='@') + '/latest'
    raw = fetch(url)
    row = metadata(lambda _: raw, url)
    if type(row) is not dict or row.get('name') != name or not stable(row.get('version')):
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
    final = [v for v, files in releases.items() if stable(v) and files
             and all(type(f) is dict and f.get('yanked') is not True for f in files)]
    if not final:
        raise ValueError(f'{name}: no current final non-yanked PyPI release')
    return max(final, key=stable)


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
    # Windows index describes a zip explicitly; Unix describes its platform/CPU.
    variant = f'{platform}-{architecture}' + ('-zip' if platform == 'win' else '')
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
    url = 'https://api.github.com/repos/git-for-windows/git/releases/latest'
    raw = fetch(url)
    row = metadata(lambda _: raw, url)
    match = re.fullmatch(r'v(\d+\.\d+\.\d+\.windows\.\d+)', str(row.get('tag_name', '')))
    if not match or row.get('draft') is not False or row.get('prerelease') is not False:
        raise ValueError('Git for Windows newest stable vendor build unavailable')
    version = match[1]
    base = version.split('.windows.')[0]
    suffix = {'x64': '64-bit', 'amd64': '64-bit', 'arm64': 'arm64', 'x86': '32-bit'}.get(architecture)
    release = {**row, 'version': version, 'repository': 'git-for-windows/git',
               'metadata_url': url, 'metadata_sha256': hashlib.sha256(raw).hexdigest()}
    return github_asset(release, f'MinGit-{base}-{suffix}.zip', component='git')


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
