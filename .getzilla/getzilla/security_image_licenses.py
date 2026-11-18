"""Installed image component/term custody from LIVE verified OCI bytes.

No package or image executes. This module makes no license-policy decision and
issues no qualification receipt. Complex/unsupported source groups stay explicit.
The caller must join the observation to its normal source/run/private guard.
"""
from __future__ import annotations

import base64
from collections import defaultdict
import copy
import csv
from email.parser import BytesParser
import io
import posixpath
import re

from . import security_oci as oci
from .security_license_texts import recognized_license

_PROOF = object()


def _retain(path):
    leaf = path.rsplit('/', 1)[-1].lower()
    return (path in {'var/lib/dpkg/status', 'lib/apk/db/installed'}
            or path.startswith('var/lib/dpkg/info/')
            or path.startswith(('usr/share/doc/', 'usr/share/common-licenses/')) and
            (leaf == 'copyright' or path.startswith('usr/share/common-licenses/'))
            or '.dist-info/' in path and leaf in {'metadata', 'record', 'wheel'}
            or leaf in {'vendor.txt', 'license.txt', 'license', 'copying', 'notice', 'notice.txt'}
            or 'license' in leaf or '.dist-info/licenses/' in path)


def _safe(path):
    if not isinstance(path, str) or '\\' in path or '\x00' in path:
        raise oci.OCIError('Unsafe component data path')
    path = path.lstrip('/')
    value = posixpath.normpath(path)
    if value == '..' or value.startswith('../'):
        raise oci.OCIError('Component data path escapes image root')
    return value


class _Files:
    def __init__(self, rows):
        self.rows = rows

    def resolve(self, path):
        path, seen = _safe(path), set()
        for _ in range(32):
            if path in seen:
                raise oci.OCIError('Cyclic image component data alias')
            seen.add(path)
            parts, changed = path.split('/'), False
            for n in range(1, len(parts) + 1):
                prefix = '/'.join(parts[:n])
                row = self.rows.get(prefix)
                if row and row['kind'] in {'symlink', 'hardlink'}:
                    target = row['target']
                    base = '' if row['kind'] == 'hardlink' or target.startswith('/') else posixpath.dirname(prefix)
                    path = _safe(posixpath.join(base, target.lstrip('/'), *parts[n:]))
                    changed = True
                    break
                if row and n < len(parts) and row['kind'] != 'directory':
                    raise oci.OCIError('Component path ancestor is not a directory')
            if not changed:
                return path, self.rows.get(path)
        raise oci.OCIError('Image component alias exceeds bound')

    def data(self, path):
        resolved, row = self.resolve(path)
        if row is None:
            return None
        if row['kind'] != 'file' or 'body' not in row:
            raise oci.OCIError('Component evidence is not retained regular data')
        return row['body'], dict(path=resolved, sha256=row['sha256'], bytes=row['bytes'], layer=row['layer'])


def _paragraphs(body):
    result = []
    for block in re.split(r'\n[ \t]*\n', body.decode('utf-8').replace('\r\n', '\n')):
        fields, key = {}, None
        for line in block.splitlines():
            if line.startswith((' ', '\t')) and key:
                fields[key] += '\n' + ('' if line[1:] == '.' else line[1:])
            elif re.match(r'^[A-Za-z][A-Za-z0-9-]*:', line):
                key, value = line.split(':', 1)
                if key in fields:
                    raise oci.OCIError('Duplicate component metadata field')
                fields[key] = value.lstrip()
            elif line.strip():
                raise oci.OCIError('Malformed component metadata')
        if fields:
            result.append(fields)
    return result


def _evidence(row):
    return {key: row[key] for key in ('path', 'sha256', 'bytes', 'layer')}


class ImageComponentObservation:
    __slots__ = ('_image', '_document', '_proof', '_files')

    def __init__(self, image, document, files, proof):
        if proof is not _PROOF:
            raise oci.OCIError('Image component observation requires held bytes')
        self._image, self._document, self._proof = image, document, proof
        self._files = files

    def _live(self):
        if self._proof is not _PROOF:
            raise oci.OCIError('Invalid image component observation')
        self._image.remaining_seconds()
        oci.scanner_identity({'Metadata': {'ImageID': self._image.config_digest}}, self._image)

    def document(self):
        self._live()
        return copy.deepcopy(self._document)

    def proof_files(self):
        """Exact regular proof data for the caller's existing bounded finalizer.

        Paths refer to final image data. This does not transfer OCI authority,
        issue a receipt, or persist anything outside the caller's owned store.
        """
        self._live()
        return dict(self._files)


def observe_components(image):
    """Build a component SBOM observation, never trust caller JSON as custody."""
    files = _Files(oci.observe_final_files(image, _retain))
    components, unresolved, owners = [], [], defaultdict(set)
    identities, owned_paths = set(), defaultdict(set)
    def gap(code, group, **detail):
        unresolved.append(dict(code=code, group=group, **detail))
    def add(identity, kind):
        if identity in identities:
            raise oci.OCIError('Duplicate installed component identity')
        identities.add(identity)
        component = dict(id=identity, kind=kind, expression=None, files=[], license_paths=[], notice_paths=[],
                         evidence=[], raw_license_declarations=[], requires=[])
        components.append(component)
        return component
    def own(component, paths):
        for path in paths:
            resolved, row = files.resolve(path)
            if row and row['kind'] == 'file':
                owners[resolved].add(component['id'])
                if resolved not in owned_paths[component['id']]:
                    component['files'].append(_evidence(row))
                    owned_paths[component['id']].add(resolved)
    def terms(component, entries, expression=None):
        recognized = set()
        for entry in entries:
            if entry is None:
                continue
            raw, proof = entry
            component['license_paths'].append(proof)
            text = raw.decode('utf-8')
            identifier = recognized_license(text)
            if identifier:
                recognized.add(identifier)
            else:
                gap('license-text-unrecognized', component['id'], path=proof['path'], sha256=proof['sha256'])
        # Exact six-license recognizer is reused without expanding policy. Other
        # retained terms are data, and require an explicit qualified term mapping.
        if expression and expression in recognized:
            component['expression'] = expression
        elif not expression and len(recognized) == 1:
            component['expression'] = next(iter(recognized))
        else:
            gap('license-term-unproved', component['id'], declared_expression=expression)
    status = files.data('var/lib/dpkg/status')
    if status:
        for package in _paragraphs(status[0]):
            if package.get('Status') != 'install ok installed':
                continue
            name, version, arch = (package.get(k) for k in ('Package', 'Version', 'Architecture'))
            if not all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9.+:~_-]+', v) for v in (name, version, arch)):
                raise oci.OCIError('Invalid installed Debian component identity')
            c = add(f'deb:{name}:{arch}@{version}', 'dpkg')
            if name.startswith('postgresql'):
                gap('unsupported-postgres-components', c['id'])
            c.update(source_package=package.get('Source', name), depends=package.get('Depends'), pre_depends=package.get('Pre-Depends'))
            c['evidence'].append(status[1])
            listing = [files.data('var/lib/dpkg/info/' + suffix + '.list') for suffix in (name, name + ':' + arch)]
            listing = [v for v in listing if v is not None]
            if len(listing) != 1:
                gap('dpkg-file-list-unproved', c['id'])
            for raw, proof in listing:
                c['evidence'].append(proof)
                own(c, raw.decode('utf-8').splitlines())
            # Maintainer scripts belong to this installed package, not to the
            # generated metadata group. Shared common texts remain references.
            own(c, [p for p in files.rows if p.startswith('var/lib/dpkg/info/') and
                    p.rsplit('/', 1)[-1].rsplit('.', 1)[0] in {name, name + ':' + arch}])
            copyright = files.data('usr/share/doc/' + name + '/copyright')
            if copyright is None:
                gap('dpkg-copyright-missing', c['id'])
                continue
            c['evidence'].append(copyright[1])
            raw = copyright[0]
            if b'copyright-format' not in raw.split(b'\n\n', 1)[0]:
                c['license_paths'].append(copyright[1])
                gap('dpkg-legacy-license-scope', c['id'])
                continue
            sections = _paragraphs(raw)
            declarations = [v for v in sections if 'License' in v]
            c['raw_license_declarations'] = declarations
            scope = [v for v in declarations if v.get('Files') == '*']
            labels = {v['License'].split('\n', 1)[0] for v in declarations}
            if len(scope) != 1 or len(labels) != 1:
                c['license_paths'].append(copyright[1])
                gap('dpkg-binary-license-scope', c['id'])
                continue
            label = scope[0]['License'].split('\n', 1)[0]
            inline = []
            for section in declarations:
                value = section['License'].partition('\n')[2]
                if value and not re.fullmatch(r'See /usr/share/common-licenses/[A-Za-z0-9_.+-]+\s*', value):
                    inline.append((value.encode(), copyright[1]))
            for reference in sorted(set(re.findall(rb'/usr/share/common-licenses/[A-Za-z0-9_.+-]+', raw))):
                entry = files.data(reference.decode().rstrip('.'))
                if entry is None:
                    gap('license-common-text-missing', c['id'], path=reference.decode())
                else:
                    inline.append(entry)
            c['license_paths'].append(copyright[1])
            terms(c, inline, label)
    # Installed Python distributions, including additions made by built recipes.
    python_roots = []
    for path in sorted(files.rows):
        if not path.endswith('.dist-info/METADATA'):
            continue
        metadata = files.data(path)
        if metadata is None:
            continue
        message = BytesParser().parsebytes(metadata[0])
        for key in ('Name', 'Version', 'License-Expression'):
            if len(message.get_all(key, [])) > 1:
                raise oci.OCIError('Duplicate installed Python metadata field')
        name, version = message.get('Name'), message.get('Version')
        if not name or not version or not re.fullmatch(r'[A-Za-z0-9_.+-]+', name) or not re.fullmatch(r'[A-Za-z0-9_.+!-]+', version):
            raise oci.OCIError('Invalid installed Python component identity')
        c = add('pypi:' + name.lower().replace('_', '-') + '@' + version, 'python')
        prefix, site = posixpath.dirname(path), posixpath.dirname(posixpath.dirname(path))
        python_roots.append((site, c))
        c['evidence'].append(metadata[1])
        c['raw_license_declarations'] = message.get_all('License-Expression', [])
        record = files.data(prefix + '/RECORD')
        if not record:
            gap('python-record-missing', c['id'])
        else:
            c['evidence'].append(record[1])
            seen = set()
            for row in csv.reader(io.StringIO(record[0].decode('utf-8'))):
                if len(row) != 3 or row[0] in seen:
                    raise oci.OCIError('Malformed or duplicate installed Python RECORD')
                seen.add(row[0])
                if row[0].startswith('/') or '\\' in row[0]:
                    raise oci.OCIError('Unsafe installed Python RECORD path')
                actual, entry = files.resolve(_safe(posixpath.join(site, row[0])))
                if entry is None:
                    continue  # Deleted cache/build records are not installed components.
                own(c, [actual])
                if entry['kind'] == 'file' and row[1]:
                    digest = base64.urlsafe_b64encode(bytes.fromhex(entry['sha256'])).rstrip(b'=').decode()
                    if row[1] != 'sha256=' + digest or row[2] != str(entry['bytes']):
                        gap('python-record-mismatch', c['id'], path=actual)
                elif entry['kind'] == 'file' and actual != prefix + '/RECORD':
                    gap('python-record-unhashed', c['id'], path=actual)
        licenses = []
        for label in message.get_all('License-File', []):
            if label.startswith('/') or '..' in label.split('/'):
                raise oci.OCIError('Unsafe installed Python license path')
            entry = files.data(prefix + '/licenses/' + label) or files.data(prefix + '/' + label)
            if entry is None:
                gap('python-license-file-missing', c['id'], path=label)
            licenses.append(entry)
        terms(c, licenses, message.get('License-Expression'))
    # pip bundles do not necessarily have separate dist-info records.
    for site, parent in python_roots:
        if not parent['id'].startswith('pypi:pip@'):
            continue
        vendor = files.data(site + '/pip/_vendor/vendor.txt')
        if not vendor:
            continue
        root = site + '/pip/_vendor/'
        for line in vendor[0].decode('utf-8').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'\s*([A-Za-z0-9_.-]+)==([^\s]+)\s*', line)
            if not match:
                gap('pip-vendor-declaration-unsupported', parent['id'])
                continue
            name, version = match.groups()
            alias = 'pkg_resources' if name.lower() == 'setuptools' else name.lower().replace('-', '_')
            c = add('pip-vendor:' + name.lower() + '@' + version, 'python-vendored')
            parent['requires'].append(c['id'])
            c['evidence'].append(vendor[1])
            paths = [p for p in files.rows if p.startswith(root + alias + '/')]
            own(c, paths)
            license_entries = [files.data(p) for p in paths if re.match(r'(?i)^(license|copying)(\.|$)', p.rsplit('/', 1)[-1])]
            if not paths:
                gap('pip-vendor-files-missing', c['id'])
            terms(c, license_entries)
    # Explicit source-built CPython group. Its umbrella text cannot prove every
    # bundled extension's terms, and static filenames do not observe target ABI.
    for path in sorted(files.rows):
        match = re.fullmatch(r'usr/local/lib/(python[0-9]+\.[0-9]+)/LICENSE.txt', path)
        if not match:
            continue
        root = 'usr/local/lib/' + match[1] + '/'
        c = add('cpython-source-built:' + match[1], 'source-built-python')
        license_entry = files.data(path)
        c['license_paths'].append(license_entry[1])
        own(c, [p for p in files.rows if not owners.get(p) and (p.startswith(root) or p.startswith('usr/local/include/' + match[1] + '/') or p.startswith('usr/local/bin/' + match[1]) or p.startswith('usr/local/lib/lib' + match[1]))])
        gap('cpython-bundled-terms-unproved', c['id'])
    if files.data('lib/apk/db/installed'):
        gap('unsupported-apk-components', 'apk')
    unknown = []
    go_files = []
    for path, row in files.rows.items():
        if row.get('elf') and row.get('go_binary'):
            go_files.append(_evidence(row))
        if row['kind'] == 'file' and path.endswith('.jar'):
            gap('unsupported-tool-bundle-components', 'java-bundles', file=_evidence(row))
        if row['kind'] != 'file' or owners.get(path):
            continue
        # Generated metadata is not an independent software component. Package
        # maintainer scripts were attributed above before this classification.
        generated = path.startswith(('var/log/', 'var/cache/', 'run/'))
        source = path.endswith(('.py', '.pyc', '.js', '.mjs', '.cjs', '.sh', '.rb', '.pl', '.jar', '.wasm'))
        if (row.get('elf') or row.get('executable') or source) and not generated:
            unknown.append(_evidence(row))
    if go_files:
        gap('unsupported-go-components', 'go-bundles', files=go_files)
    if unknown:
        gap('unattributed-software', 'final-installed-files', files=sorted(unknown, key=lambda v: v['path']))
    if not components and not unresolved:
        gap('software-catalog-empty', 'image')
    document = dict(schema_version=1, scope='final-installed-image-components', reference=image.reference,
                    platform=image.platform, manifest_digest=image.manifest_digest, config_digest=image.config_digest,
                    components=components, unresolved=unresolved, complete=not unresolved,
                    qualification='observation-only; source/run/native guard and policy join required')
    proofs = {path: row['body'] for path, row in files.rows.items() if 'body' in row}
    document['proof_bytes'] = sum(len(body) for body in proofs.values())
    return ImageComponentObservation(image, document, proofs, _PROOF)
