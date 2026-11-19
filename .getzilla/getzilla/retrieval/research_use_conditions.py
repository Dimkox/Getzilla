"""Exact current held source-use conditions for one private public research study.

This grants neither execution nor Phase A/B. Native imports additionally need
the owner's operation and actual supervisor resource. Model/image pins are
requirements for that supervisor, not multi-GB supplemental-license proofs.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time
from types import MappingProxyType
import zipfile
import io

from .. import fsx, state
from ..continuity import context_binding
from ..optional_modules import admit_module
from ..security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_ARCHIVE_BYTES,
    MAX_INDEX_BYTES, MAX_MEMBERS, archive_files, package_metadata,
    safe_parts, verify_origin)
from ..security_license_contracts import load_policy
from ..security_license_exceptions import condition_profile, verify_exception
from ..security_research_catalog import (PROFILE, MANIFEST_PATH, MANIFEST_SHA256,
    CATALOG_SHA256, load_catalog, image_conditions)
from ..trace_storage import native_root
from ..util import tree_fingerprint
from .contracts import digest
from .evaluation_inputs_io import _json

_ISSUER = object()
REGISTRATION_FIELDS = frozenset({'schema_version', 'kind', 'artifact_root', 'model_root',
                                'terms_root', 'software_root'})
PREPARATION_STATES = frozenset({'archive-custody-source-use-admitted', 'extracted-software-held'})
_STATE_ARCHIVES, _STATE_SOFTWARE = sorted(PREPARATION_STATES)
MAX_SOURCE_TERMS = 32 * 1024 * 1024
MAX_SOFTWARE_FILES = 4000
MAX_SECONDS = 180


def _fail(message='exact current private research source-use conditions are unavailable'):
    raise ArtifactError('research-conditions-unavailable', message)


def _identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns'))


def _owned(info, directory=False):
    if (not hasattr(os, 'geteuid') or info.st_uid != os.geteuid() or info.st_mode & 0o022
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or not directory and info.st_nlink != 1):
        _fail('research evidence must be owned, regular and non-writable by other users')


class _HeldTerms:
    """One real supplemental proof: original four-file/262144 limits unchanged."""
    def __init__(self, root, requirements):
        if (type(requirements) is not dict or not 0 < len(requirements) <= 4
                or any(type(v) not in {tuple, list} or len(v) != 2
                       or type(v[1]) is not int or v[1] <= 0 for v in requirements.values())
                or sum(value[1] for value in requirements.values()) > 262144):
            _fail('supplemental proof exceeds original limits')
        self.root, self.requirements = Path(root), requirements
        self.stack, self.rows = ExitStack(), {}

    def __enter__(self):
        try:
            self.anchor = self.stack.enter_context(fsx.ReadOnlyBoundRoot(self.root))
            _owned(self.root.lstat(), True)
            for path, (expected, size) in self.requirements.items():
                safe_parts(path)
                for n in range(1, len(Path(path).parts)):
                    directory = '/'.join(Path(path).parts[:n]) + '/__custody__'
                    ancestor, _, current = self.stack.enter_context(self.anchor.parent(directory))
                    _owned(fsx.fstat_dir(ancestor), True)
                    self.rows['@' + directory] = (ancestor, current)
                parent, name, check = self.stack.enter_context(self.anchor.parent(path))
                _owned(fsx.fstat_dir(parent), True)
                info = fsx.lstat_at(parent, name)
                _owned(info)
                fd = fsx.open_at(parent, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
                self.stack.callback(os.close, fd)
                if info.st_size != size or _identity(os.fstat(fd)) != _identity(info):
                    _fail('supplemental term identity changed')
                self.rows[path] = fd, parent, name, check, _identity(info), expected, size
            return self
        except (OSError, fsx.ComponentStateError) as error:
            self.stack.close()
            raise ArtifactError('research-conditions-unavailable', 'supplemental term custody unavailable') from error
        except BaseException:
            self.stack.close()
            raise

    def check(self):
        _owned(self.root.lstat(), True)
        for path, row in self.rows.items():
            if path.startswith('@'):
                handle, current = row
                current()
                _owned(fsx.fstat_dir(handle), True)
                continue
            fd, parent, name, check, expected, _, _ = row
            check()
            _owned(fsx.fstat_dir(parent), True)
            if _identity(os.fstat(fd)) != expected or _identity(fsx.lstat_at(parent, name)) != expected:
                _fail('supplemental term custody changed')

    def observe(self):
        self.check()
        values = {}
        for path, row in self.rows.items():
            if path.startswith('@'):
                continue
            fd, _, _, _, _, expected, size = row
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, size + 1)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != expected:
                _fail('complete supplemental term bytes changed')
            raw.decode('utf-8', 'strict')
            values[path] = raw
        self.check()
        return values

    def __exit__(self, *args):
        self.stack.close()


@dataclass(frozen=True)
class _Composition:
    profile: str
    manifest_path: str
    manifest_sha256: str
    catalog_sha256: str
    catalog: object
    fixture_profiles: object = None
    fixture_policy: object = None


_PRODUCTION = _Composition(PROFILE, MANIFEST_PATH, MANIFEST_SHA256, CATALOG_SHA256, load_catalog)


class ResearchUseConditionsRef:
    __slots__ = ('_issuer', '_capture', '_projection', '_composition')
    def __new__(cls, *args, **kwargs):
        raise TypeError('actual current held research source-use observation required')
    def __setattr__(self, name, value):
        raise AttributeError('research source-use reference is immutable')
    def __reduce__(self):
        raise TypeError('research source-use reference cannot be serialized')


class _UseCapture:
    def __init__(self, root):
        self.root = Path(os.path.abspath(root))
        self.dependencies = {}
        self.stack = ExitStack()
        self.root_handle = self.stack.enter_context(fsx.ReadOnlyBoundRoot(self.root))
        self.directory_handles = []
        self.pid, self.uid = os.getpid(), os.getuid()
        self.preparing, self.closed, self.software = True, False, None
        self.deadline = time.monotonic() + MAX_SECONDS
        try:
            with native_root(self.root) as anchor:
                self.identity = anchor.identity
                self.route = state.require_route_owner(self.root, anchor=anchor)
                self.context = context_binding(self.root, self.route, anchor=anchor)
                self.source = anchor.git_source()
            self.fingerprint = tree_fingerprint(self.root)
        except BaseException:
            self.stack.close()
            raise

    def current(self):
        if self.closed or os.getpid() != self.pid or os.getuid() != self.uid:
            _fail('research source-use held resource expired')
        if self.preparing and time.monotonic() >= self.deadline:
            _fail('research preparation deadline exceeded')
        self.root_handle.check()
        for handle in self.directory_handles:
            handle.check()
            _owned(fsx.fstat_dir(handle.handle), True)
        with native_root(self.root) as anchor:
            route = state.require_route_owner(self.root, anchor=anchor)
            if (anchor.identity != self.identity or route['logical_task_id'] != self.route['logical_task_id']
                    or context_binding(self.root, route, anchor=anchor) != self.context
                    or anchor.git_source() != self.source
                    or tree_fingerprint(self.root) != self.fingerprint
                    or not admit_module(self.root, 'retrieval-research').get('allowed')):
                _fail('research source-use owner/source/policy changed')

    def path(self, relative):
        safe_parts(relative)
        if not relative.startswith('.getzilla/runtime/'):
            _fail('research preparation roots must stay in the current owned runtime')
        return self.root / relative

    def read(self, relative, limit, *, expected=None, source=False):
        if not source:
            self.path(relative)
        with native_root(self.root) as anchor:
            # Hash-pinned public artifacts may be immutable0400. Registration
            # JSON remains the native private0600 record, never a source permit.
            private = expected is None
            with anchor.file(relative, source=source, private=private, limit=limit) as (fd, _):
                before = os.fstat(fd)
                _owned(before)
                raw = bytearray()
                while True:
                    if time.monotonic() >= self.deadline:
                        _fail('research preparation deadline exceeded')
                    block = os.read(fd, min(65536, limit + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
                    if len(raw) > limit:
                        _fail('research artifact bytes exceeded')
                if _identity(os.fstat(fd)) != _identity(before):
                    _fail('research evidence changed')
                raw = bytes(raw)
                if expected is not None and (len(raw), hashlib.sha256(raw).hexdigest()) != expected:
                    _fail('research artifact/term bytes differ from fixed catalog')
                self.dependencies[relative] = source, private, _identity(before)
                return raw

    def check_files(self):
        self.current()
        for path, (source, private, identity) in self.dependencies.items():
            with native_root(self.root) as anchor:
                with anchor.file(path, source=source, private=private, limit=identity[2]) as (fd, _):
                    if _identity(os.fstat(fd)) != identity:
                        _fail('research held evidence changed')
        if self.software is not None:
            self.software.check()

    def hold_directory(self, path):
        handle = self.stack.enter_context(fsx.ReadOnlyBoundRoot(path))
        _owned(fsx.fstat_dir(handle.handle), True)
        if stat.S_IMODE(fsx.fstat_dir(handle.handle).st_mode) != 0o700:
            _fail('original research evidence root must remain private0700')
        self.directory_handles.append(handle)

    def close(self):
        self.closed = True
        self.stack.close()


class _SoftwareCut:
    """One exact existing archive-derived software tree, never an import."""
    def __init__(self, root, expected):
        if (type(expected) is not dict or not expected or len(expected) > MAX_SOFTWARE_FILES
                or sum(v[0] for v in expected.values()) > MAX_ARCHIVE_BYTES):
            _fail('fixed software tree bounds exceeded')
        self.root, self.expected = Path(root), expected
        self.expected_directories = {''}
        for path in expected:
            parts = safe_parts(path)
            self.expected_directories.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        self.anchor = fsx.ReadOnlyBoundRoot(self.root)
        try:
            self.identities = self._walk(hash_bodies=True)
        except BaseException:
            self.anchor.close()
            raise

    def _walk(self, *, hash_bodies=False):
        result, directories, entries = {}, {}, 0
        self.anchor.check()
        def visit(handle, prefix):
            nonlocal entries
            _owned(fsx.fstat_dir(handle), True)
            directories[prefix] = _identity(fsx.fstat_dir(handle))
            for name in fsx.listdir(handle):
                entries += 1
                if entries > 8192:
                    _fail('software entry bound exceeded')
                path = prefix + name
                safe_parts(path)
                info = fsx.lstat_at(handle, name)
                if fsx.is_link(info):
                    _fail('software links are not admitted')
                if stat.S_ISDIR(info.st_mode):
                    if path not in self.expected_directories:
                        _fail('unexpected software directory')
                    child = fsx.open_dir_at(handle, name, flags=fsx.O_CLOEXEC)
                    try:
                        before = _identity(info)
                        visit(child, path + '/')
                        if _identity(fsx.lstat_at(handle, name)) != before:
                            _fail('software directory changed')
                    finally:
                        fsx.close_dir(child)
                    continue
                _owned(info)
                if path not in self.expected or info.st_size != self.expected[path][0]:
                    _fail('unexpected or changed software member')
                result[path] = _identity(info)
                if hash_bodies:
                    fd = fsx.open_at(handle, name, os.O_RDONLY | fsx.O_NOFOLLOW | fsx.O_NONBLOCK | fsx.O_CLOEXEC)
                    try:
                        before = _identity(os.fstat(fd))
                        h, total = hashlib.sha256(), 0
                        while block := os.read(fd, 65536):
                            total += len(block)
                            if total > self.expected[path][0]:
                                _fail('software member grew')
                            h.update(block)
                        if (before != result[path] or _identity(os.fstat(fd)) != before
                                or total != self.expected[path][0] or h.hexdigest() != self.expected[path][1]):
                            _fail('software member hash/custody changed')
                    finally:
                        os.close(fd)
        visit(self.anchor.handle, '')
        self.anchor.check()
        if set(result) != set(self.expected):
            _fail('software closure missing members')
        return {'files': result, 'directories': directories}

    def check(self):
        if self._walk() != self.identities:
            _fail('software current custody changed')

    def close(self):
        self.anchor.close()


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(_freeze(v) for v in value)
    return value


class _Supplement:
    def __init__(self, capture, subject, requirements, terms_root):
        if type(capture) is not _UseCapture:
            _fail('supplemental proof requires actual current owned source custody')
        self.issuer, self.capture = _ISSUER, capture
        self.subject, self.requirements = subject, requirements
        self.terms_root = terms_root


def validate_research_supplement(proof, subject, requirements):
    if (type(proof) is not _Supplement or proof.issuer is not _ISSUER
            or proof.subject != subject or proof.requirements != requirements):
        _fail('caller declarations cannot prove research supplemental custody')
    proof.capture.check_files()
    with _HeldTerms(proof.terms_root, requirements) as held:
        held.observe()
    return {'members': {p: {'sha256': v[0], 'bytes': v[1]} for p, v in requirements.items()},
            'custody': {'source_sha256': digest(proof.capture.source),
                        'run_sha256': digest(proof.capture.context),
                        'subject_sha256': digest(subject), 'image': 'private-research-held-source-use'}}


def required_public_research_layout(root):
    catalog = load_catalog()
    from ..security_artifacts import read_file
    # This is the installed/source project declaration, not model execution.
    raw = read_file(Path(root), MANIFEST_PATH, 262144)
    if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        _fail('fixed research manifest changed')
    manifest = _json(raw)
    return {'profile': PROFILE, 'manifest': MANIFEST_PATH,
            'archives': tuple((w['filename'], w['bytes'], w['sha256']) for w in catalog['wheels']),
            'indices': tuple(('indices/' + w['index_filename'], w['index_bytes'], w['index_sha256']) for w in catalog['wheels']),
            'models': tuple((key + '/' + a['path'], a['bytes'], a['sha256'])
                            for key, model in catalog['models'].items() for a in model['assets']
                            if a['runtime_referenced']),
            'terms': tuple((path, row['bytes'], row['sha256'])
                           for path, row in catalog['retained_source_terms'].items()),
            'codec': ('codec/o200k_base.tiktoken', manifest['codec']['bytes'], manifest['codec']['sha256']),
            'models_facts': fixed_public_research_model_facts()}


def fixed_public_research_model_facts():
    """Frozen expected publisher/metadata facts, never evidence of native use."""
    return tuple(_freeze({'model_key': key, **value})
                 for key, value in load_catalog()['models'].items())


def require_public_research_use(root, registration_path):
    if os.name != 'posix':
        _fail('the fixed research custody profile is unavailable on this controller platform')
    return _require_public_research_use(root, registration_path, _PRODUCTION)


def _require_public_research_use(root, registration_path, composition):
    capture = _UseCapture(root)
    try:
        return _build_public_research_use(capture, registration_path, composition)
    except BaseException:
        capture.close()
        raise


def _build_public_research_use(capture, registration_path, composition):
    if composition is not _PRODUCTION and composition.profile == PROFILE:
        _fail('private fixtures cannot claim the production research profile')
    capture.current()
    registration = _json(capture.read(registration_path, 65536))
    if (type(registration) is not dict or set(registration) != REGISTRATION_FIELDS
            or type(registration['schema_version']) is not int or registration['schema_version'] != 1
            or registration['kind'] != 'public-research162-use/v1'):
        _fail('closed research source-use registration required')
    roots = {key: capture.path(registration[key]) for key in ('artifact_root', 'model_root', 'terms_root')}
    for path in roots.values():
        capture.hold_directory(path)
    catalog = composition.catalog()
    manifest = capture.read(composition.manifest_path, 262144, source=True)
    if hashlib.sha256(manifest).hexdigest() != composition.manifest_sha256:
        _fail('research runtime manifest changed')
    manifest_document = _json(manifest)
    image_source = None
    if composition is _PRODUCTION:
        image_source = image_conditions()
        if image_source['subject'] != manifest_document['image']:
            _fail('image source conditions belong to a different image')
    if composition.fixture_policy is None:
        capture.read('.getzilla/config/license-policy.json', 65536, source=True)
        policy = load_policy(capture.root)
    else:
        policy = dict(composition.fixture_policy)
    if policy.get('error') or policy['project_repository'] != 'github.com/Dimkox/Getzilla':
        _fail('research source-use belongs to a different project')
    expected_entries = catalog['dependency_exceptions']
    if (composition.fixture_profiles is None
            and any(entry not in policy.get('dependency_exceptions', []) for entry in expected_entries)):
        _fail('exact research manifest/use/target decisions missing')
    required_terms = catalog['retained_source_terms']
    total = 0
    for path, pin in required_terms.items():
        total += pin['bytes']
        if total > MAX_SOURCE_TERMS:
            _fail('retained source term inventory exceeds existing public source bounds')
        capture.read(registration['terms_root'] + '/' + path, pin['bytes'], expected=(pin['bytes'], pin['sha256']))
    if image_source is not None:
        for component in image_source['packages']:
            for notice in component['notices']:
                if required_terms.get(notice['retained_key']) != {k: notice[k] for k in ('bytes', 'sha256')}:
                    _fail('image source notice is not part of current retained custody')
        for notice in image_source['python_terms']:
            if required_terms.get(notice['retained_key']) != {k: notice[k] for k in ('bytes', 'sha256')}:
                _fail('Python source notice is not part of current retained custody')
    extracted = {}
    for wheel, entry in zip(catalog['wheels'], expected_entries):
        payload = capture.read(registration['artifact_root'] + '/' + wheel['filename'], MAX_ARTIFACT_BYTES,
                               expected=(wheel['bytes'], wheel['sha256']))
        index = capture.read(registration['artifact_root'] + '/indices/' + wheel['index_filename'], MAX_INDEX_BYTES,
                             expected=(wheel['index_bytes'], wheel['index_sha256']))
        record = {**wheel, 'ecosystem': 'PyPI', 'origin': {'index_url': wheel['index_url'],
                  'artifact_url': wheel['url'], 'index_sha256': wheel['index_sha256']}}
        verify_origin(capture.root, record, payload, index_bytes=index)
        profile = (condition_profile(entry['condition_profile']) if composition.fixture_profiles is None
                   else composition.fixture_profiles[entry['condition_profile']])
        requested = {p for group in ('terms', 'notices', 'unchanged', 'metadata') for p in profile[group]}
        files = archive_files(payload, wheel['filename'], requested=requested)
        metadata = package_metadata(files, 'PyPI', wheel['filename'])
        subject = entry['subject']
        dep = {k: subject[k] for k in ('ecosystem', 'name', 'version', 'manifest', 'usage')}
        scope = {k: subject[k] for k in ('manifest_sha256', 'profile', 'abi', 'delivery_kind')}
        supplement = _Supplement(capture, subject, profile['supplements'], roots['terms_root']) if profile['supplements'] else None
        if composition.fixture_profiles is None:
            verify_exception(policy, dep, record, files, metadata, 'internal', scope, supplements=supplement)
        else:
            from ..security_license_exceptions import _verify_profile
            actual = {**dep, **scope, 'distribution': 'internal', 'artifact_sha256': record['sha256'],
                      'filename': record['filename'], 'artifact_url': record['origin']['artifact_url']}
            if actual != subject or subject['manifest_sha256'] != composition.manifest_sha256:
                _fail('test source composition subject changed')
            _verify_profile(entry, profile, files, metadata, supplements=supplement)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            if len(archive.infolist()) > MAX_MEMBERS:
                _fail('wheel member count exceeded')
            for item in archive.infolist():
                if item.is_dir():
                    continue
                safe_parts(item.filename)
                if item.file_size > MAX_ARCHIVE_BYTES or item.flag_bits & 1 or stat.S_ISLNK(item.external_attr >> 16):
                    _fail('unsafe research software member')
                body = archive.read(item)
                value = len(body), hashlib.sha256(body).hexdigest()
                if item.filename in extracted and extracted[item.filename] != value:
                    _fail('conflicting research software member')
                extracted[item.filename] = value
    if len(extracted) > MAX_SOFTWARE_FILES or sum(x[0] for x in extracted.values()) > MAX_ARCHIVE_BYTES:
        _fail('research software closure exceeds fixed extraction bounds')
    software_root = None
    if registration['software_root'] is not None:
        software_root = capture.path(registration['software_root'])
        capture.software = _SoftwareCut(software_root, extracted)
        capture.stack.callback(capture.software.close)
    capture.check_files()
    capture.preparing = False
    model_files = tuple((key + '/' + a['path'], a['bytes'], a['sha256'])
        for key, model in catalog['models'].items() for a in model['assets'] if a['runtime_referenced'])
    codec = manifest_document['codec']
    model_files += (('codec/o200k_base.tiktoken', codec['bytes'], codec['sha256']),)
    projection = MappingProxyType({'root': capture.root, 'conditions_sha256': composition.catalog_sha256,
        'artifact_manifest_sha256': composition.manifest_sha256, 'profile_sha256': digest(composition.profile),
        'profile': composition.profile, 'model_root': roots['model_root'], 'software_root': software_root,
        'artifact_root': roots['artifact_root'], 'terms_root': roots['terms_root'],
        'retained_source_terms': tuple((path, row['bytes'], row['sha256']) for path, row in required_terms.items()),
        'artifact_files': model_files, 'model_files': model_files,
        'archive_files': tuple((w['filename'], w['bytes'], w['sha256']) for w in catalog['wheels']),
        'software_files': tuple((p, size, sha) for p, (size, sha) in sorted(extracted.items())) if software_root else (),
        'preparation_state': _STATE_SOFTWARE if software_root else _STATE_ARCHIVES,
        'context_digest': digest(capture.context), 'source_binding': MappingProxyType(capture.source),
        'artifact_integrity': 'model-and-image-pins-required-by-owned-supervisor',
        'source_use': 'private-unmodified-no-conveyance',
        'source_use_assurance': 'exact-original-metadata-grants-and-current-held-custody',
        'image_source_use': 'retained-private-use-source-notices-not-complete-native-admission',
        'models': tuple((key, _freeze(value)) for key, value in catalog['models'].items()),
        'codec': _freeze(codec), 'image': _freeze(manifest_document['image']),
        'image_files': tuple(('blobs/sha256/' + row['digest'].split(':')[1], row['size'], row['digest'].split(':')[1])
                             for row in [manifest_document['image']['config'], *manifest_document['image']['layers']]),
        'native_sdk_closure_complete': False, 'cryptographic_compilation_verified': False})
    result = object.__new__(ResearchUseConditionsRef)
    for key, value in {'_issuer': _ISSUER, '_capture': capture, '_projection': projection,
                       '_composition': composition}.items():
        object.__setattr__(result, key, value)
    return result


def check_public_research_use(reference):
    return _check_public_research_use(reference, _PRODUCTION)


def _check_public_research_use(reference, composition):
    if type(reference) is not ResearchUseConditionsRef:
        _fail('current actual research source-use reference required')
    try:
        if reference._issuer is not _ISSUER or reference._composition is not composition:
            _fail('current actual research source-use reference required')
    except AttributeError:
        _fail('current actual research source-use reference required')
    if composition is _PRODUCTION:
        load_catalog()
        image_conditions()
    reference._capture.check_files()
    return reference._projection


def close_public_research_use(reference):
    if type(reference) is not ResearchUseConditionsRef or reference._issuer is not _ISSUER:
        _fail('actual held source-use reference required')
    reference._capture.close()
