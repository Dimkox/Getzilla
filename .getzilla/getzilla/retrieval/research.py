"""Fixed public-corpus source cuts. No model, ranking or review authority.

The local task owner admits public byte capture only. Native independent-review
publication and model resource admission remain separate and unavailable here.
"""
from contextlib import ExitStack, contextmanager
import os
import tempfile
from pathlib import Path
import time

from .. import native_access as access, state
from ..component_state import BoundRoot
from ..optional_modules import admit_module
from ..trace_storage import native_root
from .budget import RetrievalError
from .contracts import digest, sha
from .evaluation_inputs import checked_relative
from .evaluation_inputs_io import _json

PUBLIC_LIMITS = (4000, 32 * 1024 * 1024, 1048576)
BATCH_FILES = 128  # Existing Core cap; the fixed148-file corpus needs two fresh cuts.
CATALOGS = (
    ('small', '096c8d42545d3b68ea21a4f890fb2b2d8979c0bd',
     'c7728dd6d7d25f9b623def3afa301957ac4a9558dfaf200c2fa70084653206f8'),
    ('large', '8352756ccddbb7b9f13da2da689ef633d968e30f',
     '360a69ea25e36ef6ac4f47d0fe6f4d4c959b072a1f3b6be4cd9317f08778b447'))


def _identity(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid', 'st_nlink'))


def _catalog(anchor, catalogs=CATALOGS):
    rows, identities = [], []
    for corpus, commit, expected in catalogs:
        path = 'engineering/benchmarks/issue162/data/' + corpus + '-manifest.json'
        raw = anchor.read(path, limit=1048576, source=True)
        if sha(raw) != expected:
            raise RetrievalError('public_catalog_changed')
        document = _json(raw)
        if document.get('corpus') != corpus or document.get('commit') != commit:
            raise RetrievalError('public_catalog_changed')
        identities.append((path, expected))
        for row in document['files']:
            if row['candidate'] is True:
                path = corpus + '/' + checked_relative(row['path'])
                if type(row['bytes']) is not int or not 0 <= row['bytes'] <= PUBLIC_LIMITS[2]:
                    raise RetrievalError('source_file_exceeded')
                rows.append((path, row['bytes'], row['sha256'], commit))
    if len(rows) > PUBLIC_LIMITS[0] or sum(row[1] for row in rows) > PUBLIC_LIMITS[1]:
        raise RetrievalError('source_inventory_exceeded')
    if len({row[0] for row in rows}) != len(rows):
        raise RetrievalError('duplicate_source')
    return tuple(rows), tuple(identities)


class _PublicHost(access.NativeAccessHost):
    """Created only by the fixed local composition, never selected from JSON."""
    def __init__(self, root, anchor, sources, rows, identities, batch, resources, staged, review_fence=None):
        self.root, self.anchor, self.sources = root, anchor, sources
        if review_fence is not None:
            from .public_review_witness import _WitnessSourceFence
            if type(review_fence) is not _WitnessSourceFence:
                raise access.NativeAccessError('native_access_denied')
        self.review_fence = review_fence
        self.route = state.require_route_owner(root, anchor=anchor)
        self.policy = anchor.read('.getzilla/config/policy.json', source=True)
        self.manifest = anchor.read('.getzilla/managed-components.json', source=True)
        from .policy_inputs import validate_policy
        validate_policy(self.policy)
        self.rows, self.identities, self.batch = rows, identities, batch
        self.dataset = digest(rows)
        self.request, self.workflow, self.binding = object(), object(), object()
        self.observed = []
        self.resources, self.staged, self.held = resources, staged, []

    def bind_native_request(self, request, workflow, deadline):
        if request is not self.request or workflow is not self.workflow:
            raise access.NativeAccessError('native_access_denied')
        self.check_current(self.binding, deadline)
        return self.binding

    def check_current(self, binding, deadline):
        if binding is not self.binding or time.monotonic() >= deadline:
            raise access.NativeAccessError('native_access_expired')
        if self.review_fence is not None:
            self.review_fence.check_current(deadline)
        self.anchor.check_cwd()
        if (state.require_route_owner(self.root, anchor=self.anchor) != self.route
                or self.anchor.read('.getzilla/config/policy.json', source=True) != self.policy
                or self.anchor.read('.getzilla/managed-components.json', source=True) != self.manifest
                or not admit_module(self.root, 'retrieval-research').get('allowed')):
            raise access.NativeAccessError('native_access_stale')
        for path, expected in self.identities:
            if sha(self.anchor.read(path, source=True)) != expected:
                raise access.NativeAccessError('native_access_stale')
        for path, observed in self.observed:
            if self.sources.read(path, limit=PUBLIC_LIMITS[2]) != observed:
                raise access.NativeAccessError('native_access_stale')
        for descriptor, expected in self.held:
            if _identity(os.fstat(descriptor)) != expected:
                raise access.NativeAccessError('native_access_stale')
        self.sources.check()
        return access.AuthorityStamp(1, digest([sha(self.policy), sha(self.manifest)]),
                                     digest([self.route, self.dataset]))

    def load_authorized_cut(self, binding, query, deadline):
        self.check_current(binding, deadline)
        if query != self.query:
            raise access.NativeAccessError('native_access_denied')
        documents, total = [], 0
        for path, size, expected, commit in self.rows[self.batch * BATCH_FILES:(self.batch + 1) * BATCH_FILES]:
            if time.monotonic() >= deadline:
                raise access.NativeAccessError('native_access_expired')
            observed = self.sources.read(path, limit=PUBLIC_LIMITS[2])
            if observed is None or len(observed.content) != size or sha(observed.content) != expected:
                raise access.NativeAccessError('native_access_stale')
            total += size
            if total > access.MAX_CUT_BYTES:
                raise access.NativeAccessError('native_access_denied')
            self.observed.append((path, observed))
            staged = self.staged / str(len(self.held))
            with staged.open('xb') as output:
                output.write(observed.content)
            staged.chmod(0o600)
            relative = staged.relative_to(self.root).as_posix()
            descriptor, _ = self.resources.enter_context(self.anchor.file(relative, limit=PUBLIC_LIMITS[2]))
            expected_stat = _identity(os.fstat(descriptor))
            captured = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise access.NativeAccessError('native_access_expired')
                block = os.read(descriptor, 65536)
                if not block:
                    break
                captured.extend(block)
            if bytes(captured) != observed.content or _identity(os.fstat(descriptor)) != expected_stat:
                raise access.NativeAccessError('native_access_stale')
            self.held.append((descriptor, expected_stat))
            key = ('os-' + str(os.getuid()), self.anchor.binding['repository_digest'],
                   'public-research', commit, sha(path.encode()))
            documents.append(access.SourceDocument(access.SourceDependency(key, 'sha256:' + expected,
                expected, expected, 'exact-public-original-v1'), observed.content))
        self.check_current(binding, deadline)
        return access.CapturedRead(tuple(documents), self)

    def prepare_owned_response(self, binding, captured, computation, response, deadline):
        # Public source custody is not independent review or model/sink admission.
        raise access.NativeAccessError('native_access_unavailable')

    def admit_response(self, binding, prepared, deadline):
        raise access.NativeAccessError('native_access_unavailable')


@contextmanager
def _public_source_cut(root, public_sources, *, batch, review_fence=None, catalogs=CATALOGS):
    """Capture one exact batch for trusted local use; never authorizes an encoder.

    The caller must keep this context open. A new batch obtains a fresh current
    two-second source cut. No index/model lease or output admission is issued.
    """
    if type(batch) is not int or batch < 0:
        raise RetrievalError('invalid_public_batch')
    with ExitStack() as resources:
        anchor = resources.enter_context(native_root(root))
        state.require_route_owner(root, anchor=anchor)
        if not admit_module(root, 'retrieval-research').get('allowed'):
            raise RetrievalError('context_disabled')
        rows, identities = _catalog(anchor, catalogs)
        if batch * BATCH_FILES >= len(rows):
            raise RetrievalError('invalid_public_batch')
        sources = resources.enter_context(BoundRoot(Path(public_sources)))
        temporary = resources.enter_context(tempfile.TemporaryDirectory(
            prefix='public-research-', dir=Path(root) / '.getzilla/runtime'))
        staged = Path(temporary)
        staged.chmod(0o700)
        host = _PublicHost(root, anchor, sources, rows, identities, batch, resources, staged, review_fence)
        host.query = access.RegisteredQuery('public-research-source/v1', (host.dataset,), {'batch': batch})
        broker = access.NativeAccessBroker._compose(host)
        handle = broker.bind_native_request(host.request, host.workflow)
        try:
            cut = broker.load_authorized_cut(handle, host.query, absolute_deadline=time.monotonic() + 2)
            yield broker, handle, cut
        finally:
            broker.discard(handle)


@contextmanager
def public_source_cut(root, public_sources, *, batch):
    """Fixed public source facts without a review or execution grant."""
    with _public_source_cut(root, public_sources, batch=batch) as result:
        yield result
