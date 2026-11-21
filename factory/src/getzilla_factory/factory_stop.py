"""Factory-issued stop observations; no budget, permission or bearer authority."""
from dataclasses import dataclass
import asyncio
import hashlib

from .landing_contracts import _IDENTIFIER

_ISSUER = object()


class FactoryStopError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def landing_source_id(job_id: str) -> str:
    """One versioned encoding of the actual validated ID, without alias fallback."""
    if not isinstance(job_id, str) or _IDENTIFIER.fullmatch(job_id) is None:
        raise FactoryStopError('factory_stop_binding_required')
    return 'landing:v1:' + hashlib.sha256(job_id.encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class FactoryStopSnapshot:
    task_id: str
    packet_digest: str
    repository_id: str
    actor_id: str
    actor_kind: str
    job_id: str
    input_digest: str
    content_sha256: str
    exact_base_sha: str
    exact_base_tree: str
    global_revision: int
    repository_revision: int
    stopped: bool


class FactoryStopCapability:
    """Process-local service reference. JSON and request labels cannot create it."""
    __slots__ = ('_issuer', '_initial', '_observe')

    def __new__(cls, *arguments, **keywords):
        raise TypeError('Factory-issued stop capability required')

    def __setattr__(self, name, value):
        raise AttributeError('Factory stop capability is immutable')

    def __repr__(self):
        return 'FactoryStopCapability(opaque)'

    @property
    def input_digest(self):
        return self._initial.input_digest

    @property
    def content_sha256(self):
        return self._initial.content_sha256

    def check(self, *, input_digest=None, content_sha256=None):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.check_async(input_digest=input_digest, content_sha256=content_sha256))
        raise FactoryStopError('factory_stop_sync_context')

    async def check_async(self, *, input_digest=None, content_sha256=None):
        if (self._issuer is not _ISSUER or (input_digest is not None and input_digest != self.input_digest)
                or (content_sha256 is not None and content_sha256 != self.content_sha256)):
            raise FactoryStopError('factory_stop_binding_required')
        try:
            current = await self._observe()
        except FactoryStopError:
            raise
        except Exception:
            raise FactoryStopError('factory_stop_authority_unavailable') from None
        if type(current) is not FactoryStopSnapshot or current.stopped or current != self._initial:
            raise FactoryStopError('factory_stop_changed')


def require_stop_capability(value, *, input_digest=None):
    if type(value) is not FactoryStopCapability or getattr(value, '_issuer', None) is not _ISSUER:
        raise FactoryStopError('factory_stop_binding_required')
    value.check(input_digest=input_digest)
    return value


async def require_stop_capability_async(value, *, input_digest=None):
    if type(value) is not FactoryStopCapability or getattr(value, '_issuer', None) is not _ISSUER:
        raise FactoryStopError('factory_stop_binding_required')
    await value.check_async(input_digest=input_digest)
    return value


def require_factory_service(service):
    from .service import FactoryService
    from .store import PostgresFactoryStore
    if not isinstance(service, FactoryService) or not isinstance(service.store, PostgresFactoryStore):
        raise FactoryStopError('factory_stop_binding_required')
    return service


def _issue_factory_capability(service, source, actor, landing_store):
    # Only the actual server service/store boundary issues this process-local
    # reference. It never accepts a request's claimed tenant/repo as its issuer.
    require_factory_service(service)
    from .landing_sqlite_store import SQLiteLandingJobStore
    if not isinstance(landing_store, SQLiteLandingJobStore):
        raise FactoryStopError('factory_stop_binding_required')
    service._check_landing_stop_actor(source, actor)
    async def observe():
        before = landing_store.observe_job(actor.actor_id, source.repository_id, source.job_id)
        if before.source != source or before.state not in {'accepted', 'normalizing'}:
            raise FactoryStopError('factory_stop_changed')
        snapshot = await service._landing_stop_snapshot(before.source, actor)
        after = landing_store.observe_job(actor.actor_id, source.repository_id, source.job_id)
        if after != before:
            raise FactoryStopError('factory_stop_changed')
        return snapshot
    try:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            initial = asyncio.run(observe())
        else:
            raise FactoryStopError('factory_stop_sync_context')
    except FactoryStopError:
        raise
    except Exception:
        raise FactoryStopError('factory_stop_authority_unavailable') from None
    if type(initial) is not FactoryStopSnapshot or initial.stopped:
        raise FactoryStopError('factory_stop_changed')
    result = object.__new__(FactoryStopCapability)
    for name, value in (('_issuer', _ISSUER), ('_initial', initial), ('_observe', observe)):
        object.__setattr__(result, name, value)
    return result
