"""Opt-in single-owner control. A compatibility document is never paid authority."""
from dataclasses import dataclass

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .access_authority import AccessAuthority, AccessError
from .landing_contracts import LandingInputV1, LandingContractError, landing_digest, strict_json_object
from .landing_provider import LandingProviderError
from .landing_server import OwnedLandingRuntime
from .landing_service import LandingServiceError
from .paid_admission import PaidExecutionAdmission, SHARED_DISPATCH_GUARD, _authority
from .shared_landing_contracts import SharedControlBindingV1, MAX_SHARED_INPUT_BYTES, MAX_SHARED_REQUEST_BYTES, BoundSharedCredentialLoader


@dataclass(frozen=True)
class SharedLandingTask:
    actor_id: str
    admission: PaidExecutionAdmission
    service: object
    source: dict
    source_version: str
    control_task_id: str
    expected_source: LandingInputV1
    credential_digest: str


class SharedAuthorityControl:
    """Server configuration only. Neither requests nor capabilities install tasks."""
    def __init__(self, owned, authenticator, tasks):
        if (type(owned) is not OwnedLandingRuntime or owned.store is None
            or type(authenticator.access_authority) is not AccessAuthority
            or type(tasks) is not tuple or not 1 <= len(tasks) <= 25):
            raise ValueError('shared owner configuration required')
        self.owned, self.authenticator = owned, authenticator
        self.tasks = {}
        for task in tasks:
            if type(task) is not SharedLandingTask or type(task.admission) is not PaidExecutionAdmission:
                raise ValueError('shared paid authority required')
            service, admission = task.service, task.admission
            executor = getattr(service._provider, '_executor', None)
            if (service._store is not owned.store or admission.store is not owned.store
                or getattr(executor, '_admission', None) is not admission
                or service._factory_service is None):
                raise ValueError('shared executor owner mismatch')
            from .factory_stop import require_factory_service
            require_factory_service(service._factory_service)
            if type(task.expected_source) is not LandingInputV1 or task.expected_source.tenant_id != task.actor_id:
                raise ValueError('shared source configuration required')
            loader = executor._credential_loader
            if type(loader) is BoundSharedCredentialLoader:
                if loader.digest != task.credential_digest:
                    raise ValueError('shared credential configuration conflict')
            else:
                executor._credential_loader = BoundSharedCredentialLoader(loader,task.credential_digest)
            key = (task.actor_id, task.control_task_id, service._profile_digest)
            if key in self.tasks:
                raise ValueError('duplicate shared task')
            # Copy source configuration: mutable caller maps cannot change policy.
            self.tasks[key] = SharedLandingTask(task.actor_id,admission,service,dict(task.source),task.source_version,task.control_task_id,task.expected_source,task.credential_digest)

    def _session(self, authorization):
        session = self.authenticator.access_session(authorization,'landing:submit')
        self.authenticator.authenticate(authorization,'landing:read')
        return session

    def _check(self, installed, session, repository, head, tree, *, input_digest=None, provider=None, model=None):
        authority = self.authenticator.access_authority
        try:
            actor = authority.actor(session)
        except AccessError:
            raise HTTPException(403,'shared access revoked') from None
        if (actor.actor_id != installed.actor_id or not {'landing:submit','landing:read'} <= actor.scopes
            or repository not in actor.repositories and '*' not in actor.repositories
            or not authority.authorize(session,installed.source,installed.source_version,'source:read')):
            raise HTTPException(403,'shared source denied')
        admission = installed.admission
        self.owned.store.authority_time()
        with self.owned.store._transaction():
            account, task, _ = _authority(self.owned.store,admission.account_id,admission.task_id)
            if (account.tenant_id != session._tenant or account.owner_id != session._principal
                or task.repository_id != repository or task.source_head != head or task.source_tree != tree
                or task.input_digest != installed.expected_source.input_digest
                or task.source_identity != admission.source_identity or task.credential_ref != admission.credential_ref
                or input_digest is not None and task.input_digest != input_digest
                or provider is not None and [provider,model,'paid-inference'] not in [list(v) for v in task.scope]):
                raise HTTPException(403,'shared task denied')
        installed.service._provider._executor._credential_loader()
        preflight = installed.service._provider._source_preflight
        if not callable(preflight):
            raise HTTPException(503,'shared source unavailable')
        try:
            preflight()
        except Exception:
            raise HTTPException(503,'shared source unavailable') from None
        return actor

    def _select(self, actor, task_id, profile):
        import re
        if (type(task_id) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}',task_id) is None
            or type(profile) is not str or re.fullmatch(r'[0-9a-f]{64}',profile) is None):
            raise HTTPException(422,'shared selector invalid')
        installed = self.tasks.get((actor.actor_id,task_id,profile))
        if installed is None:
            raise HTTPException(403,'shared task denied')
        return installed

    def capability(self, authorization, repository, task_id, profile):
        session = self._session(authorization)
        actor = self.authenticator.access_authority.actor(session)
        installed = self._select(actor,task_id,profile)
        self.owned.store.authority_time()
        with self.owned.store._transaction():
            _, task, _ = _authority(self.owned.store,installed.admission.account_id,installed.admission.task_id)
        self._check(installed,session,repository,task.source_head,task.source_tree)
        return installed.service.backend_capability(repository_id=repository,actor=actor)

    def submit(self, authorization, repository, job, document):
        fields = {'schema_version','task_id','parent_digest','ordinal','profile_digest','source_head','source_tree','media_type','payload_base64'}
        if set(document) != fields or type(document['schema_version']) is not int or document['schema_version'] != 1:
            raise HTTPException(422,'shared request invalid')
        import base64
        import re
        if (type(document['payload_base64']) is not str or type(document['media_type']) is not str
            or type(document['source_head']) is not str or re.fullmatch('[0-9a-f]{40}',document['source_head']) is None
            or type(document['source_tree']) is not str or re.fullmatch('[0-9a-f]{40}',document['source_tree']) is None):
            raise HTTPException(422,'shared request invalid')
        try:
            payload = base64.b64decode(document['payload_base64'],validate=True)
        except (ValueError,TypeError):
            raise HTTPException(422,'shared request invalid') from None
        if document['media_type'] not in {'text/plain','application/vnd.openxmlformats-officedocument.wordprocessingml.document'} or not 1 <= len(payload) <= MAX_SHARED_INPUT_BYTES:
            raise HTTPException(422,'shared input invalid')
        session = self._session(authorization)
        actor = self.authenticator.access_authority.actor(session)
        installed = self._select(actor,document['task_id'],document['profile_digest'])
        actor = self._check(installed,session,repository,document['source_head'],document['source_tree'])
        if job != installed.expected_source.job_id:
            raise HTTPException(403,'shared child denied')
        binding = SharedControlBindingV1(actor.actor_id,installed.admission.account_id,installed.admission.task_id,document['task_id'],
            document['parent_digest'],document['ordinal'],document['profile_digest'],installed.credential_digest,document['source_head'],document['source_tree'])
        binding.encoded()
        from .landing_failover_config import PROVIDER_ORDER
        from .landing_http import HttpLandingProfile
        expected = HttpLandingProfile.for_provider(PROVIDER_ORDER[binding.ordinal],available=True)
        expected_child = 'fo-'+landing_digest('landing-failover-child-v1',
            {'parent':binding.parent_digest,'ordinal':binding.ordinal,'profile':binding.profile_digest})[:48]
        if expected.profile_digest != binding.profile_digest or job != expected_child:
            raise HTTPException(409,'shared child binding mismatch')
        def guard(admission,input_digest,provider,model):
            if admission is not installed.admission:
                raise HTTPException(403,'shared admission mismatch')
            self._check(installed,session,repository,document['source_head'],document['source_tree'],
                        input_digest=input_digest,provider=provider,model=model)

        token = SHARED_DISPATCH_GUARD.set(guard)
        try:
            result = installed.service.submit(job_id=job,repository_id=repository,
                exact_base_sha=document['source_head'],exact_base_tree=document['source_tree'],
                media_type=document['media_type'],chunks=(payload,),actor=actor,control_binding=binding,control_source=installed.expected_source)
            return result.job.job_view()
        finally:
            SHARED_DISPATCH_GUARD.reset(token)

    def observe(self, authorization,repository,job,task_id,profile):
        session = self._session(authorization)
        actor = self.authenticator.access_authority.actor(session)
        installed = self._select(actor,task_id,profile)
        record = self.owned.store.get(actor.actor_id,repository,job)
        self._check(installed,session,repository,record.source.exact_base_sha,record.source.exact_base_tree)
        row = self.owned.store._connection.execute(
            'SELECT binding FROM shared_control_bindings WHERE tenant_id=? AND repository_id=? AND job_id=?',
            (actor.actor_id,repository,job)).fetchone()
        if row is None:
            raise HTTPException(404,'shared child absent')
        bound = strict_json_object(row[0])
        if bound['control_task_id'] != task_id or bound['profile_digest'] != profile:
            raise HTTPException(403,'shared child denied')
        return installed.service.attempt_status(job,repository_id=repository,actor=actor)


def install_shared_control_api(app, control):
    """Explicit installation only; ordinary host composition never enables POST."""
    if type(control) is not SharedAuthorityControl:
        raise ValueError('shared owner configuration required')
    prefix = '/v1/shared-landing-control'
    def invoke(method,*arguments):
        try:
            return method(*arguments)
        except AccessError:
            raise HTTPException(403,'shared access denied') from None
        except LandingProviderError:
            raise HTTPException(403,'shared paid authority denied') from None
        except LandingContractError:
            raise HTTPException(422,'shared request invalid') from None
        except LandingServiceError as error:
            raise HTTPException(error.status_code,error.code) from None
    def args(request):
        from .api import _text
        return (request.headers.get('Authorization'),_text(request.headers.get('X-Repository-ID'),'X-Repository-ID',maximum=128,identifier=True))
    @app.get(prefix+'/capability', operation_id='getSharedLandingControlCapability')
    def capability(request: Request):
        return invoke(control.capability,*args(request),request.headers.get('X-Shared-Task-ID'),request.headers.get('X-Expected-Profile-Digest'))
    @app.post(prefix+'/jobs/{job}',operation_id='submitSharedLandingControlJob')
    async def submit(job: str,request: Request):
        from .api import _request_id
        _request_id(job,'job')
        # Reject missing, stale or revoked identities before reading input.
        control._session(request.headers.get('Authorization'))
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw)+len(chunk) > MAX_SHARED_REQUEST_BYTES:
                raise HTTPException(413,'shared input bound')
            raw.extend(chunk)
        try:
            document = strict_json_object(bytes(raw),maximum=MAX_SHARED_REQUEST_BYTES)
        except ValueError:
            raise HTTPException(422,'shared request invalid') from None
        result = await run_in_threadpool(invoke,control.submit,*args(request),job,document)
        return JSONResponse(result,status_code=202)
    @app.get(prefix+'/jobs/{job}',operation_id='observeSharedLandingControlJob')
    def observe(job: str,request: Request):
        from .api import _request_id
        _request_id(job,'job')
        return invoke(control.observe,*args(request),job,request.headers.get('X-Shared-Task-ID'),request.headers.get('X-Expected-Profile-Digest'))
