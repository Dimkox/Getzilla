"""Closed metadata for the opt-in, single-owner Unix control protocol."""
from dataclasses import asdict, dataclass
import re

from .contracts import canonical_json
from .landing_service import LandingServiceError

MAX_SHARED_INPUT_BYTES = 524_288
MAX_SHARED_REQUEST_BYTES = 800_000

CONTROL_SCHEMA = """
CREATE TABLE shared_control_bindings (
 tenant_id TEXT NOT NULL, repository_id TEXT NOT NULL, job_id TEXT NOT NULL,
 binding BLOB NOT NULL, PRIMARY KEY(tenant_id,repository_id,job_id),
 FOREIGN KEY(tenant_id,repository_id,job_id) REFERENCES landing_jobs(tenant_id,repository_id,job_id)
) STRICT;
CREATE TABLE shared_control_clock (singleton INTEGER NOT NULL PRIMARY KEY CHECK(singleton=1), highwater REAL NOT NULL) STRICT;
"""
CONTROL_COLUMNS = {
 'shared_control_bindings': (("tenant_id","TEXT",1,1),("repository_id","TEXT",1,2),("job_id","TEXT",1,3),("binding","BLOB",1,0)),
 'shared_control_clock': (("singleton","INTEGER",1,1),("highwater","REAL",1,0)),
}

@dataclass(frozen=True)
class SharedControlBindingV1:
    actor_id: str
    account_id: str
    task_id: str
    control_task_id: str
    parent_digest: str
    ordinal: int
    profile_digest: str
    credential_digest: str
    source_head: str
    source_tree: str

    def encoded(self):
        if (any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}',v)
                for v in (self.actor_id,self.account_id,self.task_id,self.control_task_id))
            or type(self.ordinal) is not int or not 0 <= self.ordinal < 5
            or any(type(v) is not str or not re.fullmatch('[0-9a-f]{'+str(n)+'}',v)
                   for v,n in ((self.parent_digest,64),(self.profile_digest,64),(self.credential_digest,64),(self.source_head,40),(self.source_tree,40)))):
            raise LandingServiceError('shared_binding_invalid',422,'shared control binding invalid')
        return canonical_json(asdict(self))


class BoundSharedCredentialLoader:
    """Owner-installed digest pin. Only the executor receives the current value."""
    def __init__(self, loader, digest):
        if not callable(loader) or type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None:
            raise ValueError('shared credential binding required')
        self._loader, self.digest = loader,digest

    def __call__(self):
        import hashlib
        import hmac
        from .landing_provider import LandingProviderError
        try:
            value=self._loader()
        except Exception:
            raise LandingProviderError('credential_unavailable') from None
        if type(value) is not str or not value or not hmac.compare_digest(hashlib.sha256(value.encode()).hexdigest(),self.digest):
            raise LandingProviderError('credential_stale')
        return value
