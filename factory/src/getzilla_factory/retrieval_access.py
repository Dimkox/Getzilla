"""Fixed optional retrieval computation for the existing native access owner.

Only the trusted service supplies captures and registered source metadata. This
module grants no source access, runs no model and persists no retrieval index.
"""
from dataclasses import dataclass
import hashlib
import json
import time

from getzilla import _payload_engine as engine
from getzilla.payload_transform import DataClass, FieldRule, Purpose, SourceFact, TransformPolicy, transform_candidate
from getzilla.retrieval.budget import Budget, RetrievalError
from getzilla.retrieval.contracts import SourceDocument, SourceKey, SourceSnapshot
from getzilla.retrieval.engine import pack_context, search
from getzilla.retrieval.extract import build_generation

from .access_authority import AccessError
from .payload_access import PreparedPayload, _EMAIL, _PHONE

PROFILE = 'factory.local-retrieval162/v1'
EPHEMERAL = 'factory.ephemeral-retrieval162/v1'
READER = 'factory.retrieval162/v1'


@dataclass(frozen=True)
class RetrievalQuery:
    text: str
    destination: str
    token_budget: int

    def __post_init__(self):
        if (type(self.text) is not str or len(self.text.encode('utf-8')) > 4096
                or type(self.destination) is not str or not 1 <= len(self.destination) <= 256
                or type(self.token_budget) is not int or self.token_budget not in (2048, 8192)):
            raise AccessError('invalid_access_request')


@dataclass(frozen=True, init=False)
class RetrievalProfile:
    name: str
    policy: TransformPolicy

    def __init__(self, name):
        if name not in (PROFILE, EPHEMERAL):
            raise AccessError('access_profile_unavailable')
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'policy', TransformPolicy(name, Purpose.TOOL_RESPONSE,
            (DataClass.PUBLIC, DataClass.INTERNAL), 'application/json',
            (FieldRule(('code',), 'keep', 'text'),)))

    def classification(self, value):
        if value not in ('public', 'internal'):
            raise AccessError('source_unavailable')
        return DataClass(value)

    def prepare(self, captured, registrations, max_bytes, deadline):
        request = captured.retrieval_query
        if type(request) is not RetrievalQuery or not captured.lineage:
            raise AccessError('source_unavailable')
        remaining = min(deadline, captured.deadline) - time.monotonic()
        if remaining <= 0:
            raise AccessError('access_expired')
        budget = Budget(seconds=min(2.0, remaining))
        budget.deadline = min(budget.deadline, deadline, captured.deadline)
        documents, facts = [], []
        try:
            for raw, (key, version, digest), classification in zip(captured.chunks,
                    captured.lineage, captured.classifications, strict=True):
                budget.check()
                registration = registrations[key]
                if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
                    raise AccessError('source_unavailable')
                source = SourceFact(key, version, digest, digest, 'identity/v1', self.classification(classification))
                # The fixed producer owns this one-field projection; no caller
                # can turn arbitrary personal text into a public classification.
                projection = engine.encode_json({'code': raw.decode('utf-8')}, max_bytes=262144)
                transformed = transform_candidate(policy=self.policy, chunks=(projection,), sources=(source,),
                    purpose=Purpose.TOOL_RESPONSE, absolute_deadline=budget.deadline)
                if transformed.state != 'candidate_complete':
                    raise AccessError('source_unavailable')
                text = json.loads(transformed.payload)['code']
                for pattern in (_EMAIL, _PHONE):
                    text = engine._replace_bounded(pattern, text, 262144)
                    budget.check()
                represented = text.encode('utf-8')
                documents.append(SourceDocument(SourceKey(*key), registration.relative_path, version,
                    raw, represented, self.policy.identity, self.name))
                facts.append(SourceFact(key, version, digest, hashlib.sha256(represented).hexdigest(),
                    self.name, self.classification(classification)))
            tenant, project = captured.lineage[0][0][:2]
            snapshot = SourceSnapshot.create(tenant, project, captured.context.repository_id, documents)
            generation = build_generation(snapshot, budget=budget)
            result = search(generation, request.text, budget=budget)
            packed = pack_context(snapshot, result.rankings['rrf'], lambda text: len(text.encode('utf-8')),
                request.token_budget, budget=budget)
            value = {'contract': self.name, 'context': packed.text,
                'citations': [{**item, 'source_key': list(item['source_key'])} for item in packed.citations],
                'source_snapshot': snapshot.source_identity,
                'generation_id': generation.identity, 'query_sha256': hashlib.sha256(request.text.encode()).hexdigest(),
                'components': result.component_status, 'coverage_gaps': list(generation.gaps),
                'status': result.status, 'answerability': result.answerability,
                'measurement': {'kind': 'utf8_bytes_upper_bound_estimate', 'units': packed.proxy_tokens,
                    'budget': request.token_budget, 'actual_units': None}, 'untrusted_data': True}
            if self.name == EPHEMERAL:
                if type(captured.capture_clock) is not tuple or len(captured.capture_clock) != 2:
                    raise AccessError('source_unavailable')
                value['retention'] = {'profile': self.name, 'captured_at': captured.capture_clock[0],
                    'due_at': captured.capture_clock[1]}
            payload = engine.encode_json(value, max_bytes=min(262144, max_bytes))
            budget.check()
            return PreparedPayload(payload, tuple(facts), self.policy.identity, self.name)
        except AccessError:
            raise
        except (engine.PayloadError, RetrievalError, KeyError, TypeError, ValueError, UnicodeError):
            raise AccessError('source_unavailable') from None
