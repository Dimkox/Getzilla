"""Two opt-in fixed payload profiles for the existing native Factory UDS owner.

This module does not mint access, transport or model authority. It is imported
only by explicit trusted composition; ordinary Factory startup needs no Core.
"""

from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re

from getzilla import _payload_engine as engine
from getzilla.payload_transform import DataClass, FieldRule, Purpose, SourceFact, TransformPolicy, transform_candidate
from .access_authority import AccessError
from .contracts import canonical_digest

SUMMARY = "factory.local-summary151/v1"
PUBLIC_CONTEXT = "factory.local-public-context151/v1"
_CLASSES = {item.value: item for item in DataClass}
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,4}[A-Za-z]{2,24}(?![\w.-])")
_PHONE = re.compile(r"(?<!\w)(?:\+1[- .]?)?\(?[2-9][0-9]{2}\)?[- .]?[0-9]{3}[- .]?[0-9]{4}(?!\w)")


@dataclass(frozen=True, repr=False)
class PreparedPayload:
    payload: bytes
    sources: tuple
    policy_sha256: str
    profile: str

    @property
    def binding_stamp(self):
        return canonical_digest(
            {
                "profile": self.profile,
                "policy": self.policy_sha256,
                "sources": [
                    [
                        list(source.key),
                        source.version,
                        source.content_sha256,
                        source.representation_sha256,
                        source.transform_version,
                        source.classification.value,
                    ]
                    for source in self.sources
                ],
            }
        )


@dataclass(frozen=True, init=False)
class PayloadProfile:
    name: str
    policy: TransformPolicy

    def __init__(self, name):
        if name == SUMMARY:
            policy = TransformPolicy(
                name,
                Purpose.TOOL_RESPONSE,
                (DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PERSONAL),
                "application/json",
                (
                    FieldRule(("record_count",), "keep", "integer"),
                    FieldRule(("success",), "keep", "boolean"),
                    FieldRule(("contact_name",), "redact_pii", "text", False),
                    FieldRule(("email",), "redact_pii", "text", False),
                    FieldRule(("instructions",), "drop", "text", False),
                    FieldRule(("details",), "drop", "text", False),
                ),
            )
        elif name == PUBLIC_CONTEXT:
            policy = TransformPolicy(name, Purpose.TOOL_RESPONSE, (DataClass.PUBLIC,), "text/plain", ())
        else:
            raise AccessError("access_profile_unavailable")
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "policy", policy)

    def classification(self, value):
        result = _CLASSES.get(value)
        if result not in self.policy.data_classes:
            raise AccessError("source_unavailable")
        return result

    def prepare(self, chunks, lineage, classifications, max_bytes, deadline):
        if (
            type(chunks) is not tuple
            or len(chunks) != len(lineage)
            or len(chunks) != len(classifications)
            or not 1 <= len(chunks) <= 128
        ):
            raise AccessError("source_unavailable")
        sources, records = [], []
        try:
            for raw, (key, version, digest), classification in zip(chunks, lineage, classifications, strict=True):
                engine.check_deadline(deadline)
                if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
                    raise AccessError("source_unavailable")
                source = SourceFact(key, version, digest, digest, "identity/v1", self.classification(classification))
                candidate = transform_candidate(
                    policy=self.policy,
                    chunks=(raw,),
                    sources=(source,),
                    purpose=Purpose.TOOL_RESPONSE,
                    absolute_deadline=deadline,
                )
                if candidate.state != "candidate_complete":
                    raise AccessError("source_unavailable")
                sources.extend(candidate.sources)
                if self.name == SUMMARY:
                    record = json.loads(candidate.payload)
                    if not 0 <= record["record_count"] <= 1000:
                        raise AccessError("source_unavailable")
                else:
                    text = candidate.payload.decode("utf-8")
                    # These bounded deterministic recognizers are not universal PII detection.
                    for pattern in (_EMAIL, _PHONE):
                        text = engine._replace_bounded(pattern, text, min(262144, max_bytes))
                        engine.check_deadline(deadline)
                    record = {"content": text, "untrusted_data": True}
                records.append(record)
            payload = engine.encode_json(
                {"records" if self.name == SUMMARY else "documents": records}, max_bytes=min(262144, max_bytes)
            )
            engine.check_deadline(deadline)
            return PreparedPayload(payload, tuple(sources), self.policy.identity, self.name)
        except AccessError:
            raise
        except (engine.PayloadError, ValueError, TypeError, KeyError, UnicodeError):
            raise AccessError("source_unavailable") from None
