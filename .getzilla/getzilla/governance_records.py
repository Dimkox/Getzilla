"""Immutable governance records and their canonical byte representation.

Record initialization intentionally uses object.__setattr__ only to set the
frozen canonical bytes. Storage and fitness orchestration remain separate.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Literal


class GovernanceError(ValueError):
    def __init__(self, message: str, *, code: str = "invalid") -> None:
        super().__init__(message)
        self.code = code


ActorKind = Literal["human", "agent", "system"]


RuleStatus = Literal[
    "candidate", "reviewed", "approved", "active", "deprecated", "revoked"
]


@dataclass(frozen=True)
class ActorRef:
    actor_id: str
    actor_kind: ActorKind

    def __post_init__(self) -> None:
        if not self.actor_id or self.actor_kind not in {"human", "agent", "system"}:
            raise GovernanceError("transition actor is invalid", code="actor")


@dataclass(frozen=True)
class RuleReview:
    actor_id: str
    actor_kind: Literal["human", "system"]
    reviewed_at: str


@dataclass(frozen=True)
class GovernanceApproval:
    actor_id: str
    actor_kind: Literal["human"]
    approved_at: str
    scope: Literal["governance"]


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    path: str
    sha256: str


@dataclass(frozen=True, init=False, eq=False)
class ExampleRecord:
    _canonical_document: bytes

    def __init__(self, canonical_document: bytes) -> None:
        if not isinstance(canonical_document, bytes):
            raise TypeError("canonical_document must be bytes")
        object.__setattr__(self, "_canonical_document", canonical_document)

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> ExampleRecord:
        try:
            return cls(_canonical_bytes(document))
        except (KeyError, TypeError, ValueError, UnicodeEncodeError) as exc:
            raise GovernanceError("example record is invalid", code="example") from exc

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_document)

    @property
    def example_id(self) -> str:
        return self.to_dict()["example_id"]

    @property
    def category(self) -> str:
        return self.to_dict()["category"]

    @property
    def status(self) -> str:
        return self.to_dict()["status"]

    @property
    def evidence(self) -> tuple[EvidenceRef, ...]:
        return tuple(EvidenceRef(**item) for item in self.to_dict()["evidence"])


@dataclass(frozen=True, init=False, eq=False)
class DebtRecord:
    _canonical_document: bytes

    def __init__(self, canonical_document: bytes) -> None:
        if not isinstance(canonical_document, bytes):
            raise TypeError("canonical_document must be bytes")
        object.__setattr__(self, "_canonical_document", canonical_document)

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> DebtRecord:
        try:
            return cls(_canonical_bytes(document))
        except (KeyError, TypeError, ValueError, UnicodeEncodeError) as exc:
            raise GovernanceError("debt record is invalid", code="debt") from exc

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_document)

    @property
    def debt_id(self) -> str:
        return self.to_dict()["debt_id"]

    @property
    def status(self) -> str:
        return self.to_dict()["status"]


@dataclass(frozen=True, init=False, eq=False)
class RuleRecord:
    _canonical_document: bytes

    def __init__(self, canonical_document: bytes) -> None:
        if not isinstance(canonical_document, bytes):
            raise TypeError("canonical_document must be bytes")
        object.__setattr__(self, "_canonical_document", canonical_document)

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> RuleRecord:
        try:
            canonical = _canonical_bytes(document)
        except (KeyError, TypeError, ValueError, UnicodeEncodeError) as exc:
            raise GovernanceError("rule record is invalid", code="rule") from exc
        return cls(canonical)

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self._canonical_document)

    @property
    def rule_id(self) -> str:
        return self.to_dict()["rule_id"]

    @property
    def source_task(self) -> str:
        return self.to_dict()["source_task"]

    @property
    def author(self) -> ActorRef:
        author = self.to_dict()["author"]
        return ActorRef(author["actor_id"], author["actor_kind"])

    @property
    def created_at(self) -> str:
        return self.to_dict()["created_at"]

    @property
    def expires_at(self) -> str | None:
        return self.to_dict()["expires_at"]

    @property
    def status(self) -> RuleStatus:
        return self.to_dict()["status"]

    @property
    def revision(self) -> int:
        return self.to_dict()["revision"]

    @property
    def evidence(self) -> tuple[EvidenceRef, ...]:
        return tuple(EvidenceRef(**item) for item in self.to_dict()["evidence"])

    @property
    def reviewed_by(self) -> tuple[RuleReview, ...]:
        return tuple(RuleReview(**item) for item in self.to_dict()["reviewed_by"])

    @property
    def approved_by(self) -> tuple[GovernanceApproval, ...]:
        return tuple(
            GovernanceApproval(**item) for item in self.to_dict()["approved_by"]
        )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
