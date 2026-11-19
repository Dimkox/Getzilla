"""Exact supplemental terms observed in an existing live CI image.

This proves retained bytes for one internal consumer, not legal approval or
Factory conveyance conditions. Saved JSON cannot recreate a live proof.
"""

from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from .security_artifacts import ArtifactError


@dataclass(frozen=True, eq=False)
class _Proof:
    binding: dict
    subject: dict
    requirements: dict
    fingerprint: str


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _refuse():
    raise ArtifactError("license-exception-conditions", "exact live supplemental term custody is unavailable")


def descriptors(requirements):
    return {path: dict(sha256=sha, bytes=size) for path, (sha, size) in requirements.items()}


def _observe(binding, subject, requirements):
    from . import security_image_backend as native
    from . import security_image_producer as producer
    from .security_ci_inputs import validate_binding

    if (
        producer._LIVE is None
        or native._GUARD is None
        or producer._LIVE.get("native_guard") is not native._GUARD
        or producer._LIVE.get("source") != binding["source"]
        or producer._LIVE.get("run") != binding["run"]
    ):
        _refuse()
    validate_binding(binding)
    if (
        subject["distribution"] != "internal"
        or subject["delivery_kind"] != "installed-package"
        or not requirements
        or len(requirements) > 4
        or sum(size for _, size in requirements.values()) > 262144
    ):
        _refuse()
    bodies = producer.ci_member_evidence(
        binding["ci_uses"], binding["source"], binding["run"], binding["ci_consumer"], sorted(requirements)
    )
    if set(bodies) != set(requirements):
        _refuse()
    for path, (sha, size) in requirements.items():
        raw = bodies[path]
        if type(raw) is not bytes or len(raw) != size or hashlib.sha256(raw).hexdigest() != sha:
            _refuse()
        raw.decode("utf-8", "strict")
    return dict(
        source_sha256=_digest(binding["source"]),
        run_sha256=_digest(binding["run"]),
        subject_sha256=_digest(subject),
        image=binding["ci_uses"]["consumers"][binding["ci_consumer"]]["image"],
    )


def prove_ci(binding, dep, record, scope, condition_profile):
    from .security_license_exceptions import PROFILES, scope_for
    from .security_python_target import digest
    from . import security_image_producer as producer

    profile = PROFILES.get(condition_profile)
    if not profile or not profile.get("internal_ci") or not profile.get("supplements"):
        _refuse()
    if scope_for(dep, binding, {"binding_sha256": digest(binding)}) != scope:
        _refuse()
    subject = dict(
        **{k: dep.get(k) for k in ("ecosystem", "name", "version", "manifest", "usage")},
        **scope,
        distribution="internal",
        artifact_sha256=record.get("sha256"),
        filename=record.get("filename"),
        artifact_url=record.get("origin", {}).get("artifact_url"),
    )
    if any(subject[k] != profile[k] for k in ("name", "version", "filename", "artifact_sha256")):
        _refuse()
    requirements = profile["supplements"]
    _observe(binding, subject, requirements)
    binding, subject = json.loads(json.dumps(binding)), json.loads(json.dumps(subject))
    requirements = {path: tuple(value) for path, value in requirements.items()}
    proof = _Proof(binding, subject, requirements, _digest([binding, subject, requirements]))
    proofs = producer._LIVE.setdefault("license_supplement_proofs", {})
    if len(proofs) >= 32:
        proofs.clear()
    proofs[id(proof)] = proof
    return proof


def validate(proof, subject, requirements):
    from . import security_image_producer as producer

    if (
        type(proof) is not _Proof
        or producer._LIVE is None
        or producer._LIVE.get("license_supplement_proofs", {}).get(id(proof)) is not proof
        or proof.subject != subject
        or proof.requirements != requirements
        or proof.fingerprint != _digest([proof.binding, proof.subject, proof.requirements])
    ):
        _refuse()
    # Reacquire through the native held graph at consumption, including cache
    # freshness fences. A prior good read is not a later custody observation.
    custody = _observe(proof.binding, subject, requirements)
    return dict(members=descriptors(requirements), custody=custody)
