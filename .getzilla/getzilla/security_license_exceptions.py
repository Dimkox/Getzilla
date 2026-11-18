"""Closed package-specific conditions; no SPDX allow-list or human approval.

Only reviewed immutable wheel profiles qualify. Current origin, target, source,
closure and final custody remain the caller's mandatory independent checks.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit
from .security_artifacts import ArtifactError, safe_parts


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# Hashes cover the complete original files, including the PSF history and the
# separate inline MIT notice. They are expectations, not publisher authority.
PROFILES = {
    "cffi-2.1.1-mit0-inline-mit-v1": {
        "name": "cffi",
        "version": "2.1.1",
        "expression": "MIT-0",
        "filename": "cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
        "artifact_sha256": "c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf",
        "terms": {
            "cffi-2.1.1.dist-info/licenses/LICENSE": (
                "5ba24ddc57067f9249add644c3afc41a5d6dc37e23433ef759d95df370b0af63",
                1123,
            )
        },
        "notices": {
            "cffi/_cffi_gen_src.py": ("c94479de91526ec6b7b2c17bfd53aa5d368a78be402531ccfddc99f48198f6cc", 7044)
        },
        "unchanged": {},
        "metadata": {
            "cffi-2.1.1.dist-info/METADATA": ("558bafb9093a8e790175d9ecff9688382981d744877dad86fd6770db0f4dc918", 2527)
        },
    },
    "typing-extensions-4.16.0-history-unchanged-v1": {
        "name": "typing-extensions",
        "version": "4.16.0",
        "expression": "PSF-2.0",
        "filename": "typing_extensions-4.16.0-py3-none-any.whl",
        "artifact_sha256": "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8",
        "terms": {
            "typing_extensions-4.16.0.dist-info/licenses/LICENSE": (
                "3b2f81fe21d181c499c59a256c8e1968455d6689d269aa85373bfb6af41da3bf",
                13936,
            )
        },
        "notices": {},
        "unchanged": {
            "typing_extensions.py": ("4040ca1a1ecbee00d1385c12a93084d1c5bd46f0b774f07e5ae7e91c4f55e696", 165012)
        },
        "metadata": {
            "typing_extensions-4.16.0.dist-info/METADATA": (
                "b05084ca1d50879865178d9fff9fabeab61bdfb1f361bfbde95421ffc8f9be46",
                3310,
            )
        },
    },
}
# The CP313 wheel is a distinct exact artifact with the same complete legal
# and inline notice bytes. Live CI target observation is still mandatory.
PROFILES["cffi-2.1.1-cp313-mit0-inline-mit-v1"] = {
    **PROFILES["cffi-2.1.1-mit0-inline-mit-v1"],
    "filename": "cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
    "artifact_sha256": "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2",
}

SUBJECT_FIELDS = {
    "ecosystem",
    "name",
    "version",
    "artifact_sha256",
    "filename",
    "artifact_url",
    "manifest",
    "manifest_sha256",
    "usage",
    "distribution",
    "delivery_kind",
    "profile",
    "abi",
}


def _refuse(message):
    raise ArtifactError("license-exception-conditions", message)


def validate_exceptions(entries):
    if type(entries) is not list or len(entries) > 128 or len(json.dumps(entries).encode()) > 60000:
        _refuse("dependency exceptions must be a bounded list")
    seen = set()
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"subject", "condition_profile"}:
            _refuse("exception must contain only an exact subject and reviewed condition profile")
        profile = PROFILES.get(entry["condition_profile"]) if type(entry["condition_profile"]) is str else None
        subject = entry["subject"]
        if profile is None or type(subject) is not dict or set(subject) != SUBJECT_FIELDS:
            _refuse("unsupported or incomplete dependency exception")
        if any(
            type(value) is not str or not 1 <= len(value) <= 1024 or any(ord(c) < 32 for c in value)
            for value in subject.values()
        ):
            _refuse("exception subject must contain bounded exact values")
        if (
            subject["ecosystem"] != "PyPI"
            or any(subject[key] != profile[key] for key in ("name", "version", "filename", "artifact_sha256"))
            or subject["distribution"] not in {"internal", "redistributed"}
            or subject["delivery_kind"]
            not in {"source-use", "installed-package", "unchanged-artifact", "factory-offline-archive"}
            or not re.fullmatch("[0-9a-f]{64}", subject["manifest_sha256"])
        ):
            _refuse("exception subject differs from its reviewed immutable wheel profile")
        safe_parts(subject["manifest"])
        url = urlsplit(subject["artifact_url"])
        if (
            url.scheme != "https"
            or url.netloc != "files.pythonhosted.org"
            or url.query
            or url.fragment
            or not url.path.startswith("/packages/")
            or not url.path.endswith("/" + subject["filename"])
        ):
            _refuse("exception needs one exact official artifact URL")
        key = _digest(subject)
        if key in seen:
            _refuse("duplicate or conflicting exact dependency exception")
        seen.add(key)
    return json.loads(json.dumps(entries))


def retention_paths(policy, dep):
    """Request bounded extra archive members; this grants no exception credit."""
    paths = set()
    for entry in policy.get("dependency_exceptions", []):
        subject = entry["subject"]
        if all(dep.get(key) == subject[key] for key in ("ecosystem", "name", "version", "manifest", "usage")):
            profile = PROFILES[entry["condition_profile"]]
            paths.update(profile["notices"])
            paths.update(profile["unchanged"])
            paths.update(profile["metadata"])
    return paths


def verify_exception(policy, dep, record, files, metadata, distribution, scope):
    if type(scope) is not dict or set(scope) != {"manifest_sha256", "profile", "abi", "delivery_kind"}:
        _refuse("current source manifest, named target and ABI must be independently observed")
    actual = {
        **{key: dep.get(key) for key in ("ecosystem", "name", "version", "manifest", "usage")},
        **scope,
        "distribution": distribution,
        "artifact_sha256": record.get("sha256"),
        "filename": record.get("filename"),
        "artifact_url": record.get("origin", {}).get("artifact_url"),
    }
    matches = [
        entry for entry in validate_exceptions(policy.get("dependency_exceptions", [])) if entry["subject"] == actual
    ]
    if len(matches) != 1:
        _refuse("no exact exception covers this artifact, source, use, distribution and target")
    entry = matches[0]
    profile = PROFILES[entry["condition_profile"]]
    if metadata.get("expression") != profile["expression"] or set(metadata.get("license_paths", [])) != set(
        profile["terms"]
    ):
        _refuse("original metadata differs from the reviewed full term profile")
    retained = {}
    groups = {}
    for group in ("terms", "notices", "unchanged", "metadata"):
        groups[group] = []
        for path, (sha, size) in profile[group].items():
            body = files.get(path)
            if type(body) is not bytes or len(body) != size or hashlib.sha256(body).hexdigest() != sha:
                _refuse("complete retained profile member is missing or changed: " + path)
            body.decode("utf-8", "strict")
            groups[group].append(dict(path=path, sha256=sha, bytes=size, validation="exact-reviewed-exception-profile"))
            if group != "metadata":
                retained[path] = sha
    detail = dict(
        code="policy-exception-conditions-verified",
        condition_profile=entry["condition_profile"],
        exception_sha256=_digest(entry),
        subject=actual,
        expression=profile["expression"],
        requirements_sha256=_digest(profile),
        required_retention=retained,
    )
    return dict(
        detail=detail,
        license_files=groups["terms"],
        notice_files=groups["notices"],
        required_retention=sorted(retained),
    )


def scope_for(dep, binding, observed):
    """Derive stable policy selectors from already revalidated live bindings."""
    from .security_python_target import _pin_for, digest

    if binding is None or observed is None:
        _refuse("exception needs the current source-owned Python target observation")
    pin = _pin_for(dep, binding)
    if pin is None or pin["marker_active"] is not True or observed.get("binding_sha256") != digest(binding):
        _refuse("exception source/target binding is missing or changed")
    if dep.get("delivery_context") and "ci_consumer" not in binding:
        _refuse("named installation needs a qualified actual custody adapter")
    target = binding["target"]
    profile = "python:" + ":".join(
        (target["implementation"], ".".join(target["python_version"].split(".")[:2]), target["platform"])
    )
    if "ci_consumer" in binding:
        consumer = binding["ci_uses"]["consumers"][binding["ci_consumer"]]
        profile = "ci:" + consumer["recipe"] + ":" + profile
    return dict(
        manifest_sha256=pin["manifest_sha256"],
        profile=profile,
        abi=target["abi"],
        delivery_kind=dep.get("delivery_kind", "source-use"),
    )


def detail_consistent(finding):
    """Structural replay check only; live source and custody are rechecked upstream."""
    try:
        detail = finding["policy_exception"]
        fields = {
            "code",
            "condition_profile",
            "exception_sha256",
            "subject",
            "expression",
            "requirements_sha256",
            "required_retention",
        }
        extra = {"original_diagnostic"}
        if "original_diagnostic" in detail:
            original = detail["original_diagnostic"]
            if (
                type(original) is not dict
                or set(original) != {"code", "message"}
                or any(type(value) is not str or not 1 <= len(value) <= 4096 for value in original.values())
            ):
                return False
        if (
            type(detail) is not dict
            or not fields <= set(detail) <= fields | extra
            or detail["code"] != "policy-exception-conditions-verified"
        ):
            return False
        entry = dict(subject=detail["subject"], condition_profile=detail["condition_profile"])
        validate_exceptions([entry])
        profile = PROFILES[entry["condition_profile"]]
        subject = entry["subject"]
        if (
            detail["exception_sha256"] != _digest(entry)
            or detail["requirements_sha256"] != _digest(profile)
            or detail["expression"] != profile["expression"]
            or finding["expression"] != profile["expression"]
            or finding["selected_expression"] != profile["expression"]
            or any(
                finding.get(field) != subject[key]
                for field, key in (
                    ("ecosystem", "ecosystem"),
                    ("package", "name"),
                    ("version", "version"),
                    ("manifest", "manifest"),
                    ("distribution", "distribution"),
                    ("artifact_sha256", "artifact_sha256"),
                )
            )
            or finding["origin"]["artifact_url"] != subject["artifact_url"]
        ):
            return False
        retained = {
            path: sha for group in ("terms", "notices", "unchanged") for path, (sha, _) in profile[group].items()
        }
        if detail["required_retention"] != retained:
            return False
        for field, group in (("license_files", "terms"), ("notice_files", "notices")):
            expected = [
                dict(path=path, sha256=sha, bytes=size, validation="exact-reviewed-exception-profile")
                for path, (sha, size) in profile[group].items()
            ]
            if finding[field] != expected:
                return False
        return True
    except (ValueError, KeyError, TypeError):
        return False
