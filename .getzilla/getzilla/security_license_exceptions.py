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

# Exact approved internal-use profiles; original vendor terms are not overridden.
PROFILES.update(
    {
        "certifi-2026.10.19-internal-ci-v1": {
            "name": "certifi",
            "version": "2026.10.19",
            "expression": "MPL-2.0",
            "filename": "certifi-2026.10.19-py3-none-any.whl",
            "artifact_sha256": "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b",
            "terms": {
                "certifi-2026.10.19.dist-info/licenses/LICENSE": (
                    "e93716da6b9c0d5a4a1df60fe695b370f0695603d21f6f83f053e42cfc10caf7",
                    989,
                )
            },
            "notices": {},
            "unchanged": {},
            "metadata": {
                "certifi-2026.10.19.dist-info/METADATA": (
                    "a5c0be3a42daeef0edfaf58e6ea5b7550f3e4e8eb35420f72e902df9bcf00f5c",
                    2526,
                )
            },
            "declared_terms": ["certifi-2026.10.19.dist-info/licenses/LICENSE"],
            "retain_metadata": True,
            "internal_ci": True,
            "usages": ["runtime", "runtime-and-development", "optional"],
            "supplements": {
                "usr/share/common-licenses/MPL-2.0": (
                    "fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85",
                    16726,
                )
            },
        },
        "setuptools-84.1.0-internal-ci-v1": {
            "name": "setuptools",
            "version": "84.1.0",
            "expression": "MIT",
            "filename": "setuptools-84.1.0-py3-none-any.whl",
            "artifact_sha256": "5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9",
            "terms": {
                "setuptools/_vendor/importlib_metadata-8.7.1.dist-info/licenses/LICENSE": (
                    "458502e12d97bbf64438606a20044aa85eb05fb0a8a807bb35dbec253fd1fc04",
                    10278,
                ),
                "setuptools/_vendor/jaraco_context-6.1.0.dist-info/licenses/LICENSE": (
                    "9755a18519666e5f0f4cae3daad3d7012bcae48a600b31237d75e9fe134e6683",
                    1076,
                ),
                "setuptools/_vendor/jaraco_functools-4.4.0.dist-info/licenses/LICENSE": (
                    "5a57cb4db85e2a2dd88c290628908add57e3451449e0a9a71fdfb38776fd759d",
                    1076,
                ),
                "setuptools/_vendor/more_itertools-10.8.0.dist-info/licenses/LICENSE": (
                    "09f1c8c9e941af3e584d59641ea9b87d83c0cb0fd007eb5ef391a7e2643c1a46",
                    1053,
                ),
                "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE": (
                    "cad1ef5bd340d73e074ba614d26f7deaca5c7940c3d8c34852e65c4909686c48",
                    197,
                ),
                "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE.APACHE": (
                    "0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594",
                    10174,
                ),
                "setuptools/_vendor/packaging-26.0.dist-info/licenses/LICENSE.BSD": (
                    "b70e7e9b742f1cc6f948b34c16aa39ffece94196364bc88ff0d2180f0028fac5",
                    1344,
                ),
                "setuptools/_vendor/platformdirs-4.4.0.dist-info/licenses/LICENSE": (
                    "29e0fd62e929850e86eb28c3fdccf0cefdf4fa94879011cffb3d0d4bed6d4db6",
                    1089,
                ),
                "setuptools/_vendor/tomli-2.4.0.dist-info/licenses/LICENSE": (
                    "b80816b0d530b8accb4c2211783790984a6e3b61922c2b5ee92f3372ab2742fe",
                    1072,
                ),
                "setuptools/_vendor/wheel-0.46.3.dist-info/licenses/LICENSE.txt": (
                    "30c23618679108f3e8ea1d2a658c7ca417bdfc891c98ef1a89fa4ff0c9828654",
                    1107,
                ),
                "setuptools/_vendor/zipp-3.23.0.dist-info/licenses/LICENSE": (
                    "5a57cb4db85e2a2dd88c290628908add57e3451449e0a9a71fdfb38776fd759d",
                    1076,
                ),
                "setuptools/config/NOTICE": ("2dddf08818297a3b89d43d95ff659d8da85741108c9136dfa3a4d856c0623bd8", 493),
                "setuptools/config/_validate_pyproject/NOTICE": (
                    "09c9bcea95ca086f8bc5bed174e40bc835b297d40fb5f86bbbb570fe0a5581a7",
                    18737,
                ),
                "setuptools-84.1.0.dist-info/licenses/LICENSE": (
                    "86da0f01aeae46348a3c3d465195dc1ceccde79f79e87769a64b8da04b2a4741",
                    1023,
                ),
                "setuptools/_vendor/autocommand-2.2.2.dist-info/LICENSE": (
                    "ade78d04982d69972d444a8e14a94f87a2334dd3855cc80348ea8e240aa0df2d",
                    7634,
                ),
                "setuptools/_vendor/backports.tarfile-1.2.0.dist-info/LICENSE": (
                    "86da0f01aeae46348a3c3d465195dc1ceccde79f79e87769a64b8da04b2a4741",
                    1023,
                ),
                "setuptools/_vendor/jaraco.text-4.0.0.dist-info/LICENSE": (
                    "86da0f01aeae46348a3c3d465195dc1ceccde79f79e87769a64b8da04b2a4741",
                    1023,
                ),
            },
            "notices": {},
            "unchanged": {},
            "metadata": {
                "setuptools-84.1.0.dist-info/METADATA": (
                    "adc9c90a8475c9efce59d6dbe2bfdfc3a68a9806a83b7771245ac6e9bb0e8649",
                    6581,
                ),
                "setuptools/_vendor/autocommand-2.2.2.dist-info/METADATA": (
                    "3800d9b91dceea2065a6ed6279383362e97ac38b8e56b9343f404ee531860099",
                    15006,
                ),
                "setuptools/_vendor/backports.tarfile-1.2.0.dist-info/METADATA": (
                    "8215c54ead77d9dc5a108a25c6bdc72b5999aa6f62c9499a440359412afa5a51",
                    2020,
                ),
                "setuptools/_vendor/importlib_metadata-8.7.1.dist-info/METADATA": (
                    "a3e38b9ee4326289d4864704f30e299ee769e2309ce9f4a75f0de1a50ad0a356",
                    4670,
                ),
                "setuptools/_vendor/jaraco.text-4.0.0.dist-info/METADATA": (
                    "5c2fd09012c954f139b10624978d5335a654c34014cd06f6f466ca683dbc9c56",
                    3731,
                ),
                "setuptools/_vendor/jaraco_context-6.1.0.dist-info/METADATA": (
                    "0435ebfc52055c5a9974ed20c171b6454383eaf9dbb1508814ba7ad97c59d712",
                    4270,
                ),
                "setuptools/_vendor/jaraco_functools-4.4.0.dist-info/METADATA": (
                    "2e79da8dc3469924abe3ac8b22a3feb5692a79bf9f47bbc86b6535d618641849",
                    2960,
                ),
                "setuptools/_vendor/more_itertools-10.8.0.dist-info/METADATA": (
                    "6ab3515145abe58b067f087c867631cf4cf5d653fed81b9642ee12086c3904b8",
                    39413,
                ),
                "setuptools/_vendor/packaging-26.0.dist-info/METADATA": (
                    "3362bb7d6a26da2962ba8daaa4785cd0bacac21aba908a1195cc8f59580a265a",
                    3309,
                ),
                "setuptools/_vendor/platformdirs-4.4.0.dist-info/METADATA": (
                    "bbc5216d5f4c77bfbc57227264d52e66bccde71ccf79e75e1a6046d029d30223",
                    12831,
                ),
                "setuptools/_vendor/tomli-2.4.0.dist-info/METADATA": (
                    "f5ac0a1f8fba908b4646cd655309e91aad969b6787616ac571ca462a3832ffce",
                    10567,
                ),
                "setuptools/_vendor/wheel-0.46.3.dist-info/METADATA": (
                    "22910aa97ca89cbcc20a019e27fe31360b7929a4bd66ca0d310f99a44f6ccd35",
                    2410,
                ),
                "setuptools/_vendor/zipp-3.23.0.dist-info/METADATA": (
                    "bdd67d4d16cf0bf3b893e7d18cd3d2d774adb82f37ed985bc7770c607226b35b",
                    3563,
                ),
            },
            "declared_terms": ["setuptools-84.1.0.dist-info/licenses/LICENSE"],
            "retain_metadata": True,
            "internal_ci": True,
            "usages": ["build", "build-ci", "runtime-and-development"],
            "supplements": {
                "usr/share/common-licenses/GPL-3": (
                    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
                    35149,
                )
            },
        },
        "psycopg-3.3.4-internal-ci-v1": {
            "name": "psycopg",
            "version": "3.3.4",
            "expression": "LGPL-3.0-only",
            "filename": "psycopg-3.3.4-py3-none-any.whl",
            "artifact_sha256": "b6bbc25ccf05c8fad3b061d9db2ef0909a555171b84b07f29458a447253d679a",
            "terms": {
                "psycopg-3.3.4.dist-info/licenses/LICENSE.txt": (
                    "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118",
                    7652,
                )
            },
            "notices": {},
            "unchanged": {},
            "metadata": {
                "psycopg-3.3.4.dist-info/METADATA": (
                    "daef30765d48b6c646bffb62457da8e1e969f0ff3bacf563c14da60f185c253d",
                    4313,
                )
            },
            "declared_terms": ["psycopg-3.3.4.dist-info/licenses/LICENSE.txt"],
            "retain_metadata": True,
            "internal_ci": True,
            "usages": ["runtime", "runtime-and-development", "optional"],
            "supplements": {
                "usr/share/common-licenses/GPL-3": (
                    "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
                    35149,
                )
            },
        },
    }
)

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
        if profile.get("internal_ci") and (
            subject["distribution"] != "internal"
            or subject["delivery_kind"] != "installed-package"
            or subject["profile"]
            not in {
                "ci:" + recipe + ":python:cpython:3.13:linux-x86_64"
                for recipe in (
                    "trust-ci/Dockerfile.api",
                    "trust-ci/Dockerfile.worker",
                    "trust-ci/Dockerfile.test",
                    "trust-ci/runner.Dockerfile",
                )
            }
            or subject["usage"] not in profile["usages"]
        ):
            _refuse("internal CI conditions cannot authorize another use or redistribution")
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
            paths.update(profile["terms"])
            paths.update(profile["notices"])
            paths.update(profile["unchanged"])
            paths.update(profile["metadata"])
    return paths


def _matching_entry(policy, dep, record, distribution, scope):
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
    return matches[0]


def matching_profile(policy, dep, record, distribution, scope):
    """Select one exact reviewed condition name; this supplies no proof credit."""
    return _matching_entry(policy, dep, record, distribution, scope)["condition_profile"]


def verify_exception(policy, dep, record, files, metadata, distribution, scope, *, supplements=None):
    entry = _matching_entry(policy, dep, record, distribution, scope)
    actual = entry["subject"]
    profile = PROFILES[entry["condition_profile"]]
    if metadata.get("expression") != profile["expression"] or set(metadata.get("license_paths", [])) != set(
        profile.get("declared_terms", profile["terms"])
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
            if group != "metadata" or profile.get("retain_metadata"):
                retained[path] = sha
    supplemental = {}
    if profile.get("supplements"):
        from .security_license_supplements import validate

        supplemental = validate(supplements, actual, profile["supplements"])
    detail = dict(
        code="policy-exception-conditions-verified",
        condition_profile=entry["condition_profile"],
        exception_sha256=_digest(entry),
        subject=actual,
        expression=profile["expression"],
        requirements_sha256=_digest(profile),
        required_retention=retained,
    )
    if supplemental:
        detail.update(required_supplements=supplemental["members"], supplement_custody=supplemental["custody"])
    return dict(
        detail=detail,
        license_files=groups["terms"],
        notice_files=groups["notices"],
        required_retention=sorted(retained),
        **({"required_supplements": supplemental["members"]} if supplemental else {}),
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
        extra = {"original_diagnostic", "required_supplements", "supplement_custody"}
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
            path: sha
            for group in ("terms", "notices", "unchanged", *(["metadata"] if profile.get("retain_metadata") else []))
            for path, (sha, _) in profile[group].items()
        }
        supplements = profile.get("supplements", {})
        if supplements:
            from .security_license_supplements import descriptors

            if detail.get("required_supplements") != descriptors(supplements):
                return False
            custody = detail.get("supplement_custody")
            if (
                type(custody) is not dict
                or set(custody) != {"source_sha256", "run_sha256", "subject_sha256", "image"}
                or custody["subject_sha256"] != _digest(subject)
                or any(
                    type(custody[k]) is not str or not re.fullmatch("[0-9a-f]{64}", custody[k])
                    for k in ("source_sha256", "run_sha256", "subject_sha256")
                )
                or type(custody["image"]) is not str
                or not 1 <= len(custody["image"]) <= 1024
            ):
                return False
        elif "required_supplements" in detail or "supplement_custody" in detail:
            return False
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
