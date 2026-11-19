"""Live isolated CI installation artifacts, separate from host and output uses."""

from __future__ import annotations

import hashlib
import re

from .security_artifacts import ArtifactError, artifact_context
from .security_python_target import digest, _subject, _context_key, _descriptor, validate_source_pins


_EVALUATION_ENTRY = object()
_RESULT_SEAL = object()


def _refuse():
    raise ArtifactError(
        "artifact-target-use-unobserved", "current CI installation target or source custody is unavailable"
    )


def scope(parent, index):
    from .security_image_authority import validate_ci_uses

    uses = validate_ci_uses(parent["ci_uses"], parent["source"], parent["run"])
    if type(index) is not int or not 0 <= index < len(uses["consumers"]):
        _refuse()
    consumer = uses["consumers"][index]
    if (
        consumer.get("image_target_observed") is not True
        or consumer.get("distribution") != "internal"
        or consumer.get("purpose") != "isolated-public-ci"
    ):
        _refuse()
    target = _descriptor(consumer["target"])
    tags = consumer["supported_tags"]
    if (
        type(tags) is not list
        or not 1 <= len(tags) <= 4096
        or len(set(tags)) != len(tags)
        or any(type(t) is not str or not re.fullmatch("[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+", t) for t in tags)
        or digest(tags) != target["tags_sha256"]
        or len(tags) != target["tag_count"]
    ):
        _refuse()
    original_pins = validate_source_pins(consumer["source_pins"])
    context = "ci-install-" + digest(
        dict(
            source=parent["source"],
            run=parent["run"],
            image=consumer["image"],
            recipe=consumer["recipe_sha256"],
            build=consumer["build_sha256"],
            requirements=consumer["requirements_sha256"],
            install_requirements=consumer["install_requirements"],
        )
    )
    installed = consumer["install_requirements"]
    if (type(installed) is not dict or not 1 <= len(installed) <= 3
            or consumer["requirements"] not in installed
            or installed[consumer["requirements"]] != consumer["requirements_sha256"]
            or any(type(path) is not str or path not in {'trust-ci/requirements.txt',
                'trust-ci/requirements-test.txt', 'trust-ci/requirements-runtime.txt',
                'trust-ci/requirements-build.txt', 'trust-ci/requirements-runner.txt'}
                or type(sha) is not str or not re.fullmatch('[a-f0-9]{64}', sha) for path, sha in installed.items())):
        _refuse()
    dependencies, pins = [], {}
    for original in consumer["dependencies"]:
        key = digest(_subject(original))
        pin = original_pins.get(key)
        if pin is None or pin["context_sha256"] != _context_key(original):
            _refuse()
        if not pin["marker_active"]:
            continue
        if original["manifest"] in installed:
            if pin["manifest_sha256"] != installed[original["manifest"]] or not pin["hashes"]:
                _refuse()
        else:
            matches = [
                dep
                for dep in consumer["dependencies"]
                if dep["manifest"] in installed
                and dep["name"] == original["name"]
                and dep["version"] == original["version"]
            ]
            if len(matches) != 1:
                _refuse()
            required = original_pins[digest(_subject(matches[0]))]
            if required["manifest_sha256"] != installed[matches[0]["manifest"]]:
                _refuse()
            hashes = set(required["hashes"])
            if pin["hashes"]:
                hashes &= set(pin["hashes"])
            if not required["marker_active"] or not hashes:
                _refuse()
            pin = dict(pin, hashes=sorted(hashes))
        dep = dict(original, distribution="internal", delivery_kind="installed-package", delivery_context=context)
        dependencies.append(dep)
        pins[key] = dict(pin, context_sha256=_context_key(dep))
    if not 1 <= len(dependencies) <= 512:
        _refuse()
    inventory = dict(
        schema_version=1,
        complete=True,
        gaps=[],
        dependencies=dependencies,
        tools=[],
        images=[],
        marker_environment=target["marker_environment"],
        source_head=parent["source"]["head_sha"],
        scope="one actual isolated CI installation; original source uses remain separate",
    )
    inventory["digest"] = digest(inventory)
    binding = dict(
        source=parent["source"],
        run=parent["run"],
        profile_sha256=parent["profile_sha256"],
        inventory_sha256=inventory["digest"],
        target=target,
        source_pins=pins,
        ci_uses=uses,
        ci_consumer=index,
    )
    return inventory, binding


def validate_binding(value):
    parent = dict(
        source=value["source"], run=value["run"], profile_sha256=value["profile_sha256"], ci_uses=value["ci_uses"]
    )
    _inventory, expected = scope(parent, value["ci_consumer"])
    if value != expected:
        _refuse()
    return value


def seal_evaluation(binding, output, *, _entry=None):
    """Only the evaluator's completed live CI result can discharge build inputs."""
    from .security_image_authority import _LIVE
    if _entry is not _EVALUATION_ENTRY:
        _refuse()
    validate_binding(binding)
    inventory, _ = scope(binding, binding['ci_consumer'])
    if (type(output) is not dict or output.get('status') != 'pass' or output.get('gaps') != []
            or output.get('inventory_digest') != inventory['digest']
            or type(output.get('policy_digest')) is not str
            or not re.fullmatch('[a-f0-9]{64}', output['policy_digest'])
            or type(output.get('details')) is not list):
        _refuse()
    records = _LIVE.setdefault('ci_license_evaluations', {})
    if len(records) >= 8:
        records.clear()
    records[id(output)] = (_RESULT_SEAL, output, digest(binding), digest(output))


def validated_evaluation(binding, output):
    from .security_image_authority import _LIVE
    validate_binding(binding)
    row = _LIVE.get('ci_license_evaluations', {}).get(id(output))
    if (type(row) is not tuple or len(row) != 4 or row[0] is not _RESULT_SEAL or row[1] is not output
            or row[2] != digest(binding) or row[3] != digest(output)):
        _refuse()
    return binding['ci_uses']['consumers'][binding['ci_consumer']]


def target_facts(value):
    validate_binding(value)
    return value["target"], tuple(value["ci_uses"]["consumers"][value["ci_consumer"]]["supported_tags"])


def verify_custody(binding, dependency, wheel_files, paths):
    return verify_custody_batch(binding, [(dependency, wheel_files, paths)])[0]


def verify_custody_batch(binding, entries):
    """Batch exact final WHEEL/LICENSE/NOTICE reads once per image installation."""
    from .security_image_authority import ci_member_evidence

    validate_binding(binding)
    inventory, _ = scope(binding, binding["ci_consumer"])
    expected, parts = {}, []
    for dependency, wheel_files, paths in entries:
        if (
            dependency not in inventory["dependencies"]
            or artifact_context(dependency).get("delivery_kind") != "installed-package"
        ):
            _refuse()
        wheel = [name for name in wheel_files if name.endswith(".dist-info/WHEEL") and name.count("/") == 1]
        if len(wheel) != 1:
            _refuse()
        requested = sorted(set([wheel[0], *paths]))
        if any(path not in wheel_files for path in requested):
            _refuse()
        part = {name: wheel_files[name] for name in requested}
        if any(name in expected and expected[name] != body for name, body in part.items()):
            _refuse()
        expected.update(part)
        parts.append(part)
    consumer = binding["ci_uses"]["consumers"][binding["ci_consumer"]]
    roots = consumer["site_packages"]
    if type(roots) is not list or not 1 <= len(roots) <= 2 or len(set(roots)) != len(roots):
        _refuse()
    matches = []
    for root in roots:
        try:
            observed = ci_member_evidence(
                binding["ci_uses"],
                binding["source"],
                binding["run"],
                binding["ci_consumer"],
                [root + "/" + name for name in sorted(expected)],
            )
        except ValueError:
            continue
        if all(observed.get(root + "/" + name) == body for name, body in expected.items()):
            matches.append(root)
    if len(matches) != 1:
        _refuse()
    return [
        dict(
            image=consumer["image"],
            base=consumer["base"],
            target_sha256=digest(binding["target"]),
            members={matches[0] + "/" + name: hashlib.sha256(body).hexdigest() for name, body in part.items()},
            assurance="exact installed WHEEL/license custody; no final runtime integrity claim",
        )
        for part in parts
    ]


_BASE_CODE = """import sys,sysconfig,os,json,hashlib
from pip._vendor.packaging.tags import sys_tags
from pip._vendor.packaging.markers import default_environment
tags=[str(t) for t in sys_tags()]
assert 1<=len(tags)<=4096 and len(tags)==len(set(tags))
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
value=dict(nonce=sys.argv[2],target=dict(schema_version=1,implementation=sys.implementation.name,python_version='.'.join(map(str,sys.version_info[:3])),platform=sysconfig.get_platform(),abi=sysconfig.get_config_var('SOABI'),tags_sha256=digest(tags),tag_count=len(tags),marker_environment=default_environment()),supported_tags=tags,site_packages=sorted(set(sysconfig.get_path(k).strip('/') for k in ('purelib','platlib'))))
body=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
assert len(body)<=262144
fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(body)
"""


def base_observation(value, nonce):
    if (
        type(value) is not dict
        or set(value) != {"nonce", "target", "supported_tags", "site_packages"}
        or type(nonce) is not str
        or not re.fullmatch("[a-f0-9]{32}", nonce)
        or value["nonce"] != nonce
    ):
        _refuse()
    target = _descriptor(value["target"])
    tags, roots = value["supported_tags"], value["site_packages"]
    if (
        type(tags) is not list
        or not 1 <= len(tags) <= 4096
        or len(set(tags)) != len(tags)
        or any(
            type(t) is not str or len(t) > 128 or not re.fullmatch("[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_]+", t) for t in tags
        )
        or target["tag_count"] != len(tags)
        or target["tags_sha256"] != digest(tags)
        or type(roots) is not list
        or not 1 <= len(roots) <= 2
        or len(set(roots)) != len(roots)
        or any(
            type(p) is not str
            or len(p) > 1024
            or p.startswith("/")
            or "\\" in p
            or not p.endswith("/site-packages")
            or any(v in {"", ".", ".."} for v in p.split("/"))
            for p in roots
        )
    ):
        _refuse()
    return dict(target=target, supported_tags=list(tags), site_packages=list(roots))


def observe_base(builder, base, volume, budget):
    """One fixed read-only interpreter probe through the existing native builder."""
    import json
    import shlex
    import tempfile
    import uuid
    from pathlib import Path
    from . import security_image_backend as native
    from . import security_image_authority as authority
    from .security_image_producer import _write, _unpack_export
    from .security_oci import active_limits, import_layouts, read_members, canonical, INDEX

    if (
        type(builder) is not native.BuildKit
        or authority._GUARD is None
        or builder.guard is not authority._GUARD
        or type(base) is not str
        or not re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}", base)
    ):
        _refuse()
    nonce = uuid.uuid4().hex
    member = "getzilla-observer-" + nonce + ".json"
    code = "exec(" + repr(_BASE_CODE) + ")"
    recipe = dict(context=".", dockerfile="Dockerfile", platform="linux/amd64", arguments={})
    with tempfile.TemporaryDirectory(prefix="python-base-", dir=volume) as owned:
        root = Path(owned)
        context, layout = root / "context", root / "oci"
        context.mkdir(mode=0o700)
        layout.mkdir(mode=0o700)
        dockerfile = (
            "FROM " + base + "\nRUN python -I -c " + shlex.quote(code) + " /" + member + " " + nonce + "\n"
        ).encode()
        _write(context, "Dockerfile", dockerfile)
        output = root / "export.tar"
        if builder.build(recipe, context, output, offline_control=True) is not native._ACTIVE:
            _refuse()
        descriptor = _unpack_export(output, layout)
        _write(layout, "oci-layout", canonical(dict(imageLayoutVersion="1.0.0")))
        _write(layout, "index.json", canonical(dict(schemaVersion=2, mediaType=INDEX, manifests=[descriptor])))
        reference = "getzilla.local/python-base-observer@" + descriptor["digest"]
        inventory = dict(
            digest=digest(dict(base=base, nonce=nonce)),
            complete=True,
            gaps=[],
            images=[dict(reference=reference, platform="linux/amd64")],
        )
        catalog = dict(
            schema_version=1,
            inventory_sha256=inventory["digest"],
            records=[dict(reference=reference, platform="linux/amd64", layout=str(layout))],
        )
        profile = dict(
            active_limits() if budget is None else budget.profile, images=[reference], platform="linux/amd64"
        )
        with import_layouts(catalog, inventory, profile, volume, _budget=budget) as images:
            raw = read_members(images[0], [member], member_limit=262144, total_limit=262144)[member]
            observed = base_observation(json.loads(raw), nonce)
            observed.update(
                base=base,
                observer_manifest=images[0].manifest_digest,
                observer_config=images[0].config_digest,
                observer_recipe_sha256=hashlib.sha256(dockerfile).hexdigest(),
            )
            return observed


def verify(artifacts, parent, index, policy, *, now=None):
    from .security_artifacts import read_file, MAX_INDEX_BYTES, MAX_ARTIFACT_BYTES, select_artifact, archive_files
    from .security_licenses import artifact_catalog_source
    import json

    inventory, binding = scope(parent, index)
    context = inventory["dependencies"][0]["delivery_context"]
    root = artifacts / "ci-installations" / context
    projection = artifact_catalog_source(inventory, root, policy, now=now, target_binding=binding)
    bundle = json.loads(read_file(root, "manifest.json", MAX_INDEX_BYTES))
    if len(bundle["records"]) != len(inventory["dependencies"]):
        _refuse()
    entries = []
    for dep in inventory["dependencies"]:
        record = select_artifact(dep, bundle["records"])
        files = archive_files(read_file(root, record["path"], MAX_ARTIFACT_BYTES), record["filename"])
        paths = [
            path
            for path in files
            if path.rsplit("/", 1)[-1].lower().startswith(("license", "copying", "notice"))
            or any(part.lower() in {"licenses", "licences"} for part in path.split("/"))
        ]
        entries.append((dep, files, paths))
    custody = verify_custody_batch(binding, entries)
    projection = dict(projection, installation_custody_sha256=digest(custody))
    return dict(inventory=inventory, binding=binding, root=root, projection=projection, custody=custody)


def prepare(artifacts, parent, *, now=None, fetch=None, byte_budget=512 * 1024 * 1024):
    from .security_factory_inputs import _catalog_bytes
    from .security_license_acquisition import acquire_pypi
    from .security_licenses import load_policy
    from .security_tools import TRUSTED_ROOT

    if type(byte_budget) is not int or not 0 < byte_budget <= 512 * 1024 * 1024:
        raise ArtifactError("artifact-size", "invalid shared CI package budget")
    policy = load_policy(TRUSTED_ROOT)
    used = _catalog_bytes(artifacts, now=now)
    if "factory_inputs" in parent:
        from .security_factory_inputs import verify as factory_verify

        used += factory_verify(artifacts, parent, policy, now=now)["projection"]["payload_size"]
    observed = []
    for index, consumer in enumerate(parent.get("ci_uses", {}).get("consumers", [])):
        if consumer.get("image_target_observed") is not True:
            continue
        inventory, binding = scope(parent, index)
        remaining = byte_budget - used
        if remaining <= 0:
            raise ArtifactError("artifact-size", "CI packages exceed shared aggregate budget")
        root = artifacts / "ci-installations" / inventory["dependencies"][0]["delivery_context"]
        options = {} if fetch is None else dict(fetch=fetch)
        acquire_pypi(
            inventory["dependencies"],
            root,
            inventory_digest=inventory["digest"],
            target_binding=binding,
            now=now,
            byte_budget=remaining,
            **options,
        )
        actual = verify(artifacts, parent, index, policy, now=now)
        used += actual["projection"]["payload_size"]
        if used > byte_budget:
            raise ArtifactError("artifact-size", "CI packages exceed shared aggregate budget")
        observed.append(actual)
    return observed
