"""Owner decision for one dockerd finding in the exact upstream amd64 build input."""
from datetime import datetime, timezone
import hashlib

from . import security_image_authority as authority
from .security_artifacts import read_file
from .security_oci import ImageSecurityRefusal, canonical, document
from .security_image_registry import DOCKER_CATALOG as CATALOG

FILE = '.getzilla/config/dind-vulnerability-exception.json'
CVE = 'CVE-2026-85747'
MANIFEST = 'sha256:a35dc0ba082450cbb4d372f2decb416eb71676b4788fbebdb10d1cd70fb9edae'
REFERENCE = 'docker:29.10.1-dind-rootless@' + MANIFEST
CATALOG_SHA = 'c9253aa7e20afe9db2e6604049c8bbe4b6e6c2144ee3baac763283eb9d9e2d42'
DECISION = dict(cve=CVE, manifest=MANIFEST, platform='linux/amd64', executable='usr/local/bin/dockerd',
                issue=456, expires='2026-12-25T00:00:00Z',
                reason='pull path unused (offline load) and engine has no egress; see engineering/reviews/dind-rootless-456.md')
CLI = dict(DECISION, executable='usr/local/bin/docker',
           executable_sha256='f71558dcbb6c2e028fc5c7cf67270ef6fafd9cc865570b73700d405b2c2ebc02',
           config='sha256:dd51adffd0d565cc8000986ae91e31a3bd476b852ad8b92a1f9c8ea4509a438f',
           layer='sha256:c270e2480dbc55f98c9730dd65b6df575be7d51a35a4057e9588f0dff7dd1bd3',
           reason='exact upstream build-input client absent from every final image; see engineering/reviews/dind-rootless-456.md')
EXPECTED = dict(schema_version=1, exceptions=[DECISION, CLI])
# A reviewed change to the deployed isolation, loader or job command requires requalification.
CONTROLS = '19881cc67303babc2a6a1fa3f85f34386261a0b4c02fdf6713d5f0e4c7fe4e23'


class InvalidDindPolicy(ImageSecurityRefusal):
    report_kind = 'invalid-dind-exception-policy'


def validate(config):
    if canonical(config) != canonical(EXPECTED):
        raise ValueError('invalid DinD vulnerability exception policy')


def active(now):
    return (now.tzinfo is not None and datetime(2026, 11, 25, tzinfo=timezone.utc) <= now
            < datetime(2026, 12, 25, tzinfo=timezone.utc))


def matches(finding, manifest, now):
    return (active(now) and manifest == MANIFEST and finding.get('id') == CVE
            and finding.get('target') == DECISION['executable'] and finding.get('image') == REFERENCE
            and finding.get('package') == 'github.com/docker/distribution'
            and finding.get('version') == 'v2.8.3+incompatible')


def same_upstream(catalog, index):
    if hashlib.sha256(catalog).hexdigest() != CATALOG_SHA or index.get('schemaVersion') != 2:
        return False
    entries = index.get('manifests', ())
    matches = [d['digest'] for d in entries if d.get('platform') == {'os': 'linux', 'architecture': 'amd64'}]
    return matches == [MANIFEST]


def control_digest(root):
    paths = ('compose.yaml', 'dind/Dockerfile', 'Dockerfile.worker', 'scripts/supply-chain-release.sh',
             'scripts/verify-supply-chain.sh', 'src/adaptive_trust_ci/runner_archive.py',
             'src/adaptive_trust_ci/runner_registry.py', 'src/adaptive_trust_ci/policy.py',
             'src/adaptive_trust_ci/sandbox.py', 'src/adaptive_trust_ci/worker.py')
    return hashlib.sha256(canonical([
        (p, hashlib.sha256(read_file(root, 'trust-ci/' + p, 256 * 1024)).hexdigest()) for p in paths])).hexdigest()


def qualify(root, inventory, registry):
    """Called solely during explicit acquisition inside the held build controller."""
    try:
        validate(document(read_file(root, FILE, 2048)))
    except (OSError, ValueError, TypeError) as error:
        raise InvalidDindPolicy('closed-dind-exception-policy-required') from error
    if not active(datetime.now(timezone.utc)) or control_digest(root) != CONTROLS:
        return False
    uses = [r for r in inventory['images'] if r['reference'].endswith('@' + MANIFEST)]
    if (len(uses) != 1 or uses[0]['platform'] != 'linux/amd64'
            or uses[0]['manifest'] != 'trust-ci/dind/Dockerfile' or uses[0]['reference'] != REFERENCE):
        return False
    try:
        _, catalog = registry.http.get(CATALOG, {}, 131072)
        _, raw, _ = registry._get('library/docker', 'manifests', '29.10.1-dind-rootless', 131072)
        return same_upstream(catalog, document(raw))
    except (OSError, ValueError, KeyError, TypeError):
        return False


def authorized_digest(inventory_sha):
    live = authority._LIVE
    return (isinstance(inventory_sha, str) and len(inventory_sha) == 64 and live is not None and authority._GUARD is not None and live.get('native_guard') is authority._GUARD
            and live.get('declared_inventory', {}).get('digest') == inventory_sha
            and live.get('run', {}).get('repository') == 'Dimkox/Getzilla' and live.get('dind_exception') is True)


def authorized(inventory):
    return authorized_digest(inventory['digest']) and authority._LIVE['declared_inventory'] == inventory


def partition(findings, image, inventory, now):
    if image is None or image.platform != 'linux/amd64' or not authorized(inventory):
        return findings, []
    blocking, accepted = [], []
    for finding in findings:
        if matches(finding, image.manifest_digest, now):
            accepted.append(finding)
        else:
            blocking.append(finding)
    return blocking, accepted


def removed_build_input_cli(row, base):
    from . import security_oci as oci
    from .security_image_components import _Files, _retain

    live = authority._LIVE
    if (row.get('path') != CLI['executable'] or row.get('layer') != CLI['layer']
            or row.get('sha256') != CLI['executable_sha256'] or base.manifest_digest != MANIFEST
            or base.config_digest != CLI['config'] or base.reference != REFERENCE or base.platform != CLI['platform']
            or live is None or not active(datetime.now(timezone.utc))):
        return False
    inventory = live['declared_inventory']
    images = live['images']
    if (not authorized(inventory) or inventory.get('complete') is not True or images.get(REFERENCE) is not base
            or set(images) != {use['reference'] for use in inventory['images']}):
        return False
    builds = live['builds']
    engines = [builds.get(build['build_sha256']) for build in inventory['builds']
               if build['service'] == 'docker-engine' and build['dockerfile'] == 'trust-ci/dind/Dockerfile']
    if (len(engines) != 1 or engines[0] not in images or REFERENCE in builds.values()
            or set(builds) != {build['build_sha256'] for build in inventory['builds']}
            or not set(builds.values()) <= images.keys()):
        return False

    evidence, observed = [], {}
    for reference, image in sorted(images.items()):
        if reference == REFERENCE:
            continue
        if image.reference != reference or image.manifest_digest == MANIFEST:
            return False
        history = image.layer_binary_hashes()
        if history is None:
            return False
        method = 'absent-from-all-layer-binary-hashes'
        if CLI['executable_sha256'] in history or reference == engines[0]:
            files = oci.observe_final_files(image, _retain)
            if any(member.get('sha256') == CLI['executable_sha256'] for member in files.values()):
                return False
            if reference == engines[0] and (CLI['executable'] in files or _Files(files).resolve(CLI['executable'])[1]):
                return False
            observed[image] = files
            method = 'verified-final-filesystem'
        evidence.append(dict(reference=reference, manifest=image.manifest_digest, config=image.config_digest,
                             method=method))
    live['dind_cli_component_rows'] = observed
    live['dind_cli_removal'] = dict(exception=CLI, inventory_sha256=inventory['digest'], images=evidence)
    return True
