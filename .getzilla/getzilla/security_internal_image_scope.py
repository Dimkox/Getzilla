"""Owner decision #456 for license evidence of the reviewed, non-shipped CI images."""
from .security_artifacts import ArtifactError

GAP_CODES = frozenset((
    "dpkg-binary-license-scope", "dpkg-legacy-license-scope", "dpkg-copyright-format-unproved",
    "license-text-unrecognized", "license-term-unproved", "cpython-bundled-terms-unproved",
))
_INTERNAL_USES = frozenset((
    ".getzilla/config/ci-images.json", ".github/workflows/getzilla.yml",
    "trust-ci/Dockerfile.api", "trust-ci/Dockerfile.test", "trust-ci/Dockerfile.worker",
    "trust-ci/dind/Dockerfile", "trust-ci/runner.Dockerfile", "trust-ci/compose.build.yaml", "trust-ci/compose.test.yaml",
    "trust-ci/compose.yaml",
))


def validate_policy(repository, block):
    if (repository.lower() != "github.com/dimkox/getzilla"
            or type(block) is not dict or set(block) != {"decision", "internal", "report_only_gaps"}
            or block["decision"] != "owner 2026-11-25, #456" or block["internal"] != "report-only"):
        raise ArtifactError("license-policy-review", "invalid internal image license decision")
    codes = block["report_only_gaps"]
    if (type(codes) is not list or any(type(code) is not str for code in codes)
            or len(codes) != len(GAP_CODES) or set(codes) != GAP_CODES):
        raise ArtifactError("license-policy-review", "internal image license gap inventory differs")
    return dict(block, report_only_gaps=list(codes))


def declare_internal_uses(inventory):
    # collect_inventory classified the entire source, including ZIP/Factory builders,
    # all input bytes and publication workflows. Packaging changes require a new
    # independent distribution review even if the ordinary source pin is refreshed.
    from .security_corresponding_source import CATALOG, SURFACE_SHA256, IMAGE_DELIVERY_SURFACE_SHA256
    if (SURFACE_SHA256 != IMAGE_DELIVERY_SURFACE_SHA256
            or len(inventory.get("corresponding_sources", ())) != len(CATALOG)
            or inventory.get("gaps")):
        return
    for use in inventory["images"]:
        if use.get("manifest") in _INTERNAL_USES and not {"distribution", "delivery_context", "delivery_kind"} & use.keys():
            use["distribution"] = "internal"


def image_scopes(subjects, images, delivery=None):
    """Classify every declared use; a shipped alias or shared layer takes precedence."""
    from .security_referenced_image import FACTORY_REFERENCE, PG, distribution
    if set(images) != {row["reference"] for row in subjects}:
        return set(), set()
    referenced, strict = set(), set()
    for row in subjects:
        ref = row["reference"]
        image = images[ref]
        if (row.get("manifest") == "factory/compose.yaml" and row.get("source_reference") == FACTORY_REFERENCE
                and row.get("distribution") in {None, "redistributed"} and "delivery_context" not in row
                and "delivery_kind" not in row and image.manifest_digest == "sha256:" + PG and delivery
                and distribution(delivery, image.layer_identities, image.layer_binary_hashes()) == "referenced"):
            referenced.add(ref)
        elif (row.get("distribution") != "internal" or row.get("manifest") not in _INTERNAL_USES
              or "delivery_kind" in row or "delivery_context" in row):
            strict.add(ref)
        if delivery and any(digest.removeprefix("sha256:") in delivery[0] for digest in image.layer_identities):
            strict.add(ref)
    strict_layers = set()
    for ref in strict:
        if not images[ref].layer_identities:
            return set(), set()
        strict_layers.update(images[ref].layer_identities)
    eligible = {ref for ref, image in images.items() if ref not in strict and image.layer_identities
            and image.layer_identities.isdisjoint(strict_layers)}
    return eligible, referenced & eligible


def internal_images(subjects, images):
    return image_scopes(subjects, images)[0]


def partition(rows, internal):
    observations, blocking = [], []
    for row in rows:
        (observations if internal and row["code"] in GAP_CODES else blocking).append(row)
    return observations, blocking
