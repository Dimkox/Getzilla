"""Owner decision #456 for license evidence of the reviewed, non-shipped CI images."""
from .security_artifacts import ArtifactError

GAP_CODES = frozenset((
    "dpkg-binary-license-scope", "dpkg-legacy-license-scope", "dpkg-copyright-format-unproved",
    "license-text-unrecognized", "license-term-unproved", "cpython-bundled-terms-unproved",
))
_INTERNAL_USES = frozenset((
    ".getzilla/config/ci-images.json", ".github/workflows/getzilla.yml",
    "trust-ci/Dockerfile.api", "trust-ci/Dockerfile.test", "trust-ci/Dockerfile.worker",
    "trust-ci/runner.Dockerfile", "trust-ci/compose.build.yaml", "trust-ci/compose.test.yaml",
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


def internal_images(subjects, images):
    """All aliases and compressed and uncompressed layers of a shipped use stay strict."""
    if set(images) != {row["reference"] for row in subjects}:
        return set()
    strict = {row["reference"] for row in subjects if row.get("distribution") != "internal"
              or row.get("manifest") not in _INTERNAL_USES or "delivery_kind" in row or "delivery_context" in row}
    strict_layers = set()
    for ref in strict:
        if not images[ref].layer_identities:
            return set()
        strict_layers.update(images[ref].layer_identities)
    return {ref for ref, image in images.items() if ref not in strict and image.layer_identities
            and image.layer_identities.isdisjoint(strict_layers)}


def partition(rows, internal):
    observations, blocking = [], []
    for row in rows:
        (observations if internal and row["code"] in GAP_CODES else blocking).append(row)
    return observations, blocking
