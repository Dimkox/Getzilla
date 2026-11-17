# Core Packagist artifact evidence

`security_license_acquisition.acquire_pypi(dependencies, destination, *,
inventory_digest, fetch=bounded_default, now=None, families=None)` retains its
existing interface and now dispatches exact `Packagist` dependencies as well as
PyPI. The standalone acquisition CLI uses the same producer. The ordinary
`security_cli.prepare_inputs` and explicit refresh paths already call this
producer; no installation, resolution, plugin or package execution occurs.
Unsupported ecosystems still produce explicit acquisition gaps.

The dependency uses the existing `ecosystem`, `name`, `version`, `manifest`,
`usage`, optional observed artifact selectors and delivery/context fields.
Names must be canonical lowercase vendor/package identities. Versions must be
exact stable numeric releases, optionally prefixed with `v`. Development tags,
non-GitHub distributions and ambiguous releases remain unsupported gaps.

The producer saves the complete official response from
`https://packagist.org/packages/<vendor>/<package>.json` under its SHA256. It
selects exactly one requested release and binds source and dist to the same
full Git commit and GitHub repository. Only exact GitHub API commit ZIP URLs
and their same-repository/same-commit codeload redirects are accepted. Each
archive retains its actual SHA256. A nonempty registry SHA1 must also match;
when the registry supplies none, the producer does not invent a checksum.
The ZIP must satisfy the existing archive guards, contain one root directory,
and have an exact commit comment matching source/dist metadata.

The evaluator re-reads the saved index and archive on consumption. Root
`composer.json` must match the registered name, license and runtime
require/conflict/provider/replacement metadata. If it embeds a version, that
version must agree. If absent, the version is explicitly registry-derived;
this is never reported as an embedded version. The verified origin exposes
source commit and metadata hashes without dumping arbitrary registry text.

`security_licenses.evaluate_artifacts(inventory, artifacts, policy, *, now=None)`
and `artifact_catalog_source` accept these records through their existing
catalog interfaces. The evaluator uses retained complete license/notice text,
the unchanged six-license policy, and the existing explicit distribution and
delivery rules. PHP program files such as `src/License.php` that start with a
PHP opening tag are source code, not separate license-text documents. Other
license/copying/notice candidates still require the ordinary text validation.

Runtime package requirements must be covered by one exact version in the same
Composer lock manifest and delivery context. Supported stable constraints are
numeric equality/comparisons, `^`, `~`, comma/space conjunction, `||` alternatives
and `*`. Unknown forms refuse; this adapter is not Composer's resolver. An
installed package matching a declared conflict refuses. Virtual provide/replace
and platform conflicts require further qualified coverage.

PHP/extension/library requirements remain explicit. The caller must supply
actual target observations in `inventory['marker_environment']['composer_platform']`:
version strings for version constraints, or exact `True` for an observed present
extension whose constraint is `*`. Missing facts refuse transitive coverage.
Source ZIPs never supply these facts. Existing `collect_inventory` does not
observe a PHP target; a standalone caller must bind its observed target facts
and complete inventory digest before acquisition/evaluation. A partial package
set or PHP version alone cannot establish complete platform coverage.

An explicit caller passes its complete, current inventory to `acquire_pypi`,
then the same inventory, artifact directory and project-owned license policy
to `evaluate_artifacts`. Do not set completeness or invent a policy/target to
obtain PASS. Native public evaluation additionally retains its independent
source/run/profile contract and all other applicable input families.

All existing ceilings remain: 512 selected dependencies, 512 MiB acquisition
batch, 128 MiB artifact, 16 MiB index, 2 MiB metadata member, 256 MiB unpacked
archive, 10000 archive members and 72-hour freshness. Existing fetch timeout,
redirect and atomic manifest-last publication rules remain. Failures preserve
explicit gaps; a failed pre-publication acquisition does not replace the catalog.

These are local consistency and retained-byte checks, not publisher
cryptographic authentication, independent registry attestation, legal approval,
provider execution or production acceptance. Actual Composer locks/archives
from another task are observations, not qualification transferred here.

Contracts: [Packagist API](https://packagist.org/apidoc),
[Composer versions](https://getcomposer.org/doc/articles/versions.md),
[Composer schema](https://getcomposer.org/doc/04-schema.md).
