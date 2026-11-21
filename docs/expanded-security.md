# Expanded security evidence

The expanded gate evaluates applicable objects from the actual source inventory.
An unresolved manifest, build dependency, executable tool or image is a coverage
gap. It is not evidence that no objects exist. Runtime state, dependency caches
and explicit fixture paths are excluded from discovery and disclosed in the
inventory. Unbound deployment templates remain unresolved until their actual
artifact scope and immutable references are supplied.

## Structural YAML inventory

Compose and GitHub Actions manifests are read as YAML syntax events. Block and
flow collections, quoted keys and values, job containers, service images and
step action references use the same structural traversal. Each accepted input
is bound to its exact source-byte SHA-256 and declarations retain source lines.
`docker://` action references create image obligations. Images need immutable
SHA-256 references; external actions need full commit references. Observed
Compose image-variable bindings remain supported.

The qualified checker interpreter needs the PyYAML event interface when these
YAML manifests are present. This is an operational requirement, **not a claim
that PyYAML is shipped or installed by every Getzilla consumer**. The parser is
loaded lazily. Missing parser capability produces `yaml-parser-unavailable`
and an incomplete inventory; it does not produce a structural absence result.
Projects without relevant YAML, and excluded fixtures, do not need this parser.
Getzilla does not install dependencies while collecting inventory.

The reader permits one document, at most 1 MiB of source bytes, 64 levels of
nesting, 20,000 nodes and 64 KiB per scalar. The alias limit is zero. Anchors,
aliases, merge keys, duplicate decoded keys, explicit tags, schema directives,
complex keys, multiple documents and unsupported structural types cause an
explicit coverage gap. No YAML object constructor, workflow or Compose command
is executed. The reader does not validate the whole workflow or Compose schema.

Compose `include`, `extends`, `build` and external providers, and local or
reusable Actions workflow/action references, require a qualified composition
adapter. Until then they remain incomplete even when a visible image or action
reference is also recorded. Dynamic references, mutable tags and unknown
required subtrees also remain unresolved. These gaps keep applicable security
checks required and blocked; they cannot justify `not_applicable`.

## One required result set

The isolated public Getzilla job requires these eleven results:

| Result | Required evidence |
| --- | --- |
| `security-inventory` | Source manifests, exact dependency identities, tools, images and coverage gaps |
| `known-vulnerabilities` | Complete offline OSV ecosystem snapshots and all unaccepted findings |
| `security-kev` | Current CISA catalog plus the OSV/image sources that supplied CVE identities |
| `security-epss` | Current EPSS acquisition and forecast date, plus the source CVE identities |
| `security-malicious-packages` | Active MAL records from complete OSV ecosystem snapshots |
| `security-licenses` | Actual artifact/index/license bytes, project policy, distribution scope and obligations |
| `security-container-images` | Immutable image digest/ID, actual package inventory and current Trivy DB |
| `opengrep` | Pinned executable, checker-owned rules and observed target coverage |
| `secret-scan` | Bounded text-pattern scan with redacted observations and disclosed binary inputs |
| `bandit` | Checker-owned settings and actual Python coverage |
| `trivy-config` | Pinned built-in checks and actual supported IaC target coverage |

The text scan reads UTF-8, BOM-qualified UTF-16/UTF-32 text and a closed set
of standard Python source encodings (ASCII, UTF-8, Latin-1 and Windows
1251/1252). It does not load candidate codec names. Decodable text is scanned
even when its name and prefix resemble an image or font. In opaque assets
the same patterns also inspect visible bytes; this does not cover compressed
or otherwise hidden content. Raw-byte findings include the byte offset and no
secret value. Unknown undecodable inputs and NUL-bearing text remain coverage
gaps even when a visible byte pattern is found. BOM-qualified wide text is
also checked for separately embedded sequences of visible bytes.

The wire statuses remain `pass`, `fail`, `skip` and `cancelled`. A permitted
`skip` needs a versioned `security-result` with `outcome=not_applicable` and a
complete inventory proof. Missing tools, unsupported formats, stale sources,
failed acquisition, empty scanner output and cancelled work cannot qualify.
Trivy configuration coverage includes Dockerfiles and Terraform. It does not
claim Docker Compose schema coverage; native component checks own that scope.

## Data freshness

Each source has its own `last_verified_sync_utc`. Accepted age is inclusive:
zero through 259200 seconds. A failed refresh, copied file or changed mtime does
not renew it. Atomic snapshot manifests name immutable objects by SHA-256.
Legacy `all.zip` files without verified metadata do not qualify.

Old vulnerability publication dates may remain relevant in a freshly acquired
OSV or KEV catalog. EPSS also requires a forecast date within the same 72 hours.
Trivy requires both its actual `DownloadedAt` and `UpdatedAt` within that bound.
Missing EPSS scores remain unknown; they are never replaced with zero. No EPSS
threshold clears a vulnerability. Generic OSV exceptions do not clear new KEV
or malicious-package matches.

The required plan retains exact source hashes, acquisition metadata and coverage.
Its final consumer reads those sources again. The artifact catalog binding also
rechecks raw manifest, index, archive and delivered bytes, policy and inventory.
Its `coverage.complete` describes referenced catalog records, not a claim that
the catalog covers every required package, tool or image.

## Licenses and project scope

Automatic decisions are limited to MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause,
ISC and 0BSD, with exact artifact evidence and fulfilled applicable obligations.
`AND` requires every part; `OR` records a chosen permitted branch. Unknown SPDX
identifiers, custom exceptions, incomplete text and conflicting metadata require
human review. This is a limited parser and text recognizer, not an assertion that
all SPDX expressions or license variants have been supported.

`.getzilla/config/license-policy.json` is bound to the project's repository
identity. Copying Getzilla's configuration into another project does not approve
that project's policy. `usage_distribution` must explicitly select internal use
or redistribution for each applicable usage group; an empty mapping blocks an
automatic decision. Redistributed artifacts require evidence of retained terms
and notices. Dev tools with other licenses are reviewed, not categorically banned.

Artifact acquisition and receipt consumption preserve multiple targets for the
same package version. An artifact identity binds ecosystem, name, version,
filename (including platform and ABI), SHA-256, saved registry URLs/index digest,
and its exact `context`. Acquisition copies `manifest`, `usage`, `distribution`,
`delivery_context` and `delivery_kind` from the observed dependency into that
context. Optional `artifact_filename`, `artifact_sha256` and `artifact_source`
(the registry artifact URL) select one exact source. Ambiguous targets fail.
Transitive coverage stays within the same named `delivery_context`.

Use separate context names for the standalone Factory wheel, its offline
archive and each Trust CI target. `delivery_kind=installed-package` describes
internal installation. `unchanged-artifact` can qualify a named redistributed
wheel only when its `redistributed_path` retains the exact original bytes.
`factory-offline-archive` requires actual final output evidence; retaining an
input wheel cannot qualify this output. Legacy unnamed wheel evidence remains
limited to its original unchanged-artifact claim.

The artifact manifest's optional `deliveries` list supplies offline evidence.
Each record contains `context`, `kind=factory-offline-archive`,
`profile=ubuntu-24.04-x86_64-cpython312`, archive `path` and `sha256`,
`manifest_path` and `manifest_sha256`, `sidecar_path`, and `components`.
Each component names the exact source `artifact_id` returned by
`security_artifacts.artifact_identity(record)` and `prefix=site-packages/`.
The verifier reads the actual ZIP, detached Factory member manifest and the
builder's two-line checksum file. It compares every extracted wheel member
against its source bytes, including all license and notice files. Missing,
changed, extra, colliding or unlisted components fail even when an output's
checksums were renewed. Native source wheels must use CPython 3.12 and the
current profile's manylinux2014/manylinux_2_17 x86_64 tags; universal wheels
remain supported. Final receipt consumption rechecks these output bytes.

This adapter establishes local artifact integrity for the named archive only.
It does not approve another installed package, tool, Action, image, production
delivery or an unsupported license. Those classes retain their explicit gaps.
It does not change the six-license policy or renew the catalog's 72-hour age.

PyPI acquisition stores the registry JSON and selected exact archive without
installing or executing it. Direct pins do not prove transitive completeness.
Unknown conditional dependency markers and uncovered tools/images remain gaps.
Root repository license labels and an incomplete SBOM do not license a bundled
executable's complete contents.

## Separate checker and explicit acquisition

Run the code from a separately selected, reviewed checker commit:

```sh
python -I trusted-checker/scripts/getzilla_security.py \
  --root candidate \
  --database /isolated/security-data \
  --artifacts /isolated/security-artifacts \
  --tools /isolated/security-tools \
  --refresh --provision-tools \
  --json-out /isolated/security-expanded.json
```

Only explicit `--refresh` acquires feeds, package artifacts and immutable images.
Only `--provision-tools` installs the reviewed Linux x86_64 OpenGrep/Trivy assets
into the isolated tool directory. Scanner input is a bounded source-byte copy;
candidate modules, ignore files and tool configuration are not loaded. Reports
bind candidate/checker commits and trees, current inventory and policy digests.

Local results have `assurance=local-input-integrity-only`. Artifact evaluation
has `artifact-integrity-only` assurance. Hashes and JSON cannot establish their
own publisher or execution authority. A candidate-controlled Actions workflow
also cannot manufacture independent trust by writing these fields.

The public workflow uses `GETZILLA_SECURITY_CHECKER_SHA` or the PR base commit.
The first deployment is explicitly blocked when that selected commit lacks the
checker. Selecting the first trusted commit requires a concrete independent
review and operator decision. See [isolated acceptance](isolated-ci-acceptance.md)
for the separate live jobs and the required fail-closed aggregate.

## Getzilla acceptance: artifact use and distribution

The public source and installer, the Factory package and the Factory offline
archive are redistributed outputs. The approved CI tools, GitHub Actions,
CI images and Trust CI components used for isolated public-repository checks
are internal verification inputs. Third-party CI tools and images are not
published as part of this scope. A future distribution of these objects needs
a separate decision. This decision is specific to Getzilla; an installation in
another repository does not inherit its license policy.

`usage_distribution` accepts a usage default and an exact
`manifest:<repository-relative path>#<usage>` key. The exact decision takes
precedence. An incompatible observed use is a gap. The pinned CI requirements
use the `build-ci` default. `trust-ci/requirements-test.txt` supplies the
isolated Trust CI tests. No default is inferred for `runtime-and-development`:
Factory's lock includes both production dependencies and test-only packages.

A scope decision records intended use; it does not prove artifact contents.
The Factory offline builder installs files extracted from wheels. Validation
must bind the completed archive and its retained license/NOTICE files to the
actual delivered bytes and approved target profile. Cached source wheels do
not establish that link. Tools and images still require exact component and
license evidence. The six approved licenses and per-artifact obligations are
unchanged; uses outside those verified license alternatives and unresolved
composition require review.

For the approved Factory offline profile the project policy pins the exact lock,
validated wheel inventory and builder bytes. Only a byte-identical input set in
Getzilla yields its intended redistributed wheel identities. Changed inputs
require mechanical validation with the trusted builder before publishing new
pins. The checker reads data only; it does not import or run the candidate's
builder. This output-level observation is separate from registry acquisition:
the same package/version can target CPython 3.12 in Factory and a different ABI
in Trust CI. Missing proof for the final extracted archive is a delivery gap,
not an unanswered question about the 20 declared wheels. No cached original
wheel can satisfy this gap. The separately installed ordinary Factory wheel
has a distinct composition; its dependency declarations do not establish that
it bundles these 20 wheels.

This diagnostic field does not change existing license-check statuses, findings,
gaps or flat-catalog semantics. It is not a new permanent gate, and a passing
legacy package check is not acceptance of the extracted offline archive. A
separate output-specific consumer remains required before such acceptance.
