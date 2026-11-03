# Expanded security evidence

The expanded gate evaluates applicable objects from the actual source inventory.
An unresolved manifest, build dependency, executable tool or image is a coverage
gap. It is not evidence that no objects exist. Runtime state, dependency caches
and explicit fixture paths are excluded from discovery and disclosed in the
inventory. Unbound deployment templates remain unresolved until their actual
artifact scope and immutable references are supplied.

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
