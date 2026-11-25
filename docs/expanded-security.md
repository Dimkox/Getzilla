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

The isolated public Getzilla job requires these ten results:

| Result | Required evidence |
| --- | --- |
| `security-inventory` | Source manifests, exact dependency identities, tools, images and coverage gaps |
| `known-vulnerabilities` | Complete offline OSV ecosystem snapshots and all unaccepted findings |
| `security-kev` | Current CISA catalog plus the OSV/image sources that supplied CVE identities |
| `security-epss` | Current EPSS acquisition and forecast date, plus the source CVE identities |
| `security-malicious-packages` | Active MAL records from complete OSV ecosystem snapshots |
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
The final consumer reads those sources again.

## License evaluation

The owner disabled license evaluation for every input and output on 2026-11-25. The checker records `license evaluation: disabled by owner decision 2026-11-25` and acquires no license evidence or corresponding source. Factory continues to ship its existing legal files. Component ownership, ecosystem coverage, vulnerabilities, secrets and image integrity remain required.

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

Only explicit `--refresh` acquires feeds and immutable images.
Only `--provision-tools` installs the reviewed Linux x86_64 OpenGrep/Trivy assets
into the isolated tool directory. Scanner input is a bounded source-byte copy;
candidate modules, ignore files and tool configuration are not loaded. Reports
bind candidate/checker commits and trees, current inventory and policy digests.

Local results have `assurance=local-input-integrity-only`. Hashes and JSON cannot establish their
own publisher or execution authority. A candidate-controlled Actions workflow
also cannot manufacture independent trust by writing these fields.

The public workflow uses `GETZILLA_SECURITY_CHECKER_SHA` or the PR base commit.
The first deployment is explicitly blocked when that selected commit lacks the
checker. Selecting the first trusted commit requires a concrete independent
review and operator decision. See [isolated acceptance](isolated-ci-acceptance.md)
for the separate live jobs and the required fail-closed aggregate.

## Image identity and PostgreSQL coverage

The source-built PostgreSQL server in the OCI corpus has a separate check against the
[official PostgreSQL 17 advisory table](https://www.postgresql.org/support/security/17/).
The checker compares the image configuration with the version string in the exact
server executable and records its SHA-256, layer digest, feed date and matching
core-server CVEs. It rejects unknown binaries, missing or changed reviewed advisories,
unknown layouts and responses older than 72 hours. A PostgreSQL refusal or CVE blocks
admission during the #456 infrastructure waiver. The other image components retain
their existing scanner obligations.

The source ZIP contains standalone image manifests and configurations for offline identity verification. Factory obtains its digest-pinned PostgreSQL image from Docker Hub.
