# Local deployment preflight

`getzilla deploy preflight` checks the consistency of a local public deployment package. It compares an operator, its artifacts and the project's `secret_consumers` registration. A successful result is an observation for review. It does not authorize or perform a deployment.

```bash
getzilla deploy preflight --root /absolute/path/to/project --manifest deployment/preflight.json --json
```

The root is required. The manifest path is relative to that root, including when the command runs from a subdirectory. The CLI prepares and immediately rechecks one in-memory observation. It accepts no saved observation token. Its exit codes are:

| Code | Meaning |
| --- | --- |
| `0` | `ready_for_review`: local inputs and registration match; execution is still unavailable |
| `1` | `blocked`: a fixed diagnostic explains an unsafe, missing, changed or unsupported input |
| `2` | Invalid command arguments; their values are not echoed |

The existing flat `getzilla deploy`, `deploy --json` and `deploy --record --json` commands retain release preparation and receipt approval behavior. `preflight --record` is refused before inputs are read.

## Manifest and registration

The [versioned schema](../schemas/deploy-preflight-manifest-v1.schema.json) describes the JSON structure. This example uses synthetic identifiers. Its zero hashes are placeholders and deliberately do not qualify a real package. Replace them with hashes of reviewed public files and the reviewed recovery descriptor. Check the source changes before rebuilding expectations.

```json
{
  "schema_version": "getzilla-deploy-preflight-v1",
  "project_id": "example",
  "operation": "dev-delivery",
  "operator": {
    "path": "deployment/operator.py",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "mode": 420,
    "revision": {"label": "reviewed-operator-v1", "git": null}
  },
  "artifacts": [{
    "path": "public/application.js",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "mode": 420
  }],
  "artifact_revision": {"label": "reviewed-payload-v1", "git": null},
  "target": {"identity": "dev-example", "destination_id": "web-assets", "transport": "local-fixture"},
  "credential_selector": ".env.fixture",
  "recovery": {
    "protocol_id": "fixture-only",
    "version": "v1",
    "descriptor_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

Mode `420` is POSIX `0644`. Modes are checked exactly on POSIX. Windows returns `MODE_UNSUPPORTED` before reading inputs; v1 does not claim portable mode verification.

The fixed `.getzilla/config/project-policy.json` must contain a `secret_consumers` array. The operator needs an existing record with its exact portable relative script path and the exact selector string. Preflight never adds a record. Absolute, outside-root or nonportable script spellings cannot match preflight registration; existing command authorization keeps its own unchanged identity rules. A registration match proves only that this metadata exists. It neither admits a command nor approves the operator bytes.

The selector is metadata only. Its credential file is not opened, expanded, resolved or inspected. Policy selectors from every record exclude possible local aliases, even when that record does not match the operator. Dot components, separators, absolute paths under the root and Unicode/case equivalents are normalized only for exclusion. Overlap, expansion/glob syntax, foreign roots and ambiguous selectors block public reads. Lexically outside absolute POSIX selectors are not resolved. Unknown physical aliases and secrets copied into otherwise public files are outside this path-based guarantee.

Public admission combines the strict sensitive-file classifier with the full built-in `DEFAULT_SECRET_READ` path exclusions. This includes coding-agent and cloud credential stores, `secrets/**` and Trust CI runtime. Template or public-key exceptions do not weaken this floor. Preflight uses this built-in floor plus the registered and declared selector exclusions; it does not load or bind custom `secret_read_paths` from `.getzilla/config/policy.json`. It is therefore not an evaluation of the complete effective command-admission policy. Projects must keep their proposed inputs public and account for additional project-specific exclusions before running this local observation.

## What the observation binds

The implementation admits the manifest before opening it, then admits the complete payload inventory before opening any payload. It uses bounded regular single-link reads and rejects sensitive file classes, traversal, reserved paths, control-file overlap and path collisions. The fixed policy is the configuration bootstrap input.

Both passes compare all input bytes, modes and file identities, including policy and manifest. The observation binds the filesystem root, manifest spelling, input digests, registration, schema and algorithm revision, and a 300-second lifetime. A recheck performs fresh reads. A same-path operator replacement, revoked policy, changed target or artifact, different root, clock rollback or expiry blocks reuse. Rebuilding a manifest creates different expectations and cannot establish reviewed provenance.

Input JSON is limited to 64 KiB and eight nesting levels. Duplicate keys, nonfinite values and manifest floating-point numbers are refused. The schema covers structure; runtime checks also enforce lexical integer spelling, path relationships and read admission. Policy records are limited to 64, each with at most 64 selectors. There are at most 128 artifacts, 16 MiB per payload file and 64 MiB of payload per pass. A ten-second monotonic budget is checked at read boundaries. Filesystem refusals, including size limits enforced by the bounded reader, produce fixed diagnostics. This budget does not interrupt a stalled kernel I/O call.

## Boundaries of a successful result

Every result fixes `dispatch_permitted` and `operational_grant` to `false`, and `connection` and `delivery` to `not_attempted`. Git provenance always remains `unverified`, even when the manifest declares plausible commit/tree IDs. Recovery remains `declared_unverified`; a protocol name or descriptor hash proves no crash behavior. A missing registration may coexist with a matched public package, but the result is blocked.

Preflight imports or executes no operator, starts no subprocess, uses no network and touches no target or lock. It creates no route, grant, receipt, recovery journal or import cache during ordinary CLI startup. The existing `getzilla` launcher still starts its normal Python dispatcher process. Reports contain fixed status fields, diagnostic codes, hashes and times; they omit paths, selectors, raw exceptions and command output.

The observation checksum is unkeyed consistency evidence, not authentication. Installed Getzilla is trusted. Relevant algorithm or ABI changes must bump `ALGORITHM_REVISION`; v1 does not attest loaded executable code or inspect module files, so ZIP engines remain supported. Two passes do not provide a global atomic snapshot or isolation from a hostile concurrent writer. Changes after the observation can invalidate it.

Exact Git provenance, execution admission, shared-lock crash recovery and independent DEV readback require separate qualification. A new manifest alone does not complete those steps or close the deployment-readiness issue.
