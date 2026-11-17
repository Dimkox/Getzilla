# Core public checker API v1

This in-process Python API lets an independently selected checker consume a
candidate as source data. The protected caller must obtain its own provider,
runner and workflow observations. Core validates local identity, currentness
and bytes. These checks do not grant provider authority or human approval.

```python
security_cli.public_input_scope(
    root, database, artifacts, tools, *, context,
    image_artifacts=None, declared_at=None, now=None,
)
security_cli.evaluate_public(
    root, database, artifacts, tools, *, context,
    image_artifacts=None, declared_at=None, now=None,
)
```

`public_input_scope` is a context manager. Keep it open through consumption.
It yields `inventory`, `environ`, `profile`, `run`, `image_artifacts`,
`image_selection` and `binding`. The binding contains `context`, `declared_at`,
`source_catalog_sha256`, `selection_sha256` and `profile_sha256`.
`evaluate_public` calls the canonical `evaluate` with `refresh=False` and
`provision=False`. It attaches the binding at `report['public_inputs']`.
The ordinary finalizer, required checks and freshness rules still decide the
report result. A declaration is never a passing scan result.

## Source and runner authority

The closed context object has exactly these keys:

```text
kind = "getzilla-public-execution-v1"
repository, repository_id, pr_number, base_sha, head_sha, tree_sha,
checker_sha, checker_tree_sha, runner_repository, runner_repository_id,
runner_sha, runner_tree_sha, workflow_id, workflow_blob_sha, run_id, run_attempt
```

Repository names have `owner/name` form. The six numeric identities are positive
exact integers, excluding booleans. All eight SHA identities are lowercase
40-character hexadecimal strings. Candidate/checker commits and trees must
match independent Git observations. Both checkouts must be clean and paired
to the same project. The source envelope is exactly `head_sha`, `tree_sha`,
`checker_sha`, `checker_tree_sha`, `candidate_clean`, `checker_clean`,
`same_project`.

Only the in-process ContextVar scope permits a separately observed runner
commit. Its run object is exactly `provider="github-actions"`, `repository`
(the runner repository), `run_id`, `run_attempt` and `head_sha` (the runner
commit); numeric run fields are decimal strings. Outside this scope, native
run head must equal candidate head. JSON files and environment variables
cannot install this authority. Context reads return detached copies. Nested
scopes restore prior context, including on exceptions.

## Explicit source uses and catalogs

Selection v1 is a closed JSON object:

```text
{schema_version: 1, source, run, created_at, uses: [
  {path, line, source_sha256, expression, reference, platform}
]}
```

The reader accepts at most 64 KiB and 1–512 uses. Each use binds an exact current
path, positive source line, SHA256 of the complete source file, source value
expression, immutable `name@sha256:<64 lowercase hex>` reference and supported
platform (`linux/amd64` or `linux/arm64`). Missing, duplicate, conflicting,
drifted or unused selections refuse completeness. An explicit empty binding
list cannot become default discovery. Legacy explicit variable-name dictionaries
remain supported by `collect_inventory(root, *, image_bindings=None)`.

Compose inventories both the service image and the explicit
`TRUST_CI_RUNNER_IMAGE` value in mapping or `KEY=value` sequence environment
form. The runner use has the value node's actual source line and expression.
Its selected platform must agree with the service's literal platform when one
is declared. Bare, empty or duplicate runner inputs refuse completeness. Core
does not read the process environment to resolve that input or discover other
environment image names. CI image configuration uses the same selection join
and retains its existing immutable config ID and usage fields.

Selected image rows remain `declaration-only-unverified`. The closed OCI catalog
has `schema_version=1`, `inventory_sha256`, `records` and optional
`source_bindings` and `source_catalog_sha256`. Each record is exactly
`reference`, `platform`, `layout`. Source bindings use exactly `manifest`,
`line`, `source_sha256`, `source_reference`, `reference`, `platform`.
Every selected binding must match a real current source use and selected
artifact. The catalog must cover the complete immutable image inventory.

Public input roots are explicit sibling `database`, `artifacts`, `tools`
directories in one snapshot. The input catalog and layout paths must stay in
that snapshot. Core validates the original source-bound catalog before it
projects the inventory digest to include the run declaration. The projection
retains the original catalog hash; nested projection is refused. Owned control
files live outside the candidate and snapshot and expire at scope exit.

`expanded_security.selected_inventory(root, *, environ=None, now=None)` reads
the catalog and selection again, validates independently observed source/run,
current profile, policy, roots and timestamps, and detects drift during the
read. The five default consumers use it: obligations, vulnerability report,
vulnerability check, expanded checks and artifact-license source validation.
Selection and profile ages must be between zero and the existing 72-hour limit.

## Local OCI proof and lifetime

`security_oci.import_layouts(catalog, inventory, profile, workspace)` validates
and copies selected graphs into private singleton layouts. It checks descriptor
sizes and hashes, config platform, compressed layers, decoded diff IDs, path
and link constraints, and aggregate limits. It performs no extraction,
registry access, daemon operation or image execution.

The limits are 512 images, 512 MiB each for compressed, unpacked and stored
bytes, 16 MiB per metadata object, 10,000 layers and 900 seconds shared across
the import and consumption. Smaller positive limits are permitted. Only OCI
indexes/manifests/configs and tar or gzip-tar layers are supported.

The returned `VerifiedOCIImage` objects prove identity only while their import
scope is live. Scanner reports must match the imported config digest. Core
rechecks every retained graph file after scanning. Proof and private files
expire when the scope exits. The scanner adapter uses `--input` with the
selected singleton layout and remaining deadline. A selected or declaration-only
input never falls back to daemon scanning. Missing or malformed input blocks
the result. Scanner/process effects in the new controls are mocked explicitly.

## Compatibility, failures and recovery

The additions to `evaluate`, `prepare_inputs`, `input_profile` and
`validate_input_profile` are optional keyword-only `image_artifacts` and
`image_selection` arguments. Existing callers without these inputs retain the
native path. CLI preparation supervision forwards both selected paths.
Existing default acquisition and ordinary finalization remain in their owners.

Invalid contexts and OCI objects raise `ValueError` subclasses. Source, profile
and freshness failures raise `SecurityDataError` where that interface owns the
check. Inventory gaps make completeness false; canonical evaluation preserves
its structured fail report. Restore correct source-bound input bytes or make a
reviewed forward fix, then rerun the checks. Never reuse an expired proof or
promote a prior declaration into fresh evidence.

The existing architecture model owns these Core files under
`NODE-LOCAL-ROUTE-POLICY` and the new tests under `NODE-LOCAL-VERIFIER`, both in
`TD-LOCAL-PREFLIGHT`. This API adds no service or HTTP endpoint. API availability
does not establish scanner execution, qualified production inputs, protected
workflow execution, operator approval, deployment or end-to-end acceptance.
