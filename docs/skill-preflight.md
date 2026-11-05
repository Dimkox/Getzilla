# Skill pre-install assessment

`python3 scripts/getzilla_skill_preflight.py assess intake/example` reads an explicit local source.
`interview` runs a bounded declarative trial. `install` stages supported bytes outside native discovery only after current
canonical owner/session/epoch and exact existing protected-path grants permit every eventual native destination. It returns `staged`, the actual inert runtime path and observed byte/mode proof. Native activation is unsupported; no automatic copy or adapter alias exists.
Assessment/interview exit 2 for `deny` or `needs_review`. Install does not issue a grant or activate a skill. Native clients can discover files under `.agents/skills`; this operation never publishes there.

The host selects source pins in `.getzilla/config/skill-catalog.json`. This is descriptive source data,
not another permission registry. Candidate prose cannot edit its entry through this API, approve itself,
or expand existing #150 policy. No dependency is fetched or executed by this path. Dependency declarations
must contain full Git revisions and SHA-256 digests and match the separately selected catalog entry;
that check does not prove an external dependency was acquired or is safe to run.

An intake contains `SKILL.md` and `getzilla-skill.json`. The closed descriptor has version 1, an ID/version,
`source` (repository/full revision), exact content `files` hashes, `capabilities`, `constraints` and
`dependencies`. Capabilities name an operation, exact project-relative resource and `exclusive` Boolean.
Only declared read requests can pass this bounded contract, and the actual current policy can still deny
them. Catalog entries bind ID/source, complete snapshot digest, descriptor digest and dependency pins.
Changing source, descriptor, catalog, owner or existing skill context invalidates admission.

The supported trial instruction language is a closed JSON constraint body. Native publication
requires the exact bounded frontmatter and fenced body in `SKILL.md`, for example:

````markdown
---
name: example
description: Declared skill constraints.
---
```json
{"schema_version":1,"constraints":{"tone":"concise"}}
```
````

The descriptor must repeat the name and constraints exactly. Supported preferences are tone
(`concise`/`verbose`), language (`en`/`ru`) and format (`plain`/`markdown`). Unknown constraints, including
approval/role claims, require review. Raw JSON alone can be interviewed but is not a native install.
Ordinary free-form Markdown and unmodeled
references return `needs_review` even when pinned. Obvious role/instruction/approval override claims
return `deny`; this is a bounded control, not a general semantic prompt-injection detector. Contradictory
declared constraints, changed duplicate IDs and overlapping exclusive privileges refuse. Ordinary shared
reads are reported without an exclusive-access denial. Unknown existing skills also require review.

The interview accepts at most 32 hypothetical requests and structured answers. It simulates declared
reads and denies unsupported actions. It has no process/network/provider/credential/production dispatcher.
Its answers and `approved:false` result cannot authorize publication. Unsupported native trials have no
execution fallback. API results retain `permissions_granted:false` and `semantic_safety:unqualified`.

Staging snapshots canonical source bytes into owned immutable data. It writes the same bytes to `.getzilla/runtime/skill-intake/<id>` through exclusive held file descriptors and existing no-follow component primitives. It checks observed content, platform mode semantics and inode identity before successful completion; reported modes are actual observed modes.
Canonical authority is rechecked before effects. Multi-file copying is not a transaction: uncertainty or
partial publication refuses; existing different bytes and extra files cannot be silently overwritten.
A destination-scoped incomplete diagnostic blocks every client and retry after a partial or uncertain attempt. There is no automatic recovery or overwrite of foreign files. The verified-result boundary does not physically fence an uncooperative same-user writer; it supplies no OS isolation.
No imported raw prose or secret arguments enter bounded reason-coded reports.

`skill_pinned_sources.read_pinned_tree` supports offline, capped Git-object input for artifact generation:
full commit pins only, no lazy fetch/replace refs/hooks/filters, 128KiB commit metadata, 4096 files,
2MiB per blob and 16MiB total. It checks commit/blob identities and owns the returned bytes. It never
executes the checkout; changed worktree files cannot replace the selected pinned objects.

Existing Getzilla installer/on-demand payloads and generated harnesses keep their shipped context behavior.
Their canonical/adapter byte inventory rejects conflicting aliases and reports provenance only. Normal
baseline onboarding uses [fixed generated assets](baseline.md), including upstream LICENSE custody; it
does not run an ambient installer. Source/provenance approval is separate from semantic safety.
Readable content-addressed blobs are executable supply-chain content, with per-variant manifests. Their
file extensions do not make them documentation: asset-only edits keep full verification and risk reviews.

General free-form semantic review, native script activation, universal native/MCP tool trust and cross-client
OS/credential isolation remain unqualified. #150 owns canonical action authority, #156 owns model/MCP trust
and stop mechanisms, and #166 owns lifecycle generations/observations. This feature creates no second route
for a trial, permission ledger, service, queue or daemon. Native macOS/Windows execution requires #338 evidence.

Detectable Python completion interruptions, including KeyboardInterrupt and SystemExit, use the same
bounded owned-record restoration and then propagate with their original exception semantics. The
restoration makes at most two attempts/observations and never overwrites a foreign record. If it cannot
verify denial, the original exception carries `publication_state: unknown` (and a fixed note where
supported); inspect it manually. This is not permission for automatic recovery. An undetectable hard
termination, power loss or unavailable persistent storage has no rollback/durable-denial qualification.

CLI callers receive unverifiable custody as `status: unknown`, reason `PUBLICATION_CUSTODY_UNKNOWN`,
`publication_state: unknown`, `inspection_required: true` and `retryable: false`. Value/I/O failures exit2. This differs
from an ordinary known refusal. It grants no permission and does not activate, retry or repair anything.
The CLI reads only the known scalar metadata through at most eight cause/context exceptions; truncated
graphs conservatively require inspection. It never serializes private exception text, notes, paths or
payloads for this state. Ordinary refusal and inert staged-success responses keep their existing exits.
Any future adapter must preserve these unknown/inspection semantics rather than infer safe retry.

For unknown KeyboardInterrupt, SystemExit or other BaseException outcomes, `main()` emits the fixed
unknown JSON and re-raises the same original exception. Only the terminal entrypoint maps recognized
unknown exceptions to private-text-free failure: KeyboardInterrupt130, valid nonzero signed32-bit
SystemExit codes with nonzero actual platform exit preserved, and other cases1. Zero/None, private
string codes, out-of-policy integers and codes that normalize to success become1. There is no global
exception hook. Ordinary interrupts, help and parser exits without unknown metadata keep their behavior.
