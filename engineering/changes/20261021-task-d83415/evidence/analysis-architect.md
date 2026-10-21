# Architecture analysis — reviewed verification dispositions

Use one small, versioned disposition manifest and one shared strict loader. Keep both existing checks active. Classify only exact findings after each check runs. Do not add a service, policy engine, global skip, directory allowlist or altered comparison base.

Source: Getzilla `e158ddc7263a55f5308944c5a426eb1e9f1a4327`, tree `9a7fb672e44de0d3d87e37a70fa4861d37681ce6`, at `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`. Route: `d834158878e0`; change: `20261021-task-d83415`. The active route selects architect analysis. The approved task scope supplies the design boundary; this report creates no approval or receipt. Initial status contained only the untracked active change package. This is a static design, not review of a completed implementation.

Current boundaries: `.getzilla/getzilla/verification.py:1258–1320` runs worktree, index and selected comparison-range `git diff --check` commands. Every nonzero result currently fails. Lines 1323–1338 scan three secret rules and emit only one finding per rule/file through `pattern.search()`. `source_secrets.py` is a separate Zero-Git admission scanner with different policy and confidentiality guarantees; do not change or reuse its broader exception mechanism for this task.

## Minimal contract

Use a fixed repository-relative manifest location, for example `.getzilla/verification-dispositions.json`. Absence preserves current behavior. Presence requires strict JSON decoding, including rejection of duplicate object keys, a supported exact version, closed fields, bounded size/counts, unique disposition identities and nonempty review rationale/evidence references. Reject unknown kinds, malformed hashes, unsupported rules, duplicate entries and partially valid documents. Validate the whole manifest before applying any entry.

Each entry names an exact normalized repository-relative regular-file path, SHA-256 of complete raw file bytes, one closed disposition kind, and a reason plus review-evidence reference. Reject absolute paths, traversal, empty or dot components, backslash aliases, globs, symlinks in the path and targets outside the repository. Keep the admitted path grammar conservative rather than building a Git filename parser for unusual names. Hash raw bytes without newline or encoding normalization. Bind local evidence references to exact paths and hashes too, or record immutable commit/blob references. Evidence prose is provenance, not executable policy or independently authenticated approval.

Validate every configured target and its specific finding even when it is outside the current changed-file selection. Missing files, changed bytes and entries that no longer identify their stated condition fail closed. Do not silently discard stale entries. The loader must not fall back to an empty manifest on parse, path or I/O errors. Avoid a manifest self-hash or report-reference cycle; include its digest in the verification output and normal source fingerprint instead.

## Public EVM address disposition

Replace `pattern.search()` with bounded per-match enumeration. Keep every rule and every distinct match. Only `generic-secret` findings whose matched assignment is a token field and whose entire quoted value is `0x` followed by exactly 40 hexadecimal digits can qualify. Require an exact match locator, such as line plus column/ordinal, and exact public address in the reviewed entry in addition to the complete file hash. Resolve the locator against the actual match, not a line containing a different approved address.

Do not admit arbitrary generic-secret strings or password, API-key, secret, private-key or AWS rules. A file containing both an approved public token assignment and a genuine secret must still fail. A second address occurrence needs its own disposition. Preserve case as recorded in the source binding; do not make a syntactically valid address automatically public or approved. The reviewer must establish its public token identity and intended chain from existing protocol documentation or public primary evidence.

Emit a sanitized raw finding identity for every match: rule, path and location. A qualifying match remains visible with effective severity `info`, original severity/code, disposition ID, manifest digest, file hash and review evidence. Never print unknown matched values or private material. Count unresolved findings separately from disposed findings. Secret-scan passes only when no unresolved error remains; “zero potential secrets” would misdescribe a run that contains disposed findings.

## Immutable Markdown whitespace disposition

Admit only exact non-executable regular `.md` files with an explicit immutable-history rationale and hash. For the current problem, restrict the accepted diagnostic to the reviewed blank-line-at-EOF condition. Other whitespace classes require a separately reviewed kind or remain errors. Do not edit immutable Markdown, normalize copies as evidence, set a global whitespace mode or shorten Git ranges.

Run every existing Git check and retain its original command, range, exit status, stdout and stderr. Classify only recognized whitespace diagnostics tied to an admitted path and the exact target bytes for that command. Range checks inspect the target Git blob; cached checks inspect the index blob; worktree checks inspect worktree bytes. A hash of HEAD alone cannot authorize an altered index or worktree. Preserve the source-stability check and fail if inputs change during classification.

Do not convert a command failure to PASS merely because any admitted path appears in stdout. Every failure diagnostic must be understood and disposed, with no unresolved error. Git execution errors, missing objects, invalid bases, selection findings, timeouts, malformed or unexplained output and errors on other files remain hard failures. Keep original findings as informational dispositions rather than pretending Git returned zero. Classify the complete bounded output before display truncation; truncated or incomplete output cannot establish that all failures were covered.

## Trust and reviewability

Hashes bind bytes; they do not prove benign content, historical status or review authority. A contributor can edit both source and manifest. The narrow semantic admission rules limit that power, and independent review must inspect each new disposition, its target and its evidence. Existing exact-source gates and external merge authority remain unchanged. These local records cannot waive deployed Trust CI policy or manufacture a passing review.

The manifest is executable verification policy. Include it in source fingerprints, installation/package inventories where needed and full verification scope. Do not classify it as harmless documentation. Removing the manifest restores ordinary failures, which provides a simple rollback. Do not make old reports or immutable evidence depend on rewritten bytes.

Required bounded controls: a clean approved address; changed hash; malformed/duplicate/unknown fields; absent or symlink target; a second unmatched token; an address-shaped password; private-key and AWS findings beside an approved address; missing evidence; an unused stale entry; exact historic EOF; new whitespace elsewhere; changed index/worktree bytes; Git execution/range errors; mixed disposed and unresolved diagnostics; sanitized retained findings; and source/manifest changes invalidating prior evidence. Critical parser/classifier mutation probes belong to independent review in private scratch, not this analysis.

Exit zero with zero evidence gaps must follow the full selected Liqvera gate on the final frozen source. It must not result from relabelling a skip, hiding a failure or reusing an older PASS. Report disposed findings explicitly alongside the gate result. This analysis performed repository reads only, with no application edits, tests, Git checks against historical evidence, external actions or private-data access. `reviewed-tree-modified: no`.
