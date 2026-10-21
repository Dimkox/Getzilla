REQUEST_CHANGES: one Medium security finding blocks this candidate. The focused tests pass, but the claimed standalone-token boundary does not hold.

Review scope: route `d834158878e0`; actual diff against `e158ddc7263a55f5308944c5a426eb1e9f1a4327`, including the disposition loader, verification integration, focused tests, package inclusion change, policy documentation, repository instructions and change package. This is an independent read-only security review, not authenticated external approval.

Candidate identity before and after review:

| Field | Before | After |
|---|---|---|
| HEAD | `9e29128aed4abea3dbe50d7f797aecbb26ff17d9` | `9e29128aed4abea3dbe50d7f797aecbb26ff17d9` |
| Tree | `eb9006a8a0e0b861a101b15d6094ddb6df228f96` | `eb9006a8a0e0b861a101b15d6094ddb6df228f96` |
| Git porcelain status | empty | empty |

Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`.

reviewed-tree-modified: no

SR-D01 — Medium, blocking: credential-name suffixes and member access can qualify as standalone public-token assignments. Location: `.getzilla/getzilla/verification_dispositions.py:79-83`, used by validation at line 235 and application at line 252. The function checks only the immediately preceding character against Python `[\w$.-]`. That excludes ASCII `auth_token` and `client.token`, but admits Unicode identifier continuations, JavaScript braced Unicode escapes, and property access separated by whitespace or comments.

Using only a synthetic 20-byte hexadecimal value and valid file, occurrence and separate-evidence hashes, independent end-to-end `_secret_scan` probes returned PASS with original severity `error` and effective severity `info` for all eight valid-JavaScript variants:

- `auth\u200ctoken`, `auth\u200dtoken`, `auth\u0301token` where the displayed Unicode escapes represent actual code points.
- Literal source `auth\u{005F}token`, which spells the identifier `auth_token` using a JavaScript escape.
- `client. token`, `client.` followed by a newline and `token`, `client./* member */token`, and `client. /* member */ token`.

Node `--check` accepted all eight without executing their contents. Plain `auth_token` and `client.token` failed as expected, and the standalone positive control passed. A ninth permissive scanner result for `client?. token = ...` is retained as a negative classifier input; Node rejected that assignment syntax, so it is not an executable-JavaScript example supporting the finding.

Impact is a broadened local disposition admission rule: a matching 160-bit credential-like assignment can be downgraded despite the documented exclusion of credential variable names. Full hashes preserve the wrong classification rather than correcting it. This does not demonstrate disclosure of a real credential, waiver of private-key/AWS rules, or bypass of independent authenticated Trust CI. Repair the lexical boundary conservatively, including escaped identifiers and member access across whitespace/comments; reject ambiguous contexts and add regressions through both policy validation and actual scan classification. An immediate ASCII-character allowlist alone is insufficient.

Other reviewed controls held in the bounded checks. Closed schema and whole-configuration validation reject malformed, stale and out-of-selection entries; tracked-file, mode, symlink, path and hidden-index checks constrain authority. Evidence/file/match hashes and per-occurrence positions bind classifications. Absent policy remains strict. Additional occurrences, private-key and AWS observations stay blocking. Whitespace classification binds the worktree, index and HEAD bytes separately and retains original Git commands, output and exit status; unknown diagnostics, selection failures and other whitespace remain blocking. Package inspection confirms the helper is included without shipping an active target policy. The 22 focused tests independently passed in 3.508 seconds; their missing boundary cases explain why that result does not resolve SR-D01.

Evidence is in sibling directory `getzilla-security-review/`: `source-before.json`, `source-after.json`, `focused-tests.log`, `boundary_probe.py`, `boundary-probe.json`, `syntax-probe.json`, and `evidence-bindings.json` containing SHA-256 bindings. Tests and probes used an exact committed archive in that directory, mode 0700, CPU affinity 12-15, at most one test process, and scratch-local TMPDIR. No candidate files were changed.

Limits: this review covers the stated diff and bounded synthetic local cases. It does not prove completeness of the inherited heuristic secret scanner, independently establish any real public contract identity or immutable historical provenance, or certify an external approval service. No credentials, private grants, live operations, network scans, deployment, publication or full verification gate were performed. No successor repair has been reviewed here.

Final gate: NOT_RUN, pending all required reports and repair of SR-D01.
