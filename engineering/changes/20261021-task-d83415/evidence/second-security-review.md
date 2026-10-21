REQUEST_CHANGES / FAIL: two Medium security findings block this candidate. This revised review supersedes the initial R2 PASS, which missed composed Unicode-context cases. The initial report remains byte-for-byte at `getzilla-r2-security-review-initial-pass.md`, SHA-256 `d6f2af1a465dd3fb040ddad52cd8ec2b693d931d430d8f4d922dd475ef085ee0`. All earlier probe evidence is retained.

Route `d834158878e0`; base `e158ddc7263a55f5308944c5a426eb1e9f1a4327`. Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`. The review covers the complete disposition-loader and verification-integration diff, tests, package inclusion, documentation and change evidence, including the repaired prefix classifier.

| Identity | Before revision probes | After revision probes |
|---|---|---|
| HEAD | `98ff57375f95cc93e5f3cc785a8105f23743d0a3` | `98ff57375f95cc93e5f3cc785a8105f23743d0a3` |
| Tree | `52ffc8f3b4e8acec6c0f618cf062d388e84b6782` | `52ffc8f3b4e8acec6c0f618cf062d388e84b6782` |
| Git porcelain status | empty | empty |

The initial R2 review recorded the same clean identities. The private source archive still matches the candidate's relevant runtime and test files.

reviewed-tree-modified: no

- SR-D02 — Medium, blocking: Unicode whitespace erases member-access context. Location: `.getzilla/getzilla/verification_dispositions.py:82-90` and `124-126`. Only ASCII whitespace is skipped. Non-ASCII whitespace is instead assigned to `previous`, replacing the member-access dot; a following ASCII space satisfies the immediate separator check. Independently confirmed PASS with raw severity `error` and effective severity `info` for `client.` followed by U+00A0, U+FEFF, U+2028 or U+3000 and an ASCII space before the matching assignment. NBSP followed by a block comment and space also passes. All five are valid JavaScript member assignments, not standalone names. Preserve the member punctuation through supported whitespace or reject unsupported code context; add end-to-end composed-boundary regressions.
- SR-D03 — Medium, blocking: Unicode line terminators let the classifier skip active code as a comment. Location: `.getzilla/getzilla/verification_dispositions.py:92-97`. The `//` scanner searches only CR and LF. Independently confirmed that a line comment followed by U+2028 or U+2029, then `client.`, an ASCII newline and the token assignment yields PASS/effective `info`. JavaScript ends the comment at the Unicode separator, so the assignment accesses `client.token`; this classifier skips that dot while searching for the later ASCII newline. Reject or correctly account for Unicode line-comment terminators. A repair limited to non-ASCII characters outside comments will not close this case.

Both findings were reproduced with the synthetic 20-byte hexadecimal fixture and valid occurrence, full-file and separate-evidence hashes. Node `--check -` accepted all seven problematic sources without executing them. Standalone and plain ASCII member controls behaved correctly. The nine-case revision probe therefore has seven unexpected passes. Impact is incorrect local admission of address-shaped credential/member assignments despite the documented standalone restriction. It does not demonstrate a real credential disclosure, private-key/AWS waiver, or bypass of authenticated external approval.

Original SR-D01 examples are fixed individually, but that does not establish the intended boundary. Earlier evidence remains accurate and insufficient: 24 focused tests passed in 5.250 seconds; twelve original boundary cases and 21 additional contexts matched their expectations. My earlier tests checked non-ASCII separators directly beside the token and ASCII member access, but missed their composition and Unicode comment termination. Those tests were not rerun during this revision because the candidate did not change. The earlier corrected CRLF fixture expectation and its raw Git failure remain preserved.

Other bounded controls continue to have source/test evidence: strict defaults; closed schema and complete configuration validation; tracked regular files and rejection of symlinks, traversal and hidden index flags; exact file/evidence/match hashes and occurrence positions; independent private-key/AWS and additional-occurrence failures; distinct worktree/index/HEAD whitespace snapshots; retained raw observations and original Git commands, output and statuses; failure on unknown diagnostics or Git/range errors. These controls do not compensate for the two admission defects. Package inspection shows no active policy is shipped.

Revision command, run from `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-r2-security-review`:

```sh
taskset -c 12-15 env TMPDIR="$PWD/tmp" PYTHONDONTWRITEBYTECODE=1 python3 unicode_context_probe.py
```

Scratch remains mode 0700. Execution used one probe process and bounded Node syntax-check children on CPUs 12-15. New evidence is `unicode_context_probe.py`, `unicode-context-probe.json`, `unicode-context-probe.log`, `revision-before.json`, `revision-after.json` and `revision-evidence-bindings.json`. Earlier `evidence-bindings.json`, tests, probes, source snapshots and the initial report remain intact. No candidate source mutation occurred; security probes changed only synthetic private fixtures.

Limits: this limited prefix grammar is not a complete language parser, and this review is not exhaustive across languages or syntax combinations. Hash bindings do not establish real public identity or historical provenance. No actual credentials/private grants, live actions, network scans, deployment, publication, complete packaging suite, successor repair or full qualifying gate were inspected or executed in this revision.

Final gate: NOT_RUN. Repair both findings through the sole writer and obtain fresh independent review of the next frozen candidate.
