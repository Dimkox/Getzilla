# Independent code review

Scope: issue 170 benchmark evidence publication only. This is not a merge approval.

## Initial report

PASS for evidence publication, with two Low findings. No merge approval.

- Add raw jscpd percentages: minLines 10 reports 2.52% lines and 4.34% tokens; minLines 5 reports 3.06% lines and 5.37% tokens. Keep the malformed-span warning.
- Retain the actual `.dockerignore`. `build_tests.py` sends the experiment root as its build context. The exclusions support safe reproduction.

Evidence checked:

- `python3 .getzilla/runtime/scratch/review-issue170-20261023/check.py` passed. All 117 listed files matched; their total was 5,705,503 bytes. With the manifest, the bundle totals 5,717,220 bytes.
- The archive matched all 60 source hashes. All 116 function snippets matched their source spans and hashes. Nine were overload declarations.
- Raw clone reports confirmed 4/5 pairs and two reversed spans per scan.
- Source inspection supports all 20 classifications and the low-score control.
- `git clone --bare .../artifacts/candidate.bundle .../candidate.git` passed. Its log confirmed baseline `c51f4f1f95afb2408cff5c23ac8fb53e4151869b` and managed commit `81eadf1d28792d79e49c0c538080ba5b9c8799e9`.
- Raw output records 297 passing upstream tests and a passing candidate fast check. Neither establishes PR verification. Adoption integrity was verified; installer project health was `not_run`.
- Offline launch commands expose no credentials, home mount, Docker socket, or production mount. Cleanup checks owned paths and exact image identities. No shared prune appears.

Source binding before/after:

- Publication: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/issue170-20261023T2152/publication`
- Manifest SHA-256: `08e42e17ab372d102f570312fd68bed4137eec53ec74ba69faa54fe8e010fe8b`, unchanged.
- Host HEAD: `e86027f5962401b62a750f4a0d804029b52ae397`, unchanged.
- Host tree: `e9cb97569492b5d07437dab33d43cf9f89979cb5`, unchanged.
- Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/review-issue170-20261023`; scratch and parent mode `0700`.
- `reviewed-tree-modified: no`
- `mutation: skipped (non-critical)`

Limits: I did not rerun downloads, model inference, adoption, upstream tests, or cleanup. Their outcomes rest on retained evidence and script inspection. Cleanup deletion was not executed. Initial setup totals, peak temporary disk use, and overall LLM usage remain unmeasured. The small sample establishes no general similarity threshold or recall claim.

## Final report after repair

PASS for the repaired evidence publication. No blocking findings remain.

- Raw jscpd percentages now match both reports.
- The actual `.dockerignore` is retained. It excludes all context files except `Dockerfile`.
- `finalize.py` retains both fixes.
- The hash/source check passed again: 118 listed files; source archive and all 116 function spans match.
- No benchmark rerun is needed.

Fingerprint before/after: `2691718b629fe348f99514006f71a950cbc152da840cfc8f0e819a4a47b736ba`, unchanged.

Command: `python3 .getzilla/runtime/scratch/review-issue170-20261023/check.py` → exit 0.

Host HEAD remains `e86027f5962401b62a750f4a0d804029b52ae397`; tree remains `e9cb97569492b5d07437dab33d43cf9f89979cb5`.

Private scratch: `/home/pall/projects/getzilla/.getzilla/runtime/scratch/review-issue170-20261023`; mode `0700`.

`reviewed-tree-modified: no`  
`mutation: skipped (non-critical)`

Limit: I verified the repaired bundle in full. I did not independently prove the exact old-to-new file delta because I did not retain the full old manifest. The writer’s repair script asserts only `report.md`, `finalize.py`, and `.dockerignore` changed. Earlier execution and cleanup limits still apply. This review permits evidence publication only.
