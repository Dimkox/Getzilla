# GZ-HOOK-ROOT-001

> Typed authority: [change-spec.yaml](change-spec.yaml).

Quoted argument data caused false `ambiguous-command-root` denials. The exact offline reproduction is a read-only `gh api` command with a quoted jq pipe. Root selection rejected it before the explicit workdir could be used.

Scope: one shared lexical scan for root inference, authority command chunks and shell mutation chunks. Preserve operator provenance for command and environment analysis. Add bounded denial source diagnostics. Keep existing grant, root conflict, wrapper, nested interpreter and retry boundaries.

Branch: `fix/hook-root-20261015`. Base: `7cf4f65dd2ba9bb1390dc84c6185ba0f104255c8`. Worktree: `.getzilla/runtime/worktrees/hook-root-20261015`. Route: `0cfa23ed0476`; parent diagnostic route: `e51fb363e020`. One writer: `general_implementer`.

The four selected analyses completed before implementation. No named human gate applies. PR #79 already supplied native cmd normalization and nearest-root launcher selection in this base. This change does not repeat those repairs. No live hook, deployed policy, external service or LQG candidate is changed.

Resource discovery completed in the parent before route dispatch. The attached factual snapshot records 26 verified CPUs under the owner cap. This writer uses at most six CPUs. Analyses and independent reviews stay read-only. The platform returned no native SubagentStart child ID or generation; lifecycle heartbeat evidence is unavailable, not invented.
