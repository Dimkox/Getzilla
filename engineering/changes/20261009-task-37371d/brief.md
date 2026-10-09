# Getzilla production readiness — issue #72

Owner outcome: Getzilla ready for production by 2026-10-09 08:00 GMT+3 (05:00 UTC), operating under AGENTS.md L5. Published v2.2.0 alone is not proof of operational readiness.

Candidate/base: 5d5b45f42f8a9f2bc0303b4d16b5d4e54caad5b9, tree 0f6fa49b00519f67260492320e40b1656c850549. Branch readiness/72-production-20261009, route 37371d21accb.

First scope: recover current security findings, release/installation provenance, working autonomy controls and missing runtime inputs. Produce a bounded repair plan; no production mutation, credentials, deployed policy change or external-service writes. Actual target installation and autonomous business task remain unknown; coordinator asked owner and continues independent checks.

Dependencies: four route-selected read-only analyses run in parallel. Coordinator owns workflow documentation only. No application writer until findings are synthesized and applicable scope/design gates resolved. Exactly one selected general_implementer owns any later product repair. Code/test/security/release reviews follow committed implementation and bounded controls, then one final qualifying PR verifier on report-containing frozen tree.

Resources: verified 14 physical cores, 28 online logical CPUs; widened child affinity 0-27, no finite visible ancestor CPU quota. 13 platform slots; 10 route analysis cap. Allocate repo_explorer CPUs 0-3, architect 4-7, docs_researcher 8-11, integration_architect 12-15; coordinator 16-19, reserve 20-27. Four analysis slots only; no extra agents. Heavy checks wait until inspection selects scope. Current work is read-only evidence gathering, not a repeated full verifier of unchanged published source.

Acceptance: concrete confirmed blocker ledger; targeted failing regressions for actual repairs; exact-head independent reviews and gates; immutable release provenance; safe install and usable autonomous task; observability and recovery; explicit target/action authority before production write. NO-GO if any requirement lacks evidence.
