# Repair main CI failures #19-#23

> Typed authority: [`change-spec.yaml`](change-spec.yaml). This Markdown explains context and cannot override typed IDs, risk, acceptance criteria, forbidden outcomes, or approval scopes.

Change ID: `20261008-task-1d9b18`
Created: 2026-10-08T14:30:46+00:00
Risk: medium
Complexity: standard
Domains: api

## Problem

Fix the five failures on Getzilla main reported in issues #19-#23: restore the OpenGrep verification stage lost in merge 4ae0447, register trust-ci customers.py in architecture/system.yaml, remove the duplicated landing migration note and refreeze its digest, bump vulnerable pins (cryptography, pypdf, fastapi/starlette), and fix bandit B105 in getzilla_vulns.py

## Outcome

Every check in the Getzilla linux CI job passes again on main: verifier restored, architecture drift clean, landing digest current, factory pins clean under OSV, bandit clean.

## Scope

### In scope

- Restore `_opengrep()` and its stage in `.getzilla/getzilla/verification.py` and the QG-01 skip allowance (#19).
- Register `trust-ci/src/adaptive_trust_ci/customers.py` in `architecture/system.yaml` (#20).
- Remove the duplicated migration note from the landing page and template and refreeze the copy digest (#21).
- Pin fastapi 0.142.4 and pypdf 6.19.0 in factory and relock (starlette 1.7.0) (#22, factory part).
- Clear the bandit B105 false positive in `scripts/getzilla_vulns.py` (#23).

### Out of scope

- trust-ci pins (cryptography, fastapi): a separate PR, because FIT-TRUST-CI-SEPARATION forbids mixing them.
- VERSION bump: 2.2.0 is still an unpublished source candidate.

## Constraints

- Backward compatibility: the restored stage matches the pre-merge code byte for byte.
- Data/privacy: none.
- Performance: one OpenGrep scan when the binary is installed; otherwise it is skipped.
- Operational: the seo-landing chrome test needs Node 24 (WebSocket), as documented.
- Ordering: stacked on `fix/queue-analysis-loop-widening` (change `20261008-task-d259e6`). Its architecture-fitness fix must merge first, or the `verification.py` edit here fails FIT-BOUNDED-WORKER-JOBS as unsupported.
