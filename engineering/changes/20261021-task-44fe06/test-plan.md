# Test plan

Add failing tests before behavior edits. Run focused tests with up to20 workers on verified CPUs0–25. Parallel shell checks use getzilla par. Source tests are observations, not receipts.

- Matrix: day180/day181, absent/malformed/future dates and sources, empty systems, disabled early exit.
- Risk: legacy record, strict score types, high acceptance, malformed/date-expired next review, future applicability.
- Scaffold: both languages, CLI dispatch, final glob mismatch, file-only/ambiguous/traversal paths, links, exclusive retries, unchanged registry.
- Templates: real Python and Node behavior, caller labels, missing/failing/timed-out C2PA, separate output and source preservation, idempotent labels.
- Audit: committed opt-in, base source, no CI writes or receipts, dirty/ignored inputs, normal receipt rule, identity binding, exact argv, legacy absence, bool exit rejection, verifier failure/time/output limits and untrusted execution path.
- Contract/install: v1 bytes stay intact. V2 has an exact schema version, bounded optional argv and required paired spec metadata. Reject v1 authority, bool/string/unknown versions and missing metadata. Adapters install on demand, both wrappers are managed, and malformed ISO never changes decisions.

After implementation commit, run bounded committed-HEAD controls. Coordinator obtains code/test/security/release reviews, persists reports, freezes the candidate, then runs one final PR gate and external checks. No final result is claimed before those steps.
