# Delivery — GZ-HOOK-ROOT-001

This handoff stops at a clean committed candidate and a bounded observation. The coordinator obtains the two route-selected independent reviews, saves their full reports and freezes the report-containing candidate. The coordinator then runs one final local PR gate and requires the external exact-head CI result before merge.

No push, merge, release, deployment, live hook installation or production write is part of the writer handoff. No PASS receipt is created here. The source repair is UNVERIFIED for delivery until final local and external gates pass.

Success signals: quoted read probes reach normal policy; sensitive root conflicts and writes remain denied; diagnostics identify the loaded sources and root stage without argument values. Failure signals are a changed allow/deny guard, failed source identity/redaction test or stale review identity.
