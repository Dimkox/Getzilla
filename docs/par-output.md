# Parallel command output

`getzilla par` runs synchronously after every command passes the policy check.
Its exit codes stay 0 for successful commands, 1 for a command failure, and 2 for
refused or empty input. A command timeout records exit 124.

Each batch retains at most 32 MiB of combined stdout and stderr. The runner divides
this quota across jobs. Each job retains a head and a tail. The runner continues
to drain output after the quota fills. It reports observed, retained and dropped
byte counts. Log errors and output loss have separate fields. Command success
does not establish that a required full report was saved. Save such reports as
separate evidence artifacts with their own budget.

Previews contain at most 4 KiB of UTF-8 text per job. A batch shares a 32 KiB
preview memory budget. The CLI response and `summary.json` each have a 32 KiB
byte limit. Truncation markers show omitted text or metadata. Command strings are
excluded from saved metadata and displayed output. Credential labels suppress a
preview; this heuristic cannot identify every possible secret in arbitrary output.
Raw retained logs can contain sensitive command output. POSIX files use mode 0600.
Windows files inherit the repository's access controls.

The runner uses the existing `fsx` filesystem and process backends. POSIX holds
directory descriptors. Windows uses directory identities, reparse-point refusal,
and checks before output writes. The runner does not reopen log paths to build a
response. A changed log namespace makes the artifact unavailable. A bounded reader
queue drains pipes on both platforms without socket-only selectors.

POSIX owns a child process group. Windows assigns each child to a kill-on-close
Job Object before its code runs. Timeout or cancellation stops the owned group or
job. A missing Windows ownership backend returns exit 125 with an explicit
unsupported result before commands run. POSIX groups do not sandbox a child that
deliberately leaves the group. Native Windows process and junction controls need
their real CI run; adapter tests on POSIX do not establish that qualification.

No cursor or host-path retrieval interface is provided. EX-02 must normalize old
results before restoring them to context. Historical restore integration and
global disk retention remain outside this change.
