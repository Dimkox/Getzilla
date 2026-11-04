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
Raw retained logs are private files and can contain sensitive command output.

The POSIX runner holds directory descriptors and refuses symbolic links when it
creates logs. It does not reopen log paths to build a response. A changed log
namespace makes the artifact unavailable. The runner owns its child process group
and kills that group on timeout or interruption. This is not a sandbox for a child
that deliberately leaves the group. Windows junction handling is not qualified.

No cursor or host-path retrieval interface is provided. EX-02 must normalize old
results before restoring them to context. Historical restore integration and
global disk retention remain outside this change.
