# Native installation and upgrade checks

The support inventory is [platform-support.json](../.getzilla/config/platform-support.json).
It separates intended support from native qualification. The runner labels below
were checked against [GitHub's hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) on 2026-11-04.

| OS | Architecture | Runner | Support | Required observation |
| --- | --- | --- | --- | --- |
| Linux | x64 | ubuntu-24.04 | Supported | Clean install and stable upgrade |
| Linux | ARM64 | ubuntu-24.04-arm | Supported | Clean install and stable upgrade |
| Windows | x64 | windows-2025 | Supported | Clean install and stable upgrade |
| Windows | ARM64 | windows-11-arm | Unsupported | No pinned native OpenGrep asset; bootstrap targets amd64 |
| macOS | x64 | macos-15-intel | Supported | Clean install and stable upgrade |
| macOS | ARM64 | macos-15 | Supported | Clean install and stable upgrade |

These declarations do not claim a successful native run. A missing runner,
cancelled job, skipped scenario or missing artifact blocks the aggregate.
An Intel result cannot replace an ARM64 result. Current checks conservatively
require every supported pair for each PR, main push and release-tag push.
Per-scenario and per-cell durations are retained for later risk-based scheduling;
no unqualified path selector silently removes a required cell.

The complete installed Factory unit catalog is separate from native service
support. Its filesystem tests use an inert service adapter and explicit host
resource fixtures. A separate control exercises actual host admission; the
Factory setup manager still refuses unsupported hosts before activation. An
inert test passing on macOS does not qualify the Linux Factory service there.

Factory unit evidence version 3 retains the complete problem inventory within
the existing 4 MiB report bound. Each failed parent case or class/module fixture has its outcome,
exception type and source-bound frame locations. It excludes exception messages,
locals, subtest values and absolute paths. Counts must match these records;
missing cases, unknown fields, incomplete reports and unqualified skips still
fail. The archived-engine inventory control prints this list instead of a short
raw stderr tail. Historical version 2 evidence keeps its original source grade;
it cannot qualify the new invocation. This internal report is not a Factory API
or a native-platform acceptance receipt.

`getzilla_platform_install.py` calls the actual candidate `install.sh` or
`install.ps1`, non-interactively and without installing a coding agent. Each cell
also installs the exact previous stable release, creates and commits user files
and settings, bootstraps the candidate installation, adopts the explicit legacy
adapter choice before the candidate's existing-project plan, and invokes the
actual installed `getzilla update` command.
It checks actual Git identities, installed engine version, CLI and managed-file
hashes, selection, user files, CLI help and doctor. Reports bind head/tree, run and
attempt, native OS/architecture, stable tag/object/commit, log hashes and duration.
The installed user CLI wrapper runs from the project on each platform.

The aggregate consumes the downloaded log artifacts. A completeness flag alone
cannot pass: each command needs a successful exit, confirmed cleanup, consistent
byte counts and a retained regular log with matching SHA256 and size. Both
scenarios need distinct, nonempty command references and some retained output.
Empty logs from quiet individual commands are allowed. Missing, changed, linked,
unreferenced, nested or unsafe log paths fail. Checked filesystem readers bound
each log to 8 MiB, each cell to 64 MiB and each cell's command list to 128 entries.
The runner uses the same limits and continues draining before reporting loss.
These are consistency checks on Actions observations, not execution attestation.

The pinned previous stable is **v2.3.0**, tag object
`815aeabc5d215d65e72651692a6457920de9fa71`, commit
`2bb417431f1e4b9494e4af71ebf27adb1d04d898`. This is an observed publication,
not production qualification. Native installer runs are still required for this
candidate; local unit fixtures do not replace them.

Stable v2.3.0's `getzilla update` updates tools only. Before the candidate installer
plans an existing legacy project, use the reviewed candidate checkout's explicit
components script to record the complete choice. Review and commit it first:

```text
python /path/to/candidate/Getzilla/scripts/getzilla_components.py adopt --agents qwen
git add .getzilla/managed-components.json
git commit -m "Record complete adapter selection"
# Bootstrap the candidate user installation with its normal installer, then:
/path/to/updated/Getzilla/bin/getzilla update --no-self --no-tools --baseline-release v2.3.0
```

Use `getzilla.cmd` on Windows. Adoption records membership; it does not grant
ownership over unknown old files. The explicit baseline option recognizes only
selected paths whose bytes and modes match the qualified vendor catalog. It
publishes current ownership and files together on the ordinary update branch;
the original branch remains available for rollback. Unknown files, explicit
keeps, custom settings and component selection retain their existing rules.
Changed managed files require reconciliation; an old ownership ledger does not
make a custom policy a vendor default. The option cannot combine with local
acceptance, retirement, self-update or tool updates. Windows comparisons use
the existing write-bit mode semantics rather than POSIX executable bits.

The catalog pins the published ZIP SHA256
`782219f8f74525a882f14ff2f457ee553ee725a6ba9ae434296c39be77946c11`.
During a private one-time qualification, every archive manifest entry matched
the pinned Git source; both actual historical materializers produced the same
695-file full-layout inventory. The runtime reads only the immutable catalog,
whose complete digest is pinned in code; it executes no historical source and
accepts no caller-supplied catalog or release identity. Rendered historical files
use their actual materialized bytes, not the source template hash. The full
inventory is a superset: only the project's committed selection can authorize
incoming files. This qualification does not replace native installer CI.

The catalog separately pins the two runtime anchors from the old Git install.
The published ZIP contains `.gitkeep` but omits the runtime `.gitignore`.
These anchors do not expand the common 695-file restoration payload. An ignored
managed file stays outside Git only when existing ownership or the selected
qualified baseline proves its exact bytes and mode, and the candidate already
matches both. The updater leaves that file in place, checks it for concurrent
changes, and preserves it when switching back to the original branch. Other
ignored collisions still refuse. Runtime user data remains outside the payload.

macOS upgrade cells use the explicit baseline mode `restored-v230-artifact`.
The historical v2.3.0 new-project installer calls Linux `renameat2`, which is
unavailable on macOS; its create path remains **unsupported**, not passed.
The alternative restores exactly the 695 qualified vendor files and the old
65-byte sync record into an absent directory. All file hashes and modes must
match before the current portable publisher starts its ordinary no-replace
transaction. The eleven rendered paths use only the old published templates.
No historical Python runs during restoration, no candidate payload is staged,
and no component selection, ownership proof or runtime authority is fabricated.

The restore input is the exact v2.3.0 checkout with its pinned annotated tag:

```text
python /path/to/candidate/Getzilla/scripts/getzilla_platform_install.py --restore-stable-payload /path/to/verified-v2.3.0 --project /absent/legacy-project
```

The native upgrade scenario then runs the actual old installer in its
existing-project mode and the installed old baseline application, using uv's
observed executable directory. It checks the old installation SHA/version and
the restored project's actual engine version before creating user files and
committing explicit qwen adoption. A user-authored ignore rule keeps local
runtime locks out of Git. Candidate bootstrap and update follow. Linux and
Windows retain `stock-installer-create`; their historical create result must
be `pass`. The aggregate requires the correct baseline mode and old bootstrap
outcomes for each platform. Candidate clean installation always uses the stock
candidate installer on every required native pair.

The [fa8c2cc native run](https://github.com/Dimkox/Getzilla/actions/runs/41882805843)
observed a Windows x64 clean/upgrade pass. Linux clean installs passed but both
upgrades stopped at unresolved legacy selection. macOS ARM64 clean passed;
macOS x64 clean stopped when the installed `specify` executable was outside
PATH. Both historical macOS create paths failed at `renameat2`. Every retained
command log matched its artifact hash/length. No OSV refusal occurred in that
run. These are observations of fa8c2cc; the repaired candidate still needs its
own native run. The required Linux job keeps the native failure and collects
source checks only after a successful checkout, including after earlier native
failures. Generated client evidence exports use the same checkout guard.

The [observed macOS installer failure](https://github.com/Dimkox/Getzilla/actions/runs/41841095688/job/126612562552)
on candidate `2f45b2c66f434f00373da85e481394bb2b8f44ed` followed successful clone,
venv creation and doctor. Mandatory OSV data validation then refused malformed
official PyPI/npm/Packagist alias values; the installed-project smoke did not run.
This is separate from architecture support. Keep complete-feed refusal and the
previous valid snapshot; do not trim aliases, drop records or weaken validation
to make installation green. See [#321](https://github.com/Dimkox/Getzilla/issues/321).
Later macOS jobs which acquired no runner and had no steps are infrastructure
`NOT_RUN`, not evidence that either installer passed or failed.

Public client repositories keep the existing Linux workflow by default. Owners
can opt in to supported native platforms when planning or writing the workflow:

```sh
python scripts/getzilla_ci.py --plan --visibility public --platform linux-x64 --platform macos-arm64 --platform windows-x64
python scripts/getzilla_ci.py --write --visibility public --platform linux-x64 --platform macos-arm64 --platform windows-x64
```

The generated matrix runs every selected platform with fail-fast disabled. Its
always-run `getzilla-verify` status fails when any selected cell fails, is skipped,
is cancelled, or never produces a successful job result. Unknown and unsupported
choices are refused before a workflow write. Existing differing workflows remain
protected against overwrite. Private repositories still receive no workflow.

Actions records are observations. They cannot replace the independent
[GitHub App security verdict in #326](https://github.com/Dimkox/Getzilla/issues/326),
alter its deployed policy, or authorize a merge or release. No new service,
signing key, deployment or branch-protection mutation is introduced here.
