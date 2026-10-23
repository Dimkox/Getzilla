# Source duplication analysis

Run `getzilla duplicates --root <project>` for an advisory JSON report.
Install the optional tool with `getzilla update --only jscpd`.
Default tool updates include jscpd. The updater installs exactly 4.0.5
and checks its version. Offline mirror mode skips npm and uses no network.
Missing npm produces an explicit skip. Update state records the installed version.

The scanner supports exactly jscpd 4.0.5. Other versions return unavailable.
It never installs packages or uses npx. It copies supported UTF-8 source files
to a private snapshot and runs the installed binary with its own config.
It does not read project config, package scripts or reporter modules.
Documentation, evidence, generated harness mirrors, dependencies, build output,
caches and symlinks are excluded before source reads. Getzilla core Python code
is included. Tests are excluded by default. Add `--include-tests` to include them.

Defaults are 50 tokens and 5 lines. Set `--min-tokens` or `--min-lines` to change
them. Reports bind file spans to source hashes and an inventory digest.
Invalid paths or spans produce partial results. Missing token counts are null.
Missing tools, invalid reports, timeouts and input limits never mean zero clones.
Exit 0 means a complete advisory scan, even when clones exist. Exit 2 means
unavailable, partial or error. No automatic verifier check or clone threshold
blocks merges. The tool never refactors source.

Limits: 4,000 files, 1 MiB per file, 32 MiB total source, 20,000 directory entries,
8 MiB output/report and 120 seconds per scan. Reports contain paths and hashes,
not source text. The temporary snapshot is removed after the run.
Rollback: revert the CLI, adapter, toolchain and updater integration.
Existing update-state files remain readable. No migration is needed.
