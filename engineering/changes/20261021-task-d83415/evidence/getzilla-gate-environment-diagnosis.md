Confirmed two environment causes without changing Getzilla source, tests, or assertions. The short, trusted, non-Git `TMPDIR=/home/pall/.cache/gz-gate-env` fixes the selected failures. This is bounded diagnostic evidence for rerunning the unchanged gate, not a passing full-gate result.

Candidate: `/home/pall/projects/liqvera/.getzilla/runtime/getzilla-dispositions`. Before and after: HEAD `4cf2abf21753e61383e3d89be593e0fb815afc7f`, tree `947e9f362d4f0bc862e8bf12455c8e4b1862e850`, empty `git status --porcelain=v1 --untracked-files=all`. Ten relevant source/test SHA-256 bindings are identical in `getzilla-gate-environment-diagnosis/identity-before.json` and `identity-after.json`.

reviewed-tree-modified: no

The input gate report is bound in `gate-input-binding.json`: `.getzilla/runtime/final/getzilla-pr.json` inside the candidate, SHA-256 `db7509a86319038f3f699259fc71957f9d649ff9c0a3048ba656e3d9d5a82de5`, status `fail`. Its Python summary reports 42 failed, 2224 passed, 17 skipped, 3926 passing subtests. Its output is truncated; the bounded reproductions below retain complete output.

| Unchanged native selection | Original TMPDIR | Short TMPDIR |
| --- | --- | --- |
| Eight Core cases: six stack cases, one adoption CLI plan, one non-Git/unborn fingerprint | 5 failures, 2 errors, 1 pass; 0.222 s | 8 passed; 0.403 s |
| Local Chrome lifecycle contract | 1 failure; 45.992 s | 1 passed; 6.596 s |

Each comparison used a fresh Python process, the same candidate, interpreter, arguments and CPU affinity; only `TMPDIR` changed. `PYTHONDONTWRITEBYTECODE=1` and `-B` prevented bytecode artifacts. The stack test that initializes its own Git repository passed under both environments, providing a control. The short-path fingerprint case also completed its unborn-repository assertions.

The original 74-byte temporary root is `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-tmp`. A synthetic plain fixture there resolves `git rev-parse --show-toplevel` to `/home/pall/projects/liqvera`. Its `git ls-files -co --exclude-standard -z` succeeds with no paths because `git check-ignore -v Cargo.toml` identifies `.git/info/exclude:8:/.getzilla/runtime/`. Consequently, `stacks.tree_files` accepts an empty Git inventory instead of walking a plain folder; marker detection and runner selection fail. The adoption CLI correctly returns exit 4, `GIT_PRESENT`, because it explicitly checks ancestor `.git` markers. `util.git_head` finds the outer repository's HEAD, `changed_files` returns an empty list, and adding `.qwen/tmp/probe` leaves the fingerprint unchanged. Under the short root, Git discovery exits 128, the plain walk detects Rust, and scratch creation changes the fingerprint. Complete commands and values are in `git-mechanism.json`.

The browser failure has a separate path-length cause. The native runner suppresses Chrome stderr and eventually reports `Timed out waiting for Chrome DevTools Protocol`. Launching Chrome with the same flags and a fresh disposable profile captures `FATAL:chrome/browser/process_singleton_posix.cc:315] Socket path too long` for a 115-byte path ending in `com.google.Chrome.9zttH5/SingletonSocket`; Chrome exits on signal 6. Under the short TMPDIR, Chrome announces DevTools in 0.530 s and exits cleanly after diagnostic shutdown. `chrome-startup.json` and both complete startup stdout/stderr files preserve this evidence. The diagnostic launch opened only `about:blank`; the native browser test served the unchanged showcase locally.

The short root is 29 bytes and was newly created with mode 0700, UID/GID 1000. Every ancestor was checked with `lstat`: `/` and `/home` are root-owned 0755, `/home/pall` is user-owned 0750, and `/home/pall/.cache` is user-owned 0700. No ancestor or root is a symlink, sticky, or group/other writable. Git discovery at the short root exits 128. Both roots' complete ownership/mode/discovery records are in `path-safety.json`. The evidence directory under canonical runtime is also private 0700.

Reproduction used `/home/pall/projects/liqvera/.getzilla/runtime/completion/getzilla-gate-venv/bin/python` (Python 3.12.3), bounded to CPUs 0–3. From `/home/pall/projects/liqvera`, the exact diagnostic entry points were:

```sh
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py prepare
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py core original
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py core short
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py browser original
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py browser short
env PYTHONDONTWRITEBYTECODE=1 taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/mechanisms.py git
env PYTHONDONTWRITEBYTECODE=1 taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/mechanisms.py chrome
taskset -c 0-3 .getzilla/runtime/completion/getzilla-gate-venv/bin/python -B .getzilla/runtime/completion/getzilla-gate-environment-diagnosis/run.py finish
```

`run.py` records expanded native commands, all test IDs, cwd, environment differences, exit codes, durations, hashes and full stdout/stderr in the corresponding `original-core`, `short-core`, `original-browser` and `short-browser` files. Its own successful exit means evidence was captured; the native test exit is the JSON `returncode`. Source mechanisms are `stacks.py:97`, `util.py:359`, `scripts/adopt_existing.py:90`, and `browser-contract.mjs:54–76` at the pinned tree.

Recommended environment correction: set the gate's TMPDIR to the verified short non-Git root; retain its private permissions and existing check scope/assertions. `GIT_CEILING_DIRECTORIES` alone would not repair the CLI's explicit ancestor-marker check or the socket length problem. No source repair or assertion relaxation is supported by these reproductions.

Limits: no full suite, xdist/load reproduction, full-gate rerun, mutations, deployment, publication, payments, grant access or private-state inspection. The eight reproduced failing cases do not prove all 42 failures are environmental. Other failed checks, timing-sensitive cases and PostgreSQL acceptance remain unverified here. The prior gate remains failed until a complete unchanged rerun supplies new evidence.
