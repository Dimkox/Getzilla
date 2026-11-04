# Mandatory baseline

Every Getzilla install has the same baseline, with no option to skip any part of it:

| Part | What | Pinned by |
|---|---|---|
| Security | OSV CVE database, OpenGrep scanner with Getzilla rules | OpenGrep version and SHA-256 in `updater.py` |
| Superpowers | skills for brainstorming, plans, TDD, debugging, review | tag + commit in `toolchain.json` |
| BMAD | `_bmad/` method files and the agent's BMAD skills | full source commit, dependency lock, fixed generation command and asset hash |
| Spec Kit | `.specify/` and the agent's `/speckit-*` skills | full source commit, hashed dependency closure, sh/ps variant and asset hash |

## Installer

`install.sh` / `install.ps1` install the security data, then the workflow baseline:

1. Agent runtimes remain separate from workflow asset installation.
2. Ordinary project onboarding requires neither an ambient BMAD/Spec Kit executable nor Bubblewrap.
3. `scripts/getzilla_update.py --only baseline`: each source is cloned at its pinned tag into
   `~/.getzilla/baseline/<id>` and must resolve to the pinned commit (`PINNED_COMMIT_MISMATCH` otherwise),
   and the shipped generated asset hashes are checked. This step does not install a `specify` CLI.

If any step fails, the installer stops with an error and the command to retry. A new project
(`GETZILLA_NEW_PROJECT`) is connected right after it is created.

Updating to newer upstream versions is separate: `scripts/getzilla_update.py --only agents --only sources`
fetches the latest releases for observation; a new version becomes the baseline only when
`toolchain.json` (`pinned`, `upstream_tag`, `pinned_commit`, `asset_inputs`, `generated_assets`) and the
bound assets are updated and reviewed together. A Git pin alone is not semantic approval.

## Offline mirror

`GETZILLA_UPDATE_MIRROR=/absolute/dir` makes `getzilla_update.py` (and so both installers) take every
download from a local directory. Nothing is downloaded while it is set; agent CLI updates are skipped.

```text
<dir>/osv/<Ecosystem>/all.zip          same layout as GETZILLA_OSV_DB
<dir>/opengrep/v<version>/<asset>      the pinned OpenGrep release assets
<dir>/git/<owner>/<repo>.git           Git repositories with the pinned upstream tags
<dir>/getzilla-mirror.json             optional: pins for stand-in files
```

The checks do not change: OSV archives must be complete zips, OpenGrep must match its SHA-256 and each
source must resolve to its commit. With real files the pins are those in `updater.py` and `toolchain.json`.
A mirror of small stand-in files (the installer tests use one, built by `tests/_support.offline_mirror`)
names its own pins in `getzilla-mirror.json` (`{"opengrep": {"<asset>": "<sha256>"}, "baseline":
{"<id>": "<commit>"}}`), and every result line says `pin from getzilla-mirror.json`. Do not use such a
mirror for a real install: run `getzilla_update.py --only osv --only opengrep --only baseline` without
the variable to replace stand-ins with the pinned files.

The installer end-to-end tests use a stand-in mirror and need no network. To run them once against the
real download hosts as well: `GETZILLA_E2E_TOOLCHAINS=1 python3 -m pytest tests/test_install_scripts.py`.

## Connecting a project

```text
getzilla baseline apply --project DIR [--agent claude|codex|qwen|gemini|grok|copilot]
getzilla baseline status [--project DIR] [--agent NAME]
```

- Superpowers skills and LICENSE files come from the fixed pinned-source assets. Copilot receives
  canonical context only; no marketplace plugin is installed or trusted by this path.
- BMAD/Spec Kit files come from fixed generated assets, not `npx` or ambient `specify`. Their generation
  used pinned source and hash-checked dependencies in a disposable Linux network/PID/user namespace,
  with read-only source/dependencies, an empty environment and scratch output. Exact source, dependency,
  command and per-file bindings are retained in each variant manifest and in `toolchain.json`.
- Generated output is stored as readable UTF-8 content-addressed blobs and24variant manifests, without
  binary encoding. Blob hashes bind exact original bytes, including upstream CRLF. The scoped Git
  attribute disables newline conversion while keeping normal text diff detection.
- Consumer installation validates complete manifest/blob/file custody before copying. It does not execute
  upstream code, install dependencies, activate skills or grant network/secret/tool permissions.
  Existing `_bmad/` and `.specify/` directories remain untouched; conflicting/unsafe new paths refuse.
  BMAD project-name rendering updates its file manifest and produces a separate materialized digest.
- The entire asset path is code-bearing supply-chain data. Asset-only `.txt`/`.json` edits retain full
  executable verification and security/release risk reviews; they cannot use docs-focused or light lanes.
- Six agent adapters are covered. Spec Kit has separate `sh` and `ps` assets. Native Windows/macOS
  script execution and sandbox behavior require their own qualification; data-copy tests do not prove it.

New external skills use the separate [preflight and interview](skill-preflight.md) path. The shipped
catalog is source custody, not a claim that arbitrary instructions are safe. Interrupted multi-file
materialization can leave copied files; it never reports success for an incomplete copy. Reconcile
partial state explicitly before retrying. There is no automatic execution fallback.
An incomplete bounded runtime diagnostic blocks a retry from treating its partial directory as existing
user data. This record can only cause refusal; it grants no authority and is not a permission ledger.

## Verify

In a project Getzilla was installed into (`.getzilla/AGBP_SYNC.json`), `verify --mode pr|release`
fails with `WORKFLOW_BASELINE_MISSING` / `PROJECT_BASELINE_MISSING` until the baseline is installed
and connected; `fast` mode warns. CI runners skip this check (the baseline belongs to the agent's
machine). Security tools were already mandatory in `pr`/`release`: a skipped OpenGrep or an
unconfigured vulnerability check fails the quality gate there.
