# Mandatory baseline

Every Getzilla install has the same baseline, with no option to skip any part of it:

| Part | What | Pinned by |
|---|---|---|
| Security | OSV CVE database, OpenGrep scanner with Getzilla rules | OpenGrep version and SHA-256 in `updater.py` |
| Superpowers | skills for brainstorming, plans, TDD, debugging, review | tag + commit in `toolchain.json` |
| BMAD | `_bmad/` method files and the agent's BMAD skills | npm version = tag, commit recorded |
| Spec Kit | `specify` CLI, `.specify/` and the agent's `/speckit-*` skills | tag + commit; installed with `uv` |

## Installer

`install.sh` / `install.ps1` install the security data, then the workflow baseline:

1. Node.js 20+ (pinned archives, as for the agent CLIs) for the BMAD installer;
2. `uv` 0.11.12 in Getzilla's own environment (reused when that exact version is already on PATH), which
   installs the Spec Kit CLI with its own Python 3.11+;
3. `scripts/getzilla_update.py --only baseline`: each source is cloned at its pinned tag into
   `~/.getzilla/baseline/<id>` and must resolve to the pinned commit (`PINNED_COMMIT_MISMATCH` otherwise),
   and the Spec Kit CLI is installed from the pinned tag.

If any step fails, the installer stops with an error and the command to retry. A new project
(`GETZILLA_NEW_PROJECT`) is connected right after it is created.

Updating to newer upstream versions is separate: `scripts/getzilla_update.py --only agents --only sources`
fetches the latest releases for observation; a new version becomes the baseline only when
`toolchain.json` (`pinned`, `upstream_tag`, `pinned_commit`) is updated and its verification tests pass.

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

- Superpowers skills are copied into `.agents/skills` (Getzilla's canonical skill source) and the
  agent's skill directory, with the upstream LICENSE. Copilot additionally needs the upstream
  marketplace plugin, which is not pinned.
- BMAD runs `npx bmad-method@<pinned> install --tools <agent> --yes` and Spec Kit runs
  `specify init --here --integration <agent> --non-interactive` in an empty staging directory.
  Their files are merged into the project **without overwriting** anything; kept files are listed.
  An existing `_bmad/` or `.specify/` is left as it is.

## Verify

In a project Getzilla was installed into (`.getzilla/AGBP_SYNC.json`), `verify --mode pr|release`
fails with `WORKFLOW_BASELINE_MISSING` / `PROJECT_BASELINE_MISSING` until the baseline is installed
and connected; `fast` mode warns. CI runners skip this check (the baseline belongs to the agent's
machine). Security tools were already mandatory in `pr`/`release`: a skipped OpenGrep or an
unconfigured vulnerability check fails the quality gate there.
