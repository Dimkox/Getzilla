# Quickstart — Getzilla

Use this page for the simple path. It gives you a local candidate and evidence. It does not merge, deploy, publish, or grant production authority.

**One-command install.** These installers add whatever is missing (Git, Python 3.10+, your coding agent: Qwen Code by default, or Codex, Claude Code, Gemini CLI, GitHub Copilot CLI, Grok Build), point the agent at its models (OpenRouter with your own key from https://openrouter.ai/keys by default, or the agent's own sign-in), download Getzilla to `~/Getzilla` (override with `GETZILLA_HOME`) and run the health check. They change nothing in your projects; set `GETZILLA_PROJECT` to also print the read-only plan for an existing project, or `GETZILLA_NEW_PROJECT` to create a new project at that path. Both installers, and the engine and hooks they install, run natively on Windows, Linux and macOS.

```powershell
# Windows: winget when available (installed from github.com/microsoft/winget-cli when missing, e.g. on Windows 10), otherwise official per-user downloads (no admin rights needed)
$f = Join-Path $env:TEMP 'getzilla-install.ps1'
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/Dimkox/Getzilla/v2.2.0/scripts/install.ps1 -OutFile $f
if ((Get-FileHash $f -Algorithm SHA256).Hash -eq '32F5DFD05E8B19CF327BEF6EA2B7DA1F677675573A0ECEB27C17AAB8ACA73987') { $env:GETZILLA_REF = 'v2.2.0'; Invoke-Expression (Get-Content -Raw $f) } else { throw 'install.ps1 SHA-256 mismatch: do not run it' }
```

```bash
# Linux (apt, dnf, yum, pacman, zypper, apk)
curl -fsSLo getzilla-install.sh https://raw.githubusercontent.com/Dimkox/Getzilla/v2.2.0/scripts/install.sh
echo "39e64ee54b2f3966500311aa454d920e65c1f69b2dab0ab2ea0a255c266d63b9  getzilla-install.sh" | sha256sum -c - && GETZILLA_REF=v2.2.0 bash getzilla-install.sh
```

```bash
# macOS (Homebrew or Command Line Tools)
curl -fsSLo getzilla-install.sh https://raw.githubusercontent.com/Dimkox/Getzilla/v2.2.0/scripts/install.sh
echo "39e64ee54b2f3966500311aa454d920e65c1f69b2dab0ab2ea0a255c266d63b9  getzilla-install.sh" | shasum -a 256 -c - && GETZILLA_REF=v2.2.0 bash getzilla-install.sh
```

The installer is verified before it runs: the commands download it from the `v2.2.0` release tag, compare its SHA-256 with the digest published here (the test suite keeps this digest equal to the shipped `scripts/install.sh` / `scripts/install.ps1`), run it only when the digest matches (the check and the run are one command, so a failed check stops it), and install Getzilla from the same tag. Never pipe the installer straight into `bash` or `iex`. If the check fails, do not run the file: re-download it and report the mismatch.

Without a terminal to ask in, the installers use `GETZILLA_AGENT` (`qwen` default, `codex`, `claude`, `gemini`, `copilot`, `grok`), `GETZILLA_PROVIDER` (`openrouter` default, `native`), `GETZILLA_MODEL` and `OPENROUTER_API_KEY`. The key becomes the user environment variable `OPENROUTER_API_KEY` (and `ANTHROPIC_AUTH_TOKEN` for Claude Code) that every agent reads: an owner-only `~/.getzilla/openrouter.env` sourced from your shell profiles on Linux/macOS, persistent user variables on Windows. Open a new terminal afterwards. `--forget-key` removes it. Minimum versions: Python 3.10, Node.js 20 (Qwen Code, Codex), PowerShell 7.4 on Windows (the installer adds it). Re-run the setup any time with `python3 scripts/getzilla_setup_agent.py --agent <agent>`.

At the end of every run, first install or re-run, the installer offers to update third-party tools to their latest versions (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, the CVE database) plus the pinned OpenGrep release, whose SHA-256 is checked before it is installed, and does so only after you answer `y`. Run the same update yourself at any time with `python3 scripts/getzilla_update.py` (`--status` shows the last results); agents remind you when it has not run for a day, but never start it themselves.

With the installer done, continue at step 3. The manual steps below are the same path by hand.

0. Check tools (minimum or newer; doctor offers a fallback install if something is missing):
   ```bash
   python3 scripts/getzilla_doctor.py --offer-install
   ```

1. Install one coding agent:
   - Qwen Code: `npm install -g @qwen-code/qwen-code@latest` (Node.js 20+)
   - Codex: `npm install -g @openai/codex@latest` (Node.js 20+)
   - Claude Code: `curl -fsSL https://claude.ai/install.sh | bash` (Windows: `irm https://claude.ai/install.ps1 | iex`)
   - Gemini CLI: `npm install -g @google/gemini-cli@latest` (Google sign-in or `GEMINI_API_KEY`)
   - GitHub Copilot CLI: `npm install -g @github/copilot@latest` (Node.js 22+; `/login` or `COPILOT_GITHUB_TOKEN`)
   - Grok Build: `curl -fsSL https://x.ai/cli/install.sh | bash` (Windows: `irm https://x.ai/cli/install.ps1 | iex`)

2. Models: `python3 scripts/getzilla_setup_agent.py --agent qwen` (or `codex`, `claude`) asks for your OpenRouter key and writes your user settings; `--provider native` uses the agent's own sign-in instead. Grok Build always signs in with your xAI account.

3. Plan an update for an existing repository without changing it:
   ```bash
   python3 scripts/install_into.py --plan /path/to/your/repo
   ```

   Existing repositories are read-only installer inputs. The plan is a deterministic managed-file manifest plus dependency advice; it performs no writes and executes no dependency command. The historical positional command and `--dry-run` are planning aliases. `--force` is rejected; update an existing consumer by applying the plan through a normal reviewed source-change commit.

   To create a complete installation, choose an absent path:

   ```bash
   python3 scripts/install_into.py --materialize-new /path/to/new/repo
   ```

   This materialization mode is supported only on Linux with descriptor-relative `O_NOFOLLOW`/`O_DIRECTORY` operations and both libc and the target filesystem supporting `renameat2(RENAME_NOREPLACE)`. If any required capability is unavailable or the filesystem rejects it, materialization exits nonzero and fails closed without publishing the target; there is no fallback to replace, merge, or in-place copying. Use `--plan` plus a normal reviewed source-change for an existing consumer or for a platform/filesystem without those capabilities.

   `MANAGED_DIRS`/`MANAGED_FILES` in `scripts/install_into.py` answer *what the stack owns*; a consumer answers the different question — *what this repo overrode* — in `.getzilla/AGBP_SYNC.json` (`{"schema_version": 1, "kept_local": [".coveragerc", "bandit.yaml", ".getzilla/config/routing.json"]}`). Declared paths appear in the plan as `KEEP <path> (declared by target)` and are never delivered. For an intentional managed-file divergence, add `kept_local_sha256` with the SHA-256 of each local file; the installer reports `divergent` and fails closed if those bytes later change. A kept path whose bytes differ from the stack’s without that binding remains a named conflict.

   New-target materialization uses an owned sibling stage and fail-closed no-replace publication. It refuses an existing, symlink, or special-file target. If the original identity of a newly created staging entry cannot be proven after a constructor failure, the installer preserves that unresolved entry, reports `manual cleanup required: installer ownership is unresolved`, and never deletes a same-named replacement.

   The payload delivers the architecture CLI, parser/evaluators, strict schemas, and non-authoritative examples. Every plan and payload excludes the target-owned `architecture/system.yaml`, `architecture/rules.yaml`, and `architecture/adoption.json`. It also excludes `trust-ci/` and `.github/workflows/`.

### Optional manual executable-architecture adoption

An installed repository without `architecture/adoption.json` remains backward-compatible and reports architecture as `not_configured`. Adoption is an explicit repository-owner decision: copy the examples, replace every example identity/path/policy with reviewed target truth, validate them, render/review the projections, and create the marker last. Use the reviewed model and rules as architecture input; generated diagrams are projections only.

```bash
cd /path/to/repo
mkdir -p architecture
cp .getzilla/templates/architecture/system.example.yaml architecture/system.yaml
cp .getzilla/templates/architecture/rules.example.yaml architecture/rules.yaml

# Review and replace ARCH-REPLACE-ME, owners, paths, contracts, trust/data/secret
# declarations, and every applicable policy before continuing.
python3 scripts/getzilla_architecture.py validate --json
python3 scripts/getzilla_architecture.py summary --json
python3 scripts/getzilla_architecture.py drift --json
# This prints all five bounded artifacts and does not write repository files.
python3 scripts/getzilla_architecture.py diagram --json
# Apply approved projection text through normal reviewed source edits, then compare.
python3 scripts/getzilla_architecture.py diagram --check --json
```

After review succeeds, create `architecture/adoption.json` manually with exactly the same `architecture_id` as both model documents. For the unmodified examples, the strict canonical marker bytes are exactly:

```json
{
  "architecture_id": "ARCH-REPLACE-ME",
  "schema_version": 1,
  "state": "adopted"
}
```

The marker requires sorted keys, two-space JSON, and exactly one final newline. Commit the marker with both reviewed target documents; marker present plus either missing/invalid document fails closed. The diagram command is read-only: checked-in projection changes are ordinary reviewed source edits. The marker, diagrams, Markdown, and receipts do not replace the system/rules authority, and local checks do not replace the App-owned exact-SHA Trust CI check.

Exact-state evidence uses literal 40-character commit SHAs. Use `--worktree` only for diagnostics; it never claims an exact head SHA:

```bash
python3 scripts/getzilla_architecture.py diff --base <40-char-sha> --head <40-char-sha> --json
python3 scripts/getzilla_architecture.py fitness --base <40-char-sha> --head <40-char-sha> --pre-risk red --json
```

4. Work:
   ```bash
   cd /path/to/repo
   qwen      # or: codex, claude, gemini, copilot, grok
   ```
   Each agent loads the same Getzilla hooks, agents and skills from `.qwen/`, `.codex/`, `.claude/`, `.gemini/`, `.github/hooks/` + `.github/agents/` or `.grok/`. Trust the project folder when the agent asks; Grok Build also needs `/hooks-trust` once.
   Prompt example: `Добавь обработчик события OnAfterUserAdd в local-модуль`

   If hooks did not create a route, create one explicitly:

   ```bash
   python3 scripts/getzilla_route.py "Добавить обработчик события OnAfterUserAdd в local-модуль" --session first-task --json
   python3 scripts/getzilla_change.py start --title "Первая задача"
   python3 scripts/getzilla_status.py
   ```

5. Verify before delivery:

   ```bash
   git status --short
   git diff
   python3 scripts/getzilla_verify.py --mode pr
   python3 scripts/getzilla_status.py
   ```

   Treat local evidence as preflight only. Delivery still uses a branch and pull request. Trust CI and signed approvals are advanced merge controls, not the first-run path.

5. Optional explicit skill: `/getzilla-delivery`

6. Verify before finish:
   ```bash
   python3 scripts/getzilla_verify.py --mode pr
   ```
   Then `/release-readiness` and `python3 scripts/getzilla_deploy.py` to prepare human-owned publish commands (`--record` only with production approval).

### Optional workflow artifact convergence

Create an explicit `engineering/changes/<active-id>/workflow/manifest.json` listing allowlisted GitHub Spec Kit, BMAD, or Superpowers files (accepted shapes and the known-unparsed list live in [docs/superpowers/specs/2026-09-15-workflow-artifact-adapters-upstream-amendment.md](docs/superpowers/specs/2026-09-15-workflow-artifact-adapters-upstream-amendment.md)). Inspect without writing first:

```bash
python3 scripts/getzilla_artifacts.py import --change-id <active-id>
python3 scripts/getzilla_artifacts.py compile --change-id <active-id>
python3 scripts/getzilla_artifacts.py converge --change-id <active-id>
```

Persist the exact derived `workflow/task-graph.json` / `workflow/convergence-report.json` files or marked framework projections/exports only with `--write --expected-digest <sha256>`; use 64 zeroes only to create a missing target. The graph stores source-status hints, while current canonical receipts derive ephemeral effective status without a tracked rewrite. Per-target runtime locks serialize cooperating writers. Missing targets use atomic no-clobber creation; existing targets require platform atomic exchange. Any post-exchange mismatch rolls back before displaced content is read, and a second racing entry is retained under a bounded recovery/temp name for manual forward recovery rather than deleted. Imported documents and their tightly allowlisted RED/GREEN argv are never executed and never become route, governance, approval, receipt, or merge authority. `getzilla_verify` checks stored graph/report read-only when the manifest exists and skips this check for historical packages. The `workflow_sources` currency observation is valid for 90 days after `observed_at`: before the freshness test fails, re-observe upstream latest releases, refresh `.getzilla/config/toolchain.json` and the README table, and re-point any renamed shape test.

7. Trust project hooks in the TUI: `/hooks-trust`

## Try the local browser demo

From this checkout, start the Python-only dashboard with no install and no frontend build:

```bash
python3 scripts/getzilla_demo.py --open
```

It serves `http://127.0.0.1:8765/` on loopback only. The tour uses bundled sample evidence, a fixed non-authoritative route seed, in-memory computed previews and read-only summaries from this checkout; it invokes no Git command and makes no external request or write. `--open` may ask the operating system to open your local browser. Press `Ctrl-C` to stop. See [docs/INVESTOR_DEMO.md](docs/INVESTOR_DEMO.md) for the walkthrough and port troubleshooting.

## Scope split

`install_into.py --plan` inspects an existing target read-only. On Linux with the descriptor and `renameat2(RENAME_NOREPLACE)` capabilities stated above, `install_into.py --materialize-new` publishes the local Grok stack (skills, agents, hooks, scripts, `AGENTS.md`) only at an absent target. It does **not** copy `trust-ci/`, `.github/workflows/`, target-owned architecture authority, this repository’s `README.md`, `QUICKSTART.md`, or `VERSION`. Consumer laptops do not stand up PostgreSQL.

Local `python3 scripts/getzilla_verify.py --mode pr` is preflight evidence. It is **not merge authority**. Merge trust, when deployed, is the GitHub App-owned check `adaptive-trust-ci/verified@<policy-sha12>` on the exact pull-request SHA.

This repository is **PR-only**. Do not `git push origin main`. Ship product changes on an isolated branch and a pull request.

Optional local quality tools used by `getzilla_verify --mode pr` (not required in `toolchain.json`): ruff, bandit, coverage (`fail_under` 74).

## Bitrix example

```bash
cd examples/bitrix-module
composer install
composer test
```

## Operator: Trust CI host

Dedicated Linux CI host with Docker Engine and Compose v2. Do not colocate privileged rootless DinD with production workloads. Terminate TLS in a reverse proxy (none is in-tree). Full operator contract: [`trust-ci/README.md`](trust-ci/README.md) and [`engineering/runbooks/trust-ci-rollout.md`](engineering/runbooks/trust-ci-rollout.md). Commands below match the Makefile; do not build against `compose.yaml` alone.

### PostgreSQL

One logical database `trust_ci`. Four login roles (`trust_ci_api`, `trust_ci_worker`, `trust_ci_migrator`, `trust_ci_backup`) are created by `trust-ci/postgres/init/001_roles.sh`. Schema is `sql/001_schema.sql` + `002_operational_indexes.sql` + `003_database_roles.sql`, applied by the `migrate` oneshot. The admin password is not the API/worker/migrator/backup password. The server is the Compose image `postgres:17.6-bookworm` (digest pinned at deploy), not a host `postgresql` package. Durable volume: `trust-ci-postgres`.

Copy templates. Do not commit filled files:

```bash
cd trust-ci
mkdir -p runtime/control runtime/holdout
cp .env.example .env
cp env/common.env.example env/common.env
cp env/api.env.example env/api.env
cp env/worker.env.example env/worker.env
cp env/migration.env.example env/migration.env
cp env/postgres.env.example env/postgres.env
cp env/backup.env.example env/backup.env
cp config/policy.example.json runtime/policy.json
cp config/trust-store.example.json runtime/trust-store.json
chmod 600 env/*.env .env 2>/dev/null || true
```

Replace every `REPLACE_WITH_*` placeholder, including image `name@sha256:` pins in `.env`. `runtime/trust-store.json` stays invalid until a real human public key is inserted.

### Live harness

From the repository root (exit code from `postgres-integration`, not `tests`):

```bash
make trust-ci-postgres-test
# or
./trust-ci/scripts/postgres-integration.sh
./trust-ci/scripts/postgres-restart-drill.sh
```

### Build and pin images

From the `trust-ci/` directory. `compose.yaml` has no `build:`; merge the build override:

```bash
docker compose -f compose.yaml -f compose.build.yaml --profile build build api worker runner-image
docker image inspect "$TRUST_CI_API_IMAGE" --format '{{.Id}} {{index .RepoDigests 0}}'
docker image inspect "$TRUST_CI_WORKER_IMAGE" --format '{{.Id}} {{index .RepoDigests 0}}'
docker image inspect "$TRUST_CI_RUNNER_IMAGE" --format '{{.Id}} {{index .RepoDigests 0}}'
PYTHONPATH=src python3 -m adaptive_trust_ci.cli holdout-digest --path /absolute/reviewed/holdout
```

Inspect `$TRUST_CI_*_IMAGE`. Do not inspect `adaptive-trust-ci-api:2.1.0` / `adaptive-trust-ci-worker:2.1.0` — `compose.build.yaml` does not set those tags for api/worker. Put immutable digests into `.env` and `runtime/policy.json`. Rebuilding the runner or changing policy/holdout changes the policy digest and the required check name.

### Keys

Keep the split. Never commit private keys.

- CI attestation key: worker-only (`adaptive-trust-ci keygen`).
- GitHub App RSA key: worker-only. The API must not receive App ID, installation ID, or the App private key.
- Human Ed25519 approval key: human workstation only. An agent must not generate, read, or submit it.

```bash
adaptive-trust-ci keygen \
  --private runtime/trust-ci-signing-key.pem \
  --public runtime/trust-ci-signing-key.pub.pem
chmod 600 runtime/trust-ci-signing-key.pem
```

Human key (on the human machine, not in an agent workspace):

```bash
adaptive-trust-ci keygen \
  --private ~/.config/adaptive-trust-ci/operator.pem \
  --public ~/.config/adaptive-trust-ci/operator.pub.pem
```

Copy only the public key and printed `key_id` into server-side `runtime/trust-store.json`.

### Start and health

```bash
docker compose -f compose.yaml up -d postgres migrate api worker
curl -fsS http://<loopback-trust-ci>/health/ready
```

`/health/ready` stays **503** until PostgreSQL is up **and** the trust store has an active human public key. The systemd unit `trust-ci/systemd/adaptive-trust-ci-compose.service` also starts `docker-engine` + `runner-loader` after `verify-supply-chain.sh`. Manual `up` of `postgres migrate api worker` is enough to exercise API readiness; jobs that need a runner require the systemd set (or `docker-engine` and `runner-loader` as well).

### Webhook, then prove, then branch-protect

1. Deploy API, PostgreSQL and worker.
2. Register the HMAC GitHub webhook on `/webhooks/github` (pull-request events).
3. Prove the App-owned check first on a disposable docs PR (draft or not). Do not treat a draft as the first live proof of branch protection.
4. Confirm Check Run `adaptive-trust-ci/verified@<policy-sha12>` on the exact head SHA, owned by the Trust CI GitHub App.
5. Verify the signed attestation offline.
6. Only then consider `adaptive-trust-ci branch-protect`. Applying branch protection before the App-owned check exists can lock the repository.

### Backup, kill-switch, supply-chain

```bash
adaptive-trust-ci backup-create
adaptive-trust-ci restore-drill --confirm-disposable
adaptive-trust-ci kill-switch on
adaptive-trust-ci kill-switch status
adaptive-trust-ci kill-switch off
```

A systemd timer runs daily backup. Operator-only image release:

```bash
trust-ci/scripts/supply-chain-release.sh --confirm-push
```

That script requires host tools **docker**, **trivy**, **syft**, and **cosign**. Optional extra scanner (not a product pin, not in `toolchain.json`): grype. Pointers: [`trust-ci/README.md`](trust-ci/README.md), [`engineering/runbooks/trust-ci-rollout.md`](engineering/runbooks/trust-ci-rollout.md).

### Scanner host install

Official commands (also offered by `python3 scripts/getzilla_doctor.py --offer-install` for optional tools):

```bash
# Docker Engine + Compose v2 (Ubuntu 24.04)
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2

# Syft
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin

# Trivy (Aqua contrib install script)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.74.0

# Cosign (Sigstore GitHub releases; pin fallback 2.4.x)
curl -sSfL https://github.com/sigstore/cosign/releases/download/v2.4.3/cosign-linux-amd64 -o /tmp/cosign
sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
```
