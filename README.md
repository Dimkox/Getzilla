<p align="center">
  <a href="https://getzilla.app"><img src="docs/assets/brand/getzilla-banner.webp" alt="Getzilla: AI speed. Engineering discipline." width="100%"></a>
</p>

<p align="center">
  <a href="https://getzilla.app"><b>getzilla.app</b></a> ·
  <a href="https://github.com/Dimkox/Getzilla/releases/latest">Latest release</a> ·
  <a href="QUICKSTART.md">Quick start</a> ·
  <a href="docs/SECURITY.md">Security model</a>
</p>

# Getzilla

Current source: **2.3.1 source candidate** (unpublished): all work merged to `main` since v2.3.0, up to PR #179. It adds `getzilla update`, disk cleanup (`getzilla cleanup`), session-bound grants and the light lane for small changes. Latest published: [v2.3.0](https://github.com/Dimkox/Getzilla/releases/tag/v2.3.0), source `2bb417431f1e4b9494e4af71ebf27adb1d04d898`, with [ZIP](https://github.com/Dimkox/Getzilla/releases/download/v2.3.0/getzilla-2.3.0.zip) and [checksum](https://github.com/Dimkox/Getzilla/releases/download/v2.3.0/getzilla-2.3.0.zip.sha256) assets. Publication does not prove production readiness. Continue through [START_HERE.md](START_HERE.md).

Getzilla lets an AI write code for your project and checks that code before it is allowed to stay.

The optional [EU AI Act layer](docs/eu-ai-act.md) includes matrix freshness checks, risk records,
Python and Node transparency adapters, and audit evidence. Run `getzilla compliance scaffold`
to create an adapter for a registered system on platforms with descriptor-relative file creation.
Install the layer first with `getzilla components add compliance:eu-ai-act`. Lean project installs
omit its audit and scaffold scripts; the CLI gives the installation command before any adapter write.
On Windows, copy the installed template manually; the scaffold command refuses before writing.
Read-only CI checks and a trusted installed verifier
can record signed audit execution. Normal audit bundles still need local verification receipts.
The ISO/IEC 42001 map is informational. These are engineering evidence tools, not legal advice.
Trust CI signed-argv emission and policy wiring ship in a separate successor; legacy attestations
without argv cannot establish EU execution evidence.

The local command guard checks Codex `exec_command.cmd` before policy and workdir checks. It rejects malformed native input and conflicting `cmd`/`command` fields. Legacy `command` string/list inputs remain supported. Generated hooks use the nearest installed project, so nested worktrees keep their own route and denial state. Task scratch stays under the canonical project root `.getzilla/runtime`.

## The short version

With "vibe coding", you ask an AI for something, it writes the code, and you hope it works. It is fast and fun. You usually find out later what it broke.

Getzilla keeps the fast part and adds a checking part. The AI still builds what you asked for. Before that work joins the real project, it gets checked: tests run, a second AI reviews it, and the required checks and review decide whether it can merge.

Think of a child building a LEGO tower. Building is the fun part, and nobody should slow it down. But before the tower goes on the shelf next to everything else, someone makes sure it is steady, so it does not knock the whole shelf over. Getzilla is that someone.

## Vibe coding vs. Getzilla

| | Plain vibe coding | With Getzilla |
| --- | --- | --- |
| "It works" | The AI says so | Tests and checks really ran, and the results are saved |
| Who checks the work | The same AI that wrote it | A different AI reviewer. The author cannot approve itself |
| Where changes go | Wherever the AI puts them, sometimes straight into `main` | Every task gets its own branch and pull request |
| Memory | Gone when the chat ends | Every task leaves a folder: the request, the plan, test results, reviews |
| Mistakes | The next session repeats them | [Recurring lessons](engineering/mistakes.md) link to [dated incidents](engineering/incidents/README.md); decisions remain in `decisions.md` |
| Small vs. risky tasks | Treated the same | Small tasks take a short path. Risky ones get more checks and a human sign-off |
| Something unclear | The AI guesses | Getzilla stops instead of guessing |
| Who ships | The AI | The agent uses a pull request. Under conditional L5, it merges after checks and independent review |

You do not give up vibe coding. The rule is **vibe first, check second**: build it fast, then run it through Getzilla before it is kept.

## How a task goes

1. **Build it.** Get the feature working quickly on its own branch.
2. **Sort it.** Getzilla looks at the task and decides how careful to be: which skills to use, which reviewers to call, whether a person must approve the plan first.
3. **Check it.** Tests and other checks run. The results are saved next to the task.
4. **Review it.** Separate AI reviewers read the change and write down what they find.
5. **Ship it.** A pull request is opened. Conditional L5 permits agent merge after exact-head checks, independent review and resolved threads. Teams that want an extra lock can add Trust CI, a separate service that tests the exact version again before merge.

## What it costs

- **Getzilla itself** is free.
- **Public repositories** are gated by GitHub Actions for free: `python3 scripts/getzilla_ci.py --write` adds a pinned, read-only workflow.
- **Private repositories** are gated by Trust CI, which runs on dedicated hardware. It is paid, priced on request: [ask for access](https://github.com/Dimkox/Getzilla/issues/new?template=trust-ci-access.yml).

## Try it

One command installs everything that is missing (Git, Python and a coding agent of your choice), downloads Getzilla to `~/Getzilla` and checks the machine.

**What you need.** Getzilla is free; the AI models are yours to pay for. The installer asks which coding agent to use (Qwen Code by default, or Codex, Claude Code, Gemini CLI, GitHub Copilot CLI, Grok Build) and where its models come from: [OpenRouter](https://openrouter.ai/keys) with your own key (the default for Qwen Code, Codex and Claude Code), or the agent's own sign-in (ChatGPT for Codex, Anthropic for Claude Code). Gemini CLI, Copilot CLI and Grok Build always use their own accounts (Google or `GEMINI_API_KEY`, GitHub Copilot or `COPILOT_GITHUB_TOKEN`, xAI). Your key is kept as the user environment variable `OPENROUTER_API_KEY` (plus `ANTHROPIC_AUTH_TOKEN` for Claude Code), so every agent process sees it; it never goes into a project, and Getzilla never ships or shares its own keys. On Windows, Getzilla needs PowerShell 7.4 or newer; the installer adds it with winget (Windows PowerShell 5.1 is enough to start the installer).

Windows (PowerShell):

```powershell
$f = Join-Path $env:TEMP 'getzilla-install.ps1'
Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/Dimkox/Getzilla/v2.3.0/scripts/install.ps1 -OutFile $f
if ((Get-FileHash $f -Algorithm SHA256).Hash -eq '4D89D8C77617FF3B262BBF8866F05E1A14D9FB45C6BA2C3C39E298AF9A499B76') { $env:GETZILLA_REF = 'v2.3.0'; Invoke-Expression (Get-Content -Raw $f) } else { throw 'install.ps1 SHA-256 mismatch: do not run it' }
```

Linux:

```bash
curl -fsSLo getzilla-install.sh https://raw.githubusercontent.com/Dimkox/Getzilla/v2.3.0/scripts/install.sh
echo "aa10c167d02aa8633f0d0d4478b9c0ad0fac3122ef293f633f1075f218889807  getzilla-install.sh" | sha256sum -c - && GETZILLA_REF=v2.3.0 bash getzilla-install.sh
```

macOS:

```bash
curl -fsSLo getzilla-install.sh https://raw.githubusercontent.com/Dimkox/Getzilla/v2.3.0/scripts/install.sh
echo "aa10c167d02aa8633f0d0d4478b9c0ad0fac3122ef293f633f1075f218889807  getzilla-install.sh" | shasum -a 256 -c - && GETZILLA_REF=v2.3.0 bash getzilla-install.sh
```

The installer is verified before it runs: the commands download it from the `v2.3.0` release tag, compare its SHA-256 with the digest published here (the test suite binds this digest to the installer bytes at the published tag), run it only when the digest matches (the check and the run are one command, so a failed check stops it), and install Getzilla from the same tag. Never pipe the installer straight into `bash` or `iex`. If the check fails, do not run the file: re-download it and report the mismatch.

To choose without being asked, set `GETZILLA_AGENT` (`qwen`, `codex`, `claude`, `gemini`, `copilot`, `grok`), `GETZILLA_PROVIDER` (`openrouter`, `native`) and `OPENROUTER_API_KEY` first. To switch agents later, run `getzilla setup-agent --agent codex` (or `python3 scripts/getzilla_setup_agent.py --agent codex` from the Getzilla folder).

To bring third-party tools (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, the CVE database) to their latest versions and install the pinned, SHA-256-verified OpenGrep release, run `python3 scripts/getzilla_update.py`; the installer offers this at the end of every run.

To update everything with one command, run `getzilla update` inside your project. It updates Getzilla itself, then writes the new Getzilla files into the project on a new branch `getzilla-update-<version>` and commits them there, then updates the third-party tools. The project must have no uncommitted changes. Nothing is pushed, and nothing is deleted unless you pass `--retire-legacy`; review the branch and open a pull request. `--no-self` and `--no-tools` skip the first and the last step. If a file your project keeps as its own (`.getzilla/AGBP_SYNC.json`) changed since its digest was recorded, the update stops; `getzilla update --accept-local` records the committed version as the one to keep and continues. The project's own `ruff.toml`, `bandit.yaml` and `.coveragerc` stay as they are. A project without a sync record gets one. On a pre-rename project the update lists the old pre-rename stack files and any file that still imports the old engine; `--retire-legacy` removes the old files in the same commit once nothing imports them.

Then, from the Getzilla folder, take the read-only tour in your browser:

```bash
python3 scripts/getzilla_demo.py --open
```

On Windows, use `py -3` instead of `python3`.

To add Getzilla to your own project, start by asking for a plan. This only reads your project and changes nothing:

```bash
python3 scripts/install_into.py --plan /absolute/path/to/your/repo
```

Then follow [QUICKSTART.md](QUICKSTART.md).

## Commands

All commands go through one launcher, `getzilla <command>`. The Linux and macOS installer links it to `~/.local/bin/getzilla`; add `~/.local/bin` to `PATH` if the shell does not find it. On Windows, use `bin\getzilla.cmd`. Without the launcher, run `python3 scripts/getzilla_cli.py <command>` from the Getzilla folder. `getzilla --help` lists the commands, and `getzilla <command> --help` shows the options of one command.

| Area | Command | What it does |
| --- | --- | --- |
| Set up | `getzilla doctor [--offer-install]` | Checks this machine and the repository, and offers to install missing tools |
| | `getzilla setup-agent --agent <name>` | Sets the coding agent (`qwen`, `codex`, `claude`, `gemini`, `copilot`, `grok`) and where its models come from |
| | `getzilla install-into --plan <repo>` | Shows, read-only, what Getzilla would add to a project; `--materialize-new <path>` creates a new project |
| | `getzilla adopt plan\|apply\|status\|resume\|abort` | Adopts a folder without Git into a new local workspace |
| | `getzilla components status`, `components add <name>` | Shows and adds optional parts, for example `agent:cursor`, `extra:bitrix`, `compliance:eu-ai-act`, `factory` |
| | `getzilla baseline status\|apply` | Shows or applies the mandatory pinned baseline |
| | `getzilla harness [--write]` | Checks or regenerates the agent files in `.qwen/`, `.claude/`, `.codex/`, `.gemini/`, `.github/` and `.cursor/` |
| Update | `getzilla update [--no-self] [--no-tools] [--accept-local] [--retire-legacy]` | Updates Getzilla, writes the new files into the project on a new branch, then updates third-party tools |
| A task | `getzilla cpu` | Measures and records the usable CPUs (startup step zero) |
| | `getzilla route "<task>"` | Creates the task route; `--show` prints it, `--reconcile` binds it to the committed diff, `--reconcile --add-reviewer <role>` keeps an extra reviewer |
| | `getzilla status` | Shows the route, the change package, open evidence gaps and agents |
| | `getzilla change start\|transition\|show` | Manages the change package of the task |
| | `getzilla spec validate\|summary\|coverage\|map\|generate` | Checks typed change specifications |
| | `getzilla agent start\|heartbeat\|progress\|watchdog\|watch\|...` | Records agent heartbeats and checkpoints, and finds stuck agents |
| | `getzilla par -j <n> -- "cmd1" "cmd2"` | Runs independent commands in parallel on the measured CPUs |
| Check | `getzilla test` | Runs the test suite with pytest-xdist on the measured CPUs, otherwise serial unittest |
| | `getzilla verify --mode fast\|pr\|release` | Runs the checks the route selects and records a receipt |
| | `getzilla review <kind> --status pass\|fail --report <file> --reviewed-commit <sha>` | Records an independent review |
| | `getzilla gate status`, `gate decide <gate> approved\|rejected` | Shows or records a human-gate decision |
| | `getzilla vulns [--online]` | Checks pinned dependencies against known vulnerabilities (OSV) |
| | `getzilla duplicates` | Finds duplicated source code (read-only; jscpd is optional) |
| | `getzilla graph build\|status\|impact\|export --root <dir>` | Builds a Python code graph and shows the impact of a change (read-only) |
| | `getzilla architecture validate\|summary\|drift\|diagram\|diff\|fitness` | Checks the architecture model and draws its diagrams |
| | `getzilla governance validate\|summary\|handoff\|project\|check-projections` | Checks governance rules and evidence |
| | `getzilla artifacts import\|compile\|converge\|validate\|export` | Reads Spec Kit, BMAD and Superpowers files as advisory input |
| | `getzilla risk-terms check\|languages\|scaffold` | Checks the risk vocabulary language packs |
| | `getzilla compliance scaffold` | Creates an EU AI Act adapter for a registered AI system (optional layer) |
| Deliver | `getzilla approve <scope> --reason "<why>" --action <action> --resource <exact>` | Records a delegated local grant for one exact operation; no wildcard |
| | `getzilla protected-write --manifest <file>` | Applies an approved write to a protected path |
| | `getzilla ci --plan\|--write` | Selects the CI gate by repository visibility and writes the pinned public workflow |
| | `getzilla trust-ci init\|status\|github-app\|trust-key` | Sets up and checks a self-hosted Trust CI host |
| | `getzilla deploy` | Prints, never runs, the publish commands a person runs |
| Keep clean | `getzilla cleanup inventory` | Lists what Getzilla keeps on disk, with sizes and repository copies; deletes nothing |
| | `getzilla cleanup worktrees [--remove]` | Lists worktrees and the reasons to keep them; `--remove` removes only those with no unique work |
| | `getzilla cleanup snapshot <commit>`, `snapshot --remove <path>` | Makes a review copy of one commit and removes it after the review |
| | `getzilla branches report\|apply` | Reports old branches; `apply` deletes only from a reviewed plan ([branch lifecycle](docs/branch-lifecycle.md)) |
| Look back | `getzilla report [--since all]` | Shows per-profile overhead and the defects caught before merge |
| | `getzilla history <snapshot.json>` | Offline accounting of historical evidence from a snapshot file |
| | `getzilla demo --open` | Opens the read-only local demo in your browser |

## What is inside

- `scripts/`: the commands you run, such as `getzilla_route.py` and `getzilla_verify.py`
- `.grok/` and `.agents/skills/`: instructions and skills for the AI agents (the canonical source)
- `.grok/skills/`, `.qwen/`, `.claude/`, `.codex/`, `.gemini/`, `.github/hooks/`, `.github/agents/`: the same hooks, agents and skills for Qwen Code, Claude Code, Codex, Gemini CLI and Copilot CLI, generated by `scripts/getzilla_harness.py --write`
- `.cursor/rules/getzilla/`: prompt-only Cursor rules from `.grok/cursor-rules/`, generated the same way for this repository only; `install_into.py` does not install them into consumer repositories (Cursor reads `AGENTS.md` and `.agents/skills/` itself)
- `.getzilla/`: the engine that sorts tasks, runs checks and saves the evidence
- `.getzilla/runtime/`: ignored task state, plans, analyses and reviews; `engineering/changes/` retains historical packages. Change packages are created on demand at `.getzilla/runtime/changes/<id>/`.
- Small low-risk diffs of at most 50 code lines use one review without a package or report-only commits. Full CI remains required.
- `scripts/getzilla_evidence.py`: portable local evidence archive; CI keeps its own actual run artifacts for 30 days.
- Disk use: review copies go to the runtime `snapshots` folder (created on first use) and are removed with `getzilla cleanup snapshot --remove`; test runs keep their temporary files inside their own run folder. `getzilla cleanup inventory` shows what is left.
- `architecture/`: a map of the system ([system.yaml](architecture/system.yaml), [rules.yaml](architecture/rules.yaml), [diagrams](architecture/generated/))
- `trust-ci/`: the optional outside checker, run as its own service
- `factory/`, `delivery/`, `pilot/`: bigger automation pieces, switched off by default

## What it is not

- Not a hosted service. It runs on your machine, inside your repository.
- Not a CI service. CI follows repository visibility: public repositories run the pinned GitHub Actions workflow from `scripts/getzilla_ci.py`, private ones use Trust CI.
- Conditional L5 covers repository merge, tag and release with exact grants after required checks and independent review. Deploy and production writes require separate scoped authority.

## Learn more

- [QUICKSTART.md](QUICKSTART.md): setup, step by step
- [docs/REFERENCE.md](docs/REFERENCE.md): the full technical reference, with the current state, every subsystem and the release history
- [docs/SECURITY.md](docs/SECURITY.md): the security model: threats, keys, what to do when a check fails, reviewer independence and their limits
- [docs/eu-ai-act.md](docs/eu-ai-act.md): the optional EU AI Act evidence layer (off by default): AI system register, draft risk class confirmed by a person, Art. 5/50/9-15 gates and the release audit bundle
- [START_HERE.md](START_HERE.md): where a new AI agent or contributor starts
- [AGENTS.md](AGENTS.md): the rules every agent follows
- [docs/INVESTOR_DEMO.md](docs/INVESTOR_DEMO.md): a five-minute demo walkthrough

Getzilla grew out of an [earlier project](https://github.com/Dimkox/adaptive-grok-build-pro/tree/c4e506f3d3a45e000f5b9f9121f698c1d16814e3) and was renamed. Older pull-request numbers and releases mentioned in the docs belong to that project.

Current version: [VERSION](VERSION). License: [MIT](LICENSE).
