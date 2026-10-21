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

Current source: **2.3.1 source candidate**, including the verifier child-test scope fix. Latest published: [v2.3.0](https://github.com/Dimkox/Getzilla/releases/tag/v2.3.0), source `2bb417431f1e4b9494e4af71ebf27adb1d04d898`, with [ZIP](https://github.com/Dimkox/Getzilla/releases/download/v2.3.0/getzilla-2.3.0.zip) and [checksum](https://github.com/Dimkox/Getzilla/releases/download/v2.3.0/getzilla-2.3.0.zip.sha256) assets. Publication does not prove production readiness. Continue through [START_HERE.md](START_HERE.md).

Getzilla lets an AI write code for your project and checks that code before it is allowed to stay.

The optional [EU AI Act layer](docs/eu-ai-act.md) includes matrix freshness checks, risk records,
Python and Node transparency adapters, and audit evidence. Run `getzilla compliance scaffold`
to create an adapter for a registered system. Read-only CI checks and a trusted installed verifier
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
| Mistakes | The next session repeats them | Lessons are written down in `mistakes.md` and `decisions.md` for the next session |
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

To choose without being asked, set `GETZILLA_AGENT` (`qwen`, `codex`, `claude`, `gemini`, `copilot`, `grok`), `GETZILLA_PROVIDER` (`openrouter`, `native`) and `OPENROUTER_API_KEY` first. To switch agents later, run `python3 scripts/getzilla_setup_agent.py --agent codex` from the Getzilla folder.

To bring third-party tools (agent CLIs, Superpowers, BMAD, Spec Kit, vibevm, the CVE database) to their latest versions and install the pinned, SHA-256-verified OpenGrep release, run `python3 scripts/getzilla_update.py`; the installer offers this at the end of every run.

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

## What is inside

- `scripts/`: the commands you run, such as `getzilla_route.py` and `getzilla_verify.py`
- `.grok/` and `.agents/skills/`: instructions and skills for the AI agents (the canonical source)
- `.grok/skills/`, `.qwen/`, `.claude/`, `.codex/`, `.gemini/`, `.github/hooks/`, `.github/agents/`: the same hooks, agents and skills for Qwen Code, Claude Code, Codex, Gemini CLI and Copilot CLI, generated by `scripts/getzilla_harness.py --write`
- `.cursor/rules/getzilla/`: prompt-only Cursor rules from `.grok/cursor-rules/`, generated the same way for this repository only; `install_into.py` does not install them into consumer repositories (Cursor reads `AGENTS.md` and `.agents/skills/` itself)
- `.getzilla/`: the engine that sorts tasks, runs checks and saves the evidence
- `engineering/changes/`: one folder per task, with its plan, tests and reviews
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
