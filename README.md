# Getzilla

Getzilla lets an AI write code for your project and checks that code before it is allowed to stay.

## The short version

With "vibe coding", you ask an AI for something, it writes the code, and you hope it works. It is fast and fun. You usually find out later what it broke.

Getzilla keeps the fast part and adds a checking part. The AI still builds what you asked for. Before that work joins the real project, it gets checked: tests run, a second AI reviews it, and a person decides whether to keep it.

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
| Who ships | The AI | You do. The agent works through a pull request, and a person merges it |

You do not give up vibe coding. The rule is **vibe first, check second**: build it fast, then run it through Getzilla before it is kept.

## How a task goes

1. **Build it.** Get the feature working quickly on its own branch.
2. **Sort it.** Getzilla looks at the task and decides how careful to be: which skills to use, which reviewers to call, whether a person must approve the plan first.
3. **Check it.** Tests and other checks run. The results are saved next to the task.
4. **Review it.** Separate AI reviewers read the change and write down what they find.
5. **Ship it.** A pull request is opened, and a person merges it. Teams that want an extra lock can add Trust CI, a separate service that tests the exact version again before merge.

## Try it

One command installs everything that is missing (Git, Python, the Grok Build CLI), downloads Getzilla to `~/Getzilla` and checks the machine.

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.ps1 | iex
```

Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.sh | bash
```

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
- `.grok/` and `.agents/skills/`: instructions and skills for the AI agents
- `.getzilla/`: the engine that sorts tasks, runs checks and saves the evidence
- `engineering/changes/`: one folder per task, with its plan, tests and reviews
- `architecture/`: a map of the system ([system.yaml](architecture/system.yaml), [rules.yaml](architecture/rules.yaml), [diagrams](architecture/generated/))
- `trust-ci/`: the optional outside checker, run as its own service
- `factory/`, `delivery/`, `pilot/`: bigger automation pieces, switched off by default

## What it is not

- Not a hosted service. It runs on your machine, inside your repository.
- Not a CI service. CI follows repository visibility: public repositories run the pinned GitHub Actions workflow from `scripts/getzilla_ci.py`, private ones use Trust CI.
- Not a bot that merges or deploys on its own.

## Learn more

- [QUICKSTART.md](QUICKSTART.md): setup, step by step
- [docs/REFERENCE.md](docs/REFERENCE.md): the full technical reference, with the current state, every subsystem and the release history
- [START_HERE.md](START_HERE.md): where a new AI agent or contributor starts
- [AGENTS.md](AGENTS.md): the rules every agent follows
- [docs/INVESTOR_DEMO.md](docs/INVESTOR_DEMO.md): a five-minute demo walkthrough

Getzilla grew out of an [earlier project](https://github.com/Dimkox/adaptive-grok-build-pro/tree/c4e506f3d3a45e000f5b9f9121f698c1d16814e3) and was renamed. Older pull-request numbers and releases mentioned in the docs belong to that project.

Current version: [VERSION](VERSION). License: [MIT](LICENSE).
