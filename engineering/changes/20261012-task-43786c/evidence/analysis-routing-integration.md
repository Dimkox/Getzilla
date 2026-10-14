# Routing integration analysis

Finding: default generated selector uses oldest matching ancestor before cwd. Nested candidate and installed consumer load outer root hook code. Explicit valid CLAUDE_PROJECT_DIR preserves selection of own hook. Real UserPromptSubmit with explicit payload cwd writes routes to scratch root, despite loading outer hook code. Thus selected source/policy code and runtime repository can differ. No grant authority was exercised.

Source: 4bf48f5832bac54d08b9666a2354703ce2a03e9d / tree166f0671708d76af0dde59f4eb4db31b1879b317. Private scratch /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh mode0700. CPU18-23 one worker.

Commands: git clone --quiet --no-hardlinks --no-checkout /home/pall/projects/getzilla/.getzilla/runtime/worktrees/fix-codex-cmd-20261011 /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/nested; git checkout --quiet --detach 4bf48f5832bac54d08b9666a2354703ce2a03e9d; python3 scripts/install_into.py --materialize-new /home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/consumer. All exit0. Generated .codex/hooks.json UserPromptSubmit first python3 -c branch extracted with shlex.split. Instrumented only runpy.run_path call to print selected hook path to stderr then invoke original; exact selection logic and real hook preserved. Invoked python3 -c wrapper with JSON payload stdin at nested clone and installed consumer, with project env absent then CLAUDE_PROJECT_DIR set to own root.

Original generated launcher:
```
python3 -c "import os,pathlib,runpy,sys;t='.grok/hooks/user_prompt_submit.py';p=pathlib.Path;d=p.cwd();e=[p(os.environ[k]) for k in ('CLAUDE_PROJECT_DIR','QWEN_PROJECT_DIR','GEMINI_PROJECT_DIR') if os.environ.get(k)];f=next(q/t for q in (*e,*reversed(d.parents),d) if (q/t).is_file());sys.path.insert(0,str(f.parent));sys.argv=[str(f),'--harness','codex'];runpy.run_path(str(f),run_name='__main__')" || python -c "import os,pathlib,runpy,sys;t='.grok/hooks/user_prompt_submit.py';p=pathlib.Path;d=p.cwd();e=[p(os.environ[k]) for k in ('CLAUDE_PROJECT_DIR','QWEN_PROJECT_DIR','GEMINI_PROJECT_DIR') if os.environ.get(k)];f=next(q/t for q in (*e,*reversed(d.parents),d) if (q/t).is_file());sys.path.insert(0,str(f.parent));sys.argv=[str(f),'--harness','codex'];runpy.run_path(str(f),run_name='__main__')"
```

Results:
```json
[
  {
    "case": "default",
    "exit": 0,
    "selected": "SELECTED=/home/pall/projects/getzilla/.grok/hooks/user_prompt_submit.py",
    "response": {
      "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "ADAPTIVE GROK ROUTE\nRoute ID: e7a4467a161a\nIntent: docs | Risk: medium | Complexity: standard\nDomains: api (task focus: repository default)\nRequired skills: $getzilla-delivery, $task-triage, $api-event-change\nParallel read-only analysis agents: repo_explorer, architect, docs_researcher, integration_architect\nSingle write owner: general_implementer\nParallel review agents after implementation: code_reviewer\nQuality profiles: base, contracts\nHuman gates: none\nUse /getzilla-delivery. Do not spawn agents outside the route. Run every listed read-only analysis agent in parallel (cap is a ceiling, not a quota). Keep exactly one write owner."
      }
    },
    "route_id": "e7a4467a161a",
    "allowed_agents": [
      "repo_explorer",
      "architect",
      "docs_researcher",
      "integration_architect",
      "code_reviewer",
      "general_implementer"
    ],
    "root_route_file": "/home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/nested/.getzilla/runtime/active-route.json"
  },
  {
    "case": "explicit-project",
    "exit": 0,
    "selected": "SELECTED=/home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/nested/.grok/hooks/user_prompt_submit.py",
    "response": {
      "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "ADAPTIVE GROK ROUTE\nRoute ID: e081b7d2cee6\nIntent: docs | Risk: medium | Complexity: standard\nDomains: api (task focus: repository default)\nRequired skills: $getzilla-delivery, $task-triage, $api-event-change\nParallel read-only analysis agents: repo_explorer, architect, docs_researcher, integration_architect\nSingle write owner: general_implementer\nParallel review agents after implementation: code_reviewer\nQuality profiles: base, contracts\nHuman gates: none\nUse /getzilla-delivery. Do not spawn agents outside the route. Run every listed read-only analysis agent in parallel (cap is a ceiling, not a quota). Keep exactly one write owner."
      }
    },
    "route_id": "e081b7d2cee6",
    "allowed_agents": [
      "repo_explorer",
      "architect",
      "docs_researcher",
      "integration_architect",
      "code_reviewer",
      "general_implementer"
    ],
    "root_route_file": "/home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/nested/.getzilla/runtime/active-route.json"
  },
  {
    "case": "installed-default",
    "exit": 0,
    "selected": "SELECTED=/home/pall/projects/getzilla/.grok/hooks/user_prompt_submit.py",
    "response": {
      "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "ADAPTIVE GROK ROUTE\nRoute ID: 9a2817b89777\nIntent: docs | Risk: low | Complexity: micro\nDomains: generic (task focus: repository default)\nRequired skills: $getzilla-delivery, $task-triage\nParallel read-only analysis agents: repo_explorer\nSingle write owner: general_implementer\nParallel review agents after implementation: code_reviewer\nQuality profiles: base\nHuman gates: none\nUse /getzilla-delivery. Do not spawn agents outside the route. Run every listed read-only analysis agent in parallel (cap is a ceiling, not a quota). Keep exactly one write owner."
      }
    },
    "route_id": "9a2817b89777",
    "allowed_agents": [
      "repo_explorer",
      "code_reviewer",
      "general_implementer"
    ]
  },
  {
    "case": "installed-explicit",
    "exit": 0,
    "selected": "SELECTED=/home/pall/projects/getzilla/.getzilla/runtime/reviews/20261012-codex/routing-private-mwku9mrh/consumer/.grok/hooks/user_prompt_submit.py",
    "response": {
      "hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": "ADAPTIVE GROK ROUTE\nRoute ID: 86e2bc3166d1\nIntent: docs | Risk: low | Complexity: micro\nDomains: generic (task focus: repository default)\nRequired skills: $getzilla-delivery, $task-triage\nParallel read-only analysis agents: repo_explorer\nSingle write owner: general_implementer\nParallel review agents after implementation: code_reviewer\nQuality profiles: base\nHuman gates: none\nUse /getzilla-delivery. Do not spawn agents outside the route. Run every listed read-only analysis agent in parallel (cap is a ceiling, not a quota). Keep exactly one write owner."
      }
    },
    "route_id": "86e2bc3166d1",
    "allowed_agents": [
      "repo_explorer",
      "code_reviewer",
      "general_implementer"
    ]
  }
]
```

Outer active-route before/after SHA256 a462fdc63375a809afe73e2d0e628ccdac1c9135ed519c31a78ab85cfe62a16e unchanged. No root19c route mutations. Candidate unchanged. All route writes confined to private scratch.

Repair expectation: retain explicit valid project env precedence; otherwise select own cwd/nearest ancestor before farther outer roots. Add real launcher probes from nested repo, subdirectory and installed consumer, including malformed explicit env behavior. Assert selected code root plus actual route destination and allowed selected agents; do not accept only hook JSON response. No grants from outer root may authorize inner source. Postrepair controls not run: source not repaired yet.
reviewed-tree-modified: no
