"""getzilla: one command for the Getzilla tools (`getzilla <command> [arguments]`).

Inside a project that carries Getzilla the project's own scripts run; elsewhere the scripts of
this Getzilla installation do. Arguments pass through unchanged: `getzilla route --show` runs
`python scripts/getzilla_route.py --show`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

HOME = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HOME / '.getzilla'))

from getzilla.interpreter import project_python  # noqa: E402

COMMANDS: dict[str, tuple[str, str]] = {
    'duplicates': ('getzilla_duplicates.py', 'read-only source duplication analysis (optional jscpd)'),
    'doctor': ('getzilla_doctor.py', 'check this machine and the repository'),
    'cpu': ('getzilla_startup_cpu.py', 'startup CPU step zero: measure and record capacity'),
    'par': ('getzilla_par.py', 'run independent commands in parallel on the verified CPUs'),
    'route': ('getzilla_route.py', 'create or inspect the adaptive task route'),
    'status': ('getzilla_status.py', 'show the route, change package and agents'),
    'report': ('getzilla_report.py', 'per-profile overhead and defects caught before merge'),
    'cleanup': ('getzilla_cleanup.py', 'disk inventory and guarded removal of worktrees without unique work'),
    'change': ('getzilla_change.py', 'manage engineering change packages'),
    'spec': ('getzilla_spec.py', 'validate typed change specifications'),
    'verify': ('getzilla_verify.py', 'run route-selected verification and record a receipt'),
    'review': ('getzilla_review.py', 'record an independent review receipt'),
    'gate': ('getzilla_gate.py', 'inspect or record delivery gates'),
    'approve': ('getzilla_approve.py', 'materialize an explicitly delegated local grant'),
    'protected-write': ('getzilla_protected_write.py', 'apply an approved protected-path write'),
    'agent': ('getzilla_agent.py', 'agent heartbeat, checkpoints, watchdog and repeated-failure recovery'),
    'architecture': ('getzilla_architecture.py', 'validate, diff and draw the architecture model'),
    'artifacts': ('getzilla_artifacts.py', 'compile workflow framework artifacts'),
    'governance': ('getzilla_governance.py', 'validate governance evidence'),
    'history': ('getzilla_history.py', 'offline historical evidence accounting'),
    'vulns': ('getzilla_vulns.py', 'check pinned dependencies against known vulnerabilities'),
    'update': ('getzilla_upgrade.py', 'update Getzilla, this project (on a new branch) and third-party tools'),
    'ci': ('getzilla_ci.py', 'select the CI and merge gate for this repository'),
    'git': ('getzilla_git.py', 'Git platform capabilities and offline remote identity'),
    'entire': ('getzilla_entire.py', 'optional Entire transport and Trails (extra:entire)'),
    'trust-ci': ('getzilla_trust_ci.py', 'set up and check the self-hosted Trust CI host (init, status)'),
    'deploy': ('getzilla_deploy.py', 'prepare human-owned publish commands'),
    'harness': ('getzilla_harness.py', 'regenerate the agent harness files'),
    'setup-agent': ('getzilla_setup_agent.py', 'configure the coding agent and its models'),
    'install-into': ('install_into.py', 'install Getzilla into a project (--plan, --materialize-new)'),
    'components': ('getzilla_components.py', 'components added on demand: status, add agent:<name>|factory'),
    'compliance': ('getzilla_compliance.py', 'scaffold optional compliance adapters for a registered AI system'),
    'baseline': ('getzilla_baseline.py', 'mandatory pinned baseline: status, apply to a project'),
    'risk-terms': ('getzilla_risk_terms.py', 'risk vocabulary language packs: check, scaffold, languages'),
    'adopt': ('adopt_existing.py', 'adopt a folder without Git into a new local workspace (Zero-Git)'),
    'branches': ('branch_lifecycle.py', 'branch retention report and guarded delete (dry-run by default)'),
    'graph': ('getzilla_graph.py', 'Python code graph: build, status, impact, export (read-only)'),
    'demo': ('getzilla_demo.py', 'open the local read-only demo dashboard'),
}


def usage() -> str:
    width = max(len(name) for name in [*COMMANDS, 'test'])
    lines = ['usage: getzilla <command> [arguments]', '', 'commands:']
    lines += [f'  {name:<{width}}  {summary}' for name, (_, summary) in COMMANDS.items()]
    lines.append(f"  {'test':<{width}}  run the test suite on the measured CPU capacity")
    lines += ['', "`getzilla <command> --help` shows a command's own options."]
    return '\n'.join(lines)


def script_path(name: str, cwd: Path | None = None) -> Path:
    """The project's own copy of a script when run inside a Getzilla project, else this install's."""
    start = (cwd or Path.cwd()).resolve()
    for base in (start, *start.parents):
        candidate = base / 'scripts' / name
        if (base / '.getzilla').is_dir() and candidate.is_file():
            return candidate
    return HOME / 'scripts' / name


def test_workers() -> int:
    """Workers for `getzilla test`: measured capacity with the n-2 reserve, else a safe fallback."""
    try:
        from getzilla.startup_cpu import measure

        return max(1, int(measure(reserve=2, probe=False)['chosen_capacity']))
    except Exception:  # unsupported platform or unreadable topology: never block the tests
        return max(1, (os.cpu_count() or 1) - 2)


def run_tests(args: list[str]) -> int:
    targets = args or ['tests']
    python = project_python(HOME)
    # UTF-8 mode on Windows: tests decode CLI output and fixtures as UTF-8, as on POSIX; product
    # code names its encodings (tests/test_text_writes.py) so this cannot hide a product bug. The
    # environment variable reaches the xdist workers and every child, unlike -X utf8.
    environment = {**os.environ, 'PYTHONUTF8': '1'} if os.name == 'nt' else None
    probe = subprocess.run([python, '-c', 'import pytest, xdist'], capture_output=True, check=False)
    if probe.returncode == 0:
        workers = test_workers()
        print(f'getzilla test: {workers} parallel workers', flush=True)
        command = [python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '-n', str(workers), *targets]
    else:
        print('getzilla test: pytest-xdist is not installed, running unittest serially '
              '(re-run the installer to create Getzilla\'s .venv)', flush=True)
        command = [python, '-m', 'unittest', 'discover', '-s', 'tests', '-t', '.']
    return subprocess.run(command, env=environment, check=False).returncode


def main(argv: list[str]) -> int:
    if not argv or argv[0] in {'-h', '--help', 'help'}:
        print(usage())
        return 0
    command, rest = argv[0], argv[1:]
    if command == 'test':
        return run_tests(rest)
    if command not in COMMANDS:
        print(f"getzilla: unknown command '{command}'\n\n{usage()}", file=sys.stderr)
        return 2
    # `update` changes the project from the Getzilla installation, never from the project's own copy.
    script = HOME / 'scripts' / COMMANDS[command][0] if command == 'update' else script_path(COMMANDS[command][0])
    return subprocess.run([project_python(HOME), str(script), *rest], check=False).returncode


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
