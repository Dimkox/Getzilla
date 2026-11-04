"""Run the real user installers on disposable native CI runners, never a substitute installer."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from threading import Thread

from . import fsx
from .platform_install import MAX_CELL_LOG_BYTES, MAX_COMMANDS, MAX_LOG_BYTES, load_contract, native_platform


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def run_command(arguments: list[str], *, cwd: Path, log: Path, timeout: float,
                quota: int = MAX_LOG_BYTES, env: dict | None = None) -> dict:
    """Bounded report retention with a live drain and a total process/pipe deadline."""
    started = time.monotonic()
    observed = retained = 0
    errors = []
    result = {'exit': 127, 'logs_complete': False, 'cleanup_confirmed': False, 'log': log.name}
    with log.open('xb') as output:
        process = fsx.owned_popen(arguments, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)

        def read():
            nonlocal observed, retained
            try:
                while True:
                    data = process.stdout.read(65536)
                    if not data:
                        break
                    observed += len(data)
                    if not errors:
                        try:
                            keep = data[:max(0, quota-retained)]
                            output.write(keep)
                            retained += len(keep)
                        except OSError:
                            errors.append('report write failed')
            except OSError:
                errors.append('report read failed')
            finally:
                try:
                    process.stdout.close()
                except OSError:
                    errors.append('pipe close failed')

        def stop():
            owned = fsx.owned_job(process)
            try:
                if owned is not None:
                    if not owned.terminate(1):
                        errors.append('process-tree cleanup unconfirmed')
                    owned.close()
                else:
                    fsx.kill_process_tree(process.pid)
            except OSError:
                errors.append('process-tree cleanup failed')

        reader = Thread(target=read, daemon=True, name='platform-installer-output')
        try:
            reader.start()
            try:
                process.wait(timeout=max(0.001, timeout - (time.monotonic()-started)))
                reader.join(timeout=max(0, timeout - (time.monotonic()-started)))
                if reader.is_alive():
                    raise subprocess.TimeoutExpired(arguments, timeout)
                result['exit'] = process.returncode
            except subprocess.TimeoutExpired:
                result['exit'] = 124
        finally:
            stop()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                errors.append('child reap unconfirmed')
            if reader.ident is not None:
                reader.join(timeout=2)
            else:
                process.stdout.close()
            result['cleanup_confirmed'] = not reader.is_alive() and process.poll() is not None and not errors
    result.update(observed_bytes=observed, retained_bytes=retained, dropped_bytes=observed-retained,
                  seconds=round(time.monotonic()-started, 3), sha256=digest(log),
                  logs_complete=observed == retained and not errors and not reader.is_alive())
    return result


class ScenarioFailed(RuntimeError):
    pass


def bootstrap_candidate(source, home, project, command, installer):
    """Commit the explicit legacy choice before the candidate's read-only plan."""
    command([sys.executable, source/'scripts/getzilla_components.py', 'adopt', '--agents', 'qwen'], cwd=project)
    command(['git', 'add', '.getzilla/managed-components.json'], cwd=project)
    command(['git', 'commit', '--quiet', '--allow-empty', '-m', 'Record complete adapter selection'], cwd=project)
    return installer(source, home, project, 'platform-candidate', create=False)


def run_cell(source: Path, workspace: Path, *, cell_id: str, expected_head: str) -> dict:
    """Only run installers on disposable Actions hosts; tests exercise helpers separately."""
    if os.environ.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('live platform acceptance requires a disposable GitHub Actions runner')
    if any(not re.fullmatch(r'[1-9][0-9]{0,19}', os.environ.get(name, ''))
           for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')):
        raise ValueError('live platform acceptance requires exact Actions run and attempt identities')
    if not workspace.is_absolute():
        raise ValueError('acceptance workspace must be an absolute absent path')
    workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
    contract = load_contract(source)
    cell = next((c for c in contract['cells'] if c['id'] == cell_id), None)
    if not cell or not cell['supported']:
        raise ValueError('unsupported platform cell')
    system, arch = native_platform(platform.system(), platform.machine())
    record = {'schema': 'getzilla-platform-install-v1', 'cell': cell_id, 'os': system, 'arch': arch,
              'repository': os.environ.get('GITHUB_REPOSITORY'),
              'head': expected_head, 'tree': None, 'run_id': os.environ.get('GITHUB_RUN_ID'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'), 'authority': 'observations-only',
              'stable': contract['previous_stable'], 'scenarios': {name: {'status': 'not_run'}
              for name in ('clean', 'upgrade')}, 'commands': [], 'observed_machine': platform.machine()}
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('GETZILLA_', 'GIT_'))}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT='0', GIT_CEILING_DIRECTORIES=str(workspace),
                       GIT_AUTHOR_NAME='platform-acceptance', GIT_AUTHOR_EMAIL='ci@example.invalid',
                       GIT_COMMITTER_NAME='platform-acceptance', GIT_COMMITTER_EMAIL='ci@example.invalid',
                       PYTHONDONTWRITEBYTECODE='1', GETZILLA_NONINTERACTIVE='1', GETZILLA_SKIP_AGENT='1',
                       GETZILLA_SKIP_WINGET='1', GETZILLA_EU_AI_ACT='0', GETZILLA_AGENT='qwen')
    started = time.monotonic()

    def command(argv, *, cwd=source, env=None, timeout=900):
        if len(record['commands']) >= MAX_COMMANDS:
            raise ScenarioFailed('command evidence count budget exceeded')
        label = f'{len(record["commands"])+1:03d}.log'
        remaining = MAX_CELL_LOG_BYTES - sum(command['retained_bytes'] for command in record['commands'])
        outcome = run_command([str(a) for a in argv], cwd=cwd, log=workspace/label,
                              timeout=timeout, quota=min(MAX_LOG_BYTES, remaining), env=env or environment)
        record['commands'].append(outcome)
        if outcome['exit'] != 0 or not outcome['logs_complete'] or not outcome['cleanup_confirmed']:
            raise ScenarioFailed(f'command {label} failed or its full report is unavailable')
        return outcome

    def text(argv, *, cwd=source):
        outcome = command(argv, cwd=cwd)
        with (workspace/outcome['log']).open('rb') as handle:
            data = handle.read(8193)
        if len(data) > 8192:
            raise ScenarioFailed('identity output exceeded limit')
        return data.decode('utf-8').strip()

    def cli(home, *args):
        if system == 'windows':
            return ['cmd', '/d', '/c', home/'bin/getzilla.cmd', *args]
        return [home/'bin/getzilla', *args]

    def installer(script_source, home, project, ref, *, create):
        settings = {**environment, 'GETZILLA_HOME': str(home), 'GETZILLA_REPO': mirror.as_uri(),
                    'GETZILLA_REF': ref}
        settings['GETZILLA_NEW_PROJECT' if create else 'GETZILLA_PROJECT'] = str(project)
        argv = (['pwsh', '-NoProfile', '-NonInteractive', '-File', script_source/'scripts/install.ps1']
                if system == 'windows' else ['bash', script_source/'scripts/install.sh'])
        return command(argv, env=settings, timeout=1200)

    def observe(home, project, scenario, checks):
        phase_env = {**environment, 'GETZILLA_HOME': str(home)}
        checks['installed_head'] = text(['git', '-C', home, 'rev-parse', 'HEAD'])
        checks['cli_sha256'] = digest(home/'scripts/getzilla_cli.py')
        checks['managed_sha256'] = digest(project/'scripts/getzilla_doctor.py')
        checks['version'] = text([sys.executable, '-c',
            "import sys; sys.path.insert(0,'.getzilla'); import getzilla; print(getzilla.__version__)"], cwd=project)
        checks['cli_exit'] = command(cli(home, 'help'), cwd=project, env=phase_env)['exit']
        checks['doctor_exit'] = command(cli(home, 'doctor'), cwd=project, env=phase_env)['exit']
        manifest = json.loads((project/'.getzilla/managed-components.json').read_text(encoding='utf-8'))
        checks['agents'] = manifest.get('agents')
        checks['logs_complete'] = all(c['logs_complete'] for c in record['commands'])
        wanted_version = (source/'VERSION').read_text(encoding='utf-8').strip()
        if (checks['installed_head'] != expected_head or checks['version'] != wanted_version
                or checks['cli_sha256'] != digest(source/'scripts/getzilla_cli.py')
                or checks['managed_sha256'] != digest(source/'scripts/getzilla_doctor.py')
                or checks['agents'] != ['qwen']):
            raise ScenarioFailed(f'{scenario} installed identity or selection mismatch')

    try:
        if (system, arch) != (cell['os'], cell['arch']):
            raise ScenarioFailed('actual native OS/architecture does not match the selected cell')
        record['head'] = text(['git', 'rev-parse', 'HEAD'])
        record['tree'] = text(['git', 'rev-parse', 'HEAD^{tree}'])
        if record['head'] != expected_head or text(['git', 'status', '--porcelain', '--untracked-files=normal']):
            raise ScenarioFailed('candidate checkout identity mismatch or dirty source')
        stable = contract['previous_stable']
        if (text(['git', 'rev-parse', f'refs/tags/{stable["tag"]}']) != stable['tag_object']
                or text(['git', 'rev-parse', f'refs/tags/{stable["tag"]}^{{commit}}']) != stable['commit']):
            raise ScenarioFailed('previous stable tag/object/commit mismatch')
        mirror, stable_source = workspace/'mirror.git', workspace/'stable-source'
        command(['git', 'clone', '--quiet', '--mirror', '--no-hardlinks', source, mirror])
        command(['git', '--git-dir', mirror, 'update-ref', 'refs/heads/platform-candidate', expected_head])
        command(['git', 'clone', '--quiet', '--no-hardlinks', '--branch', stable['tag'], mirror, stable_source])
        if text(['git', '-C', stable_source, 'rev-parse', 'HEAD']) != stable['commit']:
            raise ScenarioFailed('previous stable source clone differs from its immutable commit')
        for scenario in ('clean', 'upgrade'):
            checks = {'status': 'fail'}
            phase_start, command_start = time.monotonic(), len(record['commands'])
            record['scenarios'][scenario] = checks
            home, project = workspace/f'{scenario}-home', workspace/f'{scenario}-project'
            try:
                if scenario == 'clean':
                    checks['installer_exit'] = installer(source, home, project, 'platform-candidate', create=True)['exit']
                else:
                    if system == 'macos':
                        command([sys.executable, source/'scripts/getzilla_platform_install.py',
                                 '--restore-stable-payload', stable_source, '--project', project])
                        checks.update(baseline_mode='restored-v230-artifact', historical_installer_create='unsupported')
                        checks['historical_bootstrap_exit'] = installer(stable_source, home, project, stable['tag'], create=False)['exit']
                        uv = home/'.venv/bin/uv'
                        executable = str(uv) if uv.is_file() else shutil.which('uv', path=environment.get('PATH'))
                        if executable is None:
                            raise ScenarioFailed('historical baseline uv executable unavailable')
                        tool_bin = text([executable, 'tool', 'dir', '--bin'])
                        if (any(character in tool_bin for character in (os.pathsep, '\n', '\r', '\0'))
                                or not Path(tool_bin).is_absolute() or not Path(tool_bin).is_dir()):
                            raise ScenarioFailed('historical baseline tool directory unavailable')
                        old_env = {**environment, 'PATH': os.pathsep.join((tool_bin, str(home/'.venv/bin'),
                                                                         environment.get('PATH', '')))}
                        checks['historical_baseline_apply_exit'] = command([sys.executable,
                            home/'scripts/getzilla_baseline.py', 'apply', '--project', project, '--agent', 'qwen'],
                            env=old_env)['exit']
                    else:
                        checks.update(baseline_mode='stock-installer-create', historical_installer_create='pass')
                        installer(stable_source, home, project, stable['tag'], create=True)
                    checks['from_head'] = text(['git', '-C', home, 'rev-parse', 'HEAD'])
                    checks['from_version'] = (home/'VERSION').read_text(encoding='utf-8').strip()
                    checks['from_project_version'] = text([sys.executable, '-c',
                        "import sys; sys.path.insert(0,'.getzilla'); import getzilla; print(getzilla.__version__)"], cwd=project)
                    if checks['from_head'] != stable['commit'] or checks['from_version'] != stable['tag'].removeprefix('v'):
                        raise ScenarioFailed('previous stable was not actually installed')
                    if checks['from_project_version'] != checks['from_version']:
                        raise ScenarioFailed('previous stable project engine differs from the installed release')
                    command(['git', 'init', '--quiet', project])
                    (project/'user-file.txt').write_text('user-owned fixture\n', encoding='utf-8')
                    settings = project/'user-settings.json'
                    settings.write_text('{"agents":["qwen"],"theme":"fixture"}\n', encoding='utf-8')
                    ignore = project/'.gitignore'
                    if not ignore.exists():
                        ignore.write_text('.getzilla/runtime/\n', encoding='utf-8')
                    user_before, settings_before = digest(project/'user-file.txt'), digest(settings)
                    command(['git', 'add', '-A'], cwd=project)
                    command(['git', 'commit', '--quiet', '-m', 'Record stable project and user settings'], cwd=project)
                    checks['installer_exit'] = bootstrap_candidate(source, home, project, command, installer)['exit']
                    checks['update_exit'] = command(cli(home, 'update', '--no-self', '--no-tools',
                                                        '--baseline-release', stable['tag'], str(project)),
                                                    cwd=project, env={**environment, 'GETZILLA_HOME': str(home)})['exit']
                    checks['user_preserved'] = digest(project/'user-file.txt') == user_before
                    checks['settings_preserved'] = digest(settings) == settings_before
                    if not checks['user_preserved'] or not checks['settings_preserved']:
                        raise ScenarioFailed('user-owned files or settings changed')
                observe(home, project, scenario, checks)
                checks['status'] = 'pass'
            except (OSError, ValueError, ScenarioFailed) as error:
                checks['error'] = str(error)[:512] if isinstance(error, ScenarioFailed) else type(error).__name__
            finally:
                checks['seconds'] = round(time.monotonic()-phase_start, 3)
                checks['logs'] = [command['log'] for command in record['commands'][command_start:]]
        record['head_after'] = text(['git', 'rev-parse', 'HEAD'])
        record['tree_after'] = text(['git', 'rev-parse', 'HEAD^{tree}'])
        record['source_clean'] = not bool(text(['git', 'status', '--porcelain', '--untracked-files=normal']))
        if (record['head_after'] != expected_head or record['tree_after'] != record['tree']
                or not record['source_clean']):
            raise ScenarioFailed('candidate source changed during platform acceptance')
    except (OSError, ValueError, ScenarioFailed) as error:
        record['error'] = str(error)[:512] if isinstance(error, ScenarioFailed) else type(error).__name__
    finally:
        record['seconds'] = round(time.monotonic()-started, 3)
        record['producer'] = {'path': '.github/workflows/getzilla.yml',
                              'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
                              'workflow_sha': os.environ.get('GITHUB_WORKFLOW_SHA'),
                              'sha256': digest(source/'.github/workflows/getzilla.yml')}
        (workspace/'result.json').write_text(json.dumps(record, indent=2, allow_nan=False)+'\n', encoding='utf-8')
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            run_url = (f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/"
                       f"{record['run_id']}/attempts/{record['run_attempt']}")
            rows = [f"### Native installer: {cell_id}", f"Observed: {system}/{arch} ({platform.machine()}).",
                    f"Stable: {record['stable']['tag']} `{record['stable']['commit']}`.",
                    f"Candidate: `{expected_head}`; checkout: `{record['head']}`; tree: `{record['tree']}`.",
                    '', '| Scenario | Observed result | Seconds | Retained log files |', '| --- | --- | --- | --- |']
            for name, checks in record['scenarios'].items():
                rows.append(f"| {name} | {checks['status']} | {checks.get('seconds', '-')} | "
                            + ', '.join(checks.get('logs', [])) + ' |')
            upgrade = record['scenarios']['upgrade']
            rows += ['', f"Historical baseline mode: {upgrade.get('baseline_mode', 'not_run')}; "
                      f"historical installer create: {upgrade.get('historical_installer_create', 'not_run')}."]
            rows += ['', f'[Install/upgrade artifacts]({run_url}#artifacts)',
                     'Actions observations only. Missing native cells block acceptance; this is not an independent security verdict.']
            with open(summary, 'a', encoding='utf-8') as handle:
                handle.write('\n'.join(rows)+'\n')
    return record
