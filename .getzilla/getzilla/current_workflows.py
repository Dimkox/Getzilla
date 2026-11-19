"""Fresh official workflow source to bounded data payload to guarded project CAS.

No source installer runs. Imported prose grants no permissions or semantic approval.
Writable state records can preserve ownership, but cannot qualify a source payload.
"""
from __future__ import annotations

import contextvars
import json
import os
import re
import shutil
from pathlib import Path

from . import baseline_assets, state
from .architecture import ArchitectureError
from .architecture_diff import _git_command, _run_capped
from .baseline import AGENTS, AGENT_SKILL_DIRS, Step, components, temporary_cache
from .component_state import BoundRoot, ComponentStateError, component_transaction, mode_matches, path_parts
from .latest_releases import github_release, metadata
from .managed_runtime import directory as managed_directory
from .policy import evaluate_pre_tool
from .skill_pinned_sources import read_pinned_tree
from .skill_preflight import canonical, digest, parse_json
from .skill_sandbox import MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, OUTPUT_PREFIXES

_SCOPE = contextvars.ContextVar('getzilla_current_workflow_payloads', default=())


def _payload(component, agent, files, identity):
    if agent not in AGENTS or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('CURRENT_WORKFLOW_INVENTORY_BOUNDS')
    total = 0
    folded = set()
    for name, (body, mode) in files.items():
        path_parts(name)
        total += len(body)
        if name.casefold() in folded or any(p in {'.git', '.env'} for p in name.split('/')):
            raise ValueError('unsafe/duplicate current workflow path')
        folded.add(name.casefold())
        if (not name.startswith(OUTPUT_PREFIXES) or len(body) > MAX_FILE_BYTES or mode not in (0o644, 0o755)
                or total > MAX_TOTAL_BYTES or b'\0' in body):
            raise ValueError('CURRENT_WORKFLOW_ASSET_BOUNDS')
        body.decode('utf-8')
    inventory = tuple((name, body, mode) for name, (body, mode) in sorted(files.items()))
    fingerprint = digest(canonical({'source': identity, 'files': [[n, digest(b), m] for n, b, m in inventory]}))
    return baseline_assets.AssetPayload(component, agent, fingerprint, inventory)


_SPEC_COMMANDS = frozenset({'analyze', 'checklist', 'clarify', 'constitution', 'converge',
                            'implement', 'plan', 'specify', 'tasks'})
_SPEC_SKILL_DIRS = {'claude': '.claude/skills', 'codex': '.agents/skills',
                    'grok': '.grok/skills', 'copilot': '.github/skills'}


def _spec_script(header, source, script):
    text = header + '\n'
    blocks = list(re.finditer(r'(?m)^scripts:\n((?:[ \t]+[^\n]*(?:\n|$))*)', text))
    if len(blocks) != 1 or len(re.findall(r'(?m)^scripts:', text)) != 1:
        raise ValueError('unsupported Spec Kit script binding')
    bindings, indents = {}, set()
    lanes = {'sh': ('bash', 'sh'), 'ps': ('powershell', 'ps1'), 'py': ('python', 'py')}
    for line in blocks[0][1].splitlines():
        row = re.fullmatch(r'( {2,3})(sh|ps|py): (scripts/[A-Za-z0-9_./-]+(?: [A-Za-z0-9_.-]+)*)', line)
        if not row or row[2] in bindings:
            raise ValueError('unsupported Spec Kit script binding')
        indent, kind, command = row.groups()
        lane, suffix = lanes[kind]
        path = command.split()[0]
        if not re.fullmatch(r'scripts/'+lane+r'/[A-Za-z0-9_-]+\.'+suffix, path) or path not in source:
            raise ValueError('Spec Kit command references absent or unsupported source script')
        indents.add(len(indent))
        bindings[kind] = command
    if len(indents) != 1 or not {'sh', 'ps'} <= bindings.keys() or script not in bindings:
        raise ValueError('unsupported Spec Kit script binding')
    return bindings[script], (text[:blocks[0].start()] + text[blocks[0].end():]).strip()


def _spec_workflow_version(raw):
    text = raw.decode('utf-8') + '\n'
    blocks = list(re.finditer(r'(?m)^workflow:\n((?:(?: +[^\n]*)?\n)*)', text))
    roots = re.findall(r'(?m)^version: ([^\n]+)$', text)
    if blocks:
        if (len(blocks) != 1 or len(re.findall(r'(?m)^workflow:', text)) != 1
                or re.search(r'(?m)^version:', text)):
            raise ValueError('unsupported Spec Kit workflow version')
        rows = re.findall(r'(?m)^  version: ([^\n]+)$', blocks[0][1])
        if len(re.findall(r'(?m)^  version:', blocks[0][1])) != 1:
            raise ValueError('unsupported Spec Kit workflow version')
    else:
        if re.search(r'(?m)^workflow:', text) or len(re.findall(r'(?m)^version:', text)) != 1:
            raise ValueError('unsupported Spec Kit workflow version')
        rows = roots
    if len(rows) != 1:
        raise ValueError('unsupported Spec Kit workflow version')
    value = rows[0]
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', value):
        raise ValueError('unsupported Spec Kit workflow version')
    return value


def spec_payload(source, agent, version, commit, *, windows):
    """Closed source-data adapter; refuse unknown command/template layouts."""
    script, directory = ('ps', 'powershell') if windows else ('sh', 'bash')
    present = {name.removeprefix('templates/commands/')[:-3] for name in source
               if name.startswith('templates/commands/') and name.endswith('.md')}
    if agent not in AGENTS or not present <= _SPEC_COMMANDS:
        raise ValueError('unsupported Spec Kit command mapping')
    files, commands = {}, {}
    for name, raw in source.items():
        if name.startswith('templates/commands/') and name.endswith('.md'):
            stem = name.removeprefix('templates/commands/')[:-3]
            if stem not in _SPEC_COMMANDS:
                raise ValueError('unsupported Spec Kit command name')
            text = raw.decode('utf-8')
            if '\0' in text:
                raise ValueError('unsupported Spec Kit command frontmatter')
            front = re.fullmatch(r'---\n(.*?)\n---\n(.*)', text, re.S)
            if not front:
                raise ValueError('unsupported Spec Kit command frontmatter')
            header, body = front.groups()
            command, header = _spec_script(header, source, script)
            body = body.replace('{SCRIPT}', '.specify/'+command)
            skill = agent in _SPEC_SKILL_DIRS
            invocation = '$speckit-' if agent == 'codex' else '/speckit-' if skill else '/speckit.'

            def dispatch(match):
                target = match[1].lower()
                if target not in _SPEC_COMMANDS or target not in present:
                    raise ValueError('unsupported Spec Kit command mapping')
                return invocation + target

            body = re.sub(r'__SPECKIT_COMMAND_([A-Z][A-Z_]*)__', dispatch, body)
            if '__SPECKIT_COMMAND_' in body:
                raise ValueError('unsupported Spec Kit command mapping')
            body = body.replace('{ARGS}', '$ARGUMENTS')
            if '{ARGS' in body:
                raise ValueError('unsupported Spec Kit argument mapping')
            body = body.replace('`/memory/', '`.specify/memory/')
            # Keep human-facing handoffs as prose. Remove only platform dispatch
            # fields that this adapter has resolved, never evaluate source YAML.
            descriptions = re.findall(r'(?m)^description: (.+)$', header)
            if len(descriptions) != 1:
                raise ValueError('unsupported Spec Kit command description')
            if skill:
                header = 'name: speckit-'+stem+'\ndescription: '+json.dumps(descriptions[0])
                output = _SPEC_SKILL_DIRS[agent]+'/speckit-'+stem+'/SKILL.md'
            elif agent == 'gemini':
                body = body.replace('$ARGUMENTS', '{{args}}')
                output = '.gemini/commands/speckit.'+stem+'.toml'
                commands[output] = (('description = '+json.dumps(descriptions[0], ensure_ascii=False)
                                     +'\n\nprompt = '+json.dumps(body, ensure_ascii=False)+'\n').encode(), 0o644)
                continue
            else:
                output = '.qwen/commands/speckit.'+stem+'.md'
            commands[output] = (('---\n'+header+'\n---\n'+body).encode(), 0o644)
        elif name.startswith('templates/') and '/' not in name.removeprefix('templates/'):
            files['.specify/'+name] = (raw, 0o644)
        elif name.startswith('scripts/'+directory+'/'):
            files['.specify/'+name] = (raw, 0o755 if not windows else 0o644)
        elif name.startswith('workflows/speckit/'):
            files['.specify/'+name] = (raw, 0o644)
    required = {'plan', 'specify', 'tasks', 'implement', 'constitution'}
    constitution = source.get('templates/constitution-template.md')
    if not required <= present or not constitution or '.specify/workflows/speckit/workflow.yml' not in files:
        raise ValueError('unsupported Spec Kit complete source layout')
    files['.specify/memory/constitution.md'] = (constitution, 0o644)
    files['.specify/memory/.constitution-template.json'] = (canonical({'sha256': digest(constitution), 'source': 'core'}), 0o644)
    files['.specify/init-options.json'] = (canonical(dict(ai=agent, allow_symlinks=False, feature_numbering='sequential',
                                                        here=True, integration=agent, script=script, speckit_version=version)), 0o644)
    files['.specify/integration.json'] = (canonical(dict(version=version, integration_state_schema=1,
        installed_integrations=[agent], integration_settings={agent: dict(script=script, invoke_separator='-' if agent in _SPEC_SKILL_DIRS else '.')},
        integration=agent, default_integration=agent)), 0o644)
    files['.specify/integrations/'+agent+'.manifest.json'] = (canonical(dict(integration=agent, version=version,
        files={n: digest(b) for n, (b, _) in commands.items()})), 0o644)
    workflow_version = _spec_workflow_version(files['.specify/workflows/speckit/workflow.yml'][0])
    files['.specify/workflows/workflow-registry.json'] = (canonical(dict(schema_version='1.0', workflows={
        'speckit': dict(name='Full SDD Cycle', version=workflow_version, source='bundled')})), 0o644)
    files['.specify/integrations/speckit.manifest.json'] = (canonical(dict(integration='speckit', version=version,
        files={n.removeprefix('.specify/'): digest(b) for n, (b, _) in files.items()})), 0o644)
    files.update(commands)
    return _payload('spec-kit', agent, files, dict(commit=commit, version=version, generator='closed-source-data-v2'))


def _commit(repo, tag, fetch):
    url = f'https://api.github.com/repos/{repo}/git/ref/tags/{tag}'
    item = metadata(fetch, url).get('object', {})
    for _ in range(4):
        oid, kind = item.get('sha'), item.get('type')
        if not isinstance(oid, str) or not re.fullmatch('[a-f0-9]{40}', oid):
            raise ValueError('invalid official workflow source identity')
        if kind == 'commit':
            return oid
        if kind != 'tag':
            break
        item = metadata(fetch, f'https://api.github.com/repos/{repo}/git/tags/{oid}').get('object', {})
    raise ValueError('unsupported/cyclic workflow annotated tag')


def _git_failure_reason(stderr):
    # Never publish raw Git output: it can contain paths, URLs or credentials.
    text = stderr.lower()
    for marker, reason in (
            (b'unable to find remote helper', 'helper-unavailable'),
            (b'is not a git command', 'helper-unavailable'),
            (b'could not resolve host', 'dns'),
            (b'certificate', 'tls-certificate'),
            (b'ssl', 'tls'), (b'tls', 'tls'),
            (b'failed to connect', 'connection'),
            (b'authentication failed', 'authentication'),
            (b'could not read username', 'authentication'),
            (b'not our ref', 'object-unavailable'),
            (b'unadvertised object', 'object-unavailable'),
            (b"couldn't find remote ref", 'object-unavailable'),
            (b'permission denied', 'permission'),
            (b'no space left', 'storage'),
            (b'rpc failed', 'transport')):
        if marker in text:
            return reason
    return 'unclassified'


def _source(home, repo, commit, prefixes, *, version='unknown'):
    component = next((name for name, spec in components().items()
                      if name in {'superpowers', 'bmad', 'spec-kit'} and spec['repository'] == repo), 'unknown')
    version = version if isinstance(version, str) and len(version) <= 64 and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', version) else 'unknown'
    identity = commit if isinstance(commit, str) and re.fullmatch('[a-f0-9]{40}', commit) else 'unknown'

    def failure(phase, code, reason):
        return ValueError('current workflow exact Git object acquisition failed: '
                          f'component={component} version={version} commit={identity} '
                          f'phase={phase} exit={code} reason={reason}')

    parent = home/'workflow-sources'
    if home.is_symlink() or parent.is_symlink():
        raise ValueError('linked workflow source cache')
    managed_directory(parent)
    # No checkout, hooks, credential helper, user's Git config, or source execution.
    with temporary_cache(parent, prefix='current-') as directory:
        root = Path(directory)
        private = root/'private-home'
        private.mkdir(mode=0o700)
        env = {k: v for k, v in os.environ.items() if k in {'PATH', 'SystemRoot', 'WINDIR'}}
        env.update(HOME=str(private), USERPROFILE=str(private), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='', GIT_NO_REPLACE_OBJECTS='1')
        for phase, args in (('init', ['init', '-q', str(root)]), ('fetch', ['-C', str(root), '-c', 'credential.helper=', '-c', 'core.hooksPath='+str(private),
                     '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', 'fetch', '-q', '--depth=1', '--no-tags',
                     'https://github.com/'+repo+'.git', commit])):
            try:
                code, _out, error = _run_capped(_git_command(args), cwd=root, env=env, stdout_limit=4096,
                                               stderr_limit=4096, timeout=60)
            except ArchitectureError as exc:
                reason = {'timeout': 'timeout', 'limit': 'output-limit', 'git': 'git-unavailable',
                          'io': 'runner-io'}.get(exc.code, 'runner-error')
                raise failure(phase, 'not-returned', reason) from None
            except OSError as exc:
                reason = 'exec-unavailable' if isinstance(exc, FileNotFoundError) else 'exec-io'
                raise failure(phase, 'not-returned', reason) from None
            if code:
                raise failure(phase, code, _git_failure_reason(error))
        return dict(read_pinned_tree(root, commit, prefixes=prefixes).files)


def _acquire(home, agent, fetch, *, windows=False):
    if agent not in AGENTS:
        raise ValueError('unknown workflow agent')
    result = {}
    for component, spec in components().items():
        release = github_release(spec['repository'], fetch)
        tag = release['tag_name']
        commit = _commit(spec['repository'], tag, fetch)
        identity = dict(version=release['version'], tag=tag, commit=commit,
                        metadata_sha256=release['metadata_sha256'])
        if commit == spec['pinned_commit']:
            payload = baseline_assets.load(component, agent, windows=windows)
        elif component == 'superpowers':
            source = _source(home, spec['repository'], commit, ('skills/', 'LICENSE'), version=release['version'])
            files = {}
            for name, body in source.items():
                if name.startswith('skills/'):
                    for prefix in {'.agents/skills', AGENT_SKILL_DIRS.get(agent, '.github/skills')}:
                        files[prefix+'/'+name.removeprefix('skills/')] = (body, 0o644)
            payload = _payload(component, agent, files, identity)
        elif component == 'spec-kit':
            source = _source(home, spec['repository'], commit, ('templates/', 'scripts/', 'workflows/speckit/'), version=release['version'])
            payload = spec_payload(source, agent, release['version'], commit, windows=windows)
        else:
            raise ValueError(f'{component} {release["version"]}: new native generator format has no qualified closed adapter; no old assets fallback')
        result[component] = payload, identity
    return result


def _record_path(payload):
    return '.getzilla/runtime/baseline-current/'+payload.component+'-'+payload.agent+'.json'


def _publish(project, payload):
    if not any(payload is p for p in _SCOPE.get()):
        raise ValueError('CURRENT_WORKFLOW_OWNED_SOURCE_SCOPE_REQUIRED')
    def authorize(name):
        if state.route_authority_present(project):
            state.require_route_owner(project)
            allowed, _ = evaluate_pre_tool(project, {'tool_name': 'Write', 'tool_input': {'file_path': name}})
            if not allowed:
                raise ValueError('BASELINE_AUTHORITY_REQUIRED')

    desired = {n: (b, m) for n, b, m in baseline_assets.render_for_project(project, payload)}
    record_path = _record_path(payload)
    with component_transaction(project) as transaction:
        current_record = transaction.read(record_path, limit=baseline_assets.MAX_MANIFEST_BYTES)
        prior = {}
        if current_record:
            record = parse_json(current_record.content, limit=baseline_assets.MAX_MANIFEST_BYTES)
            if (type(record) is not dict or set(record) != {'version', 'status', 'files', 'asset_digest'}
                    or record['version'] != 1 or record['status'] != 'complete' or type(record['files']) is not dict):
                raise ValueError('INTERRUPTED_OR_INVALID_CURRENT_WORKFLOW_CUSTODY')
            prior = record['files']
            if len(prior) > MAX_FILES:
                raise ValueError('CURRENT_WORKFLOW_CUSTODY_BOUNDS')
            for name, row in prior.items():
                path_parts(name)
                if (not name.startswith(OUTPUT_PREFIXES) or type(row) is not dict or set(row) != {'sha256', 'mode'}
                        or not re.fullmatch('[a-f0-9]{64}', row['sha256']) or row['mode'] not in {0o644, 0o755}):
                    raise ValueError('INVALID_CURRENT_WORKFLOW_CUSTODY')
        else:
            # A legacy installation is adopted only by exact reviewed source bytes,
            # never by mere marker presence or a self-asserted source hash.
            legacy = baseline_assets.load(payload.component, payload.agent, windows=os.name == 'nt')
            prior = {n: dict(sha256=digest(b), mode=m) for n, b, m in legacy.files}
        snapshots = {}
        for name in set(desired) | set(prior):
            item = transaction.read(name)
            snapshots[name] = item
            if name in desired or item is not None:
                authorize(name)
            if item is None:
                continue
            same_desired = name in desired and item.content == desired[name][0] and mode_matches(item.mode, desired[name][1])
            same_prior = name in prior and item.sha256 == prior[name]['sha256'] and mode_matches(item.mode, prior[name]['mode'])
            if not same_desired and not same_prior:
                raise ValueError('CURRENT_WORKFLOW_USER_CAS_CONFLICT:'+name)
        record = dict(version=1, status='incomplete', asset_digest=payload.asset_digest,
                      files={n: dict(sha256=digest(b), mode=m) for n, (b, m) in desired.items()})
        transaction.write(record_path, canonical(record), 0o600, expected=current_record)
        pending = transaction.read(record_path, limit=baseline_assets.MAX_MANIFEST_BYTES)
        for name, (body, mode) in desired.items():
            with state.task_transition(project):
                authorize(name)
                transaction.write(name, body, mode, expected=snapshots[name])
        for name in set(prior)-set(desired):
            if snapshots[name] is not None:
                with state.task_transition(project):
                    authorize(name)
                    transaction.remove(name, expected=snapshots[name])
        for name, (body, mode) in desired.items():
            actual = transaction.read(name)
            if actual is None or actual.content != body or not mode_matches(actual.mode, mode):
                raise ValueError('CURRENT_WORKFLOW_CHANGED_AFTER_ACTIVATION')
        record['status'] = 'complete'
        transaction.write(record_path, canonical(record), 0o600, expected=pending)


def apply_latest(project, agent, home, *, fetch=None, windows=os.name == 'nt'):
    from .release_transport import _release_fetch
    try:
        acquired = _acquire(home, agent, fetch or _release_fetch, windows=windows)
        token = _SCOPE.set(tuple(p for p, _ in acquired.values()))
        try:
            results = []
            for component, (payload, identity) in acquired.items():
                _publish(project, payload)
                results.append(Step('project:'+component, 'ok', f'current {identity["version"]} source={identity["commit"]}; actual payload={payload.asset_digest}; semantic safety unqualified; permissions not granted'))
            return results
        finally:
            _SCOPE.reset(token)
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, ArchitectureError, ComponentStateError) as exc:
        return [Step('project:current-workflow', 'fail', str(exc)[:500])]


def prepare_latest(home, *, fetch=None):
    from .release_transport import _release_fetch
    try:
        payloads = _acquire(home, 'claude', fetch or _release_fetch)
        from .release_transport import _replace_bytes
        _replace_bytes(home/'workflow-current.json', canonical({name: identity for name, (_, identity) in payloads.items()}), mode=0o600)
        return [Step('baseline:'+name, 'ok', f'fresh exact {identity["version"]} source={identity["commit"]}; payload={payload.asset_digest}; project activation remains separate')
                for name, (payload, identity) in payloads.items()]
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, ArchitectureError) as exc:
        return [Step('baseline:current', 'fail', str(exc)[:500])]


def inspect_current(home, project=None, agent=None, *, fetch=None, which=shutil.which, environ=None):
    from .baseline import BaselineStatus, _security_availability
    from .release_transport import _release_fetch
    missing, security = _security_availability(home, which=which, environ=environ)
    try:
        acquired = _acquire(home, agent or 'claude', fetch or _release_fetch, windows=os.name == 'nt')
        details = {'security': security, 'freshness': 'fresh-official-source', 'workflow': {c: i for c, (_, i) in acquired.items()}}
        if project is not None:
            with BoundRoot(project) as binding:
                for component, (payload, _) in acquired.items():
                    for name, body, mode in baseline_assets.render_for_project(project, payload):
                        actual = binding.read(name)
                        if actual is None or actual.content != body or not mode_matches(actual.mode, mode):
                            raise ValueError('CURRENT_WORKFLOW_ACTIVE_PAYLOAD_MISMATCH:'+component+':'+name)
        return BaselineStatus(not missing, missing, details)
    except (OSError, ValueError, KeyError, TypeError, ArchitectureError, ComponentStateError) as exc:
        return BaselineStatus(False, missing + ['CURRENT_WORKFLOW_UNESTABLISHED:'+str(exc)[:300]],
                              {'security': security, 'freshness': 'incomplete'})
