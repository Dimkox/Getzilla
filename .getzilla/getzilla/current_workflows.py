"""Fresh official workflow source to bounded data payload to guarded project CAS.

No source installer runs. Imported prose grants no permissions or semantic approval.
Writable state records can preserve ownership, but cannot qualify a source payload.
"""
from __future__ import annotations

import contextvars
import json
import os
import re
import tempfile
from pathlib import Path

from . import baseline_assets, state
from .architecture import ArchitectureError
from .architecture_diff import _git_command, _run_capped
from .baseline import AGENTS, AGENT_SKILL_DIRS, Step, components
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


def spec_payload(source, agent, version, commit, *, windows):
    """Closed source-data adapter; refuse unknown command/template layouts."""
    script, directory = ('ps', 'powershell') if windows else ('sh', 'bash')
    files, commands = {}, {}
    for name, raw in source.items():
        if name.startswith('templates/commands/') and name.endswith('.md'):
            stem = name.removeprefix('templates/commands/')[:-3]
            if not re.fullmatch('[a-z][a-z0-9-]*', stem):
                raise ValueError('unsupported Spec Kit command name')
            text = raw.decode('utf-8')
            front = re.fullmatch(r'---\n(.*?)\n---\n(.*)', text, re.S)
            if not front:
                raise ValueError('unsupported Spec Kit command frontmatter')
            header, body = front.groups()
            selected = re.search(r'(?m)^  '+script+r': (scripts/'+directory+r'/[^\n]+)$', header)
            if '{SCRIPT}' in body and not selected:
                raise ValueError('unsupported Spec Kit script binding')
            if selected:
                command = selected[1]
                source_script = command.split()[0]
                if source_script not in source:
                    raise ValueError('Spec Kit command references absent source script')
                body = body.replace('{SCRIPT}', '.specify/'+command)
            body = body.replace('`/memory/', '`.specify/memory/')
            # Keep human-facing handoffs as prose. Remove only platform dispatch
            # fields that this adapter has resolved, never evaluate source YAML.
            header = re.sub(r'(?m)^scripts:\n(?:[ \t]+[^\n]*\n?)*', '', header).strip()
            if agent == 'codex':
                description = re.search(r'(?m)^description: (.+)$', header)
                if not description:
                    raise ValueError('unsupported Spec Kit command description')
                header = 'name: speckit-'+stem+'\ndescription: '+json.dumps(description[1])
                output = '.agents/skills/speckit-'+stem+'/SKILL.md'
            else:
                prefix = { 'claude': '.claude/commands', 'qwen': '.qwen/commands', 'gemini': '.gemini/commands',
                           'grok': '.grok/commands', 'copilot': '.github/prompts'}[agent]
                output = prefix+'/speckit.'+stem+('.prompt.md' if agent == 'copilot' else '.md')
            commands[output] = (('---\n'+header+'\n---\n'+body).encode(), 0o644)
        elif name.startswith('templates/') and '/' not in name.removeprefix('templates/'):
            files['.specify/'+name] = (raw, 0o644)
        elif name.startswith('scripts/'+directory+'/'):
            files['.specify/'+name] = (raw, 0o755 if not windows else 0o644)
        elif name.startswith('workflows/speckit/'):
            files['.specify/'+name] = (raw, 0o644)
    required = {'plan', 'specify', 'tasks', 'implement', 'constitution'}
    present = {name.removeprefix('templates/commands/')[:-3] for name in source if name.startswith('templates/commands/') and name.endswith('.md')}
    constitution = source.get('templates/constitution-template.md')
    if not required <= present or not constitution or '.specify/workflows/speckit/workflow.yml' not in files:
        raise ValueError('unsupported Spec Kit complete source layout')
    files['.specify/memory/constitution.md'] = (constitution, 0o644)
    files['.specify/memory/.constitution-template.json'] = (canonical({'sha256': digest(constitution), 'source': 'core'}), 0o644)
    files['.specify/init-options.json'] = (canonical(dict(ai=agent, allow_symlinks=False, feature_numbering='sequential',
                                                        here=True, integration=agent, script=script, speckit_version=version)), 0o644)
    files['.specify/integration.json'] = (canonical(dict(version=version, integration_state_schema=1,
        installed_integrations=[agent], integration_settings={agent: dict(script=script, invoke_separator='.')},
        integration=agent, default_integration=agent)), 0o644)
    files['.specify/integrations/'+agent+'.manifest.json'] = (canonical(dict(integration=agent, version=version,
        files={n: digest(b) for n, (b, _) in commands.items()})), 0o644)
    workflow = files['.specify/workflows/speckit/workflow.yml'][0].decode('utf-8')
    workflow_version = re.search(r'(?m)^version: [\"\']?([0-9]+(?:\.[0-9]+)+)', workflow)
    if not workflow_version:
        raise ValueError('unsupported Spec Kit workflow version')
    files['.specify/workflows/workflow-registry.json'] = (canonical(dict(schema_version='1.0', workflows={
        'speckit': dict(name='Full SDD Cycle', version=workflow_version[1], source='bundled')})), 0o644)
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


def _source(home, repo, commit, prefixes):
    parent = home/'workflow-sources'
    if home.is_symlink() or parent.is_symlink():
        raise ValueError('linked workflow source cache')
    managed_directory(parent)
    # No checkout, hooks, credential helper, user's Git config, or source execution.
    with tempfile.TemporaryDirectory(prefix='current-', dir=parent) as directory:
        root = Path(directory)
        private = root/'private-home'
        private.mkdir(mode=0o700)
        env = {k: v for k, v in os.environ.items() if k in {'PATH', 'SystemRoot', 'WINDIR'}}
        env.update(HOME=str(private), USERPROFILE=str(private), GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                   GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='', GIT_NO_REPLACE_OBJECTS='1')
        for args in (['init', '-q', str(root)], ['-C', str(root), '-c', 'credential.helper=', '-c', 'core.hooksPath='+str(private),
                     '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', 'fetch', '-q', '--depth=1', '--no-tags',
                     'https://github.com/'+repo+'.git', commit]):
            code, _out, _error = _run_capped(_git_command(args), cwd=root, env=env, stdout_limit=4096,
                                            stderr_limit=4096, timeout=60)
            if code:
                raise ValueError('current workflow exact Git object acquisition failed')
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
            source = _source(home, spec['repository'], commit, ('skills/', 'LICENSE'))
            files = {}
            for name, body in source.items():
                if name.startswith('skills/'):
                    for prefix in {'.agents/skills', AGENT_SKILL_DIRS.get(agent, '.github/skills')}:
                        files[prefix+'/'+name.removeprefix('skills/')] = (body, 0o644)
            payload = _payload(component, agent, files, identity)
        elif component == 'spec-kit':
            source = _source(home, spec['repository'], commit, ('templates/', 'scripts/', 'workflows/speckit/'))
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
    from .updater import _release_fetch
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
    from .updater import _release_fetch
    try:
        payloads = _acquire(home, 'claude', fetch or _release_fetch)
        from .updater import _replace_bytes
        _replace_bytes(home/'workflow-current.json', canonical({name: identity for name, (_, identity) in payloads.items()}), mode=0o600)
        return [Step('baseline:'+name, 'ok', f'fresh exact {identity["version"]} source={identity["commit"]}; payload={payload.asset_digest}; project activation remains separate')
                for name, (payload, identity) in payloads.items()]
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, ArchitectureError) as exc:
        return [Step('baseline:current', 'fail', str(exc)[:500])]


def inspect_current(home, project=None, agent=None, *, fetch=None):
    from .baseline import BaselineStatus
    from .updater import _release_fetch
    try:
        acquired = _acquire(home, agent or 'claude', fetch or _release_fetch, windows=os.name == 'nt')
        details = {'freshness': 'fresh-official-source', 'workflow': {c: i for c, (_, i) in acquired.items()}}
        if project is not None:
            with BoundRoot(project) as binding:
                for component, (payload, _) in acquired.items():
                    for name, body, mode in baseline_assets.render_for_project(project, payload):
                        actual = binding.read(name)
                        if actual is None or actual.content != body or not mode_matches(actual.mode, mode):
                            raise ValueError('CURRENT_WORKFLOW_ACTIVE_PAYLOAD_MISMATCH:'+component+':'+name)
        return BaselineStatus(True, [], details)
    except (OSError, ValueError, KeyError, TypeError, ArchitectureError, ComponentStateError) as exc:
        return BaselineStatus(False, ['CURRENT_WORKFLOW_UNESTABLISHED:'+str(exc)[:300]], {'freshness': 'incomplete'})
