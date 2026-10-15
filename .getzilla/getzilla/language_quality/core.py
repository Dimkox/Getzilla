"""Optional language gates: one policy, trusted scope, evidence and admission."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

from ..cpu_budget import cpu_budget
from ..util import changed_file_statuses, git_head
from ..verification_scope import is_valid_inventory_path
from .models import AdapterRequest


TOOLS = {'eslint': ('javascript', 'eslint'), 'detekt': ('kotlin', 'kotlin'),
         'ktlint': ('kotlin', 'kotlin'), 'dart_analyzer': ('dart', 'dart'),
         'dart_format': ('dart', 'dart'), 'swiftlint': ('swift', 'swift'),
         'swiftformat': ('swift', 'swift')}
EXTENSIONS = {'.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
              '.ts': 'javascript', '.tsx': 'javascript', '.mts': 'javascript', '.cts': 'javascript',
              '.kt': 'kotlin', '.kts': 'kotlin', '.dart': 'dart', '.swift': 'swift'}
ANCHORS = {'package.json': 'javascript', 'build.gradle': 'kotlin', 'build.gradle.kts': 'kotlin',
           'pubspec.yaml': 'dart', 'Package.swift': 'swift'}
EXCLUDED = {'node_modules', 'vendor', 'build', 'dist', 'target', 'generated', '__pycache__',
            '.git', '.getzilla', '.venv', 'venv', '.dart_tool', '.gradle', '.build', 'Pods', 'Carthage'}
CONFIGS = {'eslint': ('eslint.config.js', 'eslint.config.mjs', 'eslint.config.cjs', 'eslint.config.ts', '.eslintrc.json', '.eslintrc.yml', '.eslintrc.js'),
           'detekt': ('detekt.yml', 'detekt.yaml', 'config/detekt/detekt.yml'),
           'ktlint': ('.editorconfig',), 'dart_analyzer': ('analysis_options.yaml',),
           'dart_format': (), 'swiftlint': ('.swiftlint.yml',), 'swiftformat': ('.swiftformat',)}
MAX_FILES = 50000
MAX_INPUT_BYTES = 256 * 1024 * 1024


class PolicyError(ValueError):
    pass


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def safe_path(value: str) -> str:
    if not isinstance(value, str) or not is_valid_inventory_path(value) or any(ord(c) < 32 for c in value):
        raise ValueError('unsafe or unnormalized language gate path')
    return value


def excluded(value: str) -> bool:
    path = PurePosixPath(value)
    private_names = {'.npmrc', '.netrc', '.pypirc', 'credentials.json', 'id_rsa', 'id_ed25519', 'id_ecdsa'}
    return (bool(set(path.parts) & EXCLUDED) or path.name in private_names or path.name.startswith('.env')
            or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx', '.keystore'})


def _closed(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError('duplicate project policy key')
        result[key] = value
    return result


@dataclass(frozen=True)
class Policy:
    mode: str = 'auto'
    enforcement: str = 'shadow'
    scope: str = 'changed'
    tools: dict = field(default_factory=dict)
    sandbox: dict | None = None
    origin: str = '.getzilla/config/policy.json#language_quality_gates'
    fingerprint: str = ''
    repository_id: str = ''
    cache: str = 'shadow'


def _choices(value: dict, inherited: Policy | None = None) -> None:
    for key, choices in {'mode': {'auto', 'on', 'off'}, 'enforcement': {'shadow', 'blocking'}, 'scope': {'changed', 'full'}}.items():
        if key in value and (not isinstance(value[key], str) or value[key] not in choices):
            raise PolicyError('invalid language quality ' + key)
    if value.get('autofix', False) is not False or type(value.get('ai_retries', 0)) is not int or value.get('ai_retries', 0) != 0:
        raise PolicyError('language verification cannot fix source or invoke AI')


def load_policy(root: Path) -> Policy:
    path = root / '.getzilla/config/policy.json'
    raw = {}
    try:
        if any(p.is_symlink() for p in (path, path.parent, path.parent.parent)):
            raise PolicyError('project policy must not be a symlink')
        if path.exists():
            if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_size > 1024 * 1024:
                raise PolicyError('project policy is not a bounded regular file')
            raw = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_closed)
        if not isinstance(raw, dict):
            raise PolicyError('project policy must be an object')
        value = raw.get('language_quality_gates', {})
        allowed = {'mode', 'enforcement', 'scope', 'autofix', 'ai_retries', 'tools', 'sandbox', 'cache'}
        if not isinstance(value, dict) or set(value) - allowed:
            raise PolicyError('unknown language quality policy field')
        _choices(value)
        if value.get('cache', 'shadow') not in ('shadow', 'off'):
            raise PolicyError('cache must be shadow or off')
        tools = value.get('tools', {})
        if not isinstance(tools, dict) or set(tools) - set(TOOLS):
            raise PolicyError('unknown language quality tool')
        for tool, config in tools.items():
            allowed_tool = {'mode', 'enforcement', 'scope', 'driver', 'launcher', 'version', 'config', 'task', 'requires_macos'}
            if not isinstance(config, dict) or set(config) - allowed_tool:
                raise PolicyError('invalid tool configuration')
            _choices(config)
            if not isinstance(config.get('driver', 'cli'), str) or config.get('driver', 'cli') not in {'cli', 'gradle', 'dart', 'flutter'}:
                raise PolicyError('invalid tool driver')
            launcher = config.get('launcher', [])
            if not isinstance(launcher, list) or len(launcher) > 8 or any(not isinstance(x, str) or not x or len(x) > 512 or any(ord(c) < 32 for c in x) for x in launcher):
                raise PolicyError('invalid pinned launcher')
            if launcher and (not launcher[0].startswith('/') or '..' in PurePosixPath(launcher[0]).parts or '\\' in launcher[0]):
                raise PolicyError('launcher must be an absolute image-local executable')
            # The image entrypoint supplies the pinned tool. Extra launcher values
            # may name a script/JAR but cannot inject tool flags or installers.
            if any(x.startswith('-') for x in launcher[1:]) or (launcher and PurePosixPath(launcher[0]).name in {'sh', 'bash', 'npx', 'npm', 'yarn', 'pnpm', 'curl', 'wget'}):
                raise PolicyError('launcher cannot be a shell, installer or flag override')
            if 'version' in config and (not isinstance(config['version'], str) or not re.fullmatch(r'[A-Za-z0-9.+_-]{1,128}', config['version'])):
                raise PolicyError('invalid pinned tool version')
            if 'config' in config:
                safe_path(config['config'])
            if 'requires_macos' in config and type(config['requires_macos']) is not bool:
                raise PolicyError('requires_macos must be boolean')
            if 'task' in config and (not isinstance(config['task'], str) or not re.fullmatch(r'[:A-Za-z0-9_-]{1,128}', config['task'])):
                raise PolicyError('invalid Gradle task')
        sandbox = value.get('sandbox')
        if sandbox is not None:
            from .sandbox import validate_spec
            sandbox = validate_spec(sandbox)
        return Policy(value.get('mode', 'auto'), value.get('enforcement', 'shadow'), value.get('scope', 'changed'),
                      tools, sandbox, fingerprint=digest(value), repository_id=digest(str(root.resolve())), cache=value.get('cache', 'shadow'))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PolicyError(str(exc)) from exc


@dataclass(frozen=True)
class Package:
    path: str
    language: str
    files: tuple[str, ...]


@dataclass(frozen=True)
class Scope:
    requested: str
    actual: str
    files: tuple[str, ...]
    reason: str | None = None


def inventory(root: Path) -> tuple[str, ...]:
    command = ['git', '-C', str(root), 'ls-files', '--cached', '--others', '--exclude-standard', '-z']
    result = subprocess.run(command, capture_output=True, timeout=20, check=False)
    if result.returncode or len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError('language source inventory unavailable or too large')
    files = tuple(sorted(set(result.stdout.decode('utf-8', errors='strict').rstrip('\0').split('\0')) - {''}))
    if len(files) > MAX_FILES:
        raise ValueError('language source inventory exceeds bound')
    for path in files:
        safe_path(path)
    return tuple(path for path in files if not excluded(path))


def discover_packages(files: list[str] | tuple[str, ...]) -> tuple[Package, ...]:
    paths = [PurePosixPath(safe_path(p)) for p in files if not excluded(safe_path(p))]
    anchors = {(p.parent.as_posix(), ANCHORS[p.name]) for p in paths if p.name in ANCHORS}
    grouped = {}
    for path in paths:
        language = EXTENSIONS.get(path.suffix)
        if not language or path.name in ANCHORS or path.name in {'settings.gradle.kts'}:
            continue
        owners = [parent for parent in path.parents if (parent.as_posix(), language) in anchors]
        owner = owners[0] if owners else PurePosixPath('.')
        grouped.setdefault((owner.as_posix(), language), []).append(path.relative_to(owner).as_posix())
    return tuple(Package(path, language, tuple(sorted(files))) for (path, language), files in sorted(grouped.items()))


def approved_inputs(files: tuple[str, ...], packages: tuple[Package, ...], tools: dict) -> tuple[str, ...]:
    """Expose only source and explicit language inputs, never an entire checkout."""
    selected = {(PurePosixPath(package.path) / name).as_posix() for package in packages for name in package.files}
    known = set(ANCHORS) | {'settings.gradle', 'settings.gradle.kts', 'gradle.properties', 'gradle-wrapper.properties',
        'analysis_options.yaml', 'pubspec.lock', '.swift-version', '.node-version', '.nvmrc', '.editorconfig',
        'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb', 'Package.resolved', '.tool-versions'}
    known.update(PurePosixPath(name).name for names in CONFIGS.values() for name in names)
    for name in files:
        if PurePosixPath(name).name in known or re.fullmatch(r'tsconfig(?:\.[A-Za-z0-9_-]+)?\.json', PurePosixPath(name).name):
            selected.add(name)
    for tool, config in tools.items():
        if config.get('config'):
            for package in packages:
                if package.language == TOOLS[tool][0]:
                    name = (PurePosixPath(package.path) / config['config']).as_posix()
                    # Arbitrary private credential filenames are never approved config inputs.
                    if PurePosixPath(name).suffix not in {'.js', '.cjs', '.mjs', '.ts', '.json', '.yaml', '.yml', '.xml'}:
                        raise ValueError('unsupported explicit configuration input')
                    selected.add(name)
    return tuple(sorted(name for name in selected if name in files and not excluded(name)))


def _config_change(path: str) -> bool:
    name = PurePosixPath(path).name
    return (path == '.getzilla/config/policy.json' or name in set(ANCHORS) | {'settings.gradle', 'settings.gradle.kts', 'gradle.properties', 'gradle-wrapper.properties',
            '.editorconfig', 'analysis_options.yaml', 'pubspec.lock', '.swift-version', '.node-version', '.nvmrc',
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock', 'Package.resolved', '.tool-versions'}
            or 'eslint' in name or 'detekt' in name or name.startswith('tsconfig') or name.startswith('.swift')
            or name.endswith(('.lock', '.lockfile', '.gradle', '.gradle.kts', '.xcconfig', '.pbxproj')))


def select_scope(package: Package, requested: str, base: str | None, records: list[dict] | None, *, incremental: bool,
                 configuration_paths: tuple[str, ...] = ()) -> Scope:
    for path in configuration_paths:
        safe_path(path)
    reason = None
    if requested == 'full':
        reason = 'policy-full'
    elif not base or not re.fullmatch(r'[a-f0-9]{40,64}', base):
        reason = 'untrusted-base'
    elif records is None:
        reason = 'unknown-inventory'
    elif not incremental:
        reason = 'adapter-full-only'
    selected = set()
    for record in records or ():
        if not isinstance(record, dict) or 'path' not in record:
            raise ValueError('invalid changed file record')
        path = safe_path(record['path'])
        for path_field in ('old_path', 'source_path', 'original_path'):
            if path_field in record:
                safe_path(record[path_field])
        status = record.get('status', '')
        if not reason:
            if not isinstance(status, str) or not re.fullmatch(r'(?:[MADTU]|[RC][0-9]{1,3}|\?\?)', status):
                reason = 'unknown-status'
            elif status.startswith(('R', 'C', 'D', 'T', 'U')):
                reason = 'rename-or-delete'
            elif record.get('source') not in {'index', 'worktree', 'untracked', 'range:' + str(base)}:
                reason = 'untrusted-status-channel'
            elif _config_change(path) or path in configuration_paths:
                reason = 'configuration-change'
        prefix = '' if package.path == '.' else package.path + '/'
        if path.startswith(prefix) and path[len(prefix):] in package.files:
            selected.add(path[len(prefix):])
    if reason:
        return Scope(requested, 'full', package.files, reason)
    return Scope(requested, 'changed', tuple(sorted(selected)))


def read_input(root: Path, name: str) -> bytes:
    """Read through no-follow directory descriptors; atime is not content identity."""
    safe_path(name)
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ValueError('safe input snapshot requires no-follow directory descriptors')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(file_descriptor, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_BYTES:
                raise ValueError('language input is not a bounded regular file')
            payload = source.read(before.st_size + 1)
            after = os.fstat(source.fileno())
            def identity(item):
                return (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if len(payload) != before.st_size or identity(before) != identity(after):
                raise ValueError('language input changed during read')
            return payload
    finally:
        os.close(descriptor)


def _read_inputs(root: Path, files: tuple[str, ...], configuration_paths: tuple[str, ...] = ()) -> tuple[str, str, str]:
    content = hashlib.sha256()
    configs = hashlib.sha256()
    dependencies = hashlib.sha256()
    size = 0
    for name in files:
        payload = read_input(root, name)
        size += len(payload)
        if size > MAX_INPUT_BYTES:
            raise ValueError('language input byte limit exceeded')
        entry = name.encode() + b'\0' + hashlib.sha256(payload).digest()
        content.update(entry)
        if _config_change(name) or name in configuration_paths:
            configs.update(entry)
        if PurePosixPath(name).name in ANCHORS or '.lock' in name or name.endswith('lock.json'):
            dependencies.update(entry)
    return content.hexdigest(), configs.hexdigest(), dependencies.hexdigest()


def _result(tool: str, package: str, policy: Policy, config: dict, status: str, summary: str, **details) -> dict:
    result = {'schema_version': 1, 'tool_id': tool, 'package': package, 'execution_status': status,
              'repository_id': policy.repository_id, 'commit_sha': None, 'base_sha': None,
              'input_digest': None, 'config_digest': None, 'dependency_digest': None,
              'execution_fingerprint': None,
              'enforcement': config.get('enforcement', policy.enforcement), 'mode': config.get('mode', policy.mode),
              'requested_scope': config.get('scope', policy.scope), 'scope': None, 'fallback_reason': None,
              'summary': summary, 'diagnostics': [], 'policy_origin': policy.origin,
              'policy_digest': policy.fingerprint, 'tool_version': config.get('version'),
              'tool_version_source': 'policy-pinned-image' if config.get('version') else None,
              'cache_hit': False, 'cache_status': 'not-attempted', 'duration_ms': 0,
              'execution_performed': False, 'evidence_kind': 'not-executed',
              'executor_identity': None, **details}
    result['evidence_digest'] = digest(result)
    return result


def _cache_binding(policy, config, tool, package, scope, head, base, inputs, argv, identity, module):
    from .cache import cache_key
    if not all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{40,64}', value) for value in (head, base)):
        raise ValueError('cache needs resolved commit and base identities')
    if not isinstance(identity, str) or not identity or len(identity) > 2048:
        raise ValueError('cache needs current admitted executor identity')
    implementation = _read_inputs(Path(__file__).parent, ('core.py', 'sandbox.py', 'cache.py', 'models.py', 'adapters/' + module + '.py'))[0]
    return cache_key({'repository_id': policy.repository_id, 'local_account_id': 'uid:' + str(os.getuid()),
        'commit_sha': head, 'base_sha': base, 'package': package.path, 'tool_id': tool,
        'tool_version': config['version'], 'sdk_identity': policy.sandbox['image'],
        'input_digest': inputs[0], 'config_digest': inputs[1], 'dependency_digest': inputs[2],
        'policy_digest': policy.fingerprint, 'requested_scope': scope.requested, 'scope': scope.actual,
        'files': list(scope.files), 'argv': list(argv), 'executor_identity': identity,
        'implementation_digest': implementation, 'platform': sys.platform, 'sandbox': policy.sandbox,
        'effective_cpus': cpu_budget(policy.sandbox['cpus']).effective})


def run_registry(root: Path, base: str | None, *, executor=None, cancellation=None, preflight: bool = False) -> list[dict]:
    """Serial tool execution shares one bounded CPU allocation; no nested pool."""
    try:
        policy = load_policy(root)
    except PolicyError as exc:
        return [_result('policy', '.', Policy(enforcement='blocking'), {}, 'ERROR', str(exc))]
    if policy.mode == 'off' and all(config.get('mode', 'off') == 'off' for config in policy.tools.values()):
        return [_result(tool, '.', policy, policy.tools.get(tool, {}), 'SKIPPED_BY_POLICY', 'tool disabled') for tool in TOOLS]
    try:
        files = inventory(root)
        packages = discover_packages(files)
        inputs_files = approved_inputs(files, packages, policy.tools)
        explicit_configs = tuple((PurePosixPath(p.path) / c['config']).as_posix()
            for t, c in policy.tools.items() if c.get('config') for p in packages if p.language == TOOLS[t][0])
        records = changed_file_statuses(root, base=base) if base else None
        head = git_head(root)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return [_result(tool, '.', policy, policy.tools.get(tool, {}), 'ERROR', str(exc)) for tool in TOOLS]
    results = []
    inputs = None
    ready = time.monotonic()
    for tool, (language, module) in TOOLS.items():
        config = policy.tools.get(tool, {})
        mode = config.get('mode', policy.mode)
        matched = [p for p in packages if p.language == language]
        if mode == 'off' or not matched:
            status = 'SKIPPED_BY_POLICY' if mode == 'off' else 'NOT_CONFIGURED' if mode == 'on' else 'NOT_APPLICABLE'
            results.append(_result(tool, '.', policy, config, status, 'tool disabled' if mode == 'off' else 'no applicable source package', commit_sha=head, base_sha=base))
            continue
        for package in matched:
            start = time.monotonic()
            timings = {'queue': round((start - ready) * 1000, 3), 'setup': 0.0, 'execution': 0.0, 'validation': 0.0}
            details = {'commit_sha': head, 'base_sha': base, 'cpu_budget': cpu_budget().to_dict(), 'timings_ms': timings}
            try:
                driver = config.get('driver', 'dart' if language == 'dart' else 'cli')
                requested = config.get('scope', policy.scope)
                # This fixed capability table can be consulted before imports/configuration.
                incremental = tool not in {'detekt', 'dart_analyzer'} and driver != 'gradle'
                configuration_paths = ((PurePosixPath(package.path) / config['config']).as_posix(),) if config.get('config') else ()
                scope = select_scope(package, requested, base, records, incremental=incremental, configuration_paths=configuration_paths)
                details.update(scope=scope.actual, requested_scope=scope.requested, files=list(scope.files), fallback_reason=scope.reason)
                if not scope.files:
                    results.append(_result(tool, package.path, policy, config, 'SKIPPED_BY_POLICY', 'no source changes in package', **details))
                    continue
                package_root = root if package.path == '.' else root / package.path
                config_path = config.get('config')
                if config_path is None:
                    config_path = next((p for p in CONFIGS[tool] if (package_root / p).is_file()), None)
                needs_config = tool in {'eslint', 'detekt', 'swiftlint'}
                if config_path:
                    safe_path(config_path)
                    full = (PurePosixPath(package.path) / config_path).as_posix()
                    if full not in files or (package_root / config_path).is_symlink():
                        raise ValueError('tool configuration is not a safe inventoried input')
                launcher = config.get('launcher')
                if not launcher or not config.get('version') or (needs_config and not config_path):
                    results.append(_result(tool, package.path, policy, config, 'NOT_CONFIGURED', 'pinned image launcher, version or tool configuration is missing', **details))
                    continue
                if policy.sandbox is None or config.get('requires_macos') or os.name != 'posix':
                    results.append(_result(tool, package.path, policy, config, 'UNSUPPORTED_RUNNER', 'qualified sandbox unavailable for requested tool/platform', **details))
                    continue
                if preflight:
                    from .sandbox import ContainerExecutor
                    backend = ContainerExecutor(policy.sandbox)
                    admitted = backend.spec['image'] in backend.approved_images and backend._available()
                    results.append(_result(tool, package.path, policy, config,
                        'NOT_RUN' if admitted else 'UNSUPPORTED_RUNNER',
                        'configured and operator-admitted; tool execution and SDK availability not tested' if admitted else 'host image admission or trusted container client missing', **details))
                    continue
                if cancellation and cancellation():
                    results.append(_result(tool, package.path, policy, config, 'CANCELLED', 'cancelled before execution', **details))
                    continue
                if inputs is None:
                    inputs = _read_inputs(root, inputs_files, explicit_configs)
                details.update(input_digest=inputs[0], config_digest=inputs[1], dependency_digest=inputs[2])
                adapter = importlib.import_module('.adapters.' + module, __package__)
                capabilities = adapter.capabilities(tool, driver)
                if not capabilities.full or (scope.actual == 'changed' and not capabilities.incremental):
                    raise ValueError('adapter capability differs from registry contract')
                request = AdapterRequest(tool, driver, tuple(launcher), scope.actual, scope.files, config_path, config.get('task'))
                argv = adapter.build_argv(request)
                from .sandbox import ContainerExecutor
                backend = executor or ContainerExecutor(policy.sandbox)
                cache = None
                key = identity = None
                details['cache_status'] = 'bypassed-blocking' if config.get('enforcement', policy.enforcement) == 'blocking' else 'disabled-policy'
                if config.get('enforcement', policy.enforcement) == 'shadow' and policy.cache == 'shadow':
                    from .cache import ShadowCache
                    try:
                        identity = backend.cache_identity(root, cancellation=cancellation)
                        key = _cache_binding(policy, config, tool, package, scope, head, base, inputs, argv, identity, module)
                        cache = ShadowCache(root)
                        cached, details['cache_status'] = cache.read(key)
                        details['cache_key_digest'] = key
                    except (OSError, ValueError, TypeError, AttributeError):
                        cached = None
                        details['cache_status'] = 'disabled-incomplete-identity'
                    if cancellation and cancellation():
                        results.append(_result(tool, package.path, policy, config, 'CANCELLED', 'cancelled during cache lookup', **details))
                        continue
                    if cached is not None:
                        validation_start = time.monotonic()
                        timings['setup'] = round((validation_start - start) * 1000, 3)
                        if _read_inputs(root, inputs_files)[0] != inputs[0] or load_policy(root).fingerprint != policy.fingerprint:
                            results.append(_result(tool, package.path, policy, config, 'ERROR', 'language inputs changed during cache lookup', **details))
                            continue
                        timings['validation'] = round((time.monotonic() - validation_start) * 1000, 3)
                        details.update(cache_hit=True, evidence_kind='cached-unverified', cached_observation=cached,
                                       duration_ms=round((time.monotonic() - start) * 1000))
                        results.append(_result(tool, package.path, policy, config, 'CACHED_UNVERIFIED',
                                               'Unverified cached observation; language tool was not run', **details))
                        continue
                if _read_inputs(root, inputs_files)[0] != inputs[0]:
                    raise ValueError('language source changed before execution')
                execution_start = time.monotonic()
                timings['setup'] = round((execution_start - start) * 1000, 3)
                raw = backend.execute(root, package.path, inputs_files, argv, cancellation=cancellation, expected_digest=inputs[0])
                validation_start = time.monotonic()
                timings['execution'] = round((validation_start - execution_start) * 1000, 3)
                details.update(executor_identity=raw.identity, execution_fingerprint=digest({'argv': argv, 'input': inputs[0], 'policy': policy.fingerprint, 'executor': raw.identity}),
                               execution_performed=raw.status == 'COMPLETED', evidence_kind='fresh-execution' if raw.status == 'COMPLETED' else 'execution-attempt')
                if raw.status != 'COMPLETED':
                    status, summary = raw.status, raw.summary
                else:
                    normalized = adapter.normalize(request, raw.output)
                    status, summary = normalized.status, normalized.summary
                    diagnostics = []
                    for diagnostic in normalized.diagnostics:
                        value = asdict(diagnostic)
                        if value['path'] is not None:
                            name = value['path']
                            prefix = '/workspace/' + (package.path + '/' if package.path != '.' else '')
                            if name.startswith(prefix):
                                name = name[len(prefix):]
                            if name.startswith('./'):
                                name = name[2:]
                            safe_path(name)
                            if name not in package.files:
                                raise ValueError('diagnostic path is outside source package')
                            value['path'] = (PurePosixPath(package.path) / name).as_posix()
                        diagnostics.append(value)
                    details['diagnostics'] = diagnostics
                if _read_inputs(root, inputs_files)[0] != inputs[0] or load_policy(root).fingerprint != policy.fingerprint:
                    status, summary = 'ERROR', 'language source changed during execution'
                timings['validation'] = round((time.monotonic() - validation_start) * 1000, 3)
                details['duration_ms'] = round((time.monotonic() - start) * 1000)
                result = _result(tool, package.path, policy, config, status, summary, **details)
                if cache is not None and key and status in {'PASS', 'FAIL'} and raw.status == 'COMPLETED' and raw.identity == identity:
                    details['cache_write_status'] = 'written'
                    result = _result(tool, package.path, policy, config, status, summary, **details)
                    details['cache_write_status'] = cache.write(key, {'reported_status': status, 'summary': summary,
                        'diagnostics': result['diagnostics'], 'claimed_source_evidence_digest': result['evidence_digest']})
                    result = _result(tool, package.path, policy, config, status, summary, **details)
                results.append(result)
            except (OSError, ValueError, TypeError, ImportError, subprocess.SubprocessError) as exc:
                results.append(_result(tool, package.path, policy, config, 'ERROR', str(exc)[:512], **details))
    return results


def project_checks(results: list[dict]) -> list[dict]:
    checks = []
    for result in results:
        status = result['execution_status']
        if result.get('cache_hit') or result.get('evidence_kind') == 'cached-unverified':
            status = 'CACHED_UNVERIFIED'
        if result['enforcement'] != 'blocking' or status in {'NOT_APPLICABLE', 'SKIPPED_BY_POLICY'}:
            continue
        checks.append({'name': 'lqg-' + result['tool_id'] + ':' + result['package'],
                       'status': 'pass' if status == 'PASS' else 'cancelled' if status == 'CANCELLED' else 'fail',
                       'summary': result['summary'], 'details': [{'execution_status': status, 'enforcement': 'blocking',
                           'evidence_digest': result.get('evidence_digest', ''), 'package': result['package']}]})
    return checks
