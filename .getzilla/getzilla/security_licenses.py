"""Local artifact license policy evaluation, without network or package execution.

The result has artifact-integrity-only assurance. It is not a legal opinion,
publisher authentication, a human approval, or an independent CI qualification.
Unknown licenses, use scope and obligations remain explicit human-review gaps.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .security_osv_snapshot import VulnerabilityError, _pypi_key, _semver_key, normalize_name
from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, archive_files,
                                 artifact_identity, select_artifact, package_key, package_metadata, read_file, verify_origin)
from .security_artifacts import family_evidence, select_family
from .security_data import MAX_AGE_SECONDS, SecurityDataError, _clock, _json, _timestamp
from .security_license_texts import recognized_license
from .security_deliveries import verify_deliveries

POLICY_PATH = '.getzilla/config/license-policy.json'
ALLOWED = ('MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD')
_CANONICAL = {name.lower(): name for name in ALLOWED}
# A qualified expression subset, not a claim to parse every SPDX vocabulary
# revision. These known alternatives may occur in OR but are never autoallowed.
_NONALLOW = ('GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
             'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
             'AGPL-3.0-only', 'AGPL-3.0-or-later', 'MPL-2.0', 'EPL-2.0', 'BSD-4-Clause',
             'CC0-1.0', 'Unlicense')
_RECOGNIZED = {name.lower(): name for name in (*ALLOWED, *_NONALLOW)}


def _policy(policy: dict) -> dict:
    required = {'schema_version', 'project_repository', 'auto_allow', 'usage_distribution'}
    if not isinstance(policy, dict) or not required <= set(policy) or set(policy) - required - {'digest', 'factory_offline_profile'}:
        raise ArtifactError('license-policy-missing', 'choose an explicit project-specific license policy')
    if type(policy['schema_version']) is not int or policy['schema_version'] != 1:
        raise ArtifactError('license-policy-review', 'unsupported project license policy version')
    if not isinstance(policy['project_repository'], str) or not re.fullmatch(r'[A-Za-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', policy['project_repository']):
        raise ArtifactError('license-policy-review', 'policy requires an exact project repository identity')
    allowed = policy['auto_allow']
    if not isinstance(allowed, list) or not allowed or not all(item in ALLOWED for item in allowed) or len(set(allowed)) != len(allowed):
        raise ArtifactError('license-policy-review', 'automatic policy is limited to the explicitly approved six licenses')
    scopes = policy['usage_distribution']
    if not isinstance(scopes, dict) or not all(isinstance(key, str) and value in {'internal', 'redistributed'} for key, value in scopes.items()):
        raise ArtifactError('license-policy-review', 'project distribution scope must be explicit')
    raw = {key: policy[key] for key in sorted(required)}
    if 'factory_offline_profile' in policy:
        scope = policy['factory_offline_profile']
        hashes = {'lock_sha256', 'wheel_inventory_sha256', 'builder_sha256'}
        if (not isinstance(scope, dict) or set(scope) != hashes | {'profile', 'distribution'}
                or policy['project_repository'].lower() != 'github.com/dimkox/getzilla'
                or scope['profile'] != 'ubuntu-24.04-x86_64-cpython312' or scope['distribution'] != 'redistributed'
                or any(not isinstance(scope[k], str) or not re.fullmatch(r'[0-9a-f]{64}', scope[k]) for k in hashes)):
            raise ArtifactError('license-policy-review', 'invalid Getzilla offline profile decision')
        raw['factory_offline_profile'] = dict(scope)
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if policy.get('digest', digest) != digest:
        raise ArtifactError('license-policy-review', 'policy digest does not match its actual contents')
    return {**raw, 'digest': digest}


def _repository_identity(url: str) -> str | None:
    if re.fullmatch(r'git@[^:]+:[^/]+/[^/]+', url):
        host, path = url.removeprefix('git@').split(':', 1)
    else:
        parsed = urlsplit(url)
        if parsed.scheme not in {'https', 'ssh'} or parsed.password or parsed.port is not None or parsed.query or parsed.fragment:
            return None
        host, path = parsed.hostname or '', parsed.path.lstrip('/')
    identity = f'{host}/{path.removesuffix(".git")}'
    return identity if re.fullmatch(r'[A-Za-z0-9.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', identity) else None


def load_policy(root: Path) -> dict:
    """Read this project's policy; copying Getzilla config never selects it for a consumer."""
    try:
        policy = _policy(_json(read_file(root, POLICY_PATH, 65536)))
        process = subprocess.run(['git', '-C', str(root), 'remote', 'get-url', 'origin'],
                                 capture_output=True, text=True, encoding='utf-8', check=False, timeout=5)
        identity = _repository_identity(process.stdout.strip()) if process.returncode == 0 else None
        if identity is None or identity.lower() != policy['project_repository'].lower():
            raise ArtifactError('license-policy-missing', 'license policy belongs to another or unknown project; choose a project-specific policy')
        return policy
    except (ArtifactError, OSError, ValueError, subprocess.SubprocessError) as exc:
        return {'error': str(exc), 'digest': None}


def _distribution_for(dependency: dict, scopes: dict) -> str | None:
    """An exact manifest/use decision overrides the project-wide use default."""
    manifest, usage = dependency.get('manifest'), dependency.get('usage')
    ordinary_usage = isinstance(usage, str) and re.fullmatch(r'[a-z][a-z0-9-]*', usage) is not None
    distribution = scopes.get(usage) if ordinary_usage else None
    if isinstance(manifest, str) and ordinary_usage:
        distribution = scopes.get(f'manifest:{manifest}#{usage}', distribution)
    observed = dependency.get('distribution')
    if distribution is not None and observed is not None and distribution != observed:
        raise ArtifactError('license-scope-conflict', 'observed distribution conflicts with project policy')
    return distribution if distribution is not None else observed


def factory_offline_intent(root: Path, policy: dict) -> dict | None:
    """Recognize an independently pinned, previously builder-validated input set; never execute candidate code."""
    if 'factory_offline_profile' not in policy:
        return None
    try:
        scope = _policy(policy)['factory_offline_profile']
        origin = subprocess.run(['git', '-C', str(root), 'remote', 'get-url', 'origin'], capture_output=True,
                                text=True, encoding='utf-8', timeout=5, check=False)
        identity = _repository_identity(origin.stdout.strip()) if origin.returncode == 0 else None
        if (identity or '').lower() != policy['project_repository'].lower():
            raise ArtifactError('license-factory-project-mismatch', 'offline decision is not owned by this project')
        inputs = {'lock_sha256': ('factory/uv.lock', 4 * 1024 * 1024),
                  'wheel_inventory_sha256': ('factory/runtime/runtime-wheels-linux-x86_64-cpython312.json', 1024 * 1024),
                  'builder_sha256': ('factory/runtime/build_offline_release.py', 1024 * 1024)}
        payload = {}
        for field, (path, limit) in inputs.items():
            payload[field] = read_file(root, path, limit)
            if hashlib.sha256(payload[field]).hexdigest() != scope[field]:
                raise ArtifactError('license-factory-profile-changed', 'revalidate the declared offline profile: ' + path)
        record = _json(payload['wheel_inventory_sha256'])
        if (record.get('schema_version') != 'factory-runtime-wheels/v1' or record.get('profile') != scope['profile']
                or record.get('lock_sha256') != scope['lock_sha256'] or not isinstance(record.get('wheels'), list)
                or not record['wheels'] or len(record['wheels']) > 10000):
            raise ArtifactError('license-factory-profile-invalid', 'offline inventory does not describe the pinned profile')
        components, names = [], set()
        for wheel in record['wheels']:
            if (not isinstance(wheel, dict) or set(wheel) != {'name','version','filename','sha256'}
                    or not all(isinstance(value, str) and value for value in wheel.values())
                    or wheel['name'] in names or not re.fullmatch(r'[0-9a-f]{64}', wheel['sha256'])
                    or PurePosixPath(wheel['filename']).name != wheel['filename'] or not wheel['filename'].endswith('.whl')):
                raise ArtifactError('license-factory-profile-invalid', 'malformed or duplicate offline wheel identity')
            names.add(wheel['name'])
            components.append(dict(wheel))
        return {'code': 'license-factory-archive-delivery-unverified', 'distribution': 'redistributed',
                'profile': scope['profile'], 'components': components,
                'message': 'Offline archive use is decided; bind actual extracted LICENSE/NOTICE members to the final archive. '
                           'Not evidence that the standalone Factory wheel bundles these dependencies.'}
    except (ArtifactError, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        return {'code': getattr(exc, 'code', 'license-factory-profile-invalid'), 'message': str(exc), 'components': []}


def attach_factory_offline_intent(check: dict, intent: dict | None) -> None:
    """Report intended output use separately; this observation grants no license or delivery acceptance."""
    if intent is not None:
        check['details'][0]['factory_offline_use'] = {**intent, 'assurance': 'declared-output-scope-only',
                                                       'final_archive_evidence': 'not_evaluated'}


def _select_expression(expression: str, allowed: list[str], *, require_all: bool = False) -> tuple[list[str], set[str]]:
    if not isinstance(expression, str) or not expression.strip() or len(expression) > 4096 or '\n' in expression:
        raise ArtifactError('license-unknown', 'artifact lacks one exact SPDX expression')
    lexeme_pattern = r'[A-Za-z0-9][A-Za-z0-9.+:-]*|[()]'
    lexemes = re.findall(lexeme_pattern, expression)
    if re.sub(lexeme_pattern, '', expression).strip() or len(lexemes) > 256:
        raise ArtifactError('license-unknown', 'malformed or excessive SPDX expression')
    if any(lexeme == 'WITH' or 'licenseref-' in lexeme.lower() or lexeme.lower().startswith('documentref-') for lexeme in lexemes):
        raise ArtifactError('license-policy-review', 'WITH exceptions and custom license references require human review')
    offset = 0
    identifiers = set()

    def atom(depth=0):
        nonlocal offset
        if depth > 32 or offset >= len(lexemes):
            raise ArtifactError('license-unknown', 'incomplete or excessive SPDX expression')
        lexeme = lexemes[offset]
        offset += 1
        if lexeme == '(':
            value = disjunction(depth + 1)
            if offset >= len(lexemes) or lexemes[offset] != ')':
                raise ArtifactError('license-unknown', 'unbalanced SPDX parentheses')
            offset += 1
            return value
        if lexeme in {'AND', 'OR', ')'}:
            raise ArtifactError('license-unknown', 'malformed SPDX operator placement')
        canonical = _RECOGNIZED.get(lexeme.lower())
        if canonical is None:
            raise ArtifactError('license-unknown', f'unqualified SPDX identifier {lexeme} requires human review')
        identifiers.add(canonical)
        return ('id', canonical)

    def conjunction(depth):
        nonlocal offset
        value = atom(depth)
        while offset < len(lexemes) and lexemes[offset] == 'AND':
            offset += 1
            value = ('AND', value, atom(depth))
        return value

    def disjunction(depth):
        nonlocal offset
        value = conjunction(depth)
        while offset < len(lexemes) and lexemes[offset] == 'OR':
            offset += 1
            value = ('OR', value, conjunction(depth))
        return value

    tree = disjunction(0)
    if offset != len(lexemes):
        raise ArtifactError('license-unknown', 'malformed SPDX expression')

    if require_all:
        # Report selections contain at most the six policy-allowed identifiers.
        # Each subtree has at most 2**6 union masks, regardless of OR branch count.
        if not allowed or len(allowed) > len(ALLOWED) or not set(allowed) <= set(ALLOWED):
            raise ArtifactError('license-policy-review', 'exact branch proof requires bounded allowed identifiers')
        positions = {name: 1 << index for index, name in enumerate(dict.fromkeys(allowed))}

        def masks(node):
            if node[0] == 'id':
                return {positions[node[1]]} if node[1] in positions else set()
            left, right = masks(node[1]), masks(node[2])
            if node[0] == 'OR':
                return left | right
            return {a | b for a in left for b in right}

        if (1 << len(positions)) - 1 not in masks(tree):
            raise ArtifactError('license-policy-review', 'selected licenses do not match one complete original branch')
        return list(positions), identifiers

    def choose(node):
        if node[0] == 'id':
            if node[1] not in allowed:
                raise ArtifactError('license-policy-review', f'{node[1]} requires human review for its use and distribution')
            return [node[1]]
        if node[0] == 'AND':
            return list(dict.fromkeys(choose(node[1]) + choose(node[2])))
        try:
            return choose(node[1])
        except ArtifactError:
            return choose(node[2])

    return choose(tree), identifiers


def _license_evidence(files: dict[str, bytes], metadata: dict, identifiers: set[str], chosen: list[str], *,
                      final_wheel: bool = False) -> tuple[list[dict], list[dict]]:
    if metadata.get('dynamic'):
        dynamic=metadata['dynamic']
        fields={'platform','supported-platform','summary','description','description-content-type','keywords',
            'home-page','download-url','author','author-email','maintainer','maintainer-email','license',
            'license-expression','license-file','classifier','requires-dist','provides-dist','obsoletes-dist',
            'requires-python','requires-external','project-url','provides-extra','requires','provides','obsoletes',
            'import-name','import-namespace'}
        if (final_wheel is not True or metadata.get('metadata_version') not in {'2.2','2.3','2.4','2.5','2.6'}
                or type(dynamic) is not list or len(dynamic)>128
                or any(type(value) is not str or len(value)>128 or value.strip().lower() not in fields for value in dynamic)
                or len({value.strip().lower() for value in dynamic})!=len(dynamic)):
            raise ArtifactError('license-metadata-dynamic', 'source or forbidden Dynamic metadata has no qualified final-wheel interpretation')
    classifiers = {
        'License :: OSI Approved :: MIT License': {'MIT'},
        'License :: OSI Approved :: Apache Software License': {'Apache-2.0'},
        'License :: OSI Approved :: BSD License': {'BSD-2-Clause', 'BSD-3-Clause', '0BSD'},
        'License :: OSI Approved :: ISC License (ISCL)': {'ISC'},
    }
    for value in metadata.get('classifiers', []):
        if value.startswith('License ::') and not (classifiers.get(value, set()) & identifiers):
            raise ArtifactError('license-conflict', 'license classifier is unknown or conflicts with the exact SPDX expression')
    license_paths = set(metadata['license_paths'])
    for path in files:
        name = PurePosixPath(path).name.lower()
        if name.startswith(('license', 'copying', 'licence')):
            license_paths.add(path)
    if not license_paths:
        raise ArtifactError('license-obligation-missing', 'artifact contains no license text evidence')
    licenses, notices, recognized = [], [], set()
    for path in sorted(license_paths):
        body = files.get(path)
        if not body or not body.strip():
            raise ArtifactError('license-obligation-missing', f'declared license file is missing or empty: {path}')
        text = body.decode('utf-8')
        for declared in re.findall(r'(?im)^\s*SPDX-License-Identifier:\s*(.+?)\s*$', text):
            # These declarations are conflict evidence, never permission overrides.
            mentioned = {_RECOGNIZED.get(item.lower(), item) for item in re.findall(r'[A-Za-z0-9][A-Za-z0-9.+:-]*', declared)
                         if item not in {'AND', 'OR', 'WITH'}}
            if not mentioned <= identifiers:
                raise ArtifactError('license-conflict', 'artifact license file conflicts with distribution SPDX metadata')
        if 'GNU GENERAL PUBLIC LICENSE' in text and not any('GPL-' in value for value in identifiers):
            raise ArtifactError('license-conflict', 'GPL license text conflicts with distribution SPDX metadata')
        text_license = recognized_license(text)
        if text_license is None:
            raise ArtifactError('license-text-review', f'license text is incomplete, modified or outside the qualified templates: {path}')
        if text_license not in identifiers:
            raise ArtifactError('license-conflict', 'complete license text conflicts with the distribution SPDX expression')
        recognized.add(text_license)
        licenses.append({'path': path, 'sha256': hashlib.sha256(body).hexdigest(),
                         'bytes': len(body), 'recognized_license': text_license, 'validation': 'complete-standard-terms-and-retained-bytes'})
    if not set(chosen) <= recognized:
        raise ArtifactError('license-obligation-missing', 'selected SPDX branch lacks complete retained license terms')
    for path, body in sorted(files.items()):
        if PurePosixPath(path).name.lower().startswith('notice'):
            if not body.strip():
                raise ArtifactError('license-obligation-missing', 'artifact NOTICE is empty')
            notices.append({'path': path, 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)})
    return licenses, notices


def _satisfies(version: str, constraints: str, ecosystem: str) -> bool:
    if ecosystem == 'PyPI':
        if (type(version) is not str or len(version)>512 or type(constraints) is not str
                or len(constraints)>4096 or constraints.count(',')>128):
            raise ArtifactError('license-transitive-coverage', 'Python requirement exceeds the bounded resolver contract')
        text=constraints.strip()
        if text.startswith('(') and text.endswith(')'):
            text=text[1:-1]
        try:
            from pip._vendor.packaging.specifiers import SpecifierSet
            from pip._vendor.packaging.version import Version
            return Version(version) in SpecifierSet(text)
        except (ImportError, ValueError):
            raise ArtifactError('license-transitive-coverage', 'Python requirement has no qualified PEP440 interpretation') from None
    key = _pypi_key if ecosystem == 'PyPI' else _semver_key
    target = key(version)
    if not constraints.strip():
        return True
    constraints = constraints.strip().removeprefix('(').removesuffix(')')
    for raw in constraints.split(','):
        match = re.fullmatch(r'\s*(==|!=|>=|<=|>|<)\s*([^\s,]+)\s*', raw)
        if match is None:
            if ecosystem == 'npm' and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', raw.strip()):
                operator, bound = '==', raw.strip()
            else:
                raise ArtifactError('license-transitive-coverage', 'dependency constraint needs a qualified resolver')
        else:
            operator, bound = match.groups()
        other = key(bound)
        if not {'==': target == other, '!=': target != other, '>=': target >= other,
                '<=': target <= other, '>': target > other, '<': target < other}[operator]:
            return False
    return True


def _extra_name(value: str, *, allow_empty: bool = False) -> str:
    """Validate PEP508 spelling and compare extras using PEP685 normalization."""
    if value == '' and allow_empty:
        return ''  # The base dependency marker environment has no selected extra.
    if (not isinstance(value, str) or len(value) > 512 or
            re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?', value) is None):
        raise ArtifactError('license-transitive-coverage', 'dependency extra name is malformed')
    return re.sub(r'[-_.]+', '-', value).lower()


def _extras(values: list[str]) -> set[str]:
    if not isinstance(values, list) or len(values) > 256:
        raise ArtifactError('license-transitive-coverage', 'dependency extras must be a bounded list')
    return {_extra_name(value) for value in values}


def _validate_extra_scope(metadata: dict, dep: dict) -> None:
    """Only exact artifact declarations can cover selected Python extras."""
    if dep['ecosystem'] != 'PyPI':
        return
    values = metadata.get('provides_extra', [])
    declared = _extras(values)
    version = metadata.get('metadata_version')
    if values and version not in {'2.1', '2.2', '2.3', '2.4', '2.5', '2.6'}:
        raise ArtifactError('license-transitive-coverage', 'Provides-Extra is not defined for this metadata version')
    if len(declared) != len(values):
        raise ArtifactError('license-transitive-coverage', 'Provides-Extra declarations collide after normalization')
    if version in {'2.3', '2.4', '2.5', '2.6'} and any(value != _extra_name(value) for value in values):
        raise ArtifactError('license-transitive-coverage', 'Provides-Extra must be canonical in metadata 2.3 or newer')
    if not _extras(dep.get('extras', [])) <= declared:
        raise ArtifactError('license-transitive-coverage', 'selected extras are not declared by the exact artifact')


def _marker_required(marker: str, dep: dict, environment: dict) -> bool:
    """Bounded PEP508 evaluation with every referenced target variable explicit."""
    if (type(marker) is not str or len(marker)>4096 or marker.count('(')>32
            or type(environment) is not dict):
        raise ArtifactError('license-transitive-coverage', 'target marker exceeds the bounded resolver contract')
    try:
        from pip._vendor.packaging.markers import Marker, Variable, _evaluate_markers
        expression=Marker(marker)
        pending=[expression._markers]
        variables=set()
        count=0
        while pending:
            node=pending.pop()
            count+=1
            if count>256:
                raise ValueError('marker node bound')
            if isinstance(node,list):
                pending.extend(node)
            elif isinstance(node,tuple) and len(node)==3:
                variables.update(value.value for value in (node[0],node[2]) if isinstance(value,Variable))
                if isinstance(node[0],Variable) and isinstance(node[2],Variable):
                    raise ValueError('two-variable comparison is unresolved')
                extra_left=isinstance(node[0],Variable) and node[0].value=='extra'
                extra_right=isinstance(node[2],Variable) and node[2].value=='extra'
                if extra_left or extra_right:
                    if node[1].value not in {'==','!='}:
                        raise ValueError('unsupported extra ordering')
                    literal=node[2] if extra_left else node[0]
                    literal.value=_extra_name(literal.value,allow_empty=True)
            elif node not in {'and','or'}:
                raise ValueError('marker shape')
        if any(key!='extra' and (key not in environment or type(environment[key]) is not str
                or len(environment[key])>512) for key in variables):
            raise ValueError('unobserved target variable')
        values=_extras(dep.get('extras',[])) or {''}
        # The private evaluator consumes this explicit map directly. Marker.evaluate
        # would fill omitted fields from the ambient host, which cannot prove a target.
        return any(_evaluate_markers(expression._markers,{**environment,'extra':value}) for value in values)
    except (ImportError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ArtifactError('license-transitive-coverage', 'marker requires explicit qualified target values and extras') from None


def _closure(metadata: dict, dep: dict, dependencies: list[dict], environment: dict) -> None:
    if dep['ecosystem'] == 'Packagist':
        from .security_packagist import closure
        return closure(metadata, dep, dependencies, environment)
    if metadata.get('peer_optional') or metadata.get('requires_external'):
        raise ArtifactError('license-transitive-coverage', 'peer, optional or external dependencies need qualified artifact coverage')
    for requirement in metadata['requires']:
        if dep['ecosystem'] == 'npm':
            name, constraints = requirement
            extras = []
        else:
            parts = requirement.split(';', 1)
            if len(parts) == 2 and not _marker_required(parts[1], dep, environment):
                continue
            match = re.fullmatch(r'\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[([A-Za-z0-9_,.-]+)\])?\s*(.*?)\s*', parts[0])
            if match is None or '@' in parts[0]:
                raise ArtifactError('license-transitive-coverage', 'direct-URL or malformed transitive requirement is unresolved')
            name, extra, constraints = match.groups()
            extras = extra.split(',') if extra else []
        matches = [item for item in dependencies if item.get('ecosystem') == dep['ecosystem'] and
                   normalize_name(dep['ecosystem'], item.get('name', '')) == normalize_name(dep['ecosystem'], name)
                   and item.get('delivery_context') == dep.get('delivery_context')]
        if len({item.get('version') for item in matches}) != 1 or not matches:
            raise ArtifactError('license-transitive-coverage', f'{name} requires an exact covered transitive version')
        if not _satisfies(matches[0]['version'], constraints, dep['ecosystem']):
            raise ArtifactError('license-transitive-coverage', f'covered {name} does not satisfy the artifact requirement')
        required = _extras(extras)
        if not any(required <= _extras(item.get('extras', [])) for item in matches):
            raise ArtifactError('license-transitive-coverage', f'{name} extras are not covered by the inventory')


def evaluate_artifacts(inventory: dict, artifacts: Path, policy: dict, *, now: datetime | None = None,
                       target_binding: dict | None = None) -> dict:
    """Evaluate exact package artifacts; expose every unsupported/missing obligation."""
    result = {'status': 'fail', 'summary': '', 'details': [], 'gaps': [], 'assurance': 'artifact-integrity-only',
              'inventory_digest': inventory.get('digest') if isinstance(inventory, dict) else None, 'policy_digest': None}

    def gap(code, message, dep=None):
        result['gaps'].append({'code': code, 'message': message, **({'ecosystem': dep.get('ecosystem'),
            'package': dep.get('name'), 'version': dep.get('version'), 'manifest': dep.get('manifest')} if dep else {})})

    try:
        if not isinstance(inventory, dict) or inventory.get('complete') is not True or inventory.get('gaps'):
            raise ArtifactError('license-inventory-incomplete', 'package and artifact inventory is incomplete')
        dependencies, tools, images = (inventory.get(name) for name in ('dependencies', 'tools', 'images'))
        if not all(isinstance(values, list) and all(isinstance(item, dict) for item in values) for values in (dependencies, tools, images)):
            raise ArtifactError('license-inventory-incomplete', 'inventory artifact families are malformed or missing')
        if not isinstance(inventory.get('marker_environment', {}), dict):
            raise ArtifactError('license-transitive-coverage', 'observed target marker environment must be a mapping')
        if not dependencies and not tools and not images:
            return {**result, 'status': 'skip', 'summary': 'complete inventory has no applicable third-party artifacts'}
        policy = _policy(policy)
        result['policy_digest'] = policy['digest']
        if target_binding is not None:
            from .security_python_target import _binding
            _binding(target_binding)
            if target_binding['inventory_sha256'] != inventory.get('digest'):
                raise ArtifactError('artifact-inventory-binding', 'Python target belongs to another source inventory')
            result['python_target_scope'] = {'target':target_binding['target'],
                'assurance':'current-interpreter-only; no unobserved target or final-delivery credit'}
            if policy.get('factory_offline_profile') and 'factory_inputs' not in target_binding and any(
                    dep.get('manifest','').startswith('factory/') for dep in dependencies):
                gap('artifact-target-scope-unobserved',
                    'current interpreter observation does not qualify the separate Factory offline target and final delivery')
        raw = read_file(artifacts, 'manifest.json', MAX_INDEX_BYTES)
        bundle = _json(raw)
        if bundle.get('schema_version') != 1 or type(bundle.get('schema_version')) is not int:
            raise ArtifactError('artifact-manifest', 'unsupported artifact manifest schema')
        digest = inventory.get('digest')
        if not isinstance(digest, str) or re.fullmatch('[0-9a-f]{64}', digest) is None or bundle.get('inventory_digest') != digest:
            raise ArtifactError('artifact-inventory-binding', 'artifact manifest belongs to another inventory')
        current = _clock(now)
        age = (current - _timestamp(bundle.get('last_verified_sync_utc'))).total_seconds()
        if age < 0 or age > MAX_AGE_SECONDS:
            raise ArtifactError('artifact-stale', 'artifact acquisition is future-dated or older than 72 hours')
        records = bundle.get('records')
        if not isinstance(records, list) or len(records) > 10000 or not all(isinstance(record, dict) for record in records):
            raise ArtifactError('artifact-manifest', 'artifact manifest records are malformed')
        if bundle.get('gaps'):
            gap('artifact-acquisition-incomplete', 'artifact producer reported incomplete acquisition')
        indexed = {}
        for record in records:
            key = artifact_identity(record)
            if 'kind' in record and record['subject'] not in (images if record['kind'] == 'image' else tools):
                raise ArtifactError('artifact-inventory-binding', 'family record is not owned by this source inventory')
            if key in indexed:
                raise ArtifactError('artifact-manifest', 'duplicate exact artifact/source/use identity')
            indexed[key] = record
        deliveries = verify_deliveries(artifacts, bundle.get('deliveries', []), records, dependencies)
        result['source_evidence'] = {'manifest_sha256': hashlib.sha256(raw).hexdigest(),
            'last_verified_sync_utc': bundle['last_verified_sync_utc'], 'age_seconds': age,
            'checked_at_utc': current.isoformat(), 'coverage': {'declared_packages': len(indexed)}}
        if target_binding is not None and 'factory_inputs' in target_binding:
            from .security_factory_inputs import verify
            auxiliary=verify(artifacts,target_binding,policy,now=now)
            output=evaluate_artifacts(auxiliary['inventory'],auxiliary['root'],policy,now=now)
            result['factory_output']={'profile':target_binding['factory_inputs']['profile'],
                'status':output['status'],'source_evidence':output.get('source_evidence'),
                'assurance':'named Factory output only; original source uses remain separate'}
            result['details'].extend(output['details'])
            result['gaps'].extend(output['gaps'])
        for subject, kind in [*((item, 'action' if item.get('kind') == 'github-action' else 'tool') for item in tools),
                              *((item, 'image') for item in images)]:
            try:
                record = select_family(subject, kind, records)
                evidence = family_evidence(artifacts, record)
                _family_age(record, current, bundle['last_verified_sync_utc'])
                distribution = _distribution_for(subject, policy['usage_distribution'])
                if distribution != 'internal':
                    raise ArtifactError('license-obligation-missing', 'family needs explicit internal use or a qualified final-output adapter')
                selected, licenses, notices = [], [], []
                for component in evidence['components']:
                    chosen, identifiers = _select_expression(component['expression'], policy['auto_allow'])
                    owned = {item['path'] for item in component['files']}
                    files = {name: body for name, body in evidence['files'].items() if name in owned}
                    license_files, notice_files = _license_evidence(files, component, identifiers, chosen)
                    if any(not files.get(path, b'').strip() for path in component['notice_paths']):
                        raise ArtifactError('license-obligation-missing', 'declared component NOTICE is empty')
                    selected.extend(chosen)
                    licenses.extend(license_files)
                    notices.extend(notice_files)
                result['details'].append({'kind': kind, 'reference': subject['reference'], 'status': 'pass',
                    'selected_expression': ' AND '.join(sorted(set(selected))), 'distribution': distribution,
                    **evidence['binding'], 'license_files': licenses, 'notice_files': notices,
                    'obligations': 'internal use; exact source/component/license evidence retained'})
            except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError) as exc:
                code = getattr(exc, 'code', 'artifact-invalid')
                if code == 'license-artifact-missing':
                    code = 'license-image-coverage' if kind == 'image' else 'license-tool-coverage'
                gap(code, str(exc))
        for dep in dependencies:
            try:
                if dep.get('ecosystem') == 'PyPI':
                    _extras(dep.get('extras', []))
                distribution = _distribution_for(dep, policy['usage_distribution'])
                scope_known = isinstance(distribution, str) and distribution in {'internal', 'redistributed'}
                if not scope_known:
                    gap('license-scope-unknown', 'use/distribution scope requires an observed project decision', dep)
                key = package_key(dep.get('ecosystem'), dep.get('name'), dep.get('version'))
                record = select_artifact(dep, records)
                if 'acquired_at' in record:
                    _family_age(record, current, bundle['last_verified_sync_utc'])
                payload = read_file(artifacts, record.get('path'), MAX_ARTIFACT_BYTES)
                origin = verify_origin(artifacts, record, payload)
                if dep.get('artifact_sha256') and dep['artifact_sha256'] != record['sha256']:
                    raise ArtifactError('artifact-identity', 'artifact differs from the observed dependency artifact')
                if dep.get('artifact_filename') and dep['artifact_filename'] != record['filename']:
                    raise ArtifactError('artifact-identity', 'artifact filename differs from the observed target')
                observed = None
                if dep['ecosystem'] == 'PyPI' and (target_binding is not None or 'python_target' in record):
                    from .security_python_target import verify_record
                    observed = verify_record(record,payload,target_binding,dependency=dep)
                    if target_binding and 'source_pins' in target_binding and not target_binding['source_pins'][observed['subject_sha256']]['marker_active']:
                        raise ArtifactError('artifact-target-use-unobserved', 'this source marker requires a separately observed target; current input bytes grant no other-target use credit')
                if dep['ecosystem'] == 'PyPI' and observed is None and not (dep.get('artifact_filename') or dep.get('artifact_sha256')):
                    if not re.search(r'-(?:py3|py2\.py3)-none-any\.whl$', record['filename']):
                        raise ArtifactError('artifact-target-unknown', 'platform wheel or sdist requires an explicitly observed artifact target')
                files = archive_files(payload, record['filename'])
                metadata = package_metadata(files, dep['ecosystem'], record['filename'],
                                            **({'origin': origin} if dep['ecosystem'] == 'Packagist' else {}))
                missing_paths = set(metadata['license_paths']) - set(files)
                if missing_paths:
                    files.update(archive_files(payload, record['filename'], requested=missing_paths))
                if package_key(dep['ecosystem'], metadata['name'], metadata['version']) != key:
                    raise ArtifactError('artifact-identity', 'artifact metadata Name/Version differs from inventory')
                _validate_extra_scope(metadata, dep)
                chosen, identifiers = _select_expression(metadata['expression'], policy['auto_allow'])
                if dep['ecosystem'] == 'Packagist':
                    from .security_packagist import license_members
                    license_inputs = license_members(files, metadata)
                else:
                    license_inputs = files
                license_files, notice_files = _license_evidence(license_inputs, metadata, identifiers, chosen,
                    final_wheel=dep['ecosystem']=='PyPI' and record['filename'].endswith('.whl'))
                custody = None
                context = dep.get('delivery_context')
                if dep.get('delivery_kind') == 'factory-offline-archive' and context not in deliveries:
                    raise ArtifactError('license-obligation-missing', 'offline archive requires actual final output and composition evidence')
                if context in deliveries:
                    if distribution != 'redistributed':
                        raise ArtifactError('license-scope-conflict', 'named archive components must retain redistributed scope')
                    output = deliveries[context]
                    retained = sorted('site-packages/' + item['path'] for item in license_files + notice_files)
                    custody = {field: value for field, value in output.items() if field != 'members'}
                    custody['retained_members'] = retained
                elif distribution == 'redistributed':
                    if context and dep.get('delivery_kind') != 'unchanged-artifact':
                        raise ArtifactError('license-obligation-missing', 'named output needs its actual final delivery and composition evidence')
                    delivery = record.get('redistributed_path')
                    if not delivery:
                        raise ArtifactError('license-obligation-missing', 'redistribution needs evidence of the unchanged delivered artifact retaining LICENSE/NOTICE')
                    delivered = read_file(artifacts, delivery, MAX_ARTIFACT_BYTES)
                    if hashlib.sha256(delivered).hexdigest() != record['sha256']:
                        raise ArtifactError('license-obligation-missing', 'modified delivery needs separate notice, attribution and license review')
                markers = (target_binding['target']['marker_environment'] if observed is not None else inventory.get('marker_environment', {}))
                _closure(metadata, dep, dependencies, markers)
                if not scope_known:
                    continue
                result['details'].append({'ecosystem': dep['ecosystem'], 'package': dep['name'], 'version': dep['version'],
                    'manifest': dep.get('manifest'), 'status': 'pass', 'expression': metadata['expression'],
                    'selected_expression': ' AND '.join(chosen), 'distribution': distribution,
                    'artifact_sha256': record['sha256'], 'artifact_id': artifact_identity(record),
                    'context': {**record.get('context', {}), **({'python_target_sha256':observed['target_sha256']} if observed else {})}, **({'delivery': custody} if custody else {}),
                    'origin': origin, 'license_files': license_files,
                    'notice_files': notice_files, 'obligations': ('retained in final extracted archive' if custody else 'retained in exact artifact')
                    if distribution == 'redistributed' else 'internal use; license evidence retained'})
            except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError, VulnerabilityError) as exc:
                gap(getattr(exc, 'code', 'artifact-invalid'), str(exc), dep)
    except (ArtifactError, SecurityDataError, ValueError, TypeError, KeyError, VulnerabilityError) as exc:
        gap(getattr(exc, 'code', 'artifact-invalid'), str(exc))
    result['status'] = 'fail' if result['gaps'] else 'pass'
    result['summary'] = (f"{len(result['gaps'])} artifact license, scope or coverage gaps require resolution" if result['gaps']
                         else f"license policy and retained evidence verified for {len(result['details'])} exact package artifacts")
    return result


def _family_age(record: dict, current: datetime, catalog_time: str) -> None:
    acquired = _timestamp(record.get('acquired_at'))
    age = (current - acquired).total_seconds()
    if age < 0 or age > MAX_AGE_SECONDS or acquired < _timestamp(catalog_time):
        raise ArtifactError('artifact-stale', 'family acquisition is stale/future or catalog timestamp renews older evidence')


def artifact_catalog_source(inventory: dict, artifacts: Path, policy: dict, *, now: datetime | None = None,
                            target_binding: dict | None = None) -> dict:
    """Freeze actual catalog bytes for final-receipt revalidation, without policy PASS.

    Recompute at receipt consumption and compare the whole source projection.
    Coverage.complete describes only the structural completeness of this
    manifest's referenced records. It never claims complete dependency, tool,
    image, license or distribution coverage. evaluate_artifacts supplies those
    decisions independently. Hashes and unsigned timestamps supply integrity
    bindings only; external runner qualification supplies independent authority.

    The returned projection stays stable while bytes, inventory, policy and the
    original acquisition time stay unchanged. Clock validation runs on every
    call; copying a catalog cannot renew its 72-hour lifetime. Missing or
    inconsistent references raise ArtifactError; an invalid clock may raise
    SecurityDataError. Callers must map either exception to unavailable.
    """
    try:
        digest = inventory.get('digest') if isinstance(inventory, dict) else None
        if not isinstance(digest, str) or re.fullmatch(r'[0-9a-f]{64}', digest) is None:
            raise ArtifactError('artifact-inventory-binding', 'catalog needs the exact source inventory digest')
        selected_policy = _policy(policy)
        if target_binding is not None:
            from .security_python_target import _binding
            _binding(target_binding)
            if target_binding['inventory_sha256'] != digest:
                raise ArtifactError('artifact-inventory-binding', 'Python target belongs to another source inventory')
        current = _clock(now)
        raw = read_file(artifacts, 'manifest.json', MAX_INDEX_BYTES)
        bundle = _json(raw)
        if type(bundle.get('schema_version')) is not int or bundle['schema_version'] != 1 or bundle.get('inventory_digest') != digest:
            raise ArtifactError('artifact-inventory-binding', 'catalog schema or source inventory binding differs')
        acquired = bundle.get('last_verified_sync_utc')
        age = (current - _timestamp(acquired)).total_seconds()
        if age < 0 or age > MAX_AGE_SECONDS:
            raise ArtifactError('artifact-stale', 'catalog acquisition is future-dated or older than 72 hours')
        records = bundle.get('records')
        if not isinstance(records, list) or not records or len(records) > 10000 or not all(isinstance(record, dict) for record in records):
            raise ArtifactError('artifact-manifest', 'catalog has no bounded complete records')
        bindings, seen, total = [], set(), len(raw)
        for record in records:
            key = artifact_identity(record)
            if key in seen:
                raise ArtifactError('artifact-manifest', 'catalog repeats a package artifact identity')
            seen.add(key)
            if 'kind' in record:
                subjects = inventory.get('images' if record['kind'] == 'image' else 'tools', [])
                if record['subject'] not in subjects:
                    raise ArtifactError('artifact-inventory-binding', 'family does not belong to the current source inventory')
                _family_age(record, current, acquired)
                evidence = family_evidence(artifacts, record)
                total += evidence['bound_bytes']
                if total > 512 * 1024 * 1024:
                    raise ArtifactError('artifact-size', 'catalog exceeds the aggregate bound-byte budget')
                bindings.append(evidence['binding'])
                continue
            origin = record.get('origin')
            if not isinstance(origin, dict):
                raise ArtifactError('artifact-origin', 'catalog record lacks its saved registry index')
            if 'acquired_at' in record:
                _family_age(record, current, acquired)
            payload = read_file(artifacts, record.get('path'), MAX_ARTIFACT_BYTES)
            index = read_file(artifacts, origin.get('index_path'), MAX_INDEX_BYTES)
            verified = verify_origin(artifacts, record, payload, index_bytes=index)
            observed = None
            if record['ecosystem'] == 'PyPI' and (target_binding is not None or 'python_target' in record):
                from .security_python_target import verify_record
                observed = verify_record(record,payload,target_binding)
            bound = {'ecosystem': record['ecosystem'], 'name': record['name'], 'version': record['version'],
                     'path': record['path'], 'filename': record['filename'], 'artifact_size': len(payload),
                     'artifact_id': key, 'context': record.get('context', {}),
                     'index_path': origin['index_path'], 'index_size': len(index), **verified}
            if observed is not None:
                bound['python_target'] = observed
            total += len(payload) + len(index)
            if record.get('redistributed_path') is not None:
                delivered = read_file(artifacts, record['redistributed_path'], MAX_ARTIFACT_BYTES)
                delivery_digest = hashlib.sha256(delivered).hexdigest()
                if delivery_digest != verified['artifact_sha256']:
                    raise ArtifactError('artifact-hash', 'catalog delivered artifact bytes no longer match')
                bound['delivery'] = {'path': record['redistributed_path'], 'sha256': delivery_digest, 'size': len(delivered)}
                total += len(delivered)
            if total > 512 * 1024 * 1024:
                raise ArtifactError('artifact-size', 'catalog exceeds the aggregate bound-byte budget')
            bindings.append(bound)
        deliveries = verify_deliveries(artifacts, bundle.get('deliveries', []), records, inventory.get('dependencies', []))
        total += sum(delivery['output_bytes'] for delivery in deliveries.values())
        if total > 512 * 1024 * 1024:
            raise ArtifactError('artifact-size', 'catalog and delivered outputs exceed the aggregate bound-byte budget')
        # Also bind the supplied input contents: a caller changing an input
        # while retaining its old digest must not obtain the same projection.
        inventory_body = json.dumps(inventory, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(inventory_body) > MAX_INDEX_BYTES:
            raise ArtifactError('artifact-size', 'source inventory exceeds its byte budget')
        binding = {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'inventory_digest': digest,
                   'inventory_content_sha256': hashlib.sha256(inventory_body).hexdigest(),
                   'policy_digest': selected_policy['digest'],
                   'records': sorted(bindings, key=lambda item: item['artifact_id']),
                   'deliveries': deliveries}
        if target_binding is not None and 'factory_inputs' in target_binding:
            from .security_factory_inputs import verify
            auxiliary=verify(artifacts,target_binding,selected_policy,now=now)
            binding['factory_output']=auxiliary['projection']
            total+=auxiliary['projection']['payload_size']
            if total>512*1024*1024:
                raise ArtifactError('artifact-size','catalog and Factory output exceed the shared aggregate byte budget')
        content = json.dumps(binding, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'database': str(Path(artifacts).absolute()), 'source_id': 'artifact-license-catalog',
                'source_url': 'urn:getzilla:artifact-license-catalog:1',
                'content_sha256': hashlib.sha256(content).hexdigest(), 'payload_size': total,
                'acquisition': {'last_verified_sync_utc': acquired, 'retrieval_kind': 'catalog-binding',
                                'producer': 'getzilla-artifact-catalog-v1'},
                'coverage': {'schema': 'artifact-license-catalog-1', 'scopes': ['catalog'],
                             'record_count': len(bindings), 'complete': True}}
    except (ArtifactError, SecurityDataError):
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise ArtifactError('artifact-catalog-unavailable', str(exc)) from exc
