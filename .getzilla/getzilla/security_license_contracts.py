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

from .security_osv_snapshot import _pypi_key, _semver_key, normalize_name
from .security_artifacts import (ArtifactError, MAX_ARTIFACT_BYTES as MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES as MAX_INDEX_BYTES, artifact_identity as artifact_identity, read_file, verify_origin as verify_origin, safe_parts)
from .security_artifacts import family_evidence as family_evidence
from .security_data import MAX_AGE_SECONDS, SecurityDataError as SecurityDataError, _clock as _clock, _json, _timestamp
from .security_license_texts import recognized_license, recognized_license_bundle, reviewed_ancillary
from .security_deliveries import verify_deliveries as verify_deliveries

POLICY_PATH = '.getzilla/config/license-policy.json'


ALLOWED = ('MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD')


_CANONICAL = {name.lower(): name for name in ALLOWED}


_NONALLOW = ('GPL-2.0-only', 'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later',
             'LGPL-2.1-only', 'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
             'AGPL-3.0-only', 'AGPL-3.0-or-later', 'MPL-2.0', 'EPL-2.0', 'BSD-4-Clause',
             'CC0-1.0', 'Unlicense', 'X11', 'BlueOak-1.0.0', 'BSD-2-Clause-Views', 'PSF-2.0', 'CC-BY-4.0', 'CC-BY-SA-4.0')


_RECOGNIZED = {name.lower(): name for name in (*ALLOWED, *_NONALLOW)}


def _policy(policy: dict) -> dict:
    required = {'schema_version', 'project_repository', 'auto_allow', 'usage_distribution'}
    if not isinstance(policy, dict) or not required <= set(policy) or set(policy) - required - {'digest', 'factory_offline_profile', 'dependency_exceptions', 'image_license_scope', 'referenced_image_scope'}:
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
    if 'image_license_scope' in policy:
        from .security_internal_image_scope import validate_policy
        raw['image_license_scope'] = validate_policy(policy['project_repository'], policy['image_license_scope'])
    if 'referenced_image_scope' in policy:
        from .security_referenced_image import validate_policy as referenced_policy
        if 'image_license_scope' not in raw:
            raise ArtifactError('license-policy-review', 'referenced scope requires the Getzilla image policy')
        raw['referenced_image_scope'] = referenced_policy(policy['referenced_image_scope'])
    if 'factory_offline_profile' in policy:
        scope = policy['factory_offline_profile']
        hashes = {'lock_sha256', 'wheel_inventory_sha256', 'builder_sha256'}
        if (not isinstance(scope, dict) or set(scope) != hashes | {'profile', 'distribution'}
                or policy['project_repository'].lower() != 'github.com/dimkox/getzilla'
                or scope['profile'] != 'ubuntu-24.04-x86_64-cpython312' or scope['distribution'] != 'redistributed'
                or any(not isinstance(scope[k], str) or not re.fullmatch(r'[0-9a-f]{64}', scope[k]) for k in hashes)):
            raise ArtifactError('license-policy-review', 'invalid Getzilla offline profile decision')
        raw['factory_offline_profile'] = dict(scope)
    if 'dependency_exceptions' in policy:
        from .security_license_exceptions import validate_exceptions
        raw['dependency_exceptions'] = validate_exceptions(policy['dependency_exceptions'])
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
    licenses, notices, recognized, ancillary_paths = [], [], set(), set()
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
        text_identifiers = (text_license,) if text_license is not None else recognized_license_bundle(text)
        if text_identifiers is None:
            ancillary=reviewed_ancillary(text)
            if ancillary is None:
                raise ArtifactError('license-text-review', f'license text is incomplete, modified or outside the qualified templates: {path}')
            if (type(ancillary) is not dict or set(ancillary)!={'kind','expression','required_files'}
                    or ancillary['kind'] not in {'attribution','license-declaration'}
                    or type(ancillary['required_files']) is not dict or not 1<=len(ancillary['required_files'])<=16):
                raise ArtifactError('license-text-review','ancillary declaration has no closed reviewed reference contract')
            if ancillary['expression']!=metadata.get('expression'):
                raise ArtifactError('license-conflict','ancillary declaration conflicts with the exact distribution SPDX expression')
            references,reference_terms=[],set()
            for relative,expected_sha in sorted(ancillary['required_files'].items()):
                parts=safe_parts(relative)
                reference=str(PurePosixPath(path).parent.joinpath(*parts))
                complete=files.get(reference)
                if (reference==path or reference not in license_paths or not complete or not complete.strip()
                        or type(expected_sha) is not str or re.fullmatch('[0-9a-f]{64}',expected_sha) is None
                        or hashlib.sha256(complete).hexdigest()!=expected_sha):
                    raise ArtifactError('license-obligation-missing','ancillary declaration requires its exact independently retained complete terms')
                identifier=recognized_license(complete.decode('utf-8'))
                reference_identifiers=(identifier,) if identifier is not None else recognized_license_bundle(complete.decode('utf-8'))
                if reference_identifiers is None:
                    raise ArtifactError('license-text-review','ancillary reference does not independently contain recognized complete terms')
                if not set(reference_identifiers) <= identifiers:
                    raise ArtifactError('license-conflict','ancillary reference conflicts with the distribution SPDX expression')
                reference_terms.update(reference_identifiers)
                terms_identity=({'recognized_license':identifier} if identifier is not None else
                    {'recognized_licenses':list(reference_identifiers)})
                references.append({'path':reference,'sha256':expected_sha,**terms_identity})
            # Every referenced branch is checked, even when metadata permits OR.
            # Ancillary bytes themselves never enter recognized or license_files.
            if not identifiers<=reference_terms:
                raise ArtifactError('license-obligation-missing','ancillary declaration lacks complete referenced terms for its exact expression')
            ancillary_paths.add(path)
            notices.append({'path':path,'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body),
                'ancillary_kind':ancillary['kind'],'expression':ancillary['expression'],
                'validation':'exact-reviewed-ancillary-with-independent-complete-terms','required_files':references})
            continue
        if not set(text_identifiers) <= identifiers:
            raise ArtifactError('license-conflict', 'complete license text conflicts with the distribution SPDX expression')
        recognized.update(text_identifiers)
        terms_identity=({'recognized_license':text_license} if text_license is not None else
            {'recognized_licenses':list(text_identifiers)})
        licenses.append({'path': path, 'sha256': hashlib.sha256(body).hexdigest(),
                         'bytes': len(body), **terms_identity, 'validation': 'complete-standard-terms-and-retained-bytes'})
    if not set(chosen) <= recognized:
        raise ArtifactError('license-obligation-missing', 'selected SPDX branch lacks complete retained license terms')
    for path, body in sorted(files.items()):
        if PurePosixPath(path).name.lower().startswith('notice'):
            if not body.strip():
                raise ArtifactError('license-obligation-missing', 'artifact NOTICE is empty')
            if path not in ancillary_paths:
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


def _family_age(record: dict, current: datetime, catalog_time: str) -> None:
    acquired = _timestamp(record.get('acquired_at'))
    age = (current - acquired).total_seconds()
    if age < 0 or age > MAX_AGE_SECONDS or acquired < _timestamp(catalog_time):
        raise ArtifactError('artifact-stale', 'family acquisition is stale/future or catalog timestamp renews older evidence')


from .expanded_security import artifact_catalog_source as artifact_catalog_source
