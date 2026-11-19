"""Explicit protected public execution context; no environment/file authority.

Native CLI declarations keep their original run-head=candidate contract. Only
an in-process protected entry can bind the separately observed runner context.
This is a data contract, not independent provider/execution qualification.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import json
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path

from .python_test_runner import execute
from .verification_actions import retain_stop, stop_details, updated_stop
from .security_data import MAX_AGE_SECONDS, SecurityDataError
from .security_artifacts import ArtifactError
from .security_inventory import canonical_digest
from .security_licenses import _repository_identity
from .security_osv_snapshot import VulnerabilityError, _source_git_root
from .security_tools import _environment

_CURRENT = ContextVar('getzilla_public_security_context', default=None)
_FIELDS = {'kind', 'repository', 'repository_id', 'pr_number', 'base_sha', 'head_sha', 'tree_sha',
           'checker_sha', 'checker_tree_sha', 'runner_repository', 'runner_repository_id',
           'runner_sha', 'runner_tree_sha', 'workflow_id', 'workflow_blob_sha', 'run_id', 'run_attempt'}


def validate_context(context, source):
    if type(context) is not dict or set(context) != _FIELDS or context['kind'] != 'getzilla-public-execution-v1':
        raise ValueError('public execution context is malformed')
    for key in ('repository_id','pr_number','runner_repository_id','workflow_id','run_id','run_attempt'):
        if type(context[key]) is not int or context[key] <= 0:
            raise ValueError('public execution identity is malformed')
    for key in ('repository','runner_repository'):
        if type(context[key]) is not str or re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',context[key]) is None:
            raise ValueError('public execution repository is malformed')
    for key in ('base_sha','head_sha','tree_sha','checker_sha','checker_tree_sha','runner_sha','runner_tree_sha','workflow_blob_sha'):
        if type(context[key]) is not str or re.fullmatch('[0-9a-f]{40}',context[key]) is None:
            raise ValueError('public execution source is malformed')
    if any(source.get(key) != context[key] for key in ('head_sha','tree_sha','checker_sha','checker_tree_sha')):
        raise ValueError('public execution differs from actual candidate/checker source')
    if any(source.get(key) is not True for key in ('candidate_clean','checker_clean','same_project')):
        raise ValueError('public execution source is not clean and paired')
    return {'provider':'github-actions','repository':context['runner_repository'],
            'run_id':str(context['run_id']),'run_attempt':str(context['run_attempt']),'head_sha':context['runner_sha']}


def current_context():
    value=_CURRENT.get()
    return json.loads(value) if value is not None else None


@contextmanager
def bind_context(context, source):
    validate_context(context,source)
    token=_CURRENT.set(json.dumps(context,sort_keys=True,separators=(',',':')))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def selection_document(inventory, source, run, created_at):
    """Source declarations only, derived after validating the ORIGINAL catalog."""
    uses = []
    for row in inventory['images']:
        uses.append(dict(path=row['manifest'], line=row['line'], source_sha256=row['source_sha256'],
                         expression=row['source_reference'], reference=row['reference'], platform=row['platform']))
    return dict(schema_version=1, source=source, run=run, created_at=created_at, uses=uses)


def project_catalog(catalog, inventory_digest):
    """Keep original graph/selection identity when binding a current declaration.

    This projection is not validation. The caller must first validate the raw
    catalog against independently collected source and then validate the derived
    catalog against the full current declaration inventory.
    """
    if 'source_catalog_sha256' in catalog:
        raise ValueError('nested public catalog projection refused')
    value=json.loads(json.dumps(catalog))
    value['source_catalog_sha256']=digest(catalog)
    value['inventory_sha256']=inventory_digest
    return value


# Exact source/run and finite profile declarations do not depend on the command facade.

def _image_refusal(code: str, message: str) -> SecurityDataError:
    error = SecurityDataError(message)
    error.image_input_refusal = code
    return error


def validate_selection_authority(source: dict, run: dict, selection=None, *, now=None) -> None:
    """Shared CLI/native independently observed source/checker/run contract."""
    keys = {'head_sha', 'tree_sha', 'checker_sha', 'checker_tree_sha', 'candidate_clean', 'checker_clean', 'same_project'}
    if (not isinstance(source, dict) or set(source) != keys or source['candidate_clean'] is not True
            or source['checker_clean'] is not True or type(source['same_project']) is not bool
            or any(not isinstance(source[key], str) or not re.fullmatch('[0-9a-f]{40}', source[key])
                   for key in ('head_sha', 'tree_sha', 'checker_sha', 'checker_tree_sha'))):
        raise SecurityDataError('input profile requires clean exact source and checker identities')
    public = current_context()
    expected_run = validate_context(public, source) if public is not None else None
    if (not isinstance(run, dict) or set(run) != {'provider', 'repository', 'run_id', 'run_attempt', 'head_sha'}
            or run['provider'] != 'github-actions' or (run != expected_run if expected_run is not None else run['head_sha'] != source['head_sha'])
            or not isinstance(run['repository'], str) or not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', run['repository'])
            or any(not isinstance(run[key], str) or not re.fullmatch('[1-9][0-9]{0,19}', run[key]) for key in ('run_id', 'run_attempt'))):
        raise SecurityDataError('input profile needs the actual exact CI run and attempt')
    if selection is not None:
        from .security_data import _timestamp
        if (type(selection) is not dict or set(selection) != {'schema_version', 'source', 'run', 'created_at', 'uses'}
                or type(selection['schema_version']) is not int or selection['schema_version'] != 1
                or not isinstance(selection['uses'], list) or not 1 <= len(selection['uses']) <= 512):
            raise SecurityDataError('image selection document is malformed')
        if selection['source'] != source or selection['run'] != run:
            raise _image_refusal('image-selection-source-mismatch',
                                 'image selection differs from independently observed source/checker/run/attempt')
        age = (_clock(now) - _timestamp(selection.get('created_at'))).total_seconds()
        if not 0 <= age <= MAX_AGE_SECONDS:
            raise _image_refusal('image-selection-stale', 'image selection is future or stale at consumption')


def input_profile(source: dict, inventory: dict, roots: dict, run: dict, policy: str, *, now=None, image_artifacts=None, image_selection=None,
                  package_target=None, package_pins=None, factory_inputs=None, package_graphs=None, package_ci_uses=None, network_selection=None) -> dict:
    """A finite declaration for one source/run; never scan or attestation credit."""
    validate_selection_authority(source, run, image_selection, now=now)
    if isinstance(inventory, dict) and inventory.get('builds'):
        from .security_image_authority import require_builds
        require_builds(inventory, source, run)
    if package_ci_uses is not None:
        from .security_image_authority import validate_ci_uses
        package_ci_uses=validate_ci_uses(package_ci_uses,source,run)
    public=current_context()
    declared=_profile_declaration(source,inventory,roots,run,policy,now=now,image_artifacts=image_artifacts,
        image_selection=image_selection,package_target=package_target,package_pins=package_pins,
        factory_inputs=factory_inputs,package_graphs=package_graphs,package_ci_uses=package_ci_uses,
        public_execution=canonical_digest(public) if public is not None else None, network_selection=network_selection)
    if image_artifacts is not None:
        from .security_oci import validate_selection
        validate_selection(image_artifacts,inventory,declared['image_profile'])
    return declared


def _profile_declaration(source,inventory,roots,run,policy,*,now=None,image_artifacts=None,image_selection=None,
                         package_target=None,package_pins=None,factory_inputs=None,package_graphs=None,
                         package_ci_uses=None,public_execution=None,image_limits=None,network_selection=None):
    """Pure normalized declaration; never grants native/build observation credit."""
    if (not isinstance(inventory, dict) or inventory.get('complete') is not True or inventory.get('gaps') != []
            or not _digest(inventory.get('digest')) or not _digest(policy)):
        raise SecurityDataError('input profile needs complete source declarations and policy identity')
    counts = {}
    for family in ('dependencies', 'tools', 'images'):
        values = inventory.get(family)
        if not isinstance(values, list) or len(values) > 512 or not all(isinstance(item, dict) for item in values):
            raise SecurityDataError('input profile source family is malformed or exceeds its finite bound')
        counts[family] = len(values)
    if (not isinstance(roots, dict) or set(roots) != {'database', 'artifacts', 'tools'}
            or not all(isinstance(value, str) and Path(value).is_absolute() and '..' not in Path(value).parts for value in roots.values())):
        raise SecurityDataError('input profile requires three explicit absolute owned roots')
    paths = list(map(Path, roots.values()))
    if any(a.is_relative_to(b) for i, a in enumerate(paths) for j, b in enumerate(paths) if i != j):
        raise SecurityDataError('input roots must be separate and nonoverlapping')
    body = {'schema_version': 1, 'kind': 'public-security-input-profile', 'source': source, 'run': run,
            'inventory_sha256': inventory['digest'], 'policy_sha256': policy, 'roots': roots,
            'created_at': _clock(now).isoformat(), 'observed_counts': counts,
            'limits': {'dependencies': 512, 'tools': 512, 'images': 512, 'catalog_bytes': 512 * 1024 * 1024,
                       'deadline_seconds': 600, 'cleanup_seconds': 5},
            'assurance': 'declaration-only-not-evidence-or-authority'}
    osv = sorted({f'osv:{item.get("ecosystem")}' for item in inventory['dependencies']})
    images = ['trivy-db'] if counts['images'] else []
    body['required_sources'] = {
        'security-inventory': [], 'known-vulnerabilities': osv,
        'security-kev': ['kev', *osv, *images] if counts['dependencies'] or counts['images'] else [],
        'security-epss': ['epss', *osv, *images] if counts['dependencies'] or counts['images'] else [],
        'security-malicious-packages': osv,
        'security-licenses': ['artifact-license-catalog'] if any(counts.values()) else [],
        'security-container-images': images}
    body['image_profile'] = None
    if counts['images']:
        if any(not isinstance(item.get('reference'), str) or re.fullmatch(r'[^\s$@]+@sha256:[0-9a-f]{64}', item['reference']) is None for item in inventory['images']):
            raise SecurityDataError('image input requires explicit immutable identities')
        platforms = {item.get('platform') for item in inventory['images']}
        if len(platforms) != 1 or not platforms <= {'linux/amd64', 'linux/arm64'}:
            raise SecurityDataError('image input platform remains unproved')
        from .security_oci import active_limits,LIMITS,CI_BYTES
        limits=active_limits() if image_limits is None else image_limits
        ci_limits={**LIMITS,**{key:CI_BYTES for key in ('max_compressed_bytes','max_unpacked_bytes','max_storage_bytes')}}
        if limits not in (LIMITS,ci_limits):
            raise SecurityDataError('image limits differ from a supported declaration')
        body['image_profile'] = dict(limits, images=sorted({item['reference'] for item in inventory['images']}),
                                     platform=next(iter(platforms)))
    if image_artifacts is not None:
        body['image_artifacts_sha256'] = hashlib.sha256(json.dumps(image_artifacts, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if image_selection is not None:
        body['image_selection_sha256'] = canonical_digest(image_selection)
    if package_target is not None:
        from .security_python_target import validate_target
        body['python_target'] = validate_target(package_target)
        if package_pins is None and any(dep['ecosystem']=='PyPI' for dep in inventory['dependencies']):
            raise SecurityDataError('current Python target needs independently observed source artifact pins')
        if package_pins is not None:
            from .security_python_target import validate_source_pins
            body['python_source_pins'] = validate_source_pins(package_pins)
    if factory_inputs is not None:
        from .security_factory_inputs import validate_declaration
        body['factory_inputs']=validate_declaration(factory_inputs)
        if body['factory_inputs']['inventory_sha256']!=inventory['digest']:
            raise SecurityDataError('Factory input declaration belongs to another inventory')
    if package_graphs is not None:
        from .security_python_target import validate_closure_graphs
        body['python_closure_graphs']=validate_closure_graphs(package_graphs)
        if body['python_closure_graphs']['inventory_sha256']!=inventory['digest']:
            raise SecurityDataError('Python closure graphs belong to another inventory')
    if package_ci_uses is not None:
        body['python_ci_uses']=package_ci_uses
    if public_execution is not None:
        if not _digest(public_execution):
            raise SecurityDataError('public execution declaration digest is malformed')
        body['public_execution_sha256']=public_execution
    if network_selection is not None:
        from .security_tools import image_network_selection
        body['image_network_selection'] = image_network_selection(inventory, network_selection)
    body['profile_sha256'] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return json.loads(json.dumps(body))


def validate_input_profile(profile: dict, source: dict, inventory: dict, roots: dict, run: dict, policy: str, *, now=None, image_artifacts=None, image_selection=None,
                           package_pins=None, factory_inputs=None, package_graphs=None, package_ci_uses=None) -> dict:
    if not isinstance(profile, dict) or not isinstance(profile.get('created_at'), str):
        raise SecurityDataError('explicit public input profile is missing')
    from .security_data import _timestamp
    created = _timestamp(profile['created_at'])
    age = (_clock(now) - created).total_seconds()
    validate_selection_authority(source, run, image_selection, now=now)
    target = None
    if 'python_target' in profile:
        from .security_python_target import validate_target
        target = validate_target(profile['python_target'])
    if 'python_source_pins' in profile and package_pins is None:
        raise SecurityDataError('source artifact pins must be reobserved before profile consumption')
    if not 0 <= age <= MAX_AGE_SECONDS or profile != input_profile(source, inventory, roots, run, policy, now=created, image_artifacts=image_artifacts, image_selection=image_selection,
                                                               package_target=target,package_pins=package_pins,factory_inputs=factory_inputs,package_graphs=package_graphs,package_ci_uses=package_ci_uses, network_selection=profile.get('image_network_selection')):
        raise SecurityDataError('input profile is stale or differs from actual source/run/attempt/policy/roots/bounds')
    return profile


def ci_run_context(environ: dict) -> dict:
    return {'provider': 'github-actions', 'repository': environ.get('GITHUB_REPOSITORY'),
            'run_id': environ.get('GITHUB_RUN_ID'), 'run_attempt': environ.get('GITHUB_RUN_ATTEMPT'),
            'head_sha': environ.get('GITHUB_SHA')}


def _clock(now=None):
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SecurityDataError('timezone-aware security clock required')
    return current.astimezone(timezone.utc)


def _git(root: Path, arguments: list[str], scratch: Path) -> str:
    result = execute(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', str(root), *arguments],
                     scratch, _environment(scratch), timeout=30)
    if result.returncode or result.terminal_state != 'completed' or result.cleanup_error:
        error = SecurityDataError('cannot establish source identity using a completed Git observation; stop=' + json.dumps(stop_details(result), sort_keys=True))
        retain_stop(error, updated_stop(result))
        raise error
    return result.stdout.strip()


def source_binding(root: Path, checker: Path, scratch: Path) -> dict:
    values = []
    for project in (root, checker):
        try:
            if not _source_git_root(project):
                raise VulnerabilityError('selected security source must be the exact Git worktree root')
        except VulnerabilityError as exc:
            raise SecurityDataError('selected security source must be the exact Git worktree root') from exc
        identity = _git(project, ['rev-parse', 'HEAD', 'HEAD^{tree}'], scratch).splitlines()
        if len(identity) != 2 or not all(re.fullmatch(r'[a-f0-9]{40}', value) for value in identity):
            raise SecurityDataError('exact commit and tree identity required')
        clean = not _git(project, ['status', '--porcelain=v1', '--untracked-files=all'], scratch)
        repository = _repository_identity(_git(project, ['remote', 'get-url', 'origin'], scratch))
        values.append((identity, clean, repository))
    return {'head_sha': values[0][0][0], 'tree_sha': values[0][0][1],
            'checker_sha': values[1][0][0], 'checker_tree_sha': values[1][0][1],
            'candidate_clean': values[0][1], 'checker_clean': values[1][1],
            'same_project': bool(values[0][2] and values[1][2] and values[0][2].lower() == values[1][2].lower())}


def _digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None



_PREPARATION_SEAL = object()
_PREPARATION_STAGES = frozenset(('setup', 'source-binding', 'profile-declaration', 'profile-validation',
    'tool-provision', 'feeds', 'package-artifacts', 'image-artifacts', 'image-database',
    'obligations', 'licenses', 'final-binding', 'prepare-inputs', 'prepare-result', 'package-target',
    'factory-target','factory-acquisition','factory-output','license-run-scope','action-source','release-tool-source',
    'checker-tool-source'))
_PREPARATION_KINDS = frozenset(('artifact', 'security-data', 'oci', 'inventory', 'os',
    'key', 'type', 'value', 'runtime', 'other'))
_PREPARATION_CODES = frozenset(('artifact-acquisition', 'artifact-origin', 'artifact-size',
    'artifact-identity', 'artifact-hash', 'artifact-inventory-binding', 'artifact-manifest',
    'artifact-path', 'artifact-platform', 'artifact-publication-uncertain', 'artifact-stale',
    'artifact-target-unknown', 'artifact-fetch', 'artifact-fetch-timeout', 'artifact-factory-input',
    'artifact-factory-output', 'artifact-factory-source-output','license-run-scope-unavailable',
    'artifact-action-data','artifact-action-link','artifact-action-metadata','artifact-action-origin',
    'artifact-action-selector','artifact-action-source-count','artifact-action-source-provider','artifact-action-stale','artifact-action-transport',
    'artifact-npm-integrity','artifact-npm-metadata','artifact-npm-origin','artifact-npm-stale','artifact-npm-budget',
    'artifact-npm-cache','artifact-npm-transport','artifact-archive','artifact-family-preparation','artifact-context',
    'license-conflict','license-metadata-missing','license-text-review','license-obligation-missing','license-transitive-coverage','other'))


def _preparation_detail(value):
    """Closed refusal observations only; never authority, exception text or paths."""
    if (type(value) is not dict or set(value) != {'stage', 'error_kind', 'error_code', 'errno'}
            or type(value['stage']) is not str or value['stage'] not in _PREPARATION_STAGES
            or type(value['error_kind']) is not str or value['error_kind'] not in _PREPARATION_KINDS
            or value['error_code'] is not None and (type(value['error_code']) is not str
                or value['error_code'] not in _PREPARATION_CODES)
            or value['error_kind'] != 'artifact' and value['error_code'] is not None
            or value['errno'] is not None and (type(value['errno']) is not int or not 0 <= value['errno'] <= 4095)):
        return {}
    return dict(value)


def _preparation_fault(error):
    value = getattr(error, '_getzilla_preparation', None)
    if type(value) is not tuple or len(value) != 2 or value[0] is not _PREPARATION_SEAL:
        return {}
    return _preparation_detail(value[1])


@contextmanager
def _preparation_step(stage):
    if type(stage) is not str or stage not in _PREPARATION_STAGES:
        raise ValueError('unknown fixed preparation step')
    try:
        yield
    except Exception as error:
        if not _preparation_fault(error):
            from .security_oci import OCIError
            kind = {ArtifactError: 'artifact', SecurityDataError: 'security-data', OCIError: 'oci',
                VulnerabilityError: 'inventory', KeyError: 'key', TypeError: 'type', ValueError: 'value',
                RuntimeError: 'runtime'}.get(type(error), 'os' if isinstance(error, OSError) else 'other')
            code = (error.code if type(error) is ArtifactError and type(error.code) is str
                    and error.code in _PREPARATION_CODES else 'other')
            number = getattr(error, 'errno', None)
            error._getzilla_preparation = (_PREPARATION_SEAL, dict(stage=stage, error_kind=kind,
                error_code=code if kind == 'artifact' else None,
                errno=number if type(number) is int and 0 <= number <= 4095 else None))
        raise
