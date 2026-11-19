"""Held live evidence consumption and exact parser observation ownership."""
from __future__ import annotations
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import time
import tomllib
from . import fsx, factory_tests, live_contracts
from .python_test_runner import execute, cleanup_details
from .verification_policy_source import _producer_digest as _producer_digest

OUTPUT_LIMIT = 2 * 1024 * 1024


CELLS = {'factory': ('factory-postgres-exit',),
         'trust-ci': ('trust-ci-postgres', 'trust-ci-postgres-restart'),
         'lifecycle': ('factory-lifecycle',)}


_BINDING_KEYS = {'head', 'tree', 'run_id', 'attempt', 'cell', 'namespace', 'nonce', 'producer_sha256'}


_EVIDENCE_NAMES = frozenset({'invocation.json','observer.json','command.log','factory-resources.json',
    'factory-ack.json','factory-suite.json','factory-restart.json','trust-ci-resources.json','trust-ci-ack.json',
    'trust-ci-suite.json','trust-ci-restart.json','lifecycle.json','lifecycle-resource-index.json',
    'protected-resources.json','protected-ack.json','protected-evidence.txt'})


def evidence_name(name):
    return live_contracts.evidence_name(name)


def _pairs(rows):
    result = {}
    for key, value in rows:
        if key in result:
            raise ValueError('Duplicate live report field')
        result[key] = value
    return result


def _held_bytes(path, limit=OUTPUT_LIMIT):
    path = Path(path).absolute()
    with fsx.ReadOnlyBoundRoot(path.parent) as root:
        snapshot = root.read(path.name, limit=limit)
        if snapshot is None:
            raise FileNotFoundError(path)
        if fsx._file_identity(fsx.lstat_at(root.handle, path.name)) != snapshot.identity:
            raise ValueError('Live report changed during held read')
        root.check()
        return snapshot.content


def read_document(path):
    result = json.loads(_held_bytes(path), object_pairs_hook=_pairs)
    if not isinstance(result, dict):
        raise ValueError('Live report must be an object')
    return result


def valid_binding(binding):
    return (isinstance(binding, dict) and set(binding) == _BINDING_KEYS
            and all(isinstance(value, str) and 0 < len(value) <= 256 for value in binding.values())
            and all(re.fullmatch('[0-9a-f]{40}', binding[key]) for key in ('head', 'tree'))
            and re.fullmatch('[0-9a-f]{32}', binding['nonce']) is not None
            and re.fullmatch('[0-9a-f]{64}', binding['producer_sha256']) is not None
            and binding['cell'] in CELLS and re.fullmatch('gz-[a-z0-9-]{1,120}', binding['namespace']) is not None)


def _ids(value):
    return (isinstance(value, list) and len(value) <= 10000
            and all(isinstance(item, str) and 0 < len(item) <= 2048 for item in value)
            and len(set(value)) == len(value))


_PARSER_MODULE = 'factory.tests.test_landing_pdf_worker'


_PARSER_SOURCE = 'factory/tests/test_landing_pdf_worker.py'


_PARSER_ENV = {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}


_PARSER_PROBE = ("import json,importlib.metadata as m,importlib.util as u; "
                 "print(json.dumps({'pypdf_version':m.version('pypdf') if u.find_spec('pypdf') is not None else None}))")


_OBSERVATION_KEY = object()


class _ParserObservation:
    __slots__ = ('root','python','policy','data','proof')

    def __init__(self,root,python,policy,data,proof):
        self.root,self.python,self.policy,self.data,self.proof=root,python,policy,data,proof


def _parser_policy(root, required):
    raw = _held_bytes(root/_PARSER_SOURCE)
    metadata = _held_bytes(root/'factory/pyproject.toml')
    declarations = tomllib.loads(metadata.decode())['project']['dependencies']
    pins = [value.removeprefix('pypdf==') for value in declarations if value.startswith('pypdf==')]
    if len(pins) != 1 or type(required) is not bool:
        raise ValueError('Unknown parser capability profile')
    expected = {
        'PdfWorkerWithoutParser': "unittest.skipIf(CHILD_PYPDF_VERSION is not None, 'pypdf present; unavailable branch cannot run')",
        'PdfWorkerWithPinnedParser': "unittest.skipUnless(CHILD_PYPDF_VERSION is not None, 'requires pypdf installed for the child interpreter')"}
    found, identifiers = set(), []
    for node in ast.parse(raw).body:
        if isinstance(node,ast.ClassDef) and node.name in expected:
            if (node.name in found or len(node.decorator_list) != 1
                    or ast.dump(node.decorator_list[0],include_attributes=False) != ast.dump(ast.parse(expected[node.name],mode='eval').body,include_attributes=False)):
                raise ValueError('Parser applicability source decorators changed')
            found.add(node.name)
            identifiers.extend(_PARSER_MODULE+'.'+node.name+'.'+method.name for method in node.body
                               if isinstance(method,ast.FunctionDef) and method.name.startswith('test_'))
    if found != set(expected) or not identifiers:
        raise ValueError('Incomplete parser applicability source')
    policy = {'source_sha256':{_PARSER_SOURCE:hashlib.sha256(raw).hexdigest(),
                              'factory/pyproject.toml':hashlib.sha256(metadata).hexdigest()},
              'canonical_policy_sha256':hashlib.sha256(factory_tests.__loader__.get_data(factory_tests.__file__)).hexdigest(),
              'probe_sha256':hashlib.sha256(json.dumps([_PARSER_PROBE,_PARSER_ENV],sort_keys=True).encode()).hexdigest(),
              'eligible_ids':sorted(identifiers),'parser_pin':pins[0],'required_parser':required}
    policy['digest'] = hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()
    return policy


def _python_identity(python):
    def identity(info):
        return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    return {'named':identity(python.lstat()),'target':identity(python.stat())}


def observe_parser_applicability(root,binding,*,python,required=False):
    """Observe only the isolated dependency; never import the old PDF workload."""
    if not valid_binding(binding) or binding['cell'] != 'factory':
        raise ValueError('Parser observation invocation mismatch')
    root,python=Path(root).absolute(),Path(python).absolute()
    policy=_parser_policy(root,required)
    identity=_python_identity(python)
    native=execute([str(python),'-B','-I','-c',_PARSER_PROBE],Path('/'),dict(_PARSER_ENV),timeout=30)
    cleanup=cleanup_details(native)
    if (native.returncode or native.terminal_state != 'completed' or native.stderr
            or cleanup['facts'] or cleanup['overflow'] or cleanup['unavailable']):
        raise ValueError('Parser capability observation unavailable')
    observed=json.loads(native.stdout,object_pairs_hook=_pairs)
    if not isinstance(observed,dict) or set(observed) != {'pypdf_version'}:
        raise ValueError('Parser capability observation did not return a fact')
    value=observed['pypdf_version']
    if value not in (None,policy['parser_pin']) or required and value is None:
        raise ValueError('Parser version/profile requirement not met')
    if _python_identity(python) != identity or _parser_policy(root,required) != policy:
        raise ValueError('Parser observation source or interpreter changed')
    data={'binding':dict(binding),'python':str(python),'python_identity':identity,
          'policy_digest':policy['digest'],'pypdf_version':value,'observed_ns':time.time_ns()}
    return _ParserObservation(root,python,policy,data,_OBSERVATION_KEY)


def _measured(observation,binding):
    return (type(observation) is _ParserObservation and observation.proof is _OBSERVATION_KEY
            and observation.data['binding'] == binding)


def _parser_allowances(observation,expected):
    context={'unit_database_bindings':'live_required','host_supported':True,'procfs_descriptor_reopen':True,
             'jsonschema_cli':'required','pypdf_version':observation.data['pypdf_version']}
    if not set(observation.policy['eligible_ids']) <= set(expected):
        raise ValueError('Parser source cases are missing from complete discovery')
    result={}
    for identifier in observation.policy['eligible_ids']:
        allowance=factory_tests.skip_allowance(identifier,context)
        if allowance is not None:
            rule,reason=allowance
            if rule not in {'parser-present','parser-absent'}:
                raise ValueError('Unsupported live applicability rule')
            result[identifier]={'rule':rule,'reason':reason}
    return result


def retained_parser_contract(root):
    """Derive supported retained applicability from current canonical source rules.

    This reads no old environment and makes no new capability measurement.
    The required hosted cell uses the existing optional parser profile.
    """
    policy = _parser_policy(root, False)
    variants = {}
    for version in (None, policy['parser_pin']):
        context = {'unit_database_bindings': 'live_required', 'host_supported': True,
                   'procfs_descriptor_reopen': True, 'jsonschema_cli': 'required',
                   'pypdf_version': version}
        allowances = {}
        for identifier in policy['eligible_ids']:
            rule = factory_tests.skip_allowance(identifier, context)
            if rule is not None:
                if rule[0] not in {'parser-present', 'parser-absent'}:
                    raise ValueError('Unsupported retained parser rule')
                allowances[identifier] = {'rule': rule[0], 'reason': rule[1]}
        variants['absent' if version is None else 'pinned'] = allowances
    return {'policy': policy, 'allowances_by_version': variants}


def _validated_applicability(document,binding,observation):
    value=document['applicability']
    if value is None:
        if any(identifier.startswith(_PARSER_MODULE+'.') for identifier in document['expected_ids']):
            raise ValueError('Source parser cases require measured applicability')
        return {}
    if not _measured(observation,binding) or set(value) != {'policy','observations','module_fact'}:
        raise ValueError('Live applicability requires fresh observed facts, not caller JSON')
    if value['policy'] != observation.policy or _parser_policy(observation.root,observation.policy['required_parser']) != observation.policy:
        raise ValueError('Live parser source/policy binding changed')
    rows=value['observations']
    if not isinstance(rows,list) or len(rows) != 3:
        raise ValueError('Missing before/discovery/after parser observations')
    times=[]
    for row in rows:
        if set(row) != set(observation.data) or any(row[key] != observation.data[key] for key in row if key != 'observed_ns'):
            raise ValueError('Conflicting parser invocation/interpreter/facts')
        stamp=row['observed_ns']
        if type(stamp) is not int or not 0 <= observation.data['observed_ns']-stamp <= 1800*1_000_000_000:
            raise ValueError('Stale/future parser observation')
        times.append(stamp)
    expected_fact={'module':_PARSER_MODULE,'path':str(observation.root/_PARSER_SOURCE),
                   'pypdf_version':observation.data['pypdf_version'],'observed':True}
    if times != sorted(times) or value['module_fact'] != {'discovery':expected_fact,'after':expected_fact}:
        raise ValueError('Parser module fact was not returned or disagrees')
    return _parser_allowances(observation,document['expected_ids'])


def accepted_suite(document, binding, *, parser_observation=None):
    try:
        if not valid_binding(binding) or document['schema'] != 'getzilla-live-suite-v1' or document['binding'] != binding:
            return False
        fields = ('expected_ids', 'collected_ids', 'required_ids', 'started', 'executed', 'missing_required','inapplicable_ids')
        if not all(_ids(document[key]) for key in fields):
            return False
        if any(type(document[key]) is not int or not 0 <= document[key] <= 10000
               for key in ('tests_run', 'failures', 'errors', 'loader_errors')):
            return False
        skipped = document['skipped']
        if not isinstance(skipped, list) or not all(isinstance(row, dict) and set(row) == {'id', 'reason','applicability'} for row in skipped):
            return False
        skipped_ids = [row['id'] for row in skipped]
        if not _ids(skipped_ids) or not set(skipped_ids) <= set(document['started']):
            return False
        allowances=_validated_applicability(document,binding,parser_observation)
        if document['allowed_skips'] != allowances or set(document['inapplicable_ids']) != set(allowances):
            return False
        if set(skipped_ids) != set(allowances) or any(allowances[row['id']] != {'rule':row['applicability'],'reason':row['reason']} for row in skipped):
            return False
        expected, collected, required, started, executed = (set(document[key]) for key in fields[:5])
        return bool(document['status'] == 'pass' and expected and expected == collected == started
                    and set(document['executed']) == started - set(skipped_ids)
                    and set(document['required_ids']) == expected - set(allowances)
                    and set(document['required_ids']) <= set(document['executed'])
                    and not document['missing_required'] and document['source_stable'] is True
                    and type(document['tests_run']) is int and document['tests_run'] == len(started)
                    and document['failures'] == document['errors'] == 0
                    and not document['loader_errors'] and not document['problems'] and document['requirements_complete'] is True)
    except (KeyError, TypeError, ValueError):
        return False


def restart_observation(before, after, seeded_job=None, verified_job=None):
    if (set(before) != {'postmaster', 'cluster'} or set(after) != {'postmaster', 'cluster'}
            or not isinstance(before['cluster'], str) or not before['cluster'].isdigit()
            or before['cluster'] != after['cluster'] or seeded_job != verified_job):
        raise ValueError('Restart cluster or job identity mismatch')
    first, second = datetime.fromisoformat(before['postmaster']), datetime.fromisoformat(after['postmaster'])
    if first.tzinfo is None or second.tzinfo is None or first >= second:
        raise ValueError('Restart did not change the postmaster')
    return {'before': before['postmaster'], 'after': after['postmaster'], 'cluster': before['cluster'],
            'synthetic_job_id': verified_job}


def read_component(output, report_name, binding):
    envelope = read_document(output/(report_name + '.envelope.json'))
    if set(envelope) != {'schema', 'binding', 'report', 'journal'} or envelope['schema'] != 'getzilla-live-envelope-v1' or envelope['binding'] != binding:
        raise ValueError('Component invocation mismatch')
    for key in ('report', 'journal'):
        item = envelope[key]
        if (set(item) != {'path', 'sha256'} or Path(item['path']).name != item['path']
                or hashlib.sha256(_held_bytes(output/item['path'])).hexdigest() != item['sha256']):
            raise ValueError('Component bytes changed or unbound')
    if envelope['report']['path'] != report_name:
        raise ValueError('Component report name mismatch')
    return read_document(output/report_name)


def validate_components(output, cell, binding, *, parser_observation=None):
    try:
        if not valid_binding(binding) or binding['cell'] != cell:
            return False
        if cell == 'lifecycle':
            from .live_lifecycle import cycles_accepted
            report = read_component(output, 'lifecycle.json', binding)
            index = read_document(output/'lifecycle-resource-index.json')
            journals = {path.name for path in output.glob('*-resources.json')}
            if index['binding'] != binding or set(index['journals']) != journals or len(journals) != 101:
                return False
            if index.get('cleanup_ledger_sha256') != hashlib.sha256(_held_bytes(output/'lifecycle-cleanup-ledger.json')).hexdigest():
                return False
            for name, digest in index['journals'].items():
                if hashlib.sha256(_held_bytes(output/name)).hexdigest() != digest:
                    return False
                journal = read_document(output/name)
                _cleanup_ack(output, type('RetainedOwner', (), dict(manifest=output/name, namespace=journal['namespace'], nonce=journal['nonce']))(), binding['namespace'])
            return (report['binding'] == binding and report['status'] == 'pass' and cycles_accepted(report['cycles'])
                    and report['resources_before'] == report['resources_after'])
        suite = read_component(output, cell+'-suite.json', binding)
        restart = read_component(output, cell+'-restart.json', binding)
        if not accepted_suite(suite, binding,parser_observation=parser_observation) or not suite.get('source_inventory'):
            return False
        if cell == 'factory' and not (any('FreshClusterArtifactAttestorMigrationTests.' in name for name in suite['executed'])
                and any('test_postgres_integration.' in name for name in suite['executed'])):
            return False
        if restart['schema'] != 'getzilla-live-restart-v1' or restart['binding'] != binding or restart['status'] != 'pass':
            return False
        if len(restart['restarts']) != (2 if cell == 'factory' else 1):
            return False
        for row in restart['restarts']:
            restart_observation({'postmaster':row['before'],'cluster':row['cluster']},
                                {'postmaster':row['after'],'cluster':row['cluster']}, row['synthetic_job_id'],row['synthetic_job_id'])
            if cell == 'trust-ci' and not row['synthetic_job_id']:
                return False
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _cleanup_ack(output, owner, namespace):
    path = owner.manifest.with_name(owner.manifest.name.replace('-resources.json', '-ack.json'))
    if path.exists():
        return read_document(path)
    binding = read_document(output / 'invocation.json')
    if not valid_binding(binding) or binding['namespace'] != namespace:
        raise ValueError('Cleanup ledger original invocation is unavailable')
    return live_contracts.ledger_ack(read_document(output / 'lifecycle-cleanup-ledger.json'), binding,
                                    path.name, {'namespace': owner.namespace, 'nonce': owner.nonce})

