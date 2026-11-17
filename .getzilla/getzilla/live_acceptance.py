"""Bounded candidate live observations. These reports are not attestations."""
from __future__ import annotations

from datetime import datetime
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import unittest
import time
import secrets
import sys
import uuid
import tomllib
import tempfile
import stat
import ctypes

from .factory_tests import RecordedResult, cases, test_id
from .python_test_runner import execute, cleanup_details, RunCancelled
from . import fsx
from . import factory_tests

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
    plain = name.removesuffix('.envelope.json')
    return plain in _EVIDENCE_NAMES or re.fullmatch(r'gz-[a-z0-9-]+-(resources|sample|ack)\.json',plain) is not None


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


def _write(path, value):
    content = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    _publish(path, content)


def _publish(path, content):
    if len(content) > OUTPUT_LIMIT:
        raise ValueError('Live report exceeds bound')
    path = Path(path)
    with fsx.ReadOnlyBoundRoot(path.parent) as root:
        fd = fsx.open_at(root.handle, path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsx.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            if fsx._file_identity(os.fstat(stream.fileno())) != fsx._file_identity(fsx.lstat_at(root.handle, path.name)):
                raise ValueError('Live output replaced during write')
        root.check()
        fsx.fsync_dir(root.handle)


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


def _parser_module_fact(observation):
    returned=sys.modules.get(_PARSER_MODULE)
    value=getattr(returned,'CHILD_PYPDF_VERSION',None)
    path=str(getattr(returned,'__file__',''))
    observed=(returned is not None and hasattr(returned,'CHILD_PYPDF_VERSION')
              and value in (None,observation.policy['parser_pin'])
              and path==str(observation.root/_PARSER_SOURCE))
    return {'module':_PARSER_MODULE,'path':path if observed else 'unavailable',
            'pypdf_version':value if observed else 'unavailable','observed':observed}


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


def record_suite(suite, *, expected_ids, required_ids, loader_errors, binding, source_stable,
                 stream, source_root=None, source_paths=(), allowed_skips=None,parser_observation=None):
    """Execute the actual suite without clearing database environment bindings."""
    if not valid_binding(binding):
        raise ValueError('Invalid live invocation binding')
    collected = [test_id(case) for case in cases(suite)]
    applicability=None
    allowances={}
    current=None
    if parser_observation is not None:
        if not _measured(parser_observation,binding):
            raise ValueError('Unobserved parser applicability input')
        current=observe_parser_applicability(parser_observation.root,binding,python=parser_observation.python,
                                            required=parser_observation.policy['required_parser'])
        fact=_parser_module_fact(current)
        if not fact['observed'] or fact['pypdf_version'] != current.data['pypdf_version']:
            raise ValueError('Parser module did not return a matching fact')
        applicability={'policy':parser_observation.policy,'observations':[parser_observation.data,current.data],
                       'module_fact':{'discovery':fact}}
        allowances=_parser_allowances(current,expected_ids)
    def recorder(*args, **kwargs):
        return RecordedResult(*args, source_root=source_root, source_paths=source_paths, **kwargs)
    result = unittest.TextTestRunner(stream=stream, verbosity=0, resultclass=recorder).run(suite)
    if current is not None:
        current=observe_parser_applicability(current.root,binding,python=current.python,required=current.policy['required_parser'])
        applicability['observations'].append(current.data)
        applicability['module_fact']['after']=_parser_module_fact(current)
    document = {'schema': 'getzilla-live-suite-v1', 'binding': dict(binding), 'status': 'pass',
                'expected_ids': list(expected_ids), 'collected_ids': collected,
                'required_ids': sorted(set(expected_ids)-set(allowances)), 'started': result.started, 'executed': result.executed,
                'requirements_complete':set(required_ids)==set(expected_ids) and not allowed_skips,
                'applicability':applicability,'inapplicable_ids':sorted(allowances),
                'tests_run': result.testsRun, 'failures': len(result.failures) + len(result.expectedFailures) + len(result.unexpectedSuccesses),
                'errors': len(result.errors), 'loader_errors': len(loader_errors),
                'source_stable': source_stable(), 'allowed_skips': allowances,
                'skipped': [{'id':test_id(case),'reason':reason if allowances.get(test_id(case),{}).get('reason')==reason else 'unqualified-skip',
                             'applicability':allowances.get(test_id(case),{}).get('rule') if allowances.get(test_id(case),{}).get('reason')==reason else None} for case,reason in result.skipped],
                'missing_required': sorted(set(expected_ids)-set(allowances)-set(result.executed)), 'problems': result.problems}
    if not accepted_suite(document, binding,parser_observation=current):
        document['status'] = 'fail'
    return document


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


def seal_component(output, report_name, journal_name, binding):
    if not valid_binding(binding) or Path(report_name).name != report_name or Path(journal_name).name != journal_name:
        raise ValueError('Invalid component binding')
    document = {'schema': 'getzilla-live-envelope-v1', 'binding': binding,
                'report': {'path': report_name, 'sha256': hashlib.sha256(_held_bytes(output/report_name)).hexdigest()},
                'journal': {'path': journal_name, 'sha256': hashlib.sha256(_held_bytes(output/journal_name)).hexdigest()}}
    _write(output/(report_name + '.envelope.json'), document)


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


def acknowledge_cleanup(owner):
    if owner.cleanup_status != 'removed' or any(row['status'] != 'removed' for row in owner.resources):
        raise ValueError('Native resource cleanup is not confirmed')
    _write(owner.manifest.with_name(owner.manifest.name.replace('-resources.json', '-ack.json')),
           {'cleanup': 'removed', 'namespace': owner.namespace, 'nonce': owner.nonce})


def observe(command, *, root, environment, output, timeout, namespace=None, require_resources=False):
    """Native execution owns the child group; this outer observer survives its stop."""
    from .disposable_resources import OwnedDocker
    output = Path(output)
    if not 0 < timeout <= 1800:
        raise ValueError('Unbounded live deadline')
    started = time.monotonic()
    result = {'primary_outcome': 'unknown', 'cleanup_outcome': 'unknown', 'status': 'fail',
              'child_exit_confirmed': False, 'child_returncode': None}
    native = None
    try:
        try:
            native = execute(command, root, environment, timeout=timeout)
        except RunCancelled as cancelled:
            native = cancelled.result
            result['primary_outcome'] = 'cancelled'
        if native is None:
            raise ValueError('Missing typed child result')
        typed = cleanup_details(native)
        process_clean = not (typed['facts'] or typed['overflow'] or typed['unavailable'])
        result['process_cleanup'] = typed
        result['child_exit_confirmed'] = process_clean
        result['child_returncode'] = native.returncode
        if result['primary_outcome'] != 'cancelled':
            result['primary_outcome'] = ('timed_out' if native.terminal_state == 'timeout' else
                                         'cancelled' if native.terminal_state == 'cancelled' else
                                         'passed' if native.returncode == 0 else 'failed')
        raw = (native.stdout + native.stderr).encode('utf-8')[:OUTPUT_LIMIT]
        result['raw_log_sha256'] = hashlib.sha256(raw).hexdigest()
        result['log_digest_scope'] = 'Retained native decoded capture encoded as UTF-8 before redaction; original undecoded stream unavailable'
        log = raw.decode('utf-8', errors='backslashreplace')
        log = re.sub(r"(postgres(?:ql)?://[^\s'\"/@:]+:)[^\s'\"/@]+@", r'\1[redacted]@', log)
        log = re.sub(r"(?i)(password\s*=\s*)(?:'[^']*'|\"[^\"]*\"|[^\s'\";]+)", r'\1[redacted]', log)
        _publish(output/'command.log', log.encode('utf-8'))
        journals = sorted(output.glob('*-resources.json'))
        statuses = []
        if process_clean:
            deadline = time.monotonic() + 60
            for path in journals:
                try:
                    owner = OwnedDocker.recover(path)
                    if namespace is None or not (owner.namespace == namespace or owner.namespace.startswith(namespace+'-')):
                        raise ValueError('Foreign resource journal')
                    ack = read_document(path.with_name(path.name.replace('-resources.json', '-ack.json')))
                    required_ack = {'cleanup': 'removed', 'namespace': owner.namespace, 'nonce': owner.nonce}
                    if (any(ack.get(key) != value for key, value in required_ack.items())
                            or set(ack) - set(required_ack) not in (set(), {'allocator_pid', 'primary_exit', 'primary_error'})):
                        raise ValueError('Missing bound native cleanup acknowledgement')
                    native_clean = owner.cleanup_status == 'removed'
                    owner.cleanup(deadline=deadline)
                    statuses.append('confirmed' if native_clean else 'rescued')
                except Exception:
                    statuses.append('unknown')
        result['cleanup_outcome'] = ('unknown' if not process_clean or require_resources and not journals or 'unknown' in statuses else
                                     'rescued' if 'rescued' in statuses else 'confirmed' if statuses else 'not_applicable')
        result['status'] = 'pass' if result['primary_outcome'] == 'passed' and process_clean and result['cleanup_outcome'] in {'confirmed', 'not_applicable'} else 'fail'
    except Exception as error:
        result['observer_error'] = type(error).__name__
    finally:
        result['seconds'] = round(time.monotonic()-started, 3)
        _write(output/'observer.json', result)
    return result


def owned_postgres_endpoint(journal, *, container_id, container_name, nonce, namespace, network_id, pin):
    """Compare live inspections to original journal births before and after endpoint read."""
    from . import disposable_resources as resources
    snapshot = resources._read(Path(journal), private=True)
    data = json.loads(snapshot.content, object_pairs_hook=_pairs)
    if (set(data) != {'schema', 'namespace', 'nonce', 'resources', 'cleanup_status', 'owner_process'}
            or data['schema'] != 'getzilla-disposable-owner-v1'
            or data['namespace'] != namespace or data['nonce'] != nonce):
        raise ValueError('Owned PostgreSQL journal identity mismatch')
    owner = resources.OwnedDocker.__new__(resources.OwnedDocker)
    for field in ('namespace', 'nonce', 'resources', 'cleanup_status', 'owner_process'):
        setattr(owner, field, data[field])
    owner._validate()
    selected = []
    for kind, identifier in (('container', container_id), ('network', network_id)):
        key = 'id' if kind == 'container' else 'Id'
        matches = [row for row in data['resources'] if row['kind'] == kind and row.get('identity', {}).get(key) == identifier]
        if len(matches) != 1 or matches[0]['status'] != 'bound':
            raise ValueError('PostgreSQL original birth is absent')
        selected.append(matches[0])
    def check_births():
        for row in selected:
            identifier = row['identity']['id' if row['kind'] == 'container' else 'Id']
            actual = resources._identity(row['kind'], resources._inspect(row['kind'], identifier))
            if actual != row['identity']:
                raise ValueError('PostgreSQL original resource birth changed')
    check_births()
    endpoint = resources.internal_postgres_endpoint(container_id=container_id, container_name=container_name,
        nonce=nonce, namespace=namespace, network_id=network_id, image=pin['reference'], image_id=pin['image_id'])
    check_births()
    if resources._read(Path(journal), private=True).identity != snapshot.identity:
        raise ValueError('PostgreSQL ownership journal changed during observation')
    return endpoint


class _CommandFailed(RuntimeError):
    def __init__(self, code):
        super().__init__('Bounded live command failed')
        self.returncode = code


def _run(command, *, root=None, environment=None, timeout=60):
    native = execute(list(command), Path.cwd() if root is None else root,
                     dict(os.environ) if environment is None else environment, timeout=timeout)
    facts = cleanup_details(native)
    if (native.terminal_state != 'completed' or facts['facts'] or facts['overflow'] or facts['unavailable']):
        raise RuntimeError('Bounded live command failed or cleanup is unknown')
    if native.returncode:
        raise _CommandFailed(native.returncode)
    return native.stdout.strip()


def _producer_digest(root, cell):
    from . import disposable_resources, factory_tests, python_test_runner, live_lifecycle
    hashes = {}
    for module in (sys.modules[__name__], disposable_resources, factory_tests, python_test_runner, live_lifecycle):
        hashes[module.__name__] = hashlib.sha256(module.__loader__.get_data(module.__file__)).hexdigest()
    files = {'factory': ('factory/tests/run_live_suite.py', 'factory/tests/run_disposable_exit.py',
                         'factory/tests/postgres_restart_probe.py', 'factory/tests/test_postgres_integration.py',
                         'factory/tests/test_execution_persistence_postgres.py'),
             'trust-ci': ('trust-ci/tests/run_postgres_suite.py', 'trust-ci/tests/postgres_restart_probe.py'),
             'lifecycle': ('scripts/getzilla_live_lifecycle.py',)}[cell]
    for name in files:
        hashes[name] = hashlib.sha256(_held_bytes(root/name)).hexdigest()
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()


def _trust_ci(root, output, binding):
    """Use pre-acquired pinned images and an explicit offline wheelhouse only."""
    _require_trust_producer(root)
    from .disposable_resources import OwnedDocker, image_pins
    wheelhouse = Path(os.environ['GETZILLA_LIVE_WHEELHOUSE']).absolute()
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise ValueError('An explicit offline wheelhouse is required')
    pins = image_pins(root)
    owner = OwnedDocker(output/'trust-ci-resources.json', binding['namespace'])
    primary = None
    try:
        network = owner.network('db-network')
        deps = owner.volume('dependencies')
        provision = owner.container('provision', pins['python']['reference'], volume=deps, volume_target='/deps',
            network=network, bind={root/'trust-ci': '/src', wheelhouse: '/wheelhouse'},
            command=('python3', '-m', 'pip', 'install', '--no-index', '--find-links', '/wheelhouse',
                     '--disable-pip-version-check', '--no-cache-dir', '--require-hashes', '--target', '/deps',
                     '-r', '/src/requirements-test.txt'))
        def wait_container(item):
            deadline = time.monotonic()+300
            while time.monotonic() < deadline:
                state = json.loads(_run(['docker','container','inspect','--format','{{json .State}}',item['id']]))
                if not state['Running']:
                    if state['ExitCode'] != 0:
                        raise RuntimeError('Offline dependency provisioning failed')
                    return
                time.sleep(.25)
            raise TimeoutError('Offline dependency provisioning deadline exceeded')
        wait_container(provision)
        data = owner.volume('data')
        passwords = {role: secrets.token_urlsafe(24) for role in ('admin','api','worker','migrator','backup')}
        postgres = owner.container('db', pins['postgres']['reference'], volume=data, network=network,
            bind={root/'trust-ci/postgres/init': '/docker-entrypoint-initdb.d'},
            environment={'POSTGRES_DB':'trust_ci_test','POSTGRES_USER':'trust_ci_admin_test',
                'POSTGRES_PASSWORD':passwords['admin'],'TRUST_CI_API_DB_PASSWORD':passwords['api'],
                'TRUST_CI_WORKER_DB_PASSWORD':passwords['worker'],'TRUST_CI_MIGRATOR_DB_PASSWORD':passwords['migrator'],
                'TRUST_CI_BACKUP_DB_PASSWORD':passwords['backup']})
        def endpoint():
            return owned_postgres_endpoint(owner.manifest, container_id=postgres['id'], container_name=postgres['name'],
                nonce=owner.nonce, namespace=owner.namespace, network_id=network['identity']['Id'], pin=pins['postgres'])
        def ready():
            deadline = time.monotonic()+60
            while time.monotonic() < deadline:
                endpoint()
                command = ['docker','exec',postgres['id'],'sh','-c',
                    'test "$(head -n1 "$PGDATA/postmaster.pid")" = 1 && pg_isready -U trust_ci_admin_test -d trust_ci_test']
                try:
                    _run(command, timeout=10)
                    return
                except _CommandFailed as error:
                    if error.returncode not in (1,2):
                        raise
                    time.sleep(.25)
            raise TimeoutError('Trust PostgreSQL final postmaster readiness deadline exceeded')
        ready()
        host, port = endpoint()
        environment = {'PYTHONPATH':'/deps:/repo/.getzilla:/repo/trust-ci/src:/repo/trust-ci/tests:/repo/trust-ci',
            'PYTHONDONTWRITEBYTECODE':'1','GETZILLA_LIVE_BINDING':'/artifacts/invocation.json',
            'GETZILLA_LIVE_ARTIFACTS':'/tmp'}  # nosec B108: private test-container path, not a host temporary file
        for label, role in (('', 'migrator'), ('API_','api'), ('WORKER_','worker'), ('BACKUP_','backup')):
            environment['TRUST_CI_TEST_'+label+'DATABASE_URL'] = f'postgresql://trust_ci_{role}:{passwords[role]}@{host}:{port}/trust_ci_test'
        tester = owner.container('tests', pins['python']['reference'], volume=deps, volume_target='/deps', network=network,
            bind={root/'.getzilla':'/repo/.getzilla', root/'trust-ci':'/repo/trust-ci', output:'/artifacts'},
            working_directory='/repo/trust-ci', environment=environment, command=('sleep','1200'))
        for item, key in ((postgres,'postgres'),(tester,'python'),(provision,'python')):
            if item['image_id'] != pins[key]['image_id']:
                raise ValueError('Trust image configuration identity mismatch')
        endpoint()
        suite = json.loads(_run(['docker','exec',tester['id'],'python3','tests/run_postgres_suite.py','--stdout'], timeout=600), object_pairs_hook=_pairs)
        if not accepted_suite(suite, binding):
            raise ValueError('Trust suite did not complete all required cases')
        _write(output/'trust-ci-suite.json', suite)
        def observation():
            endpoint()
            value = _run(['docker','exec',postgres['id'],'psql','-U','trust_ci_admin_test','-d','trust_ci_test','-Atc',
                          'SELECT pg_postmaster_start_time(),system_identifier FROM pg_control_system()'])
            start, cluster = value.split('|')
            return {'postmaster':start, 'cluster':cluster}
        before = observation()
        seeded = _run(['docker','exec',tester['id'],'python3','-m','tests.postgres_restart_probe','seed'])
        endpoint()
        _run(['docker','restart',postgres['id']], timeout=45)
        endpoint()  # Recheck the original birth and endpoint before waiting.
        ready()
        after = observation()
        verified = _run(['docker','exec',tester['id'],'python3','-m','tests.postgres_restart_probe','verify'])
        if not seeded or not verified:
            raise ValueError('Trust restart test job observation is absent')
        row = restart_observation(before, after, seeded, verified)
        _write(output/'trust-ci-restart.json', {'schema':'getzilla-live-restart-v1','binding':binding,
            'status':'pass','restarts':[row], 'scope':'Synthetic persistence job; no deployment or external attestation'})
    except BaseException as error:
        primary = error
    finally:
        try:
            owner.cleanup()
            acknowledge_cleanup(owner)
        except BaseException as error:
            if primary is None:
                primary = error
            else:
                BaseException.add_note(primary, 'Trust resource cleanup unconfirmed: '+type(error).__name__)
    if primary is not None:
        raise primary
    for name in ('trust-ci-suite.json', 'trust-ci-restart.json'):
        seal_component(output, name, 'trust-ci-resources.json', binding)


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
            for name, digest in index['journals'].items():
                if hashlib.sha256(_held_bytes(output/name)).hexdigest() != digest:
                    return False
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


def _require_trust_producer(root):
    producer = Path(root)/'trust-ci/tests/run_postgres_suite.py'
    if producer.is_symlink() or not producer.is_file():
        raise ValueError('Trust CI source producer is unavailable; delivery and real acceptance remain OPEN')


def _directory_birth(info):
    return (info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode))


def _empty_factory_directory(descriptor):
    """Traverse the retained original object, without resolving its public name."""
    for name in os.listdir(descriptor):
        before=fsx.lstat_at(descriptor,name)
        if stat.S_ISDIR(before.st_mode) and not fsx.is_link(before):
            child=fsx.open_dir_at(descriptor,name,flags=fsx.O_CLOEXEC)
            try:
                if _directory_birth(before)!=_directory_birth(fsx.fstat_dir(child)):
                    raise ValueError('Factory cleanup child changed')
                _empty_factory_directory(child)
                if _directory_birth(fsx.lstat_at(descriptor,name))!=_directory_birth(before):
                    raise ValueError('Factory cleanup child binding changed')
                fsx.rmdir_at(descriptor,name)
                if fsx.fstat_dir(child).st_nlink!=0:
                    raise ValueError('Factory cleanup child unlink unconfirmed')
            finally:
                fsx.close_dir(child)
        else:
            fsx.unlink_at(descriptor,name)


def _remove_factory_environment(owned):
    """Capture into a fresh private anchor before any destructive traversal.

    The anchor is controller-owned and created only after confirmed child exit.
    Failed captures remain intact at the recorded relative recovery name. Never
    search for the original or recurse through a replacement/public pathname.
    Path-only platforms cannot supply this proof and must refuse cleanup.
    """
    if not isinstance(owned.directory.handle,int) or not fsx.O_NOFOLLOW:
        raise ValueError('Descriptor-bound Factory cleanup unavailable')
    rename=fsx.libc_renameat2()
    parent=owned.parent.handle
    anchor_name='factory-cleanup-'+secrets.token_hex(16)
    owned.outcome['recovery_anchor']=anchor_name
    fsx.mkdir_at(parent,anchor_name,mode=0o700)
    anchor_birth=_directory_birth(fsx.lstat_at(parent,anchor_name))
    anchor=fsx.open_dir_at(parent,anchor_name,flags=fsx.O_CLOEXEC)
    captured=None
    try:
        if _directory_birth(fsx.fstat_dir(anchor))!=anchor_birth:
            raise ValueError('Factory cleanup anchor changed')
        owned.outcome['anchor_birth']=list(anchor_birth)
        if rename(parent,os.fsencode(owned.path.name),anchor,b'environment',fsx.RENAME_NOREPLACE)!=0:
            raise OSError(ctypes.get_errno(),'Factory cleanup capture refused')
        captured=fsx.open_dir_at(anchor,'environment',flags=fsx.O_CLOEXEC)
        owned.outcome['captured_birth']=list(_directory_birth(fsx.fstat_dir(captured)))
        if owned.outcome['captured_birth']!=list(owned.birth):
            raise ValueError('Factory cleanup captured a replacement')
        if _directory_birth(fsx.lstat_at(anchor,'environment'))!=owned.birth:
            raise ValueError('Factory cleanup capture binding changed')
        try:
            fsx.lstat_at(parent,owned.path.name)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Factory environment name replaced')
        _empty_factory_directory(owned.directory.handle)
        if _directory_birth(fsx.lstat_at(anchor,'environment'))!=owned.birth:
            raise ValueError('Factory cleanup unlink binding changed')
        fsx.rmdir_at(anchor,'environment')
        owned.outcome['original_unlinked']=fsx.fstat_dir(owned.directory.handle).st_nlink==0
        if not owned.outcome['original_unlinked']:
            raise ValueError('Factory original unlink unconfirmed')
        if _directory_birth(fsx.lstat_at(parent,anchor_name))!=anchor_birth:
            raise ValueError('Factory cleanup anchor binding changed')
        fsx.rmdir_at(parent,anchor_name)
        if fsx.fstat_dir(anchor).st_nlink!=0:
            raise ValueError('Factory cleanup anchor unlink unconfirmed')
    finally:
        fsx.close_dir(captured)
        fsx.close_dir(anchor)


class _FactoryEnvironment:
    """A controller-created directory; reports never select its path or cleanup."""
    def __init__(self,output):
        self.parent=fsx.ReadOnlyBoundRoot(output).__enter__()
        self.directory=None
        try:
            info=fsx.fstat_dir(self.parent.handle)
            if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
                raise ValueError('Factory environment requires private owned output')
            self.path=Path(tempfile.mkdtemp(prefix='factory-live-venv-',dir=output))
            self.parent.check()
            self.directory=fsx.ReadOnlyBoundRoot(self.path).__enter__()
            self.birth=_directory_birth(fsx.fstat_dir(self.directory.handle))
            self.python=self.path/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
            self.outcome=None
        except BaseException:
            self.parent.close()
            raise

    def cleanup(self,*,child_exit_confirmed):
        if self.outcome is not None:
            return self.outcome
        self.outcome={'status':'unknown','original_birth':list(self.birth)}
        try:
            if not child_exit_confirmed:
                return self.outcome
            self.parent.check()
            self.directory.check()
            _remove_factory_environment(self)
            try:
                fsx.lstat_at(self.parent.handle,self.path.name)
            except FileNotFoundError:
                if self.outcome.get('original_unlinked') is True:
                    self.outcome['status']='removed'
            self.parent.check()
        except BaseException as error:
            self.outcome.update(status='unknown',error=type(error).__name__)
        finally:
            self.directory.close()
            self.parent.close()
        return self.outcome


def _run_factory_cell(command,*,root,output,environment,binding,timeout,required_parser=False):
    if type(required_parser) is not bool:
        raise ValueError('Unknown controller parser profile')
    owned=_FactoryEnvironment(output)
    environment=dict(environment,UV_PROJECT_ENVIRONMENT=str(owned.path),
                     GETZILLA_LIVE_PARSER_REQUIRED='1' if required_parser else '0')
    result={'status':'fail','primary_outcome':'unknown','child_exit_confirmed':False}
    primary=None
    try:
        result=observe(command,root=root,environment=environment,output=output,timeout=timeout,
                       namespace=binding['namespace'],require_resources=True)
        if result['status']=='pass' and result['child_exit_confirmed']:
            owned.directory.check()
            measured=observe_parser_applicability(root,binding,python=owned.python,required=required_parser)
            if not validate_components(output,'factory',binding,parser_observation=measured):
                result.update(status='fail',component_evidence='missing_or_failed')
    except BaseException as error:
        primary=error
    finally:
        cleanup=owned.cleanup(child_exit_confirmed=result['child_exit_confirmed'])
        result['venv_cleanup_outcome']=cleanup['status']
        result['venv_cleanup_evidence']={key:value for key,value in cleanup.items() if key!='recovery_anchor'}
        if cleanup['status']!='removed':
            result['status']='fail'
            if 'error' in cleanup:
                result['venv_cleanup_error']=cleanup['error']
    if primary is not None:
        if cleanup['status']!='removed':
            BaseException.add_note(primary,'Factory controller environment cleanup unconfirmed')
        raise primary
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--cell', choices=CELLS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout-seconds', type=int, default=1500)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    root, output = args.root.absolute(), args.output.absolute()
    if args.cell == 'trust-ci':
        _require_trust_producer(root)
    if args.worker:
        binding = read_document(Path(os.environ['GETZILLA_LIVE_BINDING']))
        if not valid_binding(binding) or binding['cell'] != args.cell:
            raise ValueError('Live worker invocation mismatch')
        if args.cell == 'trust-ci':
            _trust_ci(root, output, binding)
        elif args.cell == 'lifecycle':
            from .live_lifecycle import run
            run(root, output, binding['namespace'], binding)
        else:
            raise ValueError('Factory uses its own live producer entrypoint')
        return 0
    if not 0 < args.timeout_seconds <= 1800:
        raise ValueError('Live deadline exceeds bound')
    head = _run(['git','rev-parse','HEAD'], root=root)
    tree = _run(['git','rev-parse','HEAD^{tree}'], root=root)
    if os.environ.get('GETZILLA_EXPECTED_HEAD', head) != head or _run(['git','status','--porcelain'], root=root):
        raise ValueError('Live observations require unchanged expected committed source')
    binding = {'head':head,'tree':tree,'run_id':os.environ.get('GITHUB_RUN_ID','local'),
        'attempt':os.environ.get('GITHUB_RUN_ATTEMPT','1'),'cell':args.cell,
        'namespace':'gz-'+args.cell+'-'+uuid.uuid4().hex[:12], 'nonce':uuid.uuid4().hex,
        'producer_sha256':_producer_digest(root,args.cell)}
    if not valid_binding(binding):
        raise ValueError('Invalid live invocation identity')
    output.mkdir(mode=0o700, exist_ok=False)
    _write(output/'invocation.json', binding)
    environment = dict(os.environ, GETZILLA_LIVE_NAMESPACE=binding['namespace'],
        GETZILLA_LIVE_BINDING=str(output/'invocation.json'), GETZILLA_LIVE_ARTIFACTS=str(output))
    command = ([sys.executable,str(root/'factory/tests/run_disposable_exit.py')] if args.cell == 'factory' else
        [sys.executable,str(root/'scripts/getzilla_live.py'),'--root',str(root),'--cell',args.cell,'--output',str(output),'--worker'])
    if args.cell=='factory':
        required=os.environ.get('GETZILLA_LIVE_PARSER_REQUIRED','0')
        if required not in ('0','1'):
            raise ValueError('Unknown declared parser profile')
        result=_run_factory_cell(command,root=root,environment=environment,output=output,
                                 timeout=args.timeout_seconds,binding=binding,required_parser=required=='1')
    else:
        result = observe(command,root=root,environment=environment,output=output,timeout=args.timeout_seconds,
                         namespace=binding['namespace'], require_resources=True)
        if not validate_components(output,args.cell,binding):
            result.update(status='fail',component_evidence='missing_or_failed')
    if (_run(['git','rev-parse','HEAD'],root=root) != head or _run(['git','rev-parse','HEAD^{tree}'],root=root) != tree
            or _run(['git','status','--porcelain'],root=root) or _producer_digest(root,args.cell) != binding['producer_sha256']):
        result.update(status='fail',source_mutation=True)
    report = {'schema':'getzilla-live-acceptance-v1','binding':binding,**result,
        'checks':[{'id':name,'status':result['status']} for name in CELLS[args.cell]],
        'authority':'Candidate source observations; no independent attestation or parent acceptance'}
    report['files'] = [{'path':path.name,'sha256':hashlib.sha256(_held_bytes(path)).hexdigest()}
                       for path in sorted(output.iterdir()) if evidence_name(path.name)]
    _write(output/'manifest.json', report)
    return 0 if result['status'] == 'pass' else 1
