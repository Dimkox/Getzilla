"""Bounded candidate live observations. These reports are not attestations."""
from __future__ import annotations

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
import tomllib as tomllib  # compatibility module export
import tempfile
import stat
import ctypes

from .factory_tests import RecordedResult, cases, test_id
from .python_test_runner import execute, cleanup_details, RunCancelled
from . import fsx
from . import factory_tests as factory_tests  # compatibility module export
from . import live_contracts
from .disposable_resources import image_pins, runtime_image_id

from .live_evidence import (  # noqa: F401 exact evidence/measurement compatibility exports
    CELLS, OUTPUT_LIMIT, _BINDING_KEYS, _EVIDENCE_NAMES, _OBSERVATION_KEY, _PARSER_ENV, _PARSER_MODULE, _PARSER_PROBE, _PARSER_SOURCE, _ParserObservation, _cleanup_ack, _held_bytes, _ids, _measured, _pairs, _parser_allowances, _parser_policy, _python_identity, _validated_applicability, accepted_suite, evidence_name, observe_parser_applicability, read_component, read_document, restart_observation, retained_parser_contract, valid_binding, validate_components, _producer_digest,
)

# Child execution and parent measurement must name the same owned alias.
FACTORY_PYTHON_RELATIVE = 'Scripts/python.exe' if os.name == 'nt' else 'bin/python3'










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


def _allocate_output(output):
    """Create one missing shared parent; keep the actual leaf exclusive.

    Held ancestor binding prevents following a substituted/symlinked parent.
    Existing operator parents must be owned and not group/other writable.
    This is allocation only, not workload or cleanup acceptance.
    """
    output = Path(output).absolute()
    try:
        parent = fsx.ReadOnlyBoundRoot(output.parent)
    except FileNotFoundError:
        with fsx.ReadOnlyBoundRoot(output.parent.parent) as ancestor:
            info = fsx.fstat_dir(ancestor.handle)
            if os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o022):
                raise ValueError('Live output ancestor must be owned and protected')
            try:
                fsx.mkdir_at(ancestor.handle, output.parent.name, 0o700)
            except FileExistsError:
                pass  # The held reader below validates any concurrent creation.
            ancestor.check()
        parent = fsx.ReadOnlyBoundRoot(output.parent)
    with parent:
        info = fsx.fstat_dir(parent.handle)
        if os.name != 'nt' and (info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError('Live output parent must be owned and protected')
        fsx.mkdir_at(parent.handle, output.name, 0o700)
        parent.check()






















def _parser_module_fact(observation):
    returned=sys.modules.get(_PARSER_MODULE)
    value=getattr(returned,'CHILD_PYPDF_VERSION',None)
    path=str(getattr(returned,'__file__',''))
    observed=(returned is not None and hasattr(returned,'CHILD_PYPDF_VERSION')
              and value in (None,observation.policy['parser_pin'])
              and path==str(observation.root/_PARSER_SOURCE))
    return {'module':_PARSER_MODULE,'path':path if observed else 'unavailable',
            'pypdf_version':value if observed else 'unavailable','observed':observed}






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




def seal_component(output, report_name, journal_name, binding):
    if not valid_binding(binding) or Path(report_name).name != report_name or Path(journal_name).name != journal_name:
        raise ValueError('Invalid component binding')
    document = {'schema': 'getzilla-live-envelope-v1', 'binding': binding,
                'report': {'path': report_name, 'sha256': hashlib.sha256(_held_bytes(output/report_name)).hexdigest()},
                'journal': {'path': journal_name, 'sha256': hashlib.sha256(_held_bytes(output/journal_name)).hexdigest()}}
    _write(output/(report_name + '.envelope.json'), document)




def acknowledge_cleanup(owner):
    if owner.cleanup_status != 'removed' or any(row['status'] != 'removed' for row in owner.resources):
        raise ValueError('Native resource cleanup is not confirmed')
    _write(owner.manifest.with_name(owner.manifest.name.replace('-resources.json', '-ack.json')),
           {'cleanup': 'removed', 'namespace': owner.namespace, 'nonce': owner.nonce})


def _observe_bound(command, *, root, environment, output, timeout, namespace=None, require_resources=False):
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
                    ack = _cleanup_ack(output, owner, namespace)
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
        nonce=nonce, namespace=namespace, network_id=network_id, image=pin['reference'], image_id=runtime_image_id(Path(__file__).resolve().parents[2], pin))
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




def _trust_ci(root, output, binding):
    """Use pre-acquired pinned images and an explicit offline wheelhouse only."""
    _require_trust_producer(root)
    wheelhouse = Path(os.environ['GETZILLA_LIVE_WHEELHOUSE']).absolute()
    if not wheelhouse.is_dir() or wheelhouse.is_symlink():
        raise ValueError('An explicit offline wheelhouse is required')
    expected_inventory, expected_ids = live_contracts.trust_source_contract(root)
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
            if item['image_id'] != runtime_image_id(root, pins[key]):
                raise ValueError('Trust image configuration identity mismatch')
        endpoint()
        suite = json.loads(_run(['docker','exec',tester['id'],'python3','tests/run_postgres_suite.py','--stdout'], timeout=600), object_pairs_hook=_pairs)
        if (not accepted_suite(suite, binding) or suite.get('source_inventory') != expected_inventory
                or set(suite['expected_ids']) != set(expected_ids)):
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
        primary = live_contracts.finish_owned(owner, primary, acknowledge_cleanup)
    if primary is not None:
        raise primary
    for name in ('trust-ci-suite.json', 'trust-ci-restart.json'):
        seal_component(output, name, 'trust-ci-resources.json', binding)




def _require_trust_producer(root):
    producer = Path(root)/'trust-ci/tests/run_postgres_suite.py'
    if producer.is_symlink() or not producer.is_file():
        raise ValueError('Trust CI complete source producer is unavailable; acceptance remains OPEN')
    tree = ast.parse(_held_bytes(producer))
    schemas = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == 'LIVE_SUITE_SCHEMA' for target in node.targets)
               and isinstance(node.value, ast.Constant)]
    if schemas != ['getzilla-live-suite-v1']:
        raise ValueError('Trust CI source producer does not declare the complete bound suite contract')
    selected = os.environ.get('GETZILLA_LIVE_WHEELHOUSE')
    if not selected:
        raise ValueError('GETZILLA_LIVE_WHEELHOUSE is required before any Trust allocation; prepare the hash-locked cp313/Linux inputs')
    live_contracts.validate_wheelhouse(Path(selected), Path(root)/'trust-ci/requirements-test.txt')


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
            self.python=self.path/FACTORY_PYTHON_RELATIVE
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
            else:
                _record_controller(output, 'factory', binding, parser_observation=measured)
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
    if os.environ.get('GITHUB_RUN_ID'):
        binding = live_contracts.ci_binding(head=head, tree=tree, run_id=os.environ['GITHUB_RUN_ID'],
            attempt=os.environ['GITHUB_RUN_ATTEMPT'], cell=args.cell, producer_sha256=binding['producer_sha256'])
    if not valid_binding(binding):
        raise ValueError('Invalid live invocation identity')
    _allocate_output(output)
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
        elif result['status'] == 'pass':
            _record_controller(output, args.cell, binding)
    if (_run(['git','rev-parse','HEAD'],root=root) != head or _run(['git','rev-parse','HEAD^{tree}'],root=root) != tree
            or _run(['git','status','--porcelain'],root=root) or _producer_digest(root,args.cell) != binding['producer_sha256']):
        result.update(status='fail',source_mutation=True)
    report = {'schema':'getzilla-live-acceptance-v1','binding':binding,**result,
        'checks':[{'id':name,'status':result['status']} for name in CELLS[args.cell]],
        'authority':'Candidate source observations; no independent attestation or parent acceptance'}
    report['files'] = live_contracts.evidence_inventory(output)
    _write(output/'manifest.json', report)
    return 0 if result['status'] == 'pass' else 1


import signal
import subprocess
from .disposable_resources import OwnedDocker, CleanupUnconfirmed

def _stop(process, grace):
    escalated = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(.05)
    # Descendants may survive a finished leader. Finish the entire owned group.
    try:
        os.killpg(process.pid, signal.SIGKILL)
        escalated = process.poll() is None
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    return escalated


def _observe_compat(command, *, root, environment, output, timeout, grace=75,
            namespace=None, require_resources=False):
    """Keep the observer outside its child's session and reserve bounded cleanup."""
    if os.name != "posix" or not 0 < timeout <= 1800 or not 0 < grace <= 180:
        raise ValueError("Live observer requires POSIX and bounded deadlines")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cancelled = []
    handlers = {}
    for number in (signal.SIGTERM, signal.SIGINT):
        handlers[number] = signal.signal(number, lambda n, _f: cancelled.append(n))
    result = {"primary_outcome": "unknown", "cleanup_outcome": "not_applicable",
              "child_exit_confirmed": False, "child_returncode": None, "escalated": False}
    started = time.monotonic()
    try:
        with (output / "command.log").open("xb") as log:
            process = subprocess.Popen(command, cwd=root, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while process.poll() is None:
                    if cancelled:
                        result["primary_outcome"] = "cancelled"
                        break
                    if time.monotonic() - started >= timeout:
                        result["primary_outcome"] = "timed_out"
                        break
                    if os.fstat(log.fileno()).st_size > OUTPUT_LIMIT:
                        result["primary_outcome"] = "output_limit"
                        break
                    time.sleep(.05)
            finally:
                result["escalated"] = _stop(process, grace)
                result["child_returncode"] = process.returncode
                result["child_exit_confirmed"] = process.returncode is not None
            if result["primary_outcome"] == "unknown":
                result["primary_outcome"] = "passed" if process.returncode == 0 else "failed"
            if os.fstat(log.fileno()).st_size > OUTPUT_LIMIT:
                result["primary_outcome"] = "output_limit"
                log.truncate(OUTPUT_LIMIT)
        raw_log = (output / "command.log").read_bytes()
        result["raw_log_sha256"] = hashlib.sha256(raw_log).hexdigest()
        readable = raw_log.decode("utf-8", errors="backslashreplace")
        readable = re.sub(r"(postgres(?:ql)?://[^\s'\"/@:]+:)[^\s'\"/@]+@", r"\1[redacted]@", readable)
        readable = re.sub(r"(?i)(password\s*=\s*)[^\s'\"]+", r"\1[redacted]", readable)
        (output / "command.log").write_text(readable, encoding="utf-8", newline="\n")
        journals = sorted(output.glob("*-resources.json"))
        if require_resources and not journals:
            result["cleanup_outcome"] = "unknown"
        elif journals:
            statuses = []
            cleanup_deadline = time.monotonic() + 60
            for path in journals:
                try:
                    owner = OwnedDocker.recover(path)
                    if namespace is None or not (owner.namespace == namespace or owner.namespace.startswith(namespace + "-")):
                        raise ValueError("Observer refuses a foreign resource journal")
                    native = owner.cleanup_status == "removed"
                    # The child has been reaped; recovery cannot race that child's allocator.
                    owner.cleanup(deadline=cleanup_deadline)
                    statuses.append("confirmed" if native else "rescued")
                except (OSError, ValueError, KeyError, subprocess.SubprocessError, CleanupUnconfirmed):
                    statuses.append("unknown")
            result["cleanup_outcome"] = "unknown" if "unknown" in statuses else "rescued" if "rescued" in statuses else "confirmed"
        result["status"] = "pass" if (result["primary_outcome"] == "passed"
                            and result["cleanup_outcome"] in ("confirmed", "not_applicable")) else "fail"
    except (OSError, subprocess.SubprocessError) as exc:
        result.update(status="fail", cleanup_outcome="unknown", observer_error=type(exc).__name__)
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
        result["seconds"] = round(time.monotonic() - started, 3)
        _write(output / "observer.json", result)
    return result



def observe(command, *, root, environment, output, timeout, grace=None, namespace=None, require_resources=False):
    if grace is not None:
        return _observe_compat(command, root=root, environment=environment, output=output,
                               timeout=timeout, grace=grace, namespace=namespace,
                               require_resources=require_resources)
    return _observe_bound(command, root=root, environment=environment, output=output,
                          timeout=timeout, namespace=namespace, require_resources=require_resources)




def _record_controller(output, cell, binding, *, parser_observation=None):
    if cell == 'factory' and not _measured(parser_observation, binding):
        raise ValueError('Controller receipt requires actual parser measurement before environment cleanup')
    if not validate_components(output, cell, binding, parser_observation=parser_observation):
        raise ValueError('Controller receipt requires complete actual bound component validation')
    names = (('lifecycle.json', 'lifecycle.json.envelope.json', 'lifecycle-resource-index.json',
              'lifecycle-cleanup-ledger.json') if cell == 'lifecycle' else
             (cell+'-suite.json', cell+'-suite.json.envelope.json', cell+'-restart.json',
              cell+'-restart.json.envelope.json', cell+'-resources.json'))
    files = {name: hashlib.sha256(_held_bytes(output/name)).hexdigest() for name in names}
    parser_digest = (live_contracts.digest(read_document(output/'factory-suite.json')['applicability'])
                     if cell == 'factory' else None)
    _write(output/'controller-validation.json', live_contracts.controller_observation(
        binding, files, parser_evidence_sha256=parser_digest))
