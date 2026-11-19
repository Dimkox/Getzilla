"""Client cleanup uncertainty uses inert stand-ins; no Docker or provider runs."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
import gc
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import weakref
from unittest.mock import patch

from getzilla import controlled_fixture as fixture
from getzilla import fenced_fixture
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


class InertClient:
    """A termination-uncertainty model, never a real host PID or signal target."""
    stdin = stdout = None

    def __init__(self, uncertain):
        self.pid = 424242
        self.args = None
        self.returncode = None
        self.uncertain = uncertain
        self.directory = None
        self.events = []

    def poll(self):
        return self.returncode

    def kill(self):
        assert self.directory.is_dir()
        self.events.append('kill')
        if self.uncertain == 'kill-failure':
            raise PermissionError('synthetic kill refusal')

    def wait(self,timeout):
        assert self.directory.is_dir()
        self.events.append(('wait',timeout))
        if self.returncode is None:
            if self.uncertain:
                raise subprocess.TimeoutExpired('inert client',timeout)
            self.returncode = -9
        return self.returncode


class InterruptedClient(InertClient):
    __enter__ = subprocess.Popen.__enter__
    __exit__ = subprocess.Popen.__exit__
    stderr = None
    _sigint_wait_secs = 0.01

    def communicate(self,input=None,timeout=None):
        raise KeyboardInterrupt

    def _wait(self,timeout=None):
        raise subprocess.TimeoutExpired(self.args,timeout)


@contextmanager
def public_cleanup_case(mode, *, uncertain, sync=False):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        policy = enabled_policy()
        policy['candidates'] = [{'provider':'local_fixture','account_ref':'synthetic','model':model}
            for model in ('fixture-a','fixture-b')]
        config = root/'.getzilla/config/model-continuation.json'
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps(policy))
        binding = journal.Binding('fixture-chain','fixture-task','fixture-owner','fixture-route',
            'fixture-session','a'*64,'b'*64,'c'*64)
        budget = journal.TaskBudget(2,4,'1.5',int(time.time())+120)
        process = (InterruptedClient if sync else InertClient)(uncertain)
        owners = {}

        def popen(argv,**kwargs):
            process.args = tuple(argv)
            process.directory = Path(kwargs['env']['HOME'])
            assert kwargs['env']['DOCKER_CONFIG'] == str(process.directory)
            assert process.directory.is_dir()
            return process

        def command(argv,**kwargs):
            if argv[1:3] == ['volume','create']:
                owners[argv[-1]] = argv[argv.index('--label')+1].split('=',1)[1]
                return argv[-1]
            if argv[1:3] == ['volume','inspect']:
                return json.dumps([{'Name':argv[-1],'Labels':{'getzilla.owner':owners[argv[-1]]}}])
            if argv[1] == 'create':
                return 'a'*64
            if argv[1] == 'inspect':
                return '[{}]'
            return ''

        class Lines:
            def __init__(self,child):
                assert child is process

            def read(self):
                raise fixture.FixtureError('invalid_frame')

            def close(self):
                assert process.directory.is_dir()
                process.events.append('lines.close')

        error = None
        def image(*args,**kwargs):
            fixture._command(['/never-run','image','inspect','synthetic'])
            raise AssertionError('interrupted command returned')

        with patch.object(fixture.shutil,'which',return_value='/never-run'), \
                patch.object(fixture,'_read_input'), \
                patch.object(fixture,'_immutable_image',side_effect=image) if sync else patch.object(fixture,'_immutable_image',return_value='sha256:'+'b'*64), \
                patch.object(fixture,'_validate_container',return_value=True), \
                nullcontext() if sync else patch.object(fixture,'_command',side_effect=command), \
                patch.object(fixture.subprocess,'Popen',side_effect=popen), \
                patch.object(fixture,'_Lines',Lines), \
                patch.object(fenced_fixture,'_helper',return_value=''), \
                patch.object(fenced_fixture,'_checkpoint',return_value=('a'*64,'b'*64)), \
                patch.object(fenced_fixture,'_create',return_value='a'*64):
            try:
                (fixture.run if mode == 'controlled' else fenced_fixture.run)(root,binding,budget)
            except (fixture.FixtureError,KeyboardInterrupt) as caught:
                error = caught
        assert error is not None
        try:
            yield process,error,journal.inspect_controlled_chain(root,binding)
        finally:
            # The stand-in is not a host process. Resolve it explicitly so a
            # failing assertion cannot leave a test-owned retained directory.
            context = getattr(error,'cleanup_context',None)
            if context is not None and process.directory.exists():
                process.returncode = -9
                context.reconcile((process,))


@unittest.skipIf(os.name == 'nt','public journal fixture requires POSIX directory fsync')
class ClientCleanupTests(unittest.TestCase):
    def test_two_live_clients_refuse_more_creation_without_sending_signals(self):
        clients = []

        class Client(InertClient):
            def __init__(self,argv,**kwargs):
                super().__init__(True)
                self.args = argv
                self.directory = Path(kwargs['env']['HOME'])
                clients.append(self)

        with patch.object(fixture.subprocess,'Popen',Client):
            with fixture._docker_client():
                context = fixture._DOCKER_CONFIG.get()
                try:
                    fixture._client_popen(['/never-run','attached-a'])
                    fixture._client_popen(['/never-run','attached-b'])
                    with self.assertRaisesRegex(fixture.FixtureError,'container_unavailable'):
                        fixture._client_popen(['/never-run','must-not-start'])
                    self.assertEqual(len(clients),2)
                    self.assertTrue(all(client.events==[] for client in clients))
                finally:
                    for client in clients:
                        client.returncode = 0
                        context.confirm_exit(client)

    def test_completed_attached_clients_do_not_block_synchronous_inspection(self):
        clients = []

        class Client(InertClient):
            def __init__(self,argv,**kwargs):
                super().__init__(False)
                self.args = argv
                self.directory = Path(kwargs['env']['HOME'])
                clients.append(self)

            def communicate(self,timeout):
                self.returncode = 0

        with patch.object(fixture.subprocess,'Popen',Client):
            with fixture._docker_client():
                context = fixture._DOCKER_CONFIG.get()
                try:
                    for _ in range(2):
                        process = fixture._client_popen(['/never-run','attached'])
                        process.returncode = 0
                    self.assertEqual(fixture._command(['/never-run','inspect']),'')
                    self.assertEqual(len(clients),3)
                    self.assertTrue(all(row['exit']==0 for row in context._clients))
                finally:
                    for client in clients:
                        client.returncode = 0
                        context.confirm_exit(client)

    def test_constructor_without_pid_retains_unknown_context_without_adoption(self):
        with tempfile.TemporaryDirectory() as temporary:
            original_mkdtemp = tempfile.mkdtemp

            class FailedConstructor:
                def __init__(self,*args,**kwargs):
                    raise OSError('modeled constructor with no exit proof')

            with patch.object(fixture.tempfile,'mkdtemp',side_effect=lambda **kwargs: original_mkdtemp(dir=temporary,**kwargs)), \
                    patch.object(fixture.subprocess,'Popen',FailedConstructor):
                with self.assertRaises(fixture.FixtureError) as caught:
                    fixture._command(['/never-run','synthetic'])
            context = caught.exception.cleanup_context
            self.assertTrue(context.directory.is_dir())
            self.assertFalse(context.reconcile(context.processes))
            self.assertFalse(context.reconcile(()))
            # No child exists in this inert constructor. Only the test's whole
            # owned temporary namespace removes this unreconcilable model.

    def test_real_harmless_sync_child_uses_registered_exit_proof(self):
        import sys
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary)/'harmless-client'
            executable.write_text('#!'+sys.executable+'\nprint("owned sync output")\n')
            executable.chmod(0o700)
            with fixture._docker_client():
                context = fixture._DOCKER_CONFIG.get()
                self.assertEqual(fixture._command([str(executable),'synthetic']),'owned sync output')
                self.assertEqual(len(context.processes),1)
                self.assertEqual(context._clients[0]['exit'],0)
                self.assertTrue(context.directory.is_dir())
            self.assertFalse(context.directory.exists())

    def test_sync_clients_share_exit_proof_and_constructor_failure_ownership(self):
        for failure in ('communicate','wait','constructor','interrupt-constructor'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                clients = []
                original_mkdtemp = tempfile.mkdtemp

                class Client(InertClient):
                    def __init__(self,argv,**kwargs):
                        super().__init__(True)
                        self.args = argv
                        self.directory = Path(kwargs['env']['HOME'])
                        clients.append(self)
                        if failure == 'constructor':
                            raise OSError('modeled failure after child creation')
                        if failure == 'interrupt-constructor':
                            raise KeyboardInterrupt

                    def communicate(self,timeout):
                        if failure == 'communicate':
                            raise SystemExit('modeled interrupted communicate')
                        self.returncode = 0

                    def wait(self,timeout):
                        if failure == 'wait':
                            raise KeyboardInterrupt
                        return super().wait(timeout)

                with patch.object(fixture.tempfile,'mkdtemp',side_effect=lambda **kwargs: original_mkdtemp(dir=temporary,**kwargs)), \
                        patch.object(fixture.subprocess,'Popen',Client):
                    with self.assertRaises(fixture.FixtureError) as caught:
                        fixture._command(['/never-run','synthetic'])
                error = caught.exception
                self.assertEqual(str(error),'client_cleanup_unconfirmed')
                context = error.cleanup_context
                self.assertEqual(context.processes,tuple(clients))
                self.assertTrue(context.directory.is_dir())
                client = clients[0]
                client.returncode = 0
                # Restore a normal wait on this exact object after the modeled
                # interruption. Reconciliation sends no signal or command.
                client.wait = lambda timeout: 0
                self.assertTrue(context.reconcile((client,)))

    def test_sync_success_and_failure_confirm_exit_before_config_removal(self):
        for code in (0,7):
            with self.subTest(code=code):
                clients = []

                class Client(InertClient):
                    def __init__(self,argv,**kwargs):
                        super().__init__(False)
                        self.args = argv
                        self.directory = Path(kwargs['env']['HOME'])
                        self.output = kwargs['stdout']
                        clients.append(self)

                    def communicate(self,timeout):
                        self.output.write(b'owned output\n')
                        self.returncode = code

                with patch.object(fixture.subprocess,'Popen',Client):
                    if code:
                        with self.assertRaisesRegex(fixture.FixtureError,'container_command_failed'):
                            fixture._command(['/never-run','synthetic'])
                    else:
                        self.assertEqual(fixture._command(['/never-run','synthetic']),'owned output')
                self.assertEqual(len(clients),1)
                self.assertFalse(clients[0].directory.exists())
                self.assertNotIn('kill',clients[0].events)

    def test_descriptor_cleanup_bounds_and_links_refuse_without_fd_leaks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)/'owned'
            root.mkdir()
            (root/'retained').write_bytes(b'owned bytes')
            before = len(os.listdir('/proc/self/fd')) if Path('/proc/self/fd').exists() else None
            descriptor = fixture.fsx.open_dir(root)
            try:
                with self.assertRaises(OSError):
                    fixture._empty_client_directory(descriptor,[0])
                self.assertEqual((root/'retained').read_bytes(),b'owned bytes')
                (root/'retained').unlink()
                foreign = Path(temporary)/'foreign'
                foreign.write_bytes(b'foreign bytes')
                (root/'link').symlink_to(foreign)
                with self.assertRaises(OSError):
                    fixture._empty_client_directory(descriptor,[4096])
                with self.assertRaises(OSError):
                    fixture._empty_client_directory(descriptor,[4096],17)
                self.assertTrue((root/'link').is_symlink())
                self.assertEqual(foreign.read_bytes(),b'foreign bytes')
            finally:
                fixture.fsx.close_dir(descriptor)
            if before is not None:
                self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_public_sync_interrupt_retains_owned_config_and_reconciliation_handle(self):
        for mode in ('controlled','fenced'):
            with self.subTest(mode=mode), public_cleanup_case(mode,uncertain=True,sync=True) as (process,error,state):
                self.assertTrue(process.directory.is_dir(),'sync interrupt deleted private config')
                self.assertEqual(str(error),'client_cleanup_unconfirmed')
                context = error.cleanup_context
                self.assertEqual(context.processes,(process,))
                self.assertEqual(state['attempts'][-1]['state'],'active_unknown')
                self.assertFalse(context.reconcile((process,)))
                process.returncode = -9
                self.assertTrue(context.reconcile((process,)))

    def test_root_replacement_at_deletion_preserves_foreign_data(self):
        for mode in ('controlled','fenced'):
            with self.subTest(mode=mode), public_cleanup_case(mode,uncertain=True) as (process,error,_state):
                context = error.cleanup_context
                process.returncode = -9
                original = process.directory
                moved = original.with_name(original.name+'-race-owned')
                real_rmtree = fixture.shutil.rmtree
                real_scandir = fixture.fsx.scandir
                replaced = False

                def replace():
                    nonlocal replaced
                    if replaced:
                        return
                    replaced = True
                    original.rename(moved)
                    original.mkdir()
                    (original/'foreign').write_bytes(b'preserve foreign bytes')

                def replace_then_delete(path,*args,**kwargs):
                    replace()
                    return real_rmtree(path,*args,**kwargs)

                def replace_then_scan(handle):
                    replace()
                    return real_scandir(handle)

                try:
                    with patch.object(fixture.shutil,'rmtree',side_effect=replace_then_delete), \
                            patch.object(fixture.fsx,'scandir',side_effect=replace_then_scan):
                        self.assertFalse(context.reconcile((process,)))
                    self.assertEqual((original/'foreign').read_bytes(),b'preserve foreign bytes')
                    self.assertTrue(moved.is_dir())
                finally:
                    if original.exists():
                        real_rmtree(original)
                    if moved.exists():
                        moved.rename(original)
                    if context._cleaned and original.exists():
                        real_rmtree(original)
                self.assertTrue(context.reconcile((process,)))

    def test_public_paths_retain_private_config_when_client_exit_is_unknown(self):
        for mode in ('controlled','fenced'):
            for uncertain in (True,'kill-failure'):
                with self.subTest(mode=mode,uncertain=uncertain), public_cleanup_case(mode,uncertain=uncertain) as (process,error,state):
                    self.assertTrue(process.directory.is_dir(),'unconfirmed client config was deleted')
                    self.assertEqual(str(error),'client_cleanup_unconfirmed')
                    self.assertIsNotNone(error.cleanup_context)
                    self.assertEqual(state['attempts'][-1]['state'],'send_unknown')
                    self.assertIn('kill',process.events)
                    self.assertIsNone(process.returncode)
                    gc.collect()
                    self.assertTrue(process.directory.is_dir(),'GC deleted an unknown cleanup resource')

    def test_lost_cleanup_handle_has_no_deleting_gc_finalizer(self):
        original_mkdtemp = tempfile.mkdtemp
        process = InertClient(True)
        with tempfile.TemporaryDirectory() as temporary:
            def mkdtemp(**kwargs):
                return original_mkdtemp(dir=temporary,**kwargs)

            def popen(argv,**kwargs):
                process.args = tuple(argv)
                process.directory = Path(kwargs['env']['HOME'])
                return process

            def abandon():
                try:
                    with fixture._docker_client():
                        fixture._client_popen(['/never-run','inert'])
                except fixture.FixtureError as error:
                    self.assertEqual(str(error),'client_cleanup_unconfirmed')
                    return weakref.ref(error.cleanup_context)
                self.fail('unknown client context was accepted')

            with patch.object(fixture.tempfile,'mkdtemp',side_effect=mkdtemp), \
                    patch.object(fixture.subprocess,'Popen',side_effect=popen):
                reference = abandon()
            gc.collect()
            self.assertIsNone(reference())
            self.assertTrue(process.directory.is_dir())
            # No host process exists. The outer test owns this whole namespace.
            process.returncode = -9

    def test_public_paths_remove_private_config_after_owned_client_is_reaped(self):
        for mode in ('controlled','fenced'):
            with self.subTest(mode=mode), public_cleanup_case(mode,uncertain=False) as (process,error,state):
                self.assertFalse(process.directory.exists())
                self.assertEqual(process.returncode,-9)
                self.assertEqual(str(error),'fixture_failed' if mode=='controlled' else 'invalid_frame')
                self.assertEqual(state['attempts'][-1]['state'],'send_unknown')

    def test_delayed_owned_exit_can_reconcile_without_replay_or_more_signals(self):
        for mode in ('controlled','fenced'):
            with self.subTest(mode=mode), public_cleanup_case(mode,uncertain=True) as (process,error,state):
                self.assertTrue(process.directory.is_dir())
                context = error.cleanup_context
                before = list(process.events)
                self.assertFalse(context.reconcile((process,)))
                self.assertEqual(process.events,before)
                process.returncode = -9
                self.assertTrue(context.reconcile((process,)))
                self.assertFalse(process.directory.exists())
                self.assertEqual(process.events.count('kill'),1)
                self.assertEqual(state['attempts'][-1]['state'],'send_unknown')
                self.assertTrue(context.reconcile((process,)))

    def test_foreign_or_reused_process_identity_cannot_release_private_config(self):
        with public_cleanup_case('controlled',uncertain=True) as (process,error,_state):
            self.assertTrue(process.directory.is_dir())
            context = error.cleanup_context
            foreign = InertClient(False)
            foreign.args,foreign.directory,foreign.returncode = process.args,process.directory,-9
            self.assertFalse(context.reconcile((foreign,)))
            self.assertEqual(foreign.events,[])
            process.returncode = -9
            process.pid += 1
            try:
                self.assertFalse(context.reconcile((process,)))
                self.assertTrue(process.directory.is_dir())
            finally:
                process.pid -= 1
            original_args = process.args
            process.args = None
            try:
                try:
                    refused = context.reconcile((process,))
                except (TypeError,AttributeError) as malformed:
                    self.fail('malformed owned identity escaped structured refusal: '+str(malformed))
                self.assertFalse(refused)
                self.assertTrue(process.directory.is_dir())
            finally:
                process.args = original_args
            self.assertTrue(context.reconcile((process,)))

    def test_cleaned_handle_refuses_a_reused_directory_without_touching_it(self):
        with public_cleanup_case('controlled',uncertain=True) as (process,error,_state):
            self.assertTrue(process.directory.is_dir())
            context = error.cleanup_context
            process.returncode = -9
            self.assertTrue(context.reconcile((process,)))
            process.directory.mkdir()
            sentinel = process.directory/'foreign'
            sentinel.write_bytes(b'unrelated bytes')
            try:
                self.assertFalse(context.reconcile((process,)))
                self.assertEqual(sentinel.read_bytes(),b'unrelated bytes')
            finally:
                sentinel.unlink()
                process.directory.rmdir()

    def test_real_inert_child_keeps_context_until_confirmed_reap(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root/'inert-client'
            import sys
            executable.write_text('#!'+sys.executable+'\nimport sys\nsys.stdin.buffer.read(1)\n')
            executable.chmod(0o700)
            with fixture._docker_client():
                directory = Path(fixture._docker_environment()['HOME'])
                process = fixture._client_popen([str(executable),'inert'],stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    self.assertTrue(directory.is_dir())
                    self.assertIsNone(process.poll())
                    with fixture._docker_client():
                        self.assertEqual(fixture._docker_environment()['HOME'],str(directory))
                    process.stdin.write(b'x')
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=5),0)
                    self.assertTrue(fixture._stop_client(process))
                    self.assertTrue(directory.is_dir())
                finally:
                    if process.poll() is None:
                        self.assertTrue(fixture._stop_client(process))
                    process.stdin.close()
            self.assertFalse(directory.exists())

    def test_replaced_or_linked_directory_is_never_deleted_as_owned_config(self):
        for linked in (False,True):
            with self.subTest(linked=linked), public_cleanup_case('fenced',uncertain=True) as (process,error,_state):
                self.assertTrue(process.directory.is_dir())
                context = error.cleanup_context
                process.returncode = -9
                original = process.directory
                moved = original.with_name(original.name+'-test-owned-moved')
                original.rename(moved)
                foreign = original.with_name(original.name+'-test-foreign') if linked else original
                foreign.mkdir()
                sentinel = foreign/'sentinel'
                sentinel.write_bytes(b'foreign bytes')
                if linked:
                    original.symlink_to(foreign,target_is_directory=True)
                try:
                    self.assertFalse(context.reconcile((process,)))
                    self.assertEqual(sentinel.read_bytes(),b'foreign bytes')
                    self.assertTrue(moved.is_dir())
                finally:
                    if linked:
                        original.unlink()
                    sentinel.unlink()
                    foreign.rmdir()
                    moved.rename(original)
                self.assertTrue(context.reconcile((process,)))
