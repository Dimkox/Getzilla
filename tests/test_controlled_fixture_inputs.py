"""Real file-admission and client-environment boundaries, without Docker effects."""
from __future__ import annotations

import errno
import hashlib
import json
import multiprocessing
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from getzilla import controlled_fixture as fixture
from getzilla import fenced_fixture
from getzilla import model_continuation_state as journal
from tests.test_model_continuation import enabled_policy


def _fifo_input_probe(root, mode, result):
    root = Path(root)
    source = root/'bin/codex'
    original_which = fixture.shutil.which
    original_open = os.open

    def which(name, **kwargs):
        return '/never-run-docker' if name == 'docker' else original_which(name, **kwargs)

    def race(path, *args, **kwargs):
        if os.fspath(path) == str(source):
            source.unlink()
            os.mkfifo(source, 0o700)
        return original_open(path, *args, **kwargs)

    try:
        with patch.dict(os.environ, {'PATH':str(source.parent)}), \
                patch.object(fixture.shutil, 'which', side_effect=which), \
                patch.object(fixture, '_command', side_effect=AssertionError('Docker must not run')), \
                patch.object(fixture.os, 'open', side_effect=race if mode == 'race-copy' else original_open):
            if mode in ('copy', 'race-copy'):
                fixture._copy_input(source, root/'copied', '0'*64, 'codex_unqualified')
            else:
                binding = journal.Binding('fixture-chain','fixture-task','fixture-owner','fixture-route',
                    'fixture-session','a'*64,'b'*64,'c'*64)
                budget = journal.TaskBudget(2,4,'1.5',int(time.time())+120)
                runner = fixture.run if mode == 'run' else fenced_fixture.run
                runner(root,binding,budget)
    except fixture.FixtureError as error:
        result.send(('refused',str(error)))
    except BaseException as error:
        result.send(('unexpected',type(error).__name__))
    else:
        result.send(('accepted',None))
    finally:
        result.close()


class FixtureInputTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os,'mkfifo'), 'FIFO boundary is POSIX only')
    def test_fifo_and_executable_fifo_public_paths_refuse_without_blocking(self):
        for mode in ('copy','race-copy','run','fenced'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root/'bin').mkdir()
                source = root/'bin/codex'
                if mode == 'race-copy':
                    source.write_bytes(b'initial regular input')
                    source.chmod(0o700)
                else:
                    os.mkfifo(source,0o700)
                policy = enabled_policy()
                policy['candidates'] = [{'provider':'local_fixture','account_ref':'synthetic','model':model}
                    for model in ('fixture-a','fixture-b')]
                config = root/'.getzilla/config/model-continuation.json'
                config.parent.mkdir(parents=True)
                config.write_text(json.dumps(policy))
                before = sorted(str(path.relative_to(root)) for path in root.rglob('*'))
                self.assertEqual(fixture.shutil.which('codex',path=str(source.parent)),str(source))
                context = multiprocessing.get_context('spawn')
                receiver,sender = context.Pipe(duplex=False)
                process = context.Process(target=_fifo_input_probe,args=(directory,mode,sender))
                process.start()
                sender.close()
                try:
                    process.join(timeout=1.5)
                    self.assertFalse(process.is_alive(),'input admission blocked before Docker')
                    self.assertEqual(process.exitcode,0)
                    self.assertTrue(receiver.poll(0.1),'missing structured refusal')
                    self.assertEqual(receiver.recv(),('refused','codex_unqualified'))
                    self.assertEqual(sorted(str(path.relative_to(root)) for path in root.rglob('*')),before)
                finally:
                    if process.is_alive():
                        process.kill()
                        process.join(timeout=5)
                    receiver.close()
                    self.assertFalse(process.is_alive(),'owned probe was not reaped')

    def test_special_empty_oversize_and_wrong_digest_inputs_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root/'empty'
            empty.touch()
            folder = root/'directory'
            folder.mkdir()
            wrong = root/'wrong'
            wrong.write_bytes(b'wrong bytes')
            oversized = root/'oversized'
            with oversized.open('wb') as stream:
                stream.truncate(512*1024*1024+1)
            cases = [empty,folder,wrong,oversized]
            if hasattr(os,'symlink') and os.name != 'nt':
                linked = root/'symlink'
                linked.symlink_to(wrong)
                cases.append(linked)
            for index,source in enumerate(cases):
                with self.subTest(source=source.name):
                    with self.assertRaisesRegex(fixture.FixtureError,'codex_unqualified'):
                        fixture._copy_input(source,root/str(index),'0'*64,'codex_unqualified')

    def test_source_replacement_shrink_and_growth_are_refused_and_descriptors_close(self):
        original_fdopen = os.fdopen
        for change in ('replace','shrink','grow'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root/'source'
                source.write_bytes(b'abc')
                descriptors = []

                class MutatingStream:
                    def __init__(self,descriptor,*args,**kwargs):
                        self.stream = original_fdopen(descriptor,*args,**kwargs)
                        descriptors.append(descriptor)
                        self.changed = False

                    def __enter__(self):
                        return self

                    def __exit__(self,*args):
                        self.stream.close()

                    def fileno(self):
                        return self.stream.fileno()

                    def read(self,size):
                        data = self.stream.read(size)
                        if not self.changed:
                            self.changed = True
                            if change == 'replace':
                                replacement = root/'replacement'
                                replacement.write_bytes(b'abc')
                                replacement.replace(source)
                            elif change == 'shrink':
                                source.write_bytes(b'')
                            else:
                                with source.open('ab') as stream:
                                    stream.write(b'd')
                        return data

                with patch.object(fixture.os,'fdopen',side_effect=MutatingStream):
                    with self.assertRaisesRegex(fixture.FixtureError,'codex_unqualified'):
                        fixture._copy_input(source,root/'destination',
                            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','codex_unqualified')
                for descriptor in descriptors:
                    with self.assertRaises(OSError) as caught:
                        os.fstat(descriptor)
                    self.assertEqual(caught.exception.errno,errno.EBADF)

    def test_short_reads_copy_exact_bytes_and_destination_failure_closes_source(self):
        original_fdopen = os.fdopen
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            source.write_bytes(b'abc')
            descriptors = []

            class ShortStream:
                def __init__(self,descriptor,*args,**kwargs):
                    self.stream = original_fdopen(descriptor,*args,**kwargs)
                    descriptors.append(descriptor)

                def __enter__(self):
                    return self

                def __exit__(self,*args):
                    self.stream.close()

                def fileno(self):
                    return self.stream.fileno()

                def read(self,size):
                    return self.stream.read(min(size,1))

            with patch.object(fixture.os,'fdopen',side_effect=ShortStream):
                fixture._copy_input(source,root/'destination',
                    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad','codex_unqualified')
                with self.assertRaisesRegex(fixture.FixtureError,'codex_unqualified'):
                    fixture._copy_input(source,root/'missing/destination',hashlib.sha256(b'abc').hexdigest(),'codex_unqualified')
            self.assertEqual((root/'destination').read_bytes(),b'abc')
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE((root/'destination').stat().st_mode),0o555)
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def test_source_descriptor_closes_when_stream_wrapping_fails(self):
        original_open = os.open
        descriptors = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'source'
            source.write_bytes(b'abc')

            def opened(*args,**kwargs):
                descriptor = original_open(*args,**kwargs)
                descriptors.append(descriptor)
                return descriptor

            with patch.object(fixture.os,'open',side_effect=opened), \
                    patch.object(fixture.os,'fdopen',side_effect=OSError('synthetic wrapping failure')):
                with self.assertRaisesRegex(fixture.FixtureError,'codex_unqualified'):
                    fixture._copy_input(source,root/'destination','0'*64,'codex_unqualified')
            try:
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(descriptor)
            finally:
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    @unittest.skipIf(os.name == 'nt','executable fixture uses a POSIX shebang')
    def test_docker_client_uses_private_empty_config_home_and_removes_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root/'docker'
            fake.write_text('#!'+sys.executable+'\n'+
                'import json, os, stat, sys\nfrom pathlib import Path\n'+
                'home=os.environ.get("HOME"); config=os.environ.get("DOCKER_CONFIG")\n'+
                'print(json.dumps({"home":home,"config":config,"args":sys.argv[1:],'+
                '"empty":bool(config) and not list(Path(config).iterdir()),'+
                '"mode":stat.S_IMODE(Path(config).stat().st_mode) if config else None}))\n')
            fake.chmod(0o700)
            canary = root/'unused-host-home'
            canary.mkdir()
            (canary/'config.json').write_text('synthetic canary; never load')
            with patch.dict(os.environ,{'HOME':str(canary),'DOCKER_CONFIG':str(canary),
                    'DOCKER_HOST':'tcp://untrusted.invalid:2375','DOCKER_CONTEXT':'untrusted'}):
                result = json.loads(fixture._command([str(fake),'inspect','synthetic']))
            self.assertTrue(result['empty'])
            self.assertEqual(result['mode'],0o700)
            self.assertEqual(result['home'],result['config'])
            self.assertNotEqual(result['home'],str(canary))
            self.assertEqual(result['args'][:4],['--config',result['config'],'--host','unix:///var/run/docker.sock'])
            self.assertFalse(Path(result['config']).exists())
            self.assertEqual((canary/'config.json').read_text(),'synthetic canary; never load')
