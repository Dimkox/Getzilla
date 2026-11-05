"""Fault and real child-interruption controls; no external backend is enabled."""
from __future__ import annotations

import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from getzilla import execution, execution_store as store, fsx, state
from tests.execution_contract_support import CountingBackend, owned_route


def interrupted_submit(path, stage):
    root = Path(path)
    state.bind_session('owner')
    caller = execution.trusted_caller(root)
    real_replace, real_sync, real_dir = fsx.replace_at, os.fsync, fsx.fsync_dir
    published = False
    def replace(*args):
        nonlocal published
        if args[-1] == 'registry.json' and stage == 'before_replace':
            os._exit(91)
        result = real_replace(*args)
        if args[-1] == 'registry.json':
            published = True
            if stage == 'after_replace':
                os._exit(91)
        return result
    def file_sync(descriptor):
        real_sync(descriptor)
        if stage == 'after_file_fsync' and stat.S_ISREG(os.fstat(descriptor).st_mode):
            os._exit(91)
    def directory_sync(handle):
        real_dir(handle)
        if stage == 'after_directory_fsync' and published:
            os._exit(91)
    class MarkerBackend(CountingBackend):
        def dispatch(self, root, admission, request):
            result = super().dispatch(root, admission, request)
            (root / 'must-not-dispatch').write_text('unexpected')
            return result
    with patch.object(fsx, 'replace_at', side_effect=replace), \
         patch.object(store.state.os, 'fsync', side_effect=file_sync), \
         patch.object(fsx, 'fsync_dir', side_effect=directory_sync):
        execution.submit(root, caller, execution.SubmitRequest('crash', {}, 60), backend=MarkerBackend())


class DurabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {'GETZILLA_SESSION_ID': 'owner'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(state.bind_session, None)
        owned_route(self.root)
        self.caller = execution.trusted_caller(self.root)

    def test_write_file_flush_replace_and_directory_flush_fail_before_dispatch(self):
        real_fdopen, real_sync, real_replace, real_dir = os.fdopen, os.fsync, fsx.replace_at, fsx.fsync_dir
        for stage in ('write', 'file_fsync', 'replace', 'directory_fsync'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                owned_route(root)
                caller = execution.trusted_caller(root)
                backend = CountingBackend()
                published = False
                class FailingWriter:
                    def __init__(self, file):
                        self.file = file
                    def __enter__(self):
                        return self
                    def __exit__(self, *args):
                        self.file.close()
                    def write(self, value):
                        raise OSError('write fault')
                    def __getattr__(self, key):
                        return getattr(self.file, key)
                def fdopen(*args, **kwargs):
                    file = real_fdopen(*args, **kwargs)
                    return FailingWriter(file) if stage == 'write' else file
                def sync(descriptor):
                    if stage == 'file_fsync' and stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise OSError('file flush fault')
                    return real_sync(descriptor)
                def replace(*args):
                    nonlocal published
                    if args[-1] == 'registry.json':
                        if stage == 'replace':
                            raise OSError('rename fault')
                        published = True
                    return real_replace(*args)
                def directory_sync(handle):
                    if stage == 'directory_fsync' and published:
                        raise OSError('directory flush fault')
                    return real_dir(handle)
                with patch.object(store.state.os, 'fdopen', side_effect=fdopen), \
                     patch.object(store.state.os, 'fsync', side_effect=sync), \
                     patch.object(fsx, 'replace_at', side_effect=replace), \
                     patch.object(fsx, 'fsync_dir', side_effect=directory_sync):
                    with self.assertRaises(store.RegistryError):
                        execution.submit(root, caller, execution.SubmitRequest('fault', {}, 60), backend=backend)
                self.assertEqual(backend.calls, 0)

    @unittest.skipUnless(os.name == 'posix', 'local POSIX interruption controls; Windows directory flush is unsupported')
    def test_real_child_interruptions_never_dispatch_and_published_claim_never_restarts(self):
        context = multiprocessing.get_context('spawn')
        for stage in ('after_file_fsync', 'before_replace', 'after_replace', 'after_directory_fsync'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                owned_route(root)
                child = context.Process(target=interrupted_submit, args=(str(root), stage))
                child.start()
                child.join(15)
                self.assertEqual(child.exitcode, 91)
                self.assertFalse((root / 'must-not-dispatch').exists())
                caller = execution.trusted_caller(root)
                backend = CountingBackend()
                if stage in {'after_replace', 'after_directory_fsync'}:
                    prior = store.load_registry(root)
                    first_id = next(iter(prior['records']))
                    result = execution.submit(root, caller, execution.SubmitRequest('crash', {}, 60), backend=backend)
                    self.assertEqual(result['execution_id'], first_id)
                    self.assertEqual(backend.calls, 0)
                    restored = execution.restore(root)
                    self.assertEqual(restored['orphaned'], 1)
                else:
                    with self.assertRaises(store.RegistryError) as caught:
                        store.load_registry(root)
                    self.assertEqual(caught.exception.code, 'registry_not_found')
                    execution.submit(root, caller, execution.SubmitRequest('crash', {}, 60), backend=backend)
                    self.assertEqual(backend.calls, 1)

    def test_external_mutating_adapters_stay_disabled_even_on_posix(self):
        backend = CountingBackend()
        backend.external_mutations = True
        with self.assertRaises(execution.ExecutionError):
            execution.submit(self.root, self.caller, execution.SubmitRequest('external', {}, 60), backend=backend)
        self.assertEqual(backend.calls, 0)
        self.assertFalse((self.root / store.REGISTRY_PATH).exists())
