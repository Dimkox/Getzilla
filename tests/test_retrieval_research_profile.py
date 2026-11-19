"""Owned public-source custody fixtures; no native independent review or ranker."""
from contextlib import ExitStack, chdir
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import native_access as access, state
from getzilla.component_state import BoundRoot
from getzilla.retrieval import research
from getzilla.retrieval.contracts import sha
from getzilla.trace_storage import native_root
from tests.execution_contract_support import owned_route
from getzilla.optional_modules import manage_modules


class PublicResearchTests(unittest.TestCase):
    def test_fixed_original_catalog_is_byte_bound_and_bounded(self):
        class ActualCatalog:
            def read(self, path, **kwargs):
                return (ROOT / path).read_bytes()
        rows, identities = research._catalog(ActualCatalog())
        self.assertEqual(len(rows), 148)
        self.assertEqual(sum(row[1] for row in rows), 2334487)
        self.assertEqual(len(identities), 2)
        class ChangedCatalog:
            def read(self, path, **kwargs):
                return (ROOT / path).read_bytes() + b' '
        with self.assertRaisesRegex(ValueError, 'public_catalog_changed'):
            research._catalog(ChangedCatalog())
        self.assertEqual(access.REQUEST_SECONDS, 2.0)
        self.assertEqual(access.MAX_CUT_BYTES, 8 * 1048576)

    @unittest.skipUnless(os.name == 'posix' and hasattr(os, 'register_at_fork'), 'POSIX native-root source profile')
    def test_actual_owned_cut_and_current_policy_fence_separate_tiny_fixture(self):
        from tests.test_optional_modules import OptionalModuleTests
        fixture = OptionalModuleTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        root = fixture.root
        with chdir(root), patch.dict('os.environ', {'GETZILLA_SESSION_ID': 'owner'}), ExitStack() as resources:
            self.addCleanup(state.bind_session, None)
            owned_route(root)
            (root / '.getzilla/runtime').chmod(0o700)
            manage_modules(root, 'install', {'retrieval-research': '0.1.0'}, source=ROOT)
            manage_modules(root, 'enable', {'context-retrieval': None, 'retrieval-research': None}, source=ROOT)
            policy = root / '.getzilla/config/policy.json'
            policy.parent.mkdir(exist_ok=True)
            policy.write_text(json.dumps({'schema_version': 2, 'secret_read_paths': []}))
            policy.chmod(0o644)
            # This explicit tiny fixture does not replace the production catalog.
            sources_path = fixture.workspace / 'public'
            sources_path.mkdir(mode=0o700)
            raw = b'def public_fixture():\n    return 1\n'
            (sources_path / 'fixture.py').write_bytes(raw)
            (sources_path / 'fixture.py').chmod(0o644)
            sources = resources.enter_context(BoundRoot(sources_path))
            anchor = resources.enter_context(native_root(root))
            staged = Path(resources.enter_context(tempfile.TemporaryDirectory(dir=root / '.getzilla/runtime')))
            staged.chmod(0o700)
            rows = (('fixture.py', len(raw), sha(raw), 'a' * 40),)
            host = research._PublicHost(root, anchor, sources, rows, (), 0, resources, staged)
            host.query = access.RegisteredQuery('tiny-public-source-fixture/v1', (host.dataset,), {'batch': 0})
            broker = access.NativeAccessBroker._compose(host)
            handle = broker.bind_native_request(host.request, host.workflow)
            try:
                cut = broker.load_authorized_cut(handle, host.query, absolute_deadline=time.monotonic() + 2)
                self.assertEqual([row.content for row in cut.documents], [raw])
                self.assertTrue(host.held)
                broker.check_current(handle)
                with self.assertRaisesRegex(access.NativeAccessError, 'native_access_unavailable'):
                    broker.prepare_owned_response(handle, 'encoder', cut, 'rank', absolute_deadline=time.monotonic() + 2)
                with self.assertRaisesRegex(access.NativeAccessError, 'native_access_expired'):
                    host.check_current(host.binding, time.monotonic() - 1)
                with self.assertRaises(access.NativeAccessError):
                    host.bind_native_request(object(), host.workflow, time.monotonic() + 2)
                original = sources_path / 'fixture.py'
                original.write_bytes(b'changed original')
                with self.assertRaisesRegex(access.NativeAccessError, 'native_access_stale'):
                    host.check_current(host.binding, time.monotonic() + 2)
                original.write_bytes(raw)
                # Replacing the original inode stays a custody failure even for identical public bytes.
                original.unlink()
                original.symlink_to(staged / '0')
                with self.assertRaises(ValueError):
                    host.check_current(host.binding, time.monotonic() + 2)
                original.unlink()
                original.write_bytes(raw)
                original.chmod(0o644)
                policy.write_text(json.dumps({'schema_version': 2, 'secret_read_paths': ['fixture.py']}))
                with self.assertRaisesRegex(access.NativeAccessError, 'native_access_stale'):
                    broker.check_current(handle)
            finally:
                broker.discard(handle)


if __name__ == '__main__':
    unittest.main()
