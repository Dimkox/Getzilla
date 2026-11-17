"""NEW tiny owned snapshot fixtures; no real large artifact or Root producer."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from adaptive_trust_ci import public_admission as admission
from adaptive_trust_ci import security_bundle as bundle
ACTIVE = False
OWNED = None
FDS = set()
OPEN = os.open


def guard(event, args):
    if not ACTIVE:
        return
    if event.startswith(('socket.', 'subprocess.', 'ctypes.', 'shutil.')) or event in ('os.system', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('new fixture denies process/network/native effects')
    if event == 'open' or event.startswith('os.'):
        if event == 'open' and type(args[0]) is int and args[0] in FDS:
            return
        if not args or not isinstance(args[0], (str, bytes, os.PathLike)) or OWNED is None or not Path(os.fsdecode(args[0])).absolute().is_relative_to(OWNED):
            raise AssertionError('new fixture denies outside read')


sys.addaudithook(guard)


class SnapshotProfileControls(unittest.TestCase):
    @contextlib.contextmanager
    def owned(self):
        global ACTIVE, OWNED
        base = Path(os.environ.get('GETZILLA_PUBLIC_FIXTURE_BASE', str(Path(__file__).resolve().parents[2] / '.getzilla/runtime/test-fixtures')))
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='snapshot-owned-', dir=base) as directory:
            OWNED = Path(directory)
            def opened(path, flags, *args, **kwargs):
                if not Path(path).absolute().is_relative_to(OWNED):
                    raise AssertionError('owned open boundary')
                descriptor = OPEN(path, flags, *args, **kwargs)
                FDS.add(descriptor)
                return descriptor
            try:
                with patch.object(admission.os, 'open', side_effect=opened):
                    yield OWNED
            finally:
                ACTIVE = False
                OWNED = None
                FDS.clear()
    def run_owned(self, root, policy=None):
        global ACTIVE
        ACTIVE = True
        try:
            return admission._snapshot_preflight(root, policy)
        finally:
            ACTIVE = False
    def unavailable(self):
        if os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'):
            return False
        with self.assertRaises(bundle.BundleError):
            admission._snapshot_preflight(Path('/UNREAD-unsupported'))
        return True
    def test_profile_is_explicit_and_legacy_default_is_unchanged(self):
        self.assertEqual(bundle.snapshot_limit(), 33554432)
        self.assertEqual(bundle.snapshot_limit(bundle.BundlePolicy('a'*64, snapshot_profile='public-768')), 768*1024*1024)
        with self.assertRaises(bundle.BundleError):
            bundle.snapshot_limit({'snapshot_profile':'public-768'})
    def test_total_streamed_bytes_obey_selected_profile(self):
        if self.unavailable():
            return
        with self.owned() as root:
            (root/'opaque').write_bytes(b'x'*40)
            with patch.object(bundle, 'SNAPSHOT_PROFILES', {'legacy':32,'public-768':64}):
                with self.assertRaises(bundle.BundleError):
                    self.run_owned(root, bundle.BundlePolicy('a'*64))
                rows=self.run_owned(root, bundle.BundlePolicy('a'*64,snapshot_profile='public-768'))
            self.assertEqual(rows[0]['bytes'],40)
    def test_expanded_zip_budget_is_independent_of_compressed_size(self):
        if self.unavailable():
            return
        with self.owned() as root:
            with zipfile.ZipFile(root/'owned-zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr('owned', b'a'*300)
            with patch.object(bundle,'SNAPSHOT_PROFILES',{'legacy':128,'public-768':128}):
                with self.assertRaises(bundle.BundleError):
                    self.run_owned(root, bundle.BundlePolicy('a'*64,snapshot_profile='public-768'))
    def test_metadata_reader_never_allocates_large_readall(self):
        class Stream(io.BytesIO):
            def read(self,size=-1):
                raise AssertionError('large read must refuse before underlying reader')
        reader=admission._SnapshotStream(Stream(),768*1024*1024)
        with self.assertRaises(bundle.BundleError):
            reader.read()


if __name__ == '__main__':
    unittest.main()
