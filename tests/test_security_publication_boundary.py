"""Reader selection must not load publication implementations."""
import subprocess
import sys
import unittest
from pathlib import Path

class PublicationBoundaryTests(unittest.TestCase):
    def test_reader_import_keeps_publication_unloaded(self):
        root=Path(__file__).resolve().parents[1]
        code="""import sys
sys.path.insert(0,'.getzilla')
from getzilla import security_data as reader
assert 'getzilla.security_publication' not in sys.modules
assert 'getzilla.security_windows_publication' not in sys.modules
assert not hasattr(reader._SnapshotStore,'write')
from getzilla.security_data_windows import SnapshotReader
assert 'getzilla.security_windows_publication' not in sys.modules
assert not hasattr(SnapshotReader,'write')
"""
        result=subprocess.run([sys.executable,'-B','-c',code],cwd=root,capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_windows_publisher_reexports_canonical_identity(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'.getzilla'))
        from getzilla import security_data, security_data_windows
        from getzilla import security_publication, security_windows_publication
        self.assertIs(security_windows_publication.SnapshotStore,security_data_windows.SnapshotStore)
        self.assertIs(security_windows_publication.SecurityDataError,security_data.SecurityDataError)
        self.assertIs(security_publication.SecurityDataError,security_data.SecurityDataError)
        self.assertIs(security_publication.SnapshotWriter.read,security_data._SnapshotStore.read)
        self.assertIs(security_publication.SnapshotWriter.confirm,security_data._SnapshotStore.confirm)

    def test_actual_read_and_confirmation_do_not_load_writer(self):
        import tempfile
        root=Path(__file__).resolve().parents[1]
        sys.path.insert(0,str(root/'.getzilla'))
        from tests.test_security_data import publish, EXPANDED_NOW
        common=Path(subprocess.check_output(['git','rev-parse','--git-common-dir'],cwd=root,text=True).strip())
        if not common.is_absolute():common=(root/common).resolve()
        with tempfile.TemporaryDirectory(dir=common.parent/'.getzilla/runtime') as tmp:
            publish(Path(tmp))
            code="""import sys
from pathlib import Path
from datetime import datetime,timezone
sys.path.insert(0,'.getzilla')
from getzilla import security_data as reader
now=datetime(2026,11,3,12,tzinfo=timezone.utc)
payload,evidence=reader.read_snapshot(Path(sys.argv[1]),'osv:PyPI',now=now)
reader.confirm_snapshots(Path(sys.argv[1]),[evidence],now=now)
assert payload
assert 'getzilla.security_publication' not in sys.modules
assert 'getzilla.security_windows_publication' not in sys.modules
"""
            result=subprocess.run([sys.executable,'-B','-c',code,tmp],cwd=root,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
