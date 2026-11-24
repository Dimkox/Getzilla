"""Tiny archive controls; no download, install, root or executable invocation."""
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.security_image_provision import extract_tools


class ToolArchiveControls(unittest.TestCase):
    def test_extracts_only_exact_three_regular_tool_members(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            archive = root / 'owned.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                for name in ('buildkitd', 'buildctl', 'buildkit-runc', 'unused'):
                    value = ('owned fixture ' + name).encode()
                    member = tarfile.TarInfo('bin/' + name)
                    member.size = len(value)
                    stream.addfile(member, io.BytesIO(value))
            tools = extract_tools(archive, root / 'bin')
            self.assertEqual(set(tools), {'buildkitd', 'buildctl', 'buildkit-runc'})
            for name, row in tools.items():
                self.assertEqual(row['sha256'], hashlib.sha256(('owned fixture ' + name).encode()).hexdigest())
            self.assertFalse((root / 'bin/unused').exists())

    def test_link_tool_member_is_refused(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            archive = root / 'owned.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                member = tarfile.TarInfo('bin/buildkitd')
                member.type = tarfile.SYMTYPE
                member.linkname = '/outside-fixture'
                stream.addfile(member)
            with self.assertRaises(ValueError):
                extract_tools(archive, root / 'bin')
