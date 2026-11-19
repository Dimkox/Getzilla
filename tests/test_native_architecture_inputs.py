"""Original architecture inputs stay attached to the actual native root."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import test_architecture_model as fixtures
from getzilla import architecture, receipts
from getzilla.trace_storage import native_root


class NativeArchitectureInputTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.',os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,saved)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(os.fchdir,saved)
        self.root = Path(temporary.name)
        self.root.chmod(0o755)
        os.chdir(self.root)
        (self.root/'schemas').mkdir(mode=0o755)
        (self.root/'architecture').mkdir(mode=0o755)
        for name in ('architecture-system.schema.json','architecture-rules.schema.json'):
            shutil.copyfile(fixtures.ROOT/'schemas'/name,self.root/'schemas'/name)
            (self.root/'schemas'/name).chmod(0o644)
        for name,value in (('system.yaml',fixtures._system()),('rules.yaml',fixtures._rules())):
            path = self.root/'architecture'/name
            path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
            path.chmod(0o644)

    def test_original_model_schema_and_contract_values_match_through_anchor(self):
        expected = architecture.load_architecture(self.root)
        with native_root(self.root) as anchor:
            actual = architecture.load_architecture(self.root,anchor=anchor)
            self.assertEqual(actual,expected)
            self.assertEqual(architecture.contract_inventory(self.root,actual,anchor=anchor),())
            values = {'base_sha':'a'*40,'head_sha':'worktree:'+'b'*40,'contract_digests':{}}
            self.assertEqual(architecture.architecture_fingerprint(self.root,actual,anchor=anchor,**values),
                             architecture.architecture_fingerprint(self.root,expected,**values))

    def test_parent_replacement_cannot_change_original_model_inputs(self):
        expected = architecture.load_architecture(self.root)
        moved = self.root.with_name(self.root.name+'-moved')
        with native_root(self.root) as anchor:
            self.root.rename(moved)
            try:
                self.root.mkdir(mode=0o755)
                sentinel = self.root/'foreign-model'
                sentinel.write_text('foreign')
                with patch('pathlib.Path.resolve',side_effect=AssertionError('root hint reopened')):
                    actual = architecture.load_architecture(self.root,anchor=anchor)
                    self.assertEqual(architecture.contract_inventory(self.root,actual,anchor=anchor),())
                self.assertEqual(actual,expected)
                self.assertEqual(sentinel.read_text(),'foreign')
            finally:
                shutil.rmtree(self.root)
                moved.rename(self.root)

    def test_private_model_is_refused_before_first_source_byte(self):
        (self.root/'architecture/system.yaml').chmod(0o600)
        with native_root(self.root) as anchor:
            with patch('os.read',side_effect=AssertionError('private source consumed')):
                with self.assertRaises(architecture.ArchitectureError):
                    architecture.load_architecture(self.root,anchor=anchor)

    def test_hardlinked_schema_refuses_whole_model_input(self):
        path = self.root/'schemas/architecture-system.schema.json'
        os.link(path,path.with_name('alias.json'))
        with native_root(self.root) as anchor:
            with self.assertRaises(architecture.ArchitectureError):
                architecture.load_architecture(self.root,anchor=anchor)

    def test_original_authority_presence_uses_same_root_and_fixed_names(self):
        expected = receipts._authority_presence(self.root)
        with native_root(self.root) as anchor:
            with patch('pathlib.Path.resolve',side_effect=AssertionError('root hint reopened')):
                actual = receipts._authority_presence(self.root,anchor=anchor)
        self.assertEqual(actual,expected)

    def test_original_authority_presence_after_parent_swap_keeps_actual_root(self):
        moved = self.root.with_name(self.root.name+'-moved')
        with native_root(self.root) as anchor:
            self.root.rename(moved)
            try:
                self.root.mkdir(mode=0o755)
                (self.root/'architecture').mkdir(mode=0o755)
                actual = receipts._authority_presence(self.root,anchor=anchor)
                self.assertEqual(actual.entries,(False,True,True))
                self.assertEqual(actual.root_identity[:2],(os.fstat(anchor._fd).st_dev,os.fstat(anchor._fd).st_ino))
            finally:
                shutil.rmtree(self.root)
                moved.rename(self.root)

    def test_original_absence_inspection_refuses_unsafe_authority_alias(self):
        shutil.rmtree(self.root/'architecture')
        (self.root/'architecture').symlink_to(self.root/'schemas',target_is_directory=True)
        with native_root(self.root) as anchor:
            with self.assertRaises((architecture.ArchitectureError,ValueError,OSError)):
                receipts._authority_presence(self.root,anchor=anchor)
