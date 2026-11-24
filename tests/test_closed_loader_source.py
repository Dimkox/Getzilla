import importlib.machinery
import sys
import tempfile
import unittest
import zipfile
import zipimport
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.closed_loader_source import module_source


class ClosedLoaderSourceTests(unittest.TestCase):
    def test_zip_source_is_read_without_execution(self):
        payload = b'raise RuntimeError("source must never execute")\n'
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'source.zip'
            with zipfile.ZipFile(archive, 'w') as stream:
                stream.writestr('sample.py', payload)
            loader = zipimport.zipimporter(str(archive))
            module = SimpleNamespace(__name__='sample', __file__=loader.get_filename('sample'), __loader__=loader)
            self.assertEqual(module_source(module), payload)

    def test_bytecode_without_source_is_refused(self):
        import py_compile
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'sample.py'
            source.write_text('value = 1\n')
            compiled = py_compile.compile(str(source), cfile=str(source.with_suffix('.pyc')), doraise=True)
            source.unlink()
            loader = importlib.machinery.SourcelessFileLoader('sample', compiled)
            with self.assertRaisesRegex(ValueError, 'cannot be bound'):
                module_source(SimpleNamespace(__name__='sample', __file__=compiled, __loader__=loader))

    def test_namespace_package_has_no_qualified_source(self):
        loader = importlib.machinery.NamespaceLoader('sample', [], None)
        with self.assertRaisesRegex(ValueError, 'loader is unavailable'):
            module_source(SimpleNamespace(__name__='sample', __file__=None, __loader__=loader))
