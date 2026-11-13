"""Same-origin private journal alias control, without other test modules."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from getzilla import verification_journal as journal


def same_origin_private_module_preserves_closed_metadata(self):
    name = '_getzilla_observer_' + 'a' * 32
    package = ModuleType(name)
    package.__path__ = [str(Path(journal.__file__).parent)]
    spec = importlib.util.spec_from_file_location(name + '.verification_journal', journal.__file__)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {name: package, spec.name: module}):
        spec.loader.exec_module(module)
        result, _ = self.execute(code=124)
        self.assertEqual(module.stop_details(result), self.details(result))
        foreign = SimpleNamespace(stop_metadata=SimpleNamespace(**self.details(result)))
        self.assertEqual(module.stop_details(foreign)['decision'], 'unavailable')
