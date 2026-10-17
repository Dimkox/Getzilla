"""P0: a fresh install is an installed project, so the mandatory workflow baseline is checked there."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.verification import NOT_INSTALLED_SKIP, _workflow_baseline_check  # noqa: E402

SPEC = importlib.util.spec_from_file_location('install_into_fresh_record', ROOT / 'scripts' / 'install_into.py')
INSTALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALL
SPEC.loader.exec_module(INSTALL)


class Incomplete:
    complete = False
    missing = ['WORKFLOW_BASELINE_MISSING:superpowers']

    def to_dict(self) -> dict:
        return {'missing': self.missing}


class FreshInstallBaselineTests(unittest.TestCase):
    def test_fresh_install_writes_the_sync_record_and_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'project'
            INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection(('qwen',)))
            record = json.loads((target / '.getzilla' / 'AGBP_SYNC.json').read_text(encoding='utf-8'))
            self.assertEqual(record, {'kept_local': [], 'kept_local_sha256': {}, 'schema_version': 1})
            self.assertEqual(INSTALL._kept_local(target), frozenset())
            environment = {key: value for key, value in os.environ.items() if key not in {'CI', 'GITHUB_ACTIONS'}}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch('getzilla.baseline.inspect', return_value=Incomplete()), \
                    mock.patch('getzilla.baseline.detect_agent', return_value='qwen'):
                check = _workflow_baseline_check(target, 'pr')[0]
        self.assertNotEqual(check.summary, NOT_INSTALLED_SKIP)
        self.assertEqual(check.status, 'fail', check.summary)


if __name__ == '__main__':
    unittest.main()
