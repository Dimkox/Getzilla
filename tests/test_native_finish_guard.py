"""The original finish guard must consume the same pinned native inputs."""
import os
import hashlib
import json
import sys
import unittest

from tests._support import PROJECT, project_copy
sys.path.insert(0, str(PROJECT/'.getzilla'))
from getzilla import state
from getzilla.agent_lifecycle import start_agent
from getzilla.continuity import _ensure_idle
from getzilla.router import build_route
from getzilla.trace_storage import native_root
from getzilla import receipts
from unittest.mock import patch

SESSION = '00000000-0000-4000-8000-000000000001'


class NativeWorkerGuardTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.root = self.enterContext(project_copy(minimal_runtime=True))
        self.addCleanup(os.fchdir, saved)
        self.addCleanup(state.bind_session, None)
        os.chdir(self.root)
        self.root.chmod(0o755)
        (self.root/'.getzilla').chmod(0o755)
        state.bind_session(SESSION)
        self.route = build_route(self.root, 'Fix a README typo.', SESSION).to_dict()
        state.set_active_route(self.root, self.route)
        (self.root/'.getzilla/runtime').chmod(0o700)

    def worker(self):
        start_agent(self.root, 'native-fixture-worker', self.route['write_agent'])
        state.agent_state_path(self.root).chmod(0o600)

    def test_original_idle_check_accepts_missing_ledger_through_anchor(self):
        with native_root(self.root) as anchor:
            _ensure_idle(self.root, anchor=anchor)

    def test_actual_running_worker_still_refuses_original_finish_guard(self):
        self.worker()
        with native_root(self.root) as anchor:
            with self.assertRaisesRegex(ValueError, 'active or interrupted worker'):
                _ensure_idle(self.root, anchor=anchor)

    def test_unqualified_worker_file_cannot_be_read_as_idle(self):
        self.worker()
        state.agent_state_path(self.root).chmod(0o644)
        with native_root(self.root) as anchor:
            with self.assertRaisesRegex(ValueError, 'worker state is unavailable'):
                _ensure_idle(self.root, anchor=anchor)

    def test_parent_replacement_cannot_substitute_empty_foreign_worker_ledger(self):
        self.worker()
        original = self.root
        displaced = self.root.with_name(self.root.name+'-moved')
        with native_root(original) as anchor:
            original.rename(displaced)
            try:
                original.mkdir(mode=0o755)
                (original/'.getzilla/runtime').mkdir(parents=True)
                foreign = original/'.getzilla/runtime/agent-state.json'
                foreign.write_text('{"active":{},"history":[]}')
                before = foreign.read_bytes()
                with self.assertRaisesRegex(ValueError, 'active or interrupted worker'):
                    _ensure_idle(original, anchor=anchor)
                self.assertEqual(foreign.read_bytes(), before)
            finally:
                import shutil
                shutil.rmtree(original)
                displaced.rename(original)


class NativeReceiptGuardTests(unittest.TestCase):
    def setUp(self):
        saved = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, saved)
        self.root = self.enterContext(project_copy(minimal_runtime=True))
        self.addCleanup(os.fchdir, saved)
        os.chdir(self.root)
        self.root.chmod(0o755)
        (self.root/'.getzilla').chmod(0o755)
        self.route_id = '0123456789ab'  # Synthetic parser fixture, never a native completion.
        self.relative = f'.getzilla/runtime/receipts/{self.route_id}'
        directory = self.root/self.relative
        directory.mkdir(parents=True)
        for part in (self.root/'.getzilla/runtime', directory.parent, directory):
            part.chmod(0o700)

    def write(self, relative, value):
        path = self.root/relative
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_original_receipt_reader_uses_same_anchor_without_root_hint_open(self):
        self.write(self.relative+'/verification.json', {'status':'fail','details':{}})
        with native_root(self.root) as anchor:
            with patch.object(receipts, '_open_receipt_directory', side_effect=AssertionError('path fallback')):
                actual = receipts.get_receipt(self.root, self.route_id, 'verification', anchor=anchor)
        self.assertEqual(actual, {'status':'fail','details':{}})

    def test_missing_receipt_stays_missing(self):
        with native_root(self.root) as anchor:
            self.assertIsNone(receipts.get_receipt(self.root, self.route_id, 'verification', anchor=anchor))

    def test_public_or_hardlinked_receipt_cannot_qualify_native_guard(self):
        path = self.write(self.relative+'/verification.json', {'status':'fail','details':{}})
        for kind in ('mode','hardlink'):
            with self.subTest(kind=kind):
                if kind == 'mode':
                    path.chmod(0o644)
                else:
                    path.chmod(0o600)
                    os.link(path, path.with_suffix('.extra'))
                with native_root(self.root) as anchor:
                    with self.assertRaises(RuntimeError):
                        receipts.get_receipt(self.root, self.route_id, 'verification', anchor=anchor)

    def test_spilled_verification_details_keep_original_digest_and_binding_checks(self):
        reports = self.root/self.relative/'reports'
        reports.mkdir(mode=0o700)
        envelope = {'status':'fail','details':{}}
        details = {'synthetic_failed_control':'x'*300_000}
        artifact = {'schema_version':1,'binding':{'status':'fail'},'details':details}
        content = json.dumps(artifact).encode()
        digest = hashlib.sha256(content).hexdigest()
        path = reports/(digest+'.json')
        path.write_bytes(content)
        path.chmod(0o600)
        envelope['details'] = {'_verification_report':{
            'contract':receipts.VERIFICATION_REPORT_CONTRACT,
            'path':self.relative+'/reports/'+digest+'.json','sha256':digest,'bytes':len(content)}}
        self.write(self.relative+'/verification.json', envelope)
        with native_root(self.root) as anchor:
            actual = receipts.get_receipt(self.root, self.route_id, 'verification', anchor=anchor)
            self.assertEqual(actual['details'], details)
        path.write_bytes(content+b' ')
        with native_root(self.root) as anchor:
            with self.assertRaisesRegex(RuntimeError, 'digest or byte count'):
                receipts.get_receipt(self.root, self.route_id, 'verification', anchor=anchor)
