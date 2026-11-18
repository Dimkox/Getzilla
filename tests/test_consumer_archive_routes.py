"""Closed engine source assessment and terminal cancellation in owned consumers."""
from __future__ import annotations

import io
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.getzilla'), str(ROOT / 'scripts')]
from getzilla.baseline_assets import archive_entries
from getzilla.review_plan import assess
from getzilla.verification import GitRangeBase, GitRangeSelection
from tests.branch_support import env, git


def packed(members, *, compression=zipfile.ZIP_DEFLATED, mode=0o644, stamp=(1980, 1, 1, 0, 0, 0)):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, body in sorted(members.items()):
            item = zipfile.ZipInfo(name, stamp)
            item.compress_type = compression
            item.external_attr = mode << 16
            archive.writestr(item, body)
    return output.getvalue()


class EngineArchiveAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, 'init', '-q', '-b', 'work')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n')
        self.write('.getzilla/config/toolchain.json', b'{"workflow_sources":{"components":[]}}')
        self.write('app.py', b'value = 1\n')
        self.base = self.commit()

    def write(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)

    def commit(self):
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'owned fixture')
        return git(self.root, 'rev-parse', 'HEAD')

    def assessment(self):
        return assess(self.root, {}, GitRangeSelection([GitRangeBase('route', 'fixture', self.base, self.base)]))

    def test_added_changed_deleted_members_and_both_container_identities(self):
        self.write('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'a = 1\n', 'getzilla/b.py': b'b = 2\n'}))
        self.base = self.commit()
        self.write('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'a = 3\n', 'getzilla/c.py': b'c = 4\n'}))
        self.commit()
        result = self.assessment()
        self.assertEqual(result['risk_assessment']['status'], 'complete', result)
        self.assertEqual(result['risk'], 'high')
        self.assertEqual(set(result['review_agents']), {'code_reviewer', 'security_reviewer', 'data_reviewer', 'release_reviewer'})
        sources = result['risk_assessment']['engine_sources']
        self.assertEqual(len(sources['containers']), 2)
        self.assertTrue(all(len(item['sha256']) == 64 and item['mode'] == '100644' for item in sources['containers']))
        self.assertEqual(sources['comparisons'][0]['changed_members'], [
            {'path': '.getzilla/getzilla/a.py', 'status': 'M'},
            {'path': '.getzilla/getzilla/b.py', 'status': 'D'},
            {'path': '.getzilla/getzilla/c.py', 'status': 'A'}])
        self.assertEqual(sum(len(item['members']) for item in sources['containers']), 4)

    def test_unsafe_archives_other_binary_and_loose_conflicts_remain_closed(self):
        cases = [('.getzilla/getzilla.zip', b'unknown'),
                 ('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'x=1\n'}, mode=0o755)),
                 ('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'x=1\n'}, stamp=(2000, 1, 1, 0, 0, 0))),
                 ('other.zip', packed({'getzilla/a.py': b'x=1\n'}))]
        for name, body in cases:
            with self.subTest(name=name, body_length=len(body)):
                git(self.root, 'reset', '--hard', self.base)
                git(self.root, 'clean', '-fd')
                self.write(name, body)
                self.commit()
                self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', self.assessment()['risk_assessment']['gaps'])
        git(self.root, 'reset', '--hard', self.base)
        git(self.root, 'clean', '-fd')
        self.write('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'x=1\n'}))
        self.write('.getzilla/getzilla/a.py', b'x=2\n')
        self.commit()
        self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', self.assessment()['risk_assessment']['gaps'])

    def test_invalid_base_is_not_hidden_by_valid_head(self):
        self.write('.getzilla/getzilla.zip', b'invalid\0zip')
        self.base = self.commit()
        self.write('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'x=1\n'}))
        self.commit()
        self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', self.assessment()['risk_assessment']['gaps'])

    def test_git_modes_and_incomplete_resource_closure_remain_closed(self):
        self.write('.getzilla/getzilla.zip', packed({'getzilla/a.py': b'x=1\n'}))
        good = self.commit()
        oid = git(self.root, 'rev-parse', 'HEAD:.getzilla/getzilla.zip')
        for mode in ('100755', '120000'):
            with self.subTest(mode=mode):
                git(self.root, 'reset', '--hard', good)
                git(self.root, 'update-index', '--cacheinfo', mode + ',' + oid + ',.getzilla/getzilla.zip')
                git(self.root, 'commit', '-qm', 'unsafe source mode')
                self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', self.assessment()['risk_assessment']['gaps'])
        git(self.root, 'reset', '--hard', good)
        blob = b'owned resource\n'
        manifest = json.dumps({'files': [{'sha256': hashlib.sha256(blob).hexdigest(), 'bytes': len(blob)}]}).encode()
        path = '.getzilla/templates/baseline/owned.json'
        self.write(path, manifest)
        self.write('.getzilla/config/toolchain.json', json.dumps({'workflow_sources': {'components': [
            {'generated_assets': {'owned': {'path': path, 'sha256': hashlib.sha256(manifest).hexdigest()}}}]}}).encode())
        self.commit()
        self.assertIn('BINARY_OR_UNKNOWN_INVENTORY', self.assessment()['risk_assessment']['gaps'])

    def test_canonical_optin_preserves_legacy_decoder(self):
        legacy = packed({'getzilla/a.py': b'x=1\n'}, compression=zipfile.ZIP_STORED, stamp=(2000, 1, 1, 0, 0, 0))
        self.assertEqual(archive_entries(legacy)['.getzilla/getzilla/a.py'][0], b'x=1\n')
        with self.assertRaises(ValueError):
            archive_entries(legacy, canonical=True)

    def test_complete_catalogue_refuses_before_accounting_at_existing_route_bound(self):
        from getzilla import state
        from getzilla.continuity import submit
        from getzilla.review_plan import reconcile_route
        self.write('.getzilla/getzilla.zip', packed({'getzilla/' + 'a' * 240 + str(i) + '.py': b'x=1\n'
                                                    for i in range(4096)}))
        self.commit()
        state.bind_session('owned-catalogue-fixture')
        submit(self.root, 'Implement ordinary small fix', 'owned-catalogue-fixture')
        before = state.get_active_route(self.root)
        selection = GitRangeSelection([GitRangeBase('route', 'fixture', self.base, self.base)])
        with patch('getzilla.package_status.synchronize_accounting') as accounting:
            with self.assertRaisesRegex(ValueError, 'route byte bound'):
                reconcile_route(self.root, selection=selection)
            accounting.assert_not_called()
        self.assertEqual(state.get_active_route(self.root), before)


class ActualArchivedConsumerTests(unittest.TestCase):
    def test_pre_onboarding_base_route_to_review_receipt(self):
        import install_into
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            consumer = Path(temporary) / 'consumer'
            # No dependency installer, model, network, factory or external service.
            with patch('socket.socket', side_effect=AssertionError('network forbidden')):
                install_into._materialize_new(ROOT, consumer, include_dependencies=False, include_optional=False,
                    selection=install_into.PayloadSelection(('codex',), engine_archive=True))
            (consumer / 'app.py').write_text('value = 1\n')
            (consumer / '.gitignore').write_text('.getzilla/runtime/\n')
            git(consumer, 'init', '-q', '-b', 'work')
            git(consumer, 'add', 'app.py', '.gitignore')
            git(consumer, 'commit', '-qm', 'before onboarding')
            base = git(consumer, 'rev-parse', 'HEAD')
            git(consumer, 'update-ref', 'refs/remotes/origin/main', base)
            git(consumer, 'add', '.')
            git(consumer, 'commit', '-qm', 'actual archive onboarding')
            script = r'''
import json,sys
from pathlib import Path
root=Path.cwd()
sys.path.insert(0,str(root/'.getzilla'))
import socket,subprocess
def denied(*args,**kwargs):
    raise AssertionError('owned consumer network forbidden')
class NoNetwork(socket.socket):
    def __init__(self,*args,**kwargs):
        denied()
socket.socket=NoNetwork
socket.getaddrinfo=denied
run=subprocess.run
def local_git(command,*args,**kwargs):
    assert command[0]=='git','only owned local Git is allowed'
    return run(command,*args,**kwargs)
subprocess.run=local_git
from getzilla.state import bind_session,get_active_route
from getzilla.continuity import submit,package_documents,ack_scope,context_binding
from getzilla.change import start_change
from getzilla.review_plan import reconcile_route
from getzilla.receipts import write_receipt
from getzilla.util import git_head
bind_session('owned-consumer-fixture')
r=submit(root,'Implement ordinary owned consumer correction','owned-consumer-fixture')
assert r['base_commit']==sys.argv[1]
r=reconcile_route(root)
assert r['risk_assessment']['status']=='complete',r['risk_assessment']
assert set(r['review_agents'])=={'code_reviewer','security_reviewer','data_reviewer','release_reviewer'}
s=start_change(root,'Owned archive consumer fixture')
p=root/'.getzilla/runtime/changes'/s['change_id']
spec=json.loads((p/'change-spec.yaml').read_text())
spec['acceptance_criteria']=[{'id':'AC-001','statement':'Owned consumer fixture only','evidence':[{'receipt':'code_review'}]}]
spec['objective'].update(success_metric='owned consumer receipt',target='source-bound fixture receipt')
spec['risk']['tier']='yellow'
(p/'change-spec.yaml').write_text(json.dumps(spec))
(p/'requirements.md').write_text('Owned fixture original scope. No external authority.')
r=get_active_route(root);d=package_documents(root,r)
ack_scope(root,{'version':1,'operation_id':'owned-original','route_id':r['route_id'],'logical_task_id':r['logical_task_id'],'authority_epoch':0,'revision':r['context']['revision'],'spec_digest':d['spec_digest'],'requirements_digest':d['requirements_digest'],'items':{'original':['AC-001']}})
r=reconcile_route(root); observed=context_binding(root)
report=p/'evidence/code-review.md'
report.write_text('Synthetic owned fixture review only.\nreviewed-context-digest: '+observed['digest']+'\n')
receipt=write_receipt(root,'code_review','pass',report.relative_to(root).as_posix(),reviewed_commit=git_head(root),reviewed_context=observed['digest'])
assert receipt.is_file()
print(json.dumps({'base':r['base_commit'],'status':r['risk_assessment']['status'],'receipt':True,'members':sum(len(c['members']) for c in r['risk_assessment']['engine_sources']['containers'])}))
'''
            result = subprocess.run([sys.executable, '-B', '-c', script, base], cwd=consumer, env=env(),
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            observed = json.loads(result.stdout)
            self.assertEqual(observed['base'], base)
            self.assertTrue(observed['receipt'])
            self.assertGreater(observed['members'], 100)


class TerminalCancelledRouteTests(unittest.TestCase):
    def test_split_package_cancellation_names_explicit_recovery(self):
        from getzilla import state
        from getzilla.change import start_change, transition
        from getzilla.continuity import submit, finish_task
        from getzilla.review_plan import reconcile_route
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            git(root, 'init', '-q', '-b', 'work')
            (root / '.gitignore').write_text('.getzilla/runtime/\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'owned consumer')
            state.bind_session('owned-cancel-fixture')
            submit(root, 'Implement ordinary small fix', 'owned-cancel-fixture')
            shutil.copytree(ROOT / '.getzilla/templates/change', root / '.getzilla/templates/change')
            package = start_change(root)
            with patch('getzilla.change.update_route', side_effect=RuntimeError('owned publication fault')):
                with self.assertRaises(RuntimeError):
                    transition(root, package['change_id'], 'cancelled', 'owner cancels fixture')
            before = {p.relative_to(root): p.read_bytes() for p in (root / '.getzilla/runtime').rglob('*.json')}
            with self.assertRaisesRegex(ValueError, 'use route --cancel'):
                reconcile_route(root)
            after = {p.relative_to(root): p.read_bytes() for p in (root / '.getzilla/runtime').rglob('*.json')}
            self.assertEqual(before, after)
            closed = finish_task(root, cancel=True)
            self.assertEqual(reconcile_route(root), closed)
            with self.assertRaisesRegex(ValueError, 'cancelled.*terminal'):
                finish_task(root)

    def test_cancelled_reconcile_is_readonly_and_complete_is_explicit(self):
        from getzilla import state
        from getzilla.continuity import submit, finish_task
        from getzilla.review_plan import reconcile_route
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as temporary:
            root = Path(temporary)
            git(root, 'init', '-q', '-b', 'work')
            (root / '.gitignore').write_text('.getzilla/runtime/\n')
            (root / 'app.py').write_text('x=1\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'owned consumer')
            state.bind_session('owned-cancel-fixture')
            submit(root, 'Implement ordinary small fix', 'owned-cancel-fixture')
            cancelled = finish_task(root, cancel=True)
            before = {p.relative_to(root): p.read_bytes() for p in (root / '.getzilla/runtime').rglob('*.json')}
            self.assertEqual(reconcile_route(root), cancelled)
            after = {p.relative_to(root): p.read_bytes() for p in (root / '.getzilla/runtime').rglob('*.json')}
            self.assertEqual(before, after)
            with self.assertRaisesRegex(ValueError, 'cancelled.*terminal'):
                finish_task(root)
            self.assertEqual(state.get_active_route(root), cancelled)
            with patch('getzilla.continuity._ensure_idle', side_effect=ValueError('owned active worker')):
                with self.assertRaisesRegex(ValueError, 'active worker'):
                    reconcile_route(root)
            state.bind_session('foreign-owner')
            with self.assertRaises(ValueError):
                reconcile_route(root)
