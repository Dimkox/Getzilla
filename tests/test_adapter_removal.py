"""Owned public adapter fixtures: planning is inert; publication uses Git rollback."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.getzilla'), str(ROOT / 'scripts')]

from getzilla import harnesses  # noqa: E402
from getzilla import adapter_removal as publication  # noqa: E402
from getzilla.component_state import MANIFEST, V2, BoundRoot, encode_manifest, record_owned  # noqa: E402


def _assert_publication_modes(case: unittest.TestCase, operation: str) -> None:
    """The setup child owns022; only its separate operation child owns the tested mask."""
    program = r'''
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]); mask=int(sys.argv[2]); operation=sys.argv[3]
index_kind=sys.argv[4]; linked=sys.argv[5]=='linked'
sys.path[:0]=[str(root),str(root/'scripts'),str(root/'.getzilla')]
from getzilla import adapter_removal as publication
from getzilla.component_state import MANIFEST,STACK_SYNC_RECORD,encode_manifest,mode_matches,record_owned
from tests.test_adapter_removal import RemovalGitTests
from tests.test_getzilla_upgrade import ProjectSyncTests
fixture=(RemovalGitTests('test_git_removal_idempotence_selection_and_rollback') if operation=='remove'
         else ProjectSyncTests('test_owned_old_file_upgrades_with_its_proof_in_the_same_commit'))
fixture.setUp()
try:
    project=fixture.project
    runtime=project/'.getzilla/runtime'; runtime.mkdir(exist_ok=True)
    (runtime/'.gitignore').write_bytes((root/'.getzilla/runtime/.gitignore').read_bytes())
    retained={}
    for mode in (0o600,0o640,0o440):
        name=f'public-retained-{mode:o}.txt'; path=project/name
        path.write_bytes(b'public retained bytes'); path.chmod(mode)
    keep='public-retained-440.txt'
    (project/STACK_SYNC_RECORD).write_text(json.dumps({'schema_version':1,'kept_local':[keep],
        'kept_local_sha256':{keep:hashlib.sha256((project/keep).read_bytes()).hexdigest()}}))
    if operation=='update':
        manifest=fixture.select(())
        executable='scripts/getzilla_components.py'; path=project/executable
        path.parent.mkdir(); path.write_bytes(b'# public previous executable\n'); path.chmod(0o755)
        record_owned(manifest,executable,path.read_bytes(),0o755)
        (project/MANIFEST).write_bytes(encode_manifest(manifest))
        fixture.commit('public managed-mode fixture')
    else:
        fixture.git('add','-A'); fixture.git('commit','--quiet','-m','public retained modes')
    def git(*args):
        return subprocess.run(['git','-C',str(project),*args],check=True,capture_output=True,text=True,
                              env={**os.environ,'GIT_OPTIONAL_LOCKS':'0'}).stdout.strip()
    if linked:
        destination=project.parent/'linked-consumer'
        git('worktree','add','--quiet','-b','public-linked',str(destination))
        project=fixture.project=destination
    for mode in (0o600,0o640,0o440):
        name=f'public-retained-{mode:o}.txt'; path=project/name; path.chmod(mode)
        retained[name]=(path.read_bytes(),stat.S_IMODE(path.stat().st_mode),path.stat().st_ino)
    original=git('rev-parse','HEAD')
    original_branch=git('branch','--show-current'); original_refs=git('show-ref','--heads')
    admin={}; admin_paths={}
    for name in ('index','config'):
        path=Path(git('rev-parse','--git-path',name))
        path=path if path.is_absolute() else project/path
        admin_paths[name]=path
        path.chmod(0o644 if name=='index' else 0o600)
    index=admin_paths['index']; canary=None
    if index_kind=='absent': index.unlink()
    elif index_kind=='symlink':
        canary=project.parent/'public-index-canary'; canary.write_bytes(index.read_bytes())
        canary.chmod(0o600); index.unlink(); index.symlink_to(canary)
    elif os.name=='posix': index.chmod(int(index_kind,8))
    def snapshot(path):
        if not path.exists() and not path.is_symlink(): return None
        info=path.lstat()
        return (info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest())
    admin={n:snapshot(p) for n,p in admin_paths.items()}
    canary_before=snapshot(canary) if canary else None
    original_status=git('status','--porcelain')
    caller=r"""
import json,os,stat,sys
from pathlib import Path
from unittest import mock
root,project,operation=Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3]
sys.path[:0]=[str(root/'scripts'),str(root/'.getzilla')]
from getzilla import adapter_removal
import getzilla_upgrade
before=project.parent/'caller-before'; after=project.parent/'caller-after'
before.write_bytes(b'public mask sentinel'); cwd=Path.cwd(); session=os.environ.get('GETZILLA_SESSION_ID')
result={'operation_succeeded':False,'error_type':None,'unsupported_checkout_reason':False}
try:
    with mock.patch.object(os,'umask',side_effect=AssertionError('process-global mask change')), \
         mock.patch.object(adapter_removal,'commit_changes',wraps=adapter_removal.commit_changes) as committed:
        if operation=='remove': adapter_removal.remove_adapters(root,project)
        else: getzilla_upgrade.sync_project(root,project)
    result['operation_succeeded']=True
except (adapter_removal.UpdateError,OSError,AssertionError) as error:
    result['error_type']=type(error).__name__
    result['unsupported_checkout_reason']='mode-preserving checkout' in str(error)
after.write_bytes(b'public mask sentinel')
result.update(caller_mode_before=stat.S_IMODE(before.stat().st_mode),
              caller_mode_after=stat.S_IMODE(after.stat().st_mode),
              commit_calls=committed.call_count,
              caller_state_unchanged=Path.cwd()==cwd and os.environ.get('GETZILLA_SESSION_ID')==session)
print(json.dumps(result))
"""
    options={'umask':mask} if os.name=='posix' else {}
    done=subprocess.run([sys.executable,'-B','-c',caller,str(root),str(project),operation],
                        capture_output=True,text=True,timeout=60,**options)
    if done.returncode: raise AssertionError('isolated operation caller did not report')
    result=json.loads(done.stdout)
    admin_after={n:snapshot(p) for n,p in admin_paths.items()}
    current=git('rev-parse','HEAD'); branch=git('branch','--show-current')
    changed=git('diff','--name-only',original,current).splitlines()
    modes_ok=True; present=0
    for name in changed:
        path=project/name
        if not path.exists(): continue
        mode=git('ls-tree',current,'--',name).split()[0]
        expected=0o755 if mode=='100755' else 0o644
        modes_ok=modes_ok and mode_matches(path.stat().st_mode,expected)
        present+=1
    result.update(head_moved=current!=original,
        parent_is_original=git('rev-parse','HEAD^')==original if current!=original else False,
        expected_branch=branch.startswith('getzilla-remove-' if operation=='remove' else 'getzilla-update-'),
        working_tree_clean=not git('status','--porcelain'),planned_modes_preserved=modes_ok,
        changed_present_count=present,
        manifest_mode=stat.S_IMODE((project/MANIFEST).stat().st_mode),
        retained_preserved=all((project/n).read_bytes()==v[0] and
            stat.S_IMODE((project/n).stat().st_mode)==v[1] and (project/n).stat().st_ino==v[2]
            for n,v in retained.items()),
        admin_modes_before=admin,
        admin_modes_after=admin_after)
    # Successful checkout may replace index identity/bytes; its declared mode stays exact.
    result['admin_modes_preserved']=all(v is not None and admin_after[n] is not None and
        v[2]==admin_after[n][2] for n,v in admin.items())
    result['refusal_admin_exact']=admin==admin_after
    result['refusal_state_exact']=(current==original and branch==original_branch and
        git('show-ref','--heads')==original_refs and git('status','--porcelain')==original_status)
    result['canary_exact']=snapshot(canary)==canary_before if canary else True
    result['caller_mask_preserved']=(result['caller_mode_before']==result['caller_mode_after'] and
        (os.name!='posix' or result['caller_mode_after']==0o666 & ~mask))
    if operation=='update':
        result['executable_mode_preserved']=mode_matches((project/executable).stat().st_mode,0o755)
    print(json.dumps(result))
finally:
    fixture.doCleanups()
'''
    scenarios = ([(mask, '644', 'ordinary', True) for mask in (0o022, 0o002, 0o077)]
                 + [(0o022, mode, 'ordinary', False) for mode in ('600', '640', '664', 'absent', 'symlink')]
                 + [(0o002, '644', 'linked', True), (0o022, '600', 'linked', False)]
                 if os.name == 'posix' else [(-1, '644', 'ordinary', True)])
    for mask, index_kind, layout, success in scenarios:
        with case.subTest(operation=operation, caller_mask=mask, index=index_kind, layout=layout):
            options = {'umask': 0o022} if os.name == 'posix' else {}
            completed = subprocess.run([sys.executable, '-B', '-c', program, str(ROOT), str(mask), operation,
                                        index_kind, layout],
                                       capture_output=True, text=True, timeout=90, **options)
            case.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            for name in ('retained_preserved', 'caller_mask_preserved', 'caller_state_unchanged', 'canary_exact'):
                case.assertTrue(result[name], json.dumps({'failed_contract': name, **result}, sort_keys=True))
            if success:
                for name in ('operation_succeeded', 'head_moved', 'parent_is_original', 'expected_branch',
                             'working_tree_clean', 'planned_modes_preserved', 'admin_modes_preserved'):
                    case.assertTrue(result[name], json.dumps({'failed_contract': name, **result}, sort_keys=True))
                case.assertEqual(result['commit_calls'], 1)
                case.assertGreater(result['changed_present_count'], 0)
                if operation == 'update':
                    case.assertTrue(result['executable_mode_preserved'])
            else:
                case.assertFalse(result['operation_succeeded'], json.dumps(result, sort_keys=True))
                case.assertTrue(result['unsupported_checkout_reason'], json.dumps(result, sort_keys=True))
                case.assertEqual(result['commit_calls'], 0)
                case.assertTrue(result['refusal_admin_exact'], json.dumps(result, sort_keys=True))
                case.assertTrue(result['refusal_state_exact'], json.dumps(result, sort_keys=True))


class RemovalPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name) / 'project'
        self.project.mkdir()
        self.selected = (*harnesses.HARNESSES, 'cursor')
        with BoundRoot(ROOT) as source:
            self.outputs = harnesses._render(source, self.selected)
        self.manifest = {'schema_version': V2, 'agents': list(self.selected), 'components': {}}
        for path, content in self.outputs.items():
            self.put(path, content)
        self.put('.codex/user.txt', b'foreign user bytes', owned=False)
        self.save()

    def put(self, path: str, content: bytes, *, owned: bool = True, mode: int = 0o644) -> None:
        target = self.project / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
        if owned:
            record_owned(self.manifest, path, content, mode)

    def save(self) -> None:
        self.put(MANIFEST, encode_manifest(self.manifest), owned=False)

    def plan(self, agents=None):
        from getzilla.adapter_removal import plan_removal
        with BoundRoot(self.project) as binding:
            return plan_removal(ROOT, binding, agents)

    def test_all_formats_preserve_entire_and_unknown_without_publication(self) -> None:
        before = copy.deepcopy(self.manifest)
        plan = self.plan()
        self.assertEqual(plan.manifest['agents'], [])
        changes = {p: c for p, c, _ in plan.changes}
        for agent in ('qwen', 'claude', 'gemini', 'grok'):
            path = f'.{agent}/' + ('hooks.json' if agent == 'grok' else 'settings.json')
            self.assertIsNone(changes[path], path)
        self.assertIsNone(changes['.github/hooks/getzilla.json'])
        self.assertIsNotNone(changes['.codex/hooks.json'])
        codex = json.loads(changes['.codex/hooks.json'])
        commands = str(codex)
        self.assertIn('entire hooks codex', commands)
        self.assertNotIn('.getzilla/hooks/', commands)
        self.assertNotIn('.codex/config.toml', changes)
        self.assertNotIn('.codex/user.txt', changes)
        self.assertEqual(self.manifest, before)
        self.assertEqual((self.project / MANIFEST).read_bytes(), encode_manifest(before))
        self.assertEqual(plan.native_state, 'unverified')
        self.assertTrue(all((self.project / p).exists() for p, c in self.outputs.items()))

    def test_custom_native_fields_and_hook_groups_survive_exact_subtraction(self) -> None:
        path = '.claude/settings.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'type': 'command', 'command': 'echo public-fixture-only'}]}
        data['hooks']['Stop'].append(foreign)
        data['user'] = {'retain': True}
        self.put(path, json.dumps(data).encode())
        self.save()
        plan = self.plan(('claude',))
        contents = dict((p, c) for p, c, _ in plan.changes)[path]
        self.assertIsNotNone(contents)
        result = json.loads(contents)
        self.assertEqual(result, {'hooks': {'Stop': [foreign]}, 'user': {'retain': True}})
        self.assertNotIn(path, plan.manifest['components']['agent:claude'].get('owned', {}))
        self.assertEqual(plan.manifest['agents'], [x for x in self.selected if x != 'claude'])

    def test_changed_bytes_mode_missing_proof_and_kept_paths_refuse(self) -> None:
        path = '.codex/agents/general_implementer.toml'
        original = (self.project / path).read_bytes()
        for scenario in ('bytes', 'mode', 'proof', 'owned-custom-policy', 'kept'):
            with self.subTest(scenario=scenario):
                (self.project / path).chmod(0o644)  # reset only the preceding owned fixture case
                self.put(path, original)
                if scenario == 'bytes':
                    self.put(path, original + b'\n# changed', owned=False)
                elif scenario == 'mode':
                    (self.project / path).chmod(0o444)
                elif scenario == 'proof':
                    self.manifest['components']['agent:codex']['owned'].pop(path)
                elif scenario == 'owned-custom-policy':
                    self.put(path, original.replace(b'workspace-write', b'read-only'))
                elif scenario == 'kept':
                    self.put('.getzilla/AGBP_SYNC.json', json.dumps({'schema_version': 1, 'kept_local': [path]}).encode(), owned=False)
                self.save()
                manifest_before = (self.project / MANIFEST).read_bytes()
                content_before = (self.project / path).read_bytes()
                mode_before = (self.project / path).stat().st_mode
                with self.assertRaises(ValueError):
                    self.plan(('codex',))
                self.assertEqual((self.project / MANIFEST).read_bytes(), manifest_before)
                self.assertEqual((self.project / path).read_bytes(), content_before)
                self.assertEqual((self.project / path).stat().st_mode, mode_before)

    def test_modified_duplicate_and_invalid_native_groups_refuse(self) -> None:
        path = '.qwen/settings.json'
        data = json.loads(self.outputs[path])
        modified = copy.deepcopy(data)
        modified['hooks']['Stop'][0]['hooks'][0]['command'] += ' changed'
        duplicated = copy.deepcopy(data)
        duplicated['hooks']['Stop'] *= 2
        for content in (json.dumps(modified).encode(), json.dumps(duplicated).encode(), b'{"hooks":{},"hooks":{}}', b'[]'):
            with self.subTest(content=content[:25]):
                self.put(path, content)
                self.save()
                with self.assertRaises(ValueError):
                    self.plan(('qwen',))

    def test_unselected_and_unknown_component_files_are_retained(self) -> None:
        self.put('.codex/private-unknown.toml', b'not a Getzilla generated role')
        self.save()
        plan = self.plan(('claude',))
        paths = {p for p, _, _ in plan.changes}
        self.assertFalse(any(p.startswith('.codex/') for p in paths))
        self.assertNotIn('.codex/private-unknown.toml', paths)

    def test_unowned_custom_codex_activation_stays_when_entire_remains(self) -> None:
        path = '.codex/config.toml'
        self.put(path, b'[features]\ncodex_hooks = true\n[user]\nretain = true\n', owned=False)
        self.manifest['components']['agent:codex']['owned'].pop(path)
        self.save()
        plan = self.plan(('codex',))
        self.assertNotIn(path, {p for p, _, _ in plan.changes})
        self.assertIn(path, plan.retained)

    def test_remaining_grok_hooks_keep_unowned_custom_activation(self) -> None:
        path = '.grok/hooks.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'command': 'echo public foreign'}]}
        data['hooks']['Stop'].append(foreign)
        self.put(path, json.dumps(data).encode())
        config = b'[features]\nhooks = true\n[user]\nretain = true\n'
        self.put('.grok/config.toml', config, owned=False)
        self.save()
        plan = self.plan(('grok',))
        self.assertNotIn('.grok/config.toml', {p for p, _, _ in plan.changes})
        self.assertIn('.grok/config.toml', plan.retained)
        self.assertEqual((self.project / '.grok/config.toml').read_bytes(), config)
        self.assertEqual(json.loads(dict((p, c) for p, c, _ in plan.changes)[path]), {'hooks': {'Stop': [foreign]}})

    def test_remaining_qwen_hooks_keep_their_context(self) -> None:
        path = '.qwen/settings.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'command': 'echo public foreign'}]}
        data['hooks']['Stop'].append(foreign)
        self.put(path, json.dumps(data).encode())
        self.save()
        plan = self.plan(('qwen',))
        result = json.loads(dict((p, c) for p, c, _ in plan.changes)[path])
        self.assertEqual(result, {'context': data['context'], 'hooks': {'Stop': [foreign]}})

    def test_manifest_keep_and_native_resource_limits_refuse_without_effect(self) -> None:
        from getzilla.adapter_removal import MAX_NATIVE_BYTES
        path = '.qwen/settings.json'
        for content in (b'{"hooks":{},"padding":"' + b'x' * MAX_NATIVE_BYTES + b'"}',
                        b'{"hooks":{"Stop":' + b'[' * 1100 + b']' * 1100 + b'}}',
                        b'{"hooks":{"Stop":[NaN]}}', b'{"hooks":{},"extra":1e309}', b'\xef\xbb\xbf{"hooks":{}}',
                        b'{"hooks":{},"extra":' + b'[' * 66 + b'0' + b']' * 66 + b'}',
                        b'{"hooks":{},"extra":"\\ud800"}'):
            with self.subTest(content=content[:25]):
                self.put(path, content)
                self.save()
                with self.assertRaises(ValueError):
                    self.plan(('qwen',))
        self.put(path, self.outputs[path])
        self.put('.getzilla/AGBP_SYNC.json', json.dumps({'schema_version': 1, 'kept_local': [MANIFEST]}).encode(), owned=False)
        self.save()
        with self.assertRaisesRegex(ValueError, 'kept component manifest'):
            self.plan(('qwen',))

    def test_native_output_remains_within_the_same_byte_bound(self) -> None:
        extra = ['x' * 100] * 1600
        for _ in range(58):
            extra = [extra]
        data = json.loads(self.outputs['.qwen/settings.json'])
        data['extra'] = extra
        compact = json.dumps(data, separators=(',', ':')).encode()
        self.assertLess(len(compact), 262144)
        self.put('.qwen/settings.json', compact)
        self.save()
        with self.assertRaisesRegex(ValueError, 'native configuration.*bound'):
            self.plan(('qwen',))


class RemovalGitTests(unittest.TestCase):
    put = RemovalPlanTests.put
    save = RemovalPlanTests.save

    def setUp(self) -> None:
        RemovalPlanTests.setUp(self)
        patch = mock.patch.dict(os.environ, {'GIT_AUTHOR_NAME': 'public fixture',
                                            'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                                            'GIT_COMMITTER_NAME': 'public fixture',
                                            'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'})
        patch.start()
        self.addCleanup(patch.stop)
        self.put('.getzilla/getzilla/__init__.py', b'# installed fixture marker\n', owned=False)
        self.git('init', '--quiet', '--initial-branch=main')
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'public installed adapter fixture')
        self.original = self.git('rev-parse', 'HEAD')

    def git(self, *args: str) -> str:
        return subprocess.run(['git', '-C', str(self.project), *args], check=True,
                              text=True, capture_output=True).stdout.strip()

    def remove(self, agents=None):
        import getzilla_upgrade
        return getzilla_upgrade.remove_adapters(ROOT, self.project, agents)

    def test_checkout_preserves_modes_in_isolated_callers(self) -> None:
        _assert_publication_modes(self, 'remove')

    def test_git_removal_idempotence_selection_and_rollback(self) -> None:
        from getzilla.component_state import read_state
        result = self.remove()
        removed_head = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.git('rev-parse', 'HEAD^'), self.original)
        self.assertEqual(result['live_client_state'], 'unverified')
        self.assertEqual(read_state(self.project).require_selection(), ())
        self.assertFalse((self.project / '.codex/agents/general_implementer.toml').exists())
        self.assertEqual((self.project / '.codex/user.txt').read_bytes(), b'foreign user bytes')
        self.assertIn('entire hooks codex', (self.project / '.codex/hooks.json').read_text())
        second = self.remove()
        self.assertEqual(second['configuration'], 'unchanged')
        self.assertEqual(self.git('rev-parse', 'HEAD'), removed_head)
        self.git('switch', '--quiet', 'main')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual((self.project / '.codex/agents/general_implementer.toml').read_bytes(),
                         self.outputs['.codex/agents/general_implementer.toml'])
        self.assertEqual(read_state(self.project).require_selection(), self.selected)

    def test_before_publication_cut_keeps_original_state_and_route(self) -> None:
        import getzilla_upgrade
        with mock.patch.object(publication, 'commit_changes', side_effect=OSError('public cut')):
            with self.assertRaises(getzilla_upgrade.UpdateError):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual((self.project / '.claude/settings.json').read_bytes(), self.outputs['.claude/settings.json'])

    def test_failed_checkout_retains_recoverable_commit_and_does_not_retry(self) -> None:
        import getzilla_upgrade
        original_git = publication.git
        switches = []

        def git(project, *args, **kwargs):
            if args[:2] == ('switch', '--quiet'):
                switches.append(args)
                return subprocess.CompletedProcess(args, 1, '', 'public checkout cut')
            return original_git(project, *args, **kwargs)

        with mock.patch.object(publication, 'git', side_effect=git):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'checking it out failed'):
                self.remove(('claude',))
        self.assertEqual(len(switches), 1)
        branch = switches[0][2]
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('rev-parse', branch + '^'), self.original)
        self.assertEqual((self.project / '.claude/settings.json').read_bytes(), self.outputs['.claude/settings.json'])
        self.git('switch', '--quiet', branch)
        self.assertFalse((self.project / '.claude/settings.json').exists())

    def test_current_file_cut_before_ref_leaves_product_and_branch_unpublished(self) -> None:
        import getzilla_upgrade
        original = publication.commit_changes
        changed = self.project / '.claude/settings.json'

        def commit(*args, **kwargs):
            result = original(*args, **kwargs)
            changed.write_bytes(b'{"user":"concurrent public fixture"}\n')
            return result

        with mock.patch.object(publication, 'commit_changes', side_effect=commit):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'uncommitted|file changed'):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertIn(b'concurrent public fixture', changed.read_bytes())

    def test_after_ref_cut_reports_retained_commit_without_checkout(self) -> None:
        import getzilla_upgrade
        original = publication._git_out
        changed = self.project / '.claude/settings.json'

        def git_out(project, *args, **kwargs):
            result = original(project, *args, **kwargs)
            if args[:2] == ('update-ref', '--stdin'):
                changed.write_bytes(b'{"user":"after ref public fixture"}\n')
            return result

        with mock.patch.object(publication, '_git_out', side_effect=git_out):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'retained.*checkout not completed'):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        branches = self.git('for-each-ref', '--format=%(refname:short)', 'refs/heads/getzilla-remove-*').splitlines()
        self.assertEqual(len(branches), 1)
        self.assertEqual(self.git('rev-parse', branches[0] + '^'), self.original)
        self.assertIn(b'after ref public fixture', changed.read_bytes())

    def test_nongit_dirty_source_and_invalid_selection_refuse(self) -> None:
        import getzilla_upgrade
        with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'source checkout'):
            getzilla_upgrade.remove_adapters(ROOT, ROOT)
        with self.assertRaises(getzilla_upgrade.UpdateError):
            self.remove(('unknown',))
        self.put('user.txt', b'uncommitted foreign', owned=False)
        with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'uncommitted'):
            self.remove()
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        with tempfile.TemporaryDirectory() as tmp:
            nongit = Path(tmp)
            (nongit / '.getzilla/getzilla').mkdir(parents=True)
            (nongit / '.getzilla/getzilla/__init__.py').write_bytes(b'')
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'root of a Git repository'):
                getzilla_upgrade.remove_adapters(ROOT, nongit)


if __name__ == '__main__':
    unittest.main()
