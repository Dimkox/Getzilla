"""Owned cache fixtures; Git and Windows error/attribute observations are explicit mocks."""
import errno
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'.getzilla'))
from getzilla import baseline


class CacheCleanupTests(unittest.TestCase):
    def setUp(self):
        parent=ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True,exist_ok=True)
        owned=tempfile.TemporaryDirectory(prefix='owned-cache-cleanup-',dir=parent)
        self.addCleanup(owned.cleanup)
        self.home=Path(owned.name)
        self.target=self.home/'baseline/bmad'
        self.pack=self.target/'.git/objects/pack/owned.pack'
        self.pack.parent.mkdir(parents=True)
        self.pack.write_bytes(b'inert owned Git pack')
        self.spec={'bmad':dict(pinned_commit='b'*40,pinned='2.0.0',upstream_tag='v2.0.0',repository='owned/bmad')}
        self.cloned=False

    def git(self, command, cwd):
        if 'clone' in command:
            self.assertEqual(Path(command[-1]),self.target)
            self.assertFalse(self.target.exists())
            self.target.mkdir()
            self.cloned=True
            return subprocess.CompletedProcess(command,0,'','')
        if command[-2:]==['rev-parse','HEAD']:
            return subprocess.CompletedProcess(command,0,('b' if self.cloned else 'a')*40+'\n','')
        if command[-3:]==['--get','remote.origin.url'] or command[-2:]==['--get','remote.origin.url']:
            return subprocess.CompletedProcess(command,0,'https://github.com/owned/bmad.git\n','')
        if 'status' in command:
            return subprocess.CompletedProcess(command,0,'','')
        self.fail('unexpected native command: '+repr(command))

    def invoke(self):
        with patch('getzilla.baseline_assets.load'),patch('getzilla.state.route_authority_present',return_value=False):
            try:
                return baseline.install_user(self.home,run=self.git,config=self.spec)
            except (OSError,ValueError):
                return None

    def test_readonly_access_denied_retries_one_owned_leaf(self):
        self.pack.chmod(0o400)
        actual_unlink=os.unlink
        actual_lstat=os.lstat
        attempts=[]
        def unlink(path,*args,**kwargs):
            if Path(path).name=='owned.pack':
                attempts.append(str(path))
                if not self.pack.stat().st_mode&stat.S_IWUSR:
                    failure=PermissionError(errno.EACCES,'inert Windows access denied',str(self.pack))
                    failure.winerror=5
                    raise failure
            return actual_unlink(path,*args,**kwargs)
        def lstat(path,*args,**kwargs):
            info=actual_lstat(path,*args,**kwargs)
            if Path(path).name=='owned.pack':
                data={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
                data['st_file_attributes']=0 if info.st_mode&stat.S_IWUSR else 1
                return SimpleNamespace(**data)
            return info
        with patch.object(baseline,'_CACHE_WINDOWS',True,create=True),patch.object(os,'unlink',side_effect=unlink),patch.object(os,'lstat',side_effect=lstat):
            result=self.invoke()
        self.assertIsNotNone(result,'a verified ReadOnly access-denied leaf must be retried, not abort the updater')
        self.assertEqual(result[0].status,'ok',result)
        self.assertEqual(len(attempts),2)
        self.assertTrue(self.cloned)

    def test_nonreadonly_permission_error_remains_failure_without_chmod(self):
        actual_unlink=os.unlink
        def unlink(path,*args,**kwargs):
            if Path(path).name=='owned.pack':
                failure=PermissionError(errno.EACCES,'inert ACL denial',str(self.pack))
                failure.winerror=5
                raise failure
            return actual_unlink(path,*args,**kwargs)
        with patch.object(baseline,'_CACHE_WINDOWS',True,create=True),patch.object(os,'unlink',side_effect=unlink),patch.object(os,'fchmod',side_effect=AssertionError('must not clear nonReadOnly permissions'),create=True):
            result=self.invoke()
        self.assertIsNotNone(result,'permission failure must be reported as a failed cache step')
        self.assertEqual(result[0].status,'fail')
        self.assertEqual(self.pack.read_bytes(),b'inert owned Git pack')
        self.assertFalse(self.cloned)

    def test_linked_or_hardlinked_cache_is_preserved(self):
        outside=self.home/'outside'
        outside.write_bytes(b'user file')
        for kind in ('symlink','hardlink'):
            link=self.pack.parent/kind
            try:
                link.symlink_to(outside) if kind=='symlink' else os.link(outside,link)
            except OSError:
                continue
            result=self.invoke()
            self.assertIsNotNone(result)
            self.assertEqual(result[0].status,'fail')
            self.assertTrue(link.exists())
            self.assertEqual(outside.read_bytes(),b'user file')
            self.assertFalse(self.cloned)
            link.unlink()

    @unittest.skipUnless(os.name=='nt','native Windows ReadOnly behavior pending')
    def test_actual_windows_readonly_pack_cleanup(self):
        self.pack.chmod(stat.S_IREAD)
        try:
            result=self.invoke()
            self.assertIsNotNone(result)
            self.assertEqual(result[0].status,'ok',result)
            self.assertTrue(self.cloned)
        finally:
            if self.pack.exists():
                self.pack.chmod(stat.S_IREAD|stat.S_IWRITE)

    def test_current_source_cleanup_does_not_swallow_nonreadonly_denial(self):
        from getzilla import current_workflows
        actual_unlink=os.unlink
        denied=[]
        roots=[]
        def acquire(command,**kwargs):
            root=kwargs['cwd']
            if 'fetch' in command:
                pack=root/'.git/objects/pack/owned.pack'
                pack.parent.mkdir(parents=True)
                pack.write_bytes(b'inert acquired pack')
                roots.append(root)
            return 0,b'',b''
        def unlink(path,*args,**kwargs):
            if Path(path).name=='owned.pack' and not denied:
                denied.append(True)
                failure=PermissionError(errno.EACCES,'inert nonReadOnly ACL failure')
                failure.winerror=5
                raise failure
            return actual_unlink(path,*args,**kwargs)
        with patch.object(current_workflows,'_run_capped',side_effect=acquire), \
             patch.object(current_workflows,'read_pinned_tree',return_value=SimpleNamespace(files=(('skills/inert/SKILL.md',b'inert'),))), \
             patch.object(baseline,'_CACHE_WINDOWS',True),patch.object(os,'unlink',side_effect=unlink), \
             patch('getzilla.state.route_authority_present',return_value=False):
            with self.assertRaises(PermissionError):
                current_workflows._source(self.home,'owned/bmad','a'*40,('skills/',))
        self.assertEqual(len(roots),1)
        self.assertEqual((roots[0]/'.git/objects/pack/owned.pack').read_bytes(),b'inert acquired pack')

    def test_root_link_and_user_changes_are_preserved(self):
        outside=self.home/'user-directory'
        outside.mkdir()
        (outside/'notes').write_bytes(b'user notes')
        self.target.rename(self.home/'original-cache')
        try:
            self.target.symlink_to(outside,target_is_directory=True)
        except OSError:
            self.skipTest('directory links unavailable')
        result=self.invoke()
        self.assertIsNotNone(result)
        self.assertEqual(result[0].status,'fail')
        self.assertTrue(self.target.is_symlink())
        self.assertEqual((outside/'notes').read_bytes(),b'user notes')
        self.assertFalse(self.cloned)

    def test_dirty_cache_is_preserved_before_cleanup(self):
        actual_git=self.git
        def git(command,cwd):
            if 'status' in command:
                return subprocess.CompletedProcess(command,0,'?? user-notes\n','')
            return actual_git(command,cwd)
        with patch.object(self,'git',side_effect=git):
            result=self.invoke()
        self.assertIsNotNone(result)
        self.assertEqual(result[0].status,'fail')
        self.assertEqual(self.pack.read_bytes(),b'inert owned Git pack')
        self.assertFalse(self.cloned)

    def test_native_policy_denial_preserves_cache(self):
        with patch('getzilla.baseline_assets.load'), \
             patch('getzilla.state.route_authority_present',return_value=True), \
             patch('getzilla.state.require_route_owner'), \
             patch.object(baseline,'evaluate_pre_tool',return_value=(False,'owned denial')):
            result=baseline.install_user(self.home,run=self.git,config=self.spec)
        self.assertEqual(result[0].status,'fail')
        self.assertEqual(self.pack.read_bytes(),b'inert owned Git pack')
        self.assertFalse(self.cloned)

    def test_linked_home_does_not_create_an_outside_cache(self):
        outside=self.home/'outside-home'
        outside.mkdir()
        linked=self.home/'linked-home'
        try:
            linked.symlink_to(outside,target_is_directory=True)
        except OSError:
            self.skipTest('directory links unavailable')
        result=baseline.install_user(linked,run=lambda *args:self.fail('outside Git must not run'),config=self.spec)
        self.assertEqual(result[0].status,'fail')
        self.assertEqual(list(outside.iterdir()),[])

    def test_swapped_readonly_leaf_is_never_chmoded_or_removed(self):
        self.pack.chmod(0o400)
        original_unlink=os.unlink
        original_lstat=os.lstat
        original_replace=os.replace
        swapped=[]
        def windows_replace(source,destination):
            if not Path(destination).stat().st_mode&stat.S_IWUSR:
                raise PermissionError(errno.EACCES,'owned Windows readonly destination')
            return original_replace(source,destination)
        def lstat(path,*args,**kwargs):
            info=original_lstat(path,*args,**kwargs)
            if Path(path).name=='owned.pack':
                data={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
                data['st_file_attributes']=0 if info.st_mode&stat.S_IWUSR else 1
                return SimpleNamespace(**data)
            return info
        def unlink(path,*args,**kwargs):
            if Path(path).name=='owned.pack' and not swapped:
                user=self.home/'new-user-file'
                user.write_bytes(b'user replacement')
                user.chmod(0o400)
                # Model an attacker replacing this inert fixture leaf. Native
                # Windows first requires clearing the owned destination bit.
                self.pack.chmod(0o600)
                os.replace(user,self.pack)
                swapped.append(True)
                failure=PermissionError(errno.EACCES,'inert swapped leaf')
                failure.winerror=5
                raise failure
            return original_unlink(path,*args,**kwargs)
        with patch.object(baseline,'_CACHE_WINDOWS',True),patch.object(os,'unlink',side_effect=unlink), \
             patch.object(os,'lstat',side_effect=lstat),patch.object(os,'replace',side_effect=windows_replace), \
             patch.object(baseline,'_cache_readonly',side_effect=AssertionError('replacement must not be chmoded')):
            result=self.invoke()
        self.assertIsNotNone(result)
        self.assertEqual(result[0].status,'fail')
        self.assertEqual(swapped,[True],'fixture must reach the replacement before testing identity refusal')
        self.assertEqual(self.pack.read_bytes(),b'user replacement')
        self.assertFalse(self.pack.stat().st_mode&stat.S_IWUSR)
        self.assertFalse(self.cloned)
