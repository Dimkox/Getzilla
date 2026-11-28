"""Native finish evidence keeps the original Git guard and actual CWD."""
import os
import shutil
import sys
import struct
import tempfile
from pathlib import Path
from unittest.mock import patch

from tests import test_git_binding_guard as fixtures
from getzilla import architecture_diff as diff
from getzilla.trace_storage import native_root


class NativeGitInputTests(fixtures._GuardFixture):
    # Native finish evidence also needs the actual strict FD profile on
    # filesystems where the optional inotify-overlay profile is unavailable.
    require_native = False

    def setUp(self):
        # Strict external-ancestor metadata cannot qualify during unrelated
        # global /tmp churn. Keep this test-owned graph in ignored runtime;
        # no path/metadata check is relaxed to make the fixture pass.
        for cache in (diff._GIT_FORMAT_CACHE,diff._GIT_COMMIT_CACHE,
                      diff._GIT_BLOB_CACHE,diff._MATERIALIZED_STATE_CACHE):
            cache.clear()
        parent = fixtures.ROOT/'.getzilla/runtime'
        parent.mkdir(parents=True,exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix='native-git-fixture-',dir=parent)
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        saved = os.open('.',os.O_RDONLY|os.O_DIRECTORY)
        self.addCleanup(os.close,saved)
        self.addCleanup(os.fchdir,saved)
        before = os.umask(0o022)
        try:
            self.root,self.git_directory,self.common,self.head = self.repository()
        finally:
            os.umask(before)
        self.root.chmod(0o755)
        os.chdir(self.root)

    def linked_checkout(self, name):
        # The native guard verifies external Git directory ancestors up to /.
        # Put the real shared Git directory inside the fixture's held worktree
        # so concurrent scratch entries cannot invalidate this positive test.
        root, _, common, head = self.repository(linked='source-linked',name=name)
        main = root/'fixture-main'
        common.parent.rename(main)
        self.git(main,'worktree','repair',str(root))
        return root, head

    def test_actual_git_reads_keep_guard_and_owned_fd_cwd(self):
        actual = diff._run_capped
        calls = []
        def observed(command,**kwargs):
            if command[-2:] == ['rev-parse','HEAD']:
                calls.append(kwargs['cwd'])
                self.assertIn(kwargs['cwd'], [diff.fsx.held_directory_address(fd) for fd in kwargs['pass_fds']])
                worktree = '.' if sys.platform == 'darwin' else str(kwargs['cwd'])
                self.assertIn('--work-tree=' + worktree, command)
                self.assertTrue(kwargs['pass_fds'])
            return actual(command,**kwargs)
        with native_root(self.root) as anchor:
            with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                self.assertIsNotNone(scope.guard)
                with patch.object(diff,'_run_capped',side_effect=observed):
                    self.assertEqual(diff._git(self.root,['rev-parse','HEAD'],_scope=scope).strip(),self.head.encode())
        self.assertEqual(len(calls),1)

    def test_native_source_and_spec_fingerprint_keep_a_during_child_launch_switch(self):
        from getzilla.spec import spec_fingerprint
        real_popen = diff.subprocess.Popen
        before = os.umask(0o022)
        try:
            foreign,_,_,_ = self.repository(name='source-foreign')
            linked,linked_head = self.linked_checkout('source-linked-root')
        finally:
            os.umask(before)
        self.git(foreign,'-c','user.name=Public','-c','user.email=public@example.invalid',
                 'commit','--allow-empty','-qm','foreign public source')
        foreign_head = self.git(foreign,'rev-parse','HEAD').decode().strip()
        for root,head in ((self.root,self.head),(linked,linked_head)):
            with self.subTest(linked=root == linked):
                root.chmod(0o755)
                os.chdir(root)
                self.assertNotEqual(head,foreign_head)
                def switched(command,**kwargs):
                    # Model a sibling fixture appearing during a child launch.
                    # Only touch this test's private parent.
                    (self.parent/(root.name+'-sibling')).mkdir(exist_ok=True)
                    os.chdir(foreign)
                    try:
                        return real_popen(command,**kwargs)
                    finally:
                        os.chdir(root)
                with native_root(root) as anchor:
                    original = anchor.git_source()
                    expected = spec_fingerprint(root,root/'change-spec.yaml',{},anchor=anchor)
                    self.assertEqual(original['head'],head)
                    with patch.object(diff.subprocess,'Popen',side_effect=switched):
                        self.assertEqual(anchor.git_source(),original)
                        self.assertEqual(spec_fingerprint(root,root/'change-spec.yaml',{},anchor=anchor),expected)

    def test_linked_source_refuses_changed_external_parent(self):
        before = os.umask(0o022)
        try:
            linked,_,_,_ = self.repository(linked='external',name='external-main')
        finally:
            os.umask(before)
        os.chdir(linked)
        sibling = self.parent/'sibling'
        real_check = diff.NativeGitGraph.check
        real_fstat = os.fstat

        def check(guard):
            parent = guard._directories.get(self.parent)
            if parent is None or sibling.exists():
                return real_check(guard)

            injected = False

            def change_before_observation(descriptor):
                nonlocal injected
                self.assertFalse(injected, 'guard advanced beyond the changed parent')
                if descriptor == parent.descriptor:
                    sibling.mkdir()
                    injected = True
                return real_fstat(descriptor)

            # Change the owned external directory at its actual observation,
            # while the guard still has the original descriptor and identity.
            with patch.object(os, 'fstat', change_before_observation):
                return real_check(guard)

        with native_root(linked) as anchor, patch.object(diff.NativeGitGraph, 'check', check):
            # Competing fixtures can invalidate a shared ancestor during setup.
            # Retry only that refusal, before our mutation has occurred.
            for _ in range(5):
                with self.assertRaisesRegex(ValueError,'native_trace_source_unavailable') as refused:
                    anchor.git_source()
                cause = refused.exception.__context__
                if (sibling.exists() or not isinstance(cause, diff.ArchitectureError)
                        or str(cause) != 'Git directory binding changed'):
                    break
        self.assertTrue(sibling.is_dir())
        self.assertIn('binding changed',str(refused.exception.__context__))

    def test_native_source_uses_original_git_graph_admission(self):
        config = self.common/'config'
        config.chmod(0o664)
        identity = config.stat().st_dev,config.stat().st_ino
        real_read = os.read
        def checked(descriptor,*args):
            info = os.fstat(descriptor)
            self.assertNotEqual((info.st_dev,info.st_ino),identity,'unsafe config bytes read')
            return real_read(descriptor,*args)
        with native_root(self.root) as anchor,patch('os.read',side_effect=checked):
            with self.assertRaisesRegex(ValueError,'native_trace_source_unavailable'):
                anchor.git_source()

    def test_exact_native_commit_child_cannot_bypass_owned_fd_addressing(self):
        actual = diff._run_capped
        def observed(command,**kwargs):
            self.assertIn(kwargs['cwd'], [diff.fsx.held_directory_address(fd) for fd in kwargs['pass_fds']])
            self.assertTrue(kwargs['pass_fds'])
            return actual(command,**kwargs)
        with native_root(self.root) as anchor:
            with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                with patch.object(diff,'_run_capped',side_effect=observed):
                    self.assertEqual(diff._head_commit(self.root,_scope=scope),self.head)

    def test_native_source_budget_also_bounds_configuration_and_preflight_children(self):
        actual,timeouts = diff._run_capped,[]
        def observed(command,**kwargs):
            timeouts.append(kwargs['timeout'])
            return actual(command,**kwargs)
        with native_root(self.root) as anchor,patch.object(diff,'_run_capped',side_effect=observed):
            self.assertEqual(anchor.git_source()['head'],self.head)
        self.assertGreaterEqual(len(timeouts),3)
        self.assertTrue(all(0 < timeout <= 0.5 for timeout in timeouts))
        self.assertEqual(timeouts,sorted(timeouts,reverse=True))

    def test_preacquisition_parent_replacement_refuses_before_git_process(self):
        moved = self.root.with_name(self.root.name+'-moved')
        with native_root(self.root) as anchor:
            self.root.rename(moved)
            try:
                self.root.mkdir(mode=0o755)
                with patch.object(diff,'_run_capped',side_effect=AssertionError('foreign Git process')):
                    with self.assertRaises(diff.ArchitectureError):
                        with diff._GitOperation(self.root,native_anchor=anchor):
                            self.fail('foreign root accepted')
            finally:
                shutil.rmtree(self.root)
                moved.rename(self.root)

    def test_strict_original_command_does_not_lose_its_directory_checks(self):
        with native_root(self.root) as anchor:
            with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                original = scope.binding.verify
                strict = []
                def observed(guard=None,**kwargs):
                    if kwargs.get('strict_directories'):
                        strict.append(True)
                    return original(guard,**kwargs)
                with patch.object(type(scope.binding),'verify',side_effect=observed):
                    self.assertEqual(diff._git(self.root,['status','--porcelain=v1','-z','--untracked-files=all'],_scope=scope),b'')
                self.assertGreaterEqual(len(strict),2)

    def test_every_native_git_child_keeps_owned_a_cwd_during_switch_to_b_and_restore(self):
        real_popen = diff.subprocess.Popen
        before = os.umask(0o022)
        try:
            foreign,_,_,_ = self.repository(name='foreign')
            linked,linked_head = self.linked_checkout('linked-cwd')
        finally:
            os.umask(before)
        foreign_bytes = (foreign/'value.txt').read_bytes()
        for root,head in ((self.root,self.head),(linked,linked_head)):
            with self.subTest(linked=root == linked):
                os.chdir(root)
                root.chmod(0o755)
                reader,writer = os.pipe()
                try:
                    probe = ("import os,struct,sys; s=os.stat('.'); "
                             f"os.write({writer},struct.pack('QQ',s.st_dev,s.st_ino)); "
                             "os.execv(sys.argv[1],sys.argv[1:])")
                    def switched(command,**kwargs):
                        kwargs['pass_fds'] = (*kwargs.get('pass_fds',()),writer)
                        os.chdir(foreign)
                        try:
                            return real_popen([sys.executable,'-c',probe,*command],**kwargs)
                        finally:
                            os.chdir(root)
                    with native_root(root) as anchor:
                        with patch.object(diff.subprocess,'Popen',side_effect=switched):
                            with diff._GitOperation(root,native_anchor=anchor) as scope:
                                output = diff._git(root,['rev-parse','HEAD'],_scope=scope)
                                self.assertEqual(output.strip(),head.encode())
                    os.close(writer)
                    writer = None
                    observations = os.read(reader,4096)
                    self.assertGreaterEqual(len(observations),3*16,'config, preflight and read must be observed')
                    actual = [struct.unpack('QQ',observations[i:i+16]) for i in range(0,len(observations),16)]
                    self.assertEqual(actual,[ (root.stat().st_dev,root.stat().st_ino)]*len(actual))
                    self.assertEqual((foreign/'value.txt').read_bytes(),foreign_bytes)
                finally:
                    os.close(reader)
                    if writer is not None:
                        os.close(writer)

    def test_unsafe_operational_config_refuses_before_its_bytes(self):
        config = self.common/'config'
        original = config.read_bytes()
        for kind in ('writable','hardlink'):
            with self.subTest(kind=kind):
                config.write_bytes(original)
                config.chmod(0o664 if kind == 'writable' else 0o600)
                alias = config.with_name('config-alias')
                if kind == 'hardlink':
                    os.link(config,alias)
                real_read = os.read
                config_identity = config.stat().st_dev,config.stat().st_ino
                def checked(descriptor,*args):
                    info = os.fstat(descriptor)
                    self.assertNotEqual((info.st_dev,info.st_ino),config_identity,'unsafe config bytes consumed')
                    return real_read(descriptor,*args)
                try:
                    with native_root(self.root) as anchor,patch('os.read',side_effect=checked):
                        with self.assertRaises(diff.ArchitectureError):
                            with diff._GitOperation(self.root,native_anchor=anchor):
                                self.fail('unsafe config admitted')
                finally:
                    if alias.exists():
                        alias.unlink()

    def test_alternates_or_promisor_refuse_without_child(self):
        for relative in ('objects/info/alternates','objects/pack/value.promisor'):
            with self.subTest(relative=relative):
                path = self.common/relative
                path.write_bytes(b'PRIVATE_FOREIGN_DETAIL\n')
                path.chmod(0o600)
                try:
                    with native_root(self.root) as anchor:
                        with patch.object(diff,'_run_capped',side_effect=AssertionError('unsupported graph child')):
                            with self.assertRaises(diff.ArchitectureError):
                                with diff._GitOperation(self.root,native_anchor=anchor):
                                    self.fail('alternate/promisor admitted')
                finally:
                    path.unlink()

    def test_changed_restored_registration_censors_without_cache_publication(self):
        real_run = diff._run_capped
        def changed(command,**kwargs):
            result = real_run(command,**kwargs)
            if command[-2:] == ['rev-parse','HEAD']:
                self.transient(self.common)
            return result
        with native_root(self.root) as anchor:
            with self.assertRaises(diff.ArchitectureError):
                with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                    scope.stage('commit',('synthetic-test-only',),True)
                    with patch.object(diff,'_run_capped',side_effect=changed):
                        diff._git(self.root,['rev-parse','HEAD'],_scope=scope)
        self.assertEqual(diff._GIT_COMMIT_CACHE,{})

    def test_original_objects_neighbor_churn_allowance_is_preserved(self):
        real_run = diff._run_capped
        def changed(command,**kwargs):
            result = real_run(command,**kwargs)
            if command[-2:] == ['rev-parse','HEAD']:
                self.churn(self.common/'objects')
            return result
        with native_root(self.root) as anchor:
            with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                with patch.object(diff,'_run_capped',side_effect=changed):
                    self.assertEqual(diff._git(self.root,['rev-parse','HEAD'],_scope=scope).strip(),self.head.encode())

    def test_reused_root_fd_refuses_and_cleanup_leaves_foreign_descriptor_open(self):
        before = os.umask(0o022)
        try:
            foreign,_,_,_ = self.repository(name='reused-foreign')
        finally:
            os.umask(before)
        replacement = None
        try:
            with native_root(self.root) as anchor:
                with self.assertRaises(diff.ArchitectureError):
                    with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                        descriptor = scope.guard._directories[self.root].descriptor
                        os.close(descriptor)
                        replacement = os.open(foreign,os.O_RDONLY|os.O_DIRECTORY)
                        self.assertEqual(replacement,descriptor)
                        with patch.object(diff,'_run_capped',side_effect=AssertionError('foreign child')):
                            diff._git(self.root,['rev-parse','HEAD'],_scope=scope)
            self.assertEqual(os.fstat(replacement).st_ino,foreign.stat().st_ino)
        finally:
            if replacement is not None:
                os.close(replacement)

    def test_missing_descriptor_addressing_refuses_before_child_without_fallback(self):
        real_stat = os.stat
        def unavailable(path,*args,**kwargs):
            prefix = '/.vol/' if sys.platform == 'darwin' else '/proc/self/fd/'
            if str(path).startswith(prefix):
                raise OSError('synthetic procfs unavailable')
            return real_stat(path,*args,**kwargs)
        with native_root(self.root) as anchor:
            with patch('os.stat',side_effect=unavailable),patch.object(diff,'_run_capped',side_effect=AssertionError('fallback child')):
                with self.assertRaises(diff.ArchitectureError):
                    with diff._GitOperation(self.root,native_anchor=anchor):
                        self.fail('unsupported profile admitted')

    def test_original_public_0775_operational_directory_admission_is_preserved(self):
        self.common.chmod(0o775)
        with native_root(self.root) as anchor:
            with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                self.assertEqual(diff._git(self.root,['rev-parse','HEAD'],_scope=scope).strip(),self.head.encode())

    def test_operational_directory_mode_change_or_reference_swap_still_refuses(self):
        for kind in ('mode','reference'):
            with self.subTest(kind=kind):
                self.common.chmod(0o775)
                old_head = (self.common/'HEAD').read_bytes()
                real_run = diff._run_capped
                def changed(command,**kwargs):
                    result = real_run(command,**kwargs)
                    if command[-2:] == ['rev-parse','HEAD']:
                        if kind == 'mode':
                            self.common.chmod(0o755)
                        else:
                            replacement = self.common/'new-head'
                            replacement.write_bytes(old_head)
                            replacement.chmod(0o644)
                            os.replace(replacement,self.common/'HEAD')
                    return result
                with native_root(self.root) as anchor:
                    with self.assertRaises(diff.ArchitectureError):
                        with diff._GitOperation(self.root,native_anchor=anchor) as scope:
                            with patch.object(diff,'_run_capped',side_effect=changed):
                                diff._git(self.root,['rev-parse','HEAD'],_scope=scope)
