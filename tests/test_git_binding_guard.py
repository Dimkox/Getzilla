from __future__ import annotations

import hashlib
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))

from getzilla import architecture_diff as diff
from getzilla import git_binding_guard as native
from getzilla.architecture import ArchitectureError


class _GuardFixture(unittest.TestCase):
    require_native = True

    def setUp(self) -> None:
        for cache in (diff._GIT_FORMAT_CACHE, diff._GIT_COMMIT_CACHE,
                      diff._GIT_BLOB_CACHE, diff._MATERIALIZED_STATE_CACHE):
            cache.clear()
        temporary = tempfile.TemporaryDirectory(prefix="git-binding-guard-")
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        if self.require_native:
            guard = None
            try:
                guard = native.LinuxGitGuard()
                guard.directory(self.parent, "worktree root")
            except native.GuardUnavailable as exc:
                self.skipTest(f"unqualified native backend/filesystem: {exc}")
            finally:
                if guard is not None:
                    guard.close()

    def git(self, root: Path, *arguments: str, input: bytes | None = None) -> bytes:
        return subprocess.run(
            ["git", *arguments], cwd=root, input=input, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
        ).stdout

    def repository(self, *, linked: str | None = None, name: str = "repo") -> tuple[Path, Path, Path, str]:
        main = self.parent / name
        main.mkdir()
        self.git(main, "init", "-q")
        self.git(main, "config", "user.email", "guard@example.invalid")
        self.git(main, "config", "user.name", "Guard Tests")
        (main / "value.txt").write_bytes(b"original content\n")
        self.git(main, "add", ".")
        self.git(main, "commit", "-qm", "guard fixture")
        head = self.git(main, "rev-parse", "HEAD").decode().strip()
        common = main / ".git"
        if linked is None:
            return main, common, common, head
        root = self.parent / (name + "-linked")
        arguments = ("--detach",) if linked == "detached" else ("-b", name + "-branch")
        self.git(main, "worktree", "add", "-q", *arguments, str(root), head)
        return root, common / "worktrees" / root.name, common, head

    def churn(self, directory: Path) -> None:
        before = directory.stat()
        neighbor = directory / "harmless-neighbor"
        neighbor.write_bytes(b"temporary\n")
        neighbor.unlink()
        after = directory.stat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_mode),
                         (after.st_dev, after.st_ino, after.st_mode))
        self.assertNotEqual((before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns))

    def refused(self, operation, label: str | None = None) -> None:
        with self.assertRaises(ArchitectureError) as raised:
            operation()
        self.assertEqual(raised.exception.code, "git")
        if label:
            self.assertIn("Git " + label, str(raised.exception))
        self.assertNotIn(str(self.parent), str(raised.exception))
        self.assertNotIn("PRIVATE_FOREIGN_DETAIL", str(raised.exception))

    def transient(self, directory: Path, name: str = "commondir") -> None:
        path = directory / name
        self.assertFalse(path.exists())
        path.write_bytes(b"PRIVATE_FOREIGN_DETAIL\n")
        path.unlink()


class GitBindingGuardOperationsTests(_GuardFixture):
    def test_linked_common_directory_retains_absent_commondir_history(self) -> None:
        root, _, common, _ = self.repository(linked="attached")
        real_run = diff._run_capped
        observed = []

        def changed(command, **kwargs):
            result = real_run(command, **kwargs)
            if command[-2:] == ["rev-parse", "HEAD"]:
                self.transient(common)
                observed.append(True)
            return result

        with mock.patch.object(diff, "_run_capped", side_effect=changed):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]),
                         "common-directory registration")
        self.assertEqual(observed, [True])

    def test_unclassified_pseudoref_cannot_hide_as_neighbor_churn(self) -> None:
        root, admin, _, head = self.repository()
        tree = self.git(root, "rev-parse", "HEAD^{tree}").decode().strip()
        alternate = self.git(root, "commit-tree", tree, "-p", head, "-m", "alternate")
        self.assertNotEqual(alternate, (head + "\n").encode())
        real_run = diff._run_capped
        observed = []

        def changed(command, **kwargs):
            if command[-2:] != ["rev-parse", "CUSTOM_SELECTOR"]:
                return real_run(command, **kwargs)
            selector = admin / "CUSTOM_SELECTOR"
            selector.write_bytes(alternate)
            try:
                result = real_run(command, **kwargs)
                observed.append(result[1])
                return result
            finally:
                selector.unlink()

        with mock.patch.object(diff, "_run_capped", side_effect=changed):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "CUSTOM_SELECTOR"]))
        self.assertEqual(observed, [alternate])


    def test_real_bounded_reads_accept_neighbor_churn_in_all_directory_roles(self) -> None:
        for linked in (None, "attached", "detached"):
            root, admin, common, head = self.repository(linked=linked, name=str(linked))
            for role, directory in (("root", root), ("admin", admin),
                                    ("common", common), ("objects", common / "objects")):
                with self.subTest(linked=linked, role=role):
                    real_run = diff._run_capped
                    calls = []

                    def during_read(command, **kwargs):
                        result = real_run(command, **kwargs)
                        if command[-2:] == ["rev-parse", "HEAD"]:
                            self.churn(directory)
                            calls.append(True)
                        return result

                    with mock.patch.object(diff, "_run_capped", side_effect=during_read):
                        self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"]),
                                         (head + "\n").encode())
                    self.assertEqual(calls, [True])

    def test_discovery_is_guarded_before_its_first_result(self) -> None:
        root, admin, _, head = self.repository()
        real_run = diff._run_capped
        calls = []

        def discovery(command, **kwargs):
            result = real_run(command, **kwargs)
            if "--absolute-git-dir" in command:
                self.churn(root)
                self.churn(admin)
                calls.append(True)
            return result

        with mock.patch.object(diff, "_run_capped", side_effect=discovery):
            self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"]),
                             (head + "\n").encode())
        self.assertEqual(calls, [True])

    def test_exact_commit_and_stream_accept_neighbor_churn(self) -> None:
        root, admin, _, head = self.repository(linked="attached")
        real_run = diff._run_capped

        def commit(command, **kwargs):
            result = real_run(command, **kwargs)
            if command[-3:] == ["cat-file", "-t", head]:
                self.churn(admin)
            return result

        with mock.patch.object(diff, "_run_capped", side_effect=commit):
            self.assertEqual(diff._exact_commit(root, head, label="head"), head)
        blob = self.git(root, "rev-parse", "HEAD:value.txt").decode().strip()
        real_drain = diff._drain_blob_selector

        def streamed(*args, **kwargs):
            result = real_drain(*args, **kwargs)
            self.churn(root)
            return result

        with mock.patch.object(diff, "_drain_blob_selector", side_effect=streamed):
            self.assertEqual(diff._stream_git_blob(root, blob, 17, "value.txt"),
                             (hashlib.sha256(b"original content\n").hexdigest(), False))

    def test_transient_absent_commondir_never_admits_foreign_head(self) -> None:
        root, admin, _, _ = self.repository()
        foreign, _, _, _ = self.repository(name="foreign")
        (foreign / "value.txt").write_bytes(b"foreign content\n")
        self.git(foreign, "add", ".")
        self.git(foreign, "commit", "-qm", "foreign fixture")
        foreign_head = self.git(foreign, "rev-parse", "HEAD")
        real_run = diff._run_capped
        observed = []

        def transient(command, **kwargs):
            if command[-2:] != ["rev-parse", "HEAD"]:
                return real_run(command, **kwargs)
            registration = admin / "commondir"
            registration.write_text(str(foreign / ".git") + "\n")
            try:
                result = real_run(command, **kwargs)
                observed.append(result[1])
                return result
            finally:
                registration.unlink()

        with mock.patch.object(diff, "_run_capped", side_effect=transient):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))
        self.assertEqual(observed, [foreign_head])
        self.assertFalse((admin / "commondir").exists())

    def test_ancestor_swap_and_restore_never_admits_a_result(self) -> None:
        container = self.parent / "container"
        container.mkdir()
        self.parent = container
        root, _, _, _ = self.repository(linked="attached")
        saved = container.with_name("saved")
        real_run = diff._run_capped

        def swapped(command, **kwargs):
            if command[-2:] != ["rev-parse", "HEAD"]:
                return real_run(command, **kwargs)
            container.rename(saved)
            try:
                container.mkdir()
            finally:
                container.rmdir()
                saved.rename(container)
            return real_run(command, **kwargs)

        with mock.patch.object(diff, "_run_capped", side_effect=swapped):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]), "path ancestor")

    def test_every_named_directory_swap_and_restore_is_terminal(self) -> None:
        for linked in (None, "attached", "detached"):
            root, admin, common, _ = self.repository(linked=linked, name=str(linked))
            for role, directory in (("root", root), ("admin", admin),
                                    ("common", common), ("objects", common / "objects")):
                with self.subTest(linked=linked, role=role):
                    saved = directory.with_name(directory.name + "-saved")
                    real_run = diff._run_capped

                    def swapped(command, **kwargs):
                        result = real_run(command, **kwargs)
                        if command[-2:] == ["rev-parse", "HEAD"]:
                            directory.rename(saved)
                            directory.mkdir()
                            directory.rmdir()
                            saved.rename(directory)
                        return result

                    with mock.patch.object(diff, "_run_capped", side_effect=swapped):
                        self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))

    def test_protected_selector_names_cannot_appear_and_disappear(self) -> None:
        root, admin, common, _ = self.repository()
        for directory, name in ((root, ".git"), (admin, "HEAD"), (common, "packed-refs"),
                                (common, "config.worktree"), (common / "objects/info", "alternates"),
                                (common / "objects/pack", "unexpected.promisor")):
            with self.subTest(name=name):
                real_run = diff._run_capped

                def changed(command, **kwargs):
                    result = real_run(command, **kwargs)
                    if command[-2:] == ["rev-parse", "HEAD"]:
                        path = directory / name
                        if path.exists():
                            saved = path.with_name(path.name + "-saved")
                            path.rename(saved)
                            saved.rename(path)
                        else:
                            self.transient(directory, name)
                    return result

                with mock.patch.object(diff, "_run_capped", side_effect=changed):
                    self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))

    def test_directory_permission_change_and_restore_is_terminal(self) -> None:
        root, _, _, _ = self.repository()
        original = root.stat().st_mode & 0o777
        real_run = diff._run_capped

        def changed(command, **kwargs):
            result = real_run(command, **kwargs)
            if command[-2:] == ["rev-parse", "HEAD"]:
                root.chmod(original ^ 0o020)
                root.chmod(original)
            return result

        with mock.patch.object(diff, "_run_capped", side_effect=changed):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]), "worktree root")

    def test_failed_command_and_stream_hide_foreign_detail_after_invalidation(self) -> None:
        root, admin, _, _ = self.repository()
        real_run = diff._run_capped

        def changed(command, **kwargs):
            if command[-2:] != ["rev-parse", "HEAD"]:
                return real_run(command, **kwargs)
            self.transient(admin)
            return 1, b"", b"PRIVATE_FOREIGN_DETAIL"

        for allow_failure in (False, True):
            with self.subTest(allow_failure=allow_failure), mock.patch.object(diff, "_run_capped", side_effect=changed):
                self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"],
                                                         allow_failure=allow_failure))
        blob = self.git(root, "rev-parse", "HEAD:value.txt").decode().strip()
        real_drain = diff._drain_blob_selector

        def stream_failure(*args, **kwargs):
            _code, digest, total, binary, _stderr = real_drain(*args, **kwargs)
            self.transient(admin)
            return 1, digest, total, binary, bytearray(b"PRIVATE_FOREIGN_DETAIL")

        with mock.patch.object(diff, "_drain_blob_selector", side_effect=stream_failure):
            self.refused(lambda: diff._stream_git_blob(root, blob, 17, "value.txt"))

    def test_setup_errors_validate_before_exposing_diagnostics(self) -> None:
        root, admin, _, _ = self.repository()
        real_run = diff._run_capped
        for selector in ("--file=-", "--absolute-git-dir"):
            def failed(command, **kwargs):
                if selector in command:
                    self.transient(admin)
                    raise ArchitectureError("PRIVATE_FOREIGN_DETAIL", code="io")
                return real_run(command, **kwargs)

            with self.subTest(selector=selector), mock.patch.object(diff, "_run_capped", side_effect=failed):
                self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))

    def test_guarded_directory_size_and_times_do_not_replace_stable_identity_checks(self) -> None:
        root, _, _, _ = self.repository()
        real_identity = diff._git_path_identity
        with diff._GitOperation(root) as scope:
            def volatile(path):
                value = real_identity(path)
                return (*value[:3], value[3] + 8192, value[4] + 1000, value[5] + 1000) if path == root else value

            with mock.patch.object(diff, "_git_path_identity", side_effect=volatile):
                self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "--show-object-format"], _scope=scope),
                                 b"sha1\n")
            for index in (0, 1, 2):
                def replaced(path):
                    value = list(real_identity(path))
                    if path == root:
                        value[index] += 1
                    return tuple(value)

                with self.subTest(identity_field=index), mock.patch.object(diff, "_git_path_identity", side_effect=replaced):
                    self.refused(scope.check, "worktree root")


class GitBindingGuardAcquisitionTests(_GuardFixture):
    def test_parent_protection_precedes_child_open_and_watch(self) -> None:
        root, _, _, _ = self.repository()
        saved = root.with_name("saved")
        real_open = native.fsx.open_dir_at
        real_watch = native.LinuxGitGuard._watch

        for boundary in ("open", "watch"):
            calls = []

            def replace():
                root.rename(saved)
                root.mkdir()
                root.rmdir()
                saved.rename(root)
                calls.append(True)

            def during_open(parent, name, **kwargs):
                if name == root.name and not calls:
                    replace()
                return real_open(parent, name, **kwargs)

            def during_watch(guard, descriptor, identity, label):
                if identity[:2] == (root.stat().st_dev, root.stat().st_ino) and not calls:
                    replace()
                return real_watch(guard, descriptor, identity, label)

            target, name, replacement = ((native.fsx, "open_dir_at", during_open) if boundary == "open" else
                                         (native.LinuxGitGuard, "_watch", during_watch))
            with self.subTest(boundary=boundary), mock.patch.object(target, name, replacement):
                self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))
            self.assertEqual(calls, [True])

    def test_provisional_pointer_is_revalidated_after_topology_closes(self) -> None:
        root, _, _, _ = self.repository(linked="attached")
        real_pointer = diff._git_pointer

        def rewrite(path):
            content = real_pointer(path)
            if path == root / ".git":
                path.write_bytes(content)
            return content

        with mock.patch.object(diff, "_git_pointer", side_effect=rewrite):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]), "worktree registration")

    def test_late_protected_names_retain_already_drained_history(self) -> None:
        guard = native.LinuxGitGuard()
        self.addCleanup(guard.close)
        guard.directory(self.parent, "worktree root")
        self.transient(self.parent, "late-protected")
        guard.check()  # currently harmless; future registration still needs its history
        self.refused(lambda: guard.protect(self.parent, "late-protected", "configuration"), "configuration")
        self.refused(guard.check, "configuration")

    def test_duplicate_native_watch_keeps_name_masks_and_all_named_edges(self) -> None:
        guard = native.LinuxGitGuard()
        self.addCleanup(guard.close)
        child = self.parent / "child"
        child.mkdir()
        guard.directory(child / "..", "worktree root")
        guard.protect(self.parent, "selector", "configuration")
        record = guard._directories[self.parent]
        guard._watch(record.descriptor, record.identity, "path ancestor")
        self.transient(self.parent, "selector")
        self.refused(guard.check, "configuration")

    def test_setup_unavailability_never_discards_prior_invalidation(self) -> None:
        root, admin, _, _ = self.repository()
        real_watch = native.LinuxGitGuard._watch

        def failed_watch(guard, descriptor, identity, label):
            if identity[:2] == (admin.stat().st_dev, admin.stat().st_ino):
                root.chmod(0o700)
                raise native.GuardUnavailable("watch-resources")
            return real_watch(guard, descriptor, identity, label)

        with mock.patch.object(native.LinuxGitGuard, "_watch", failed_watch):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))

    def test_pure_binding_stays_strict_and_closed_scope_cannot_be_reused(self) -> None:
        root, _, _, _ = self.repository()
        binding = diff._git_binding(root)
        self.churn(root)
        self.refused(binding.verify, "worktree root")
        with diff._GitOperation(root) as scope:
            self.assertEqual(scope.mode, "linux-inotify-overlayfs-v1")
        self.refused(lambda: diff._git_object_id_length(root, _scope=scope), "operation")

    def test_scope_cannot_move_to_another_root_or_thread(self) -> None:
        root, _, _, _ = self.repository()
        other, _, _, _ = self.repository(name="other")
        with diff._GitOperation(root) as scope:
            self.refused(lambda: diff._git_object_id_length(other, _scope=scope), "operation")
            errors = []

            def worker():
                try:
                    diff._git_object_id_length(root, _scope=scope)
                except ArchitectureError:
                    errors.append(True)

            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [True])


class GitBindingGuardCacheTests(_GuardFixture):
    def test_materialized_state_miss_and_hit_accept_harmless_churn(self) -> None:
        from tests.test_architecture_fitness import GitArchitectureRepo, _rules, _system
        repo = GitArchitectureRepo(self)
        system = _system()
        repo.model(system, _rules())
        head = repo.commit("architecture fixture")
        real_blob = diff._git_blob

        def component(*args, **kwargs):
            value = real_blob(*args, **kwargs)
            self.churn(repo.root)
            self.churn(repo.root / ".git")
            return value

        with mock.patch.object(diff, "_git_blob", side_effect=component):
            state = diff._materialized_state(repo.root, head)
        self.assertEqual(state.snapshot.system["architecture_id"], system["architecture_id"])
        with mock.patch.object(diff, "_git_blob", side_effect=AssertionError("unexpected cache miss")):
            self.assertIs(diff._materialized_state(repo.root, head), state)

    def test_all_cache_writes_wait_for_outer_admission(self) -> None:
        root, admin, _, head = self.repository()
        operations = (
            ("format", lambda: diff._git_object_id_length(root)),
            ("commit", lambda: diff._exact_commit(root, head, label="head")),
            ("blobs", lambda: diff._git_blobs(root, head, ("value.txt",))),
            ("state", lambda: diff._materialized_state(root, head, bootstrap_baseline=True)),
        )
        for kind, operation in operations:
            with self.subTest(kind=kind):
                real_stage = diff._GitOperation.stage
                calls = []

                def after_stage(scope, staged_kind, key, value):
                    real_stage(scope, staged_kind, key, value)
                    if staged_kind == kind:
                        self.transient(admin)
                        calls.append(True)

                with mock.patch.object(diff._GitOperation, "stage", after_stage):
                    self.refused(operation)
                self.assertEqual(calls, [True])
                self.assertFalse(diff._GIT_FORMAT_CACHE)
                self.assertFalse(diff._GIT_COMMIT_CACHE)
                self.assertFalse(diff._GIT_BLOB_CACHE)
                self.assertFalse(diff._MATERIALIZED_STATE_CACHE)

    def test_cache_hits_validate_the_current_scope_before_return(self) -> None:
        root, admin, _, head = self.repository()
        operations = (
            ("_GIT_FORMAT_CACHE", lambda: diff._git_object_id_length(root)),
            ("_GIT_COMMIT_CACHE", lambda: diff._exact_commit(root, head, label="head")),
            ("_GIT_BLOB_CACHE", lambda: diff._git_blobs(root, head, ("value.txt",))),
            ("_MATERIALIZED_STATE_CACHE", lambda: diff._materialized_state(root, head, bootstrap_baseline=True)),
        )
        for cache_name, operation in operations:
            with self.subTest(cache=cache_name):
                operation()
                original = dict(getattr(diff, cache_name))
                self.assertTrue(original)
                calls = []
                fixture = self

                class ChangedCache(dict):
                    def get(self, key, default=None):
                        value = super().get(key, default)
                        if key in self and not calls:
                            fixture.transient(admin)
                            calls.append(True)
                        return value

                    def __getitem__(self, key):
                        value = super().__getitem__(key)
                        if not calls:
                            fixture.transient(admin)
                            calls.append(True)
                        return value

                replacement = ChangedCache(original)
                with mock.patch.object(diff, cache_name, replacement):
                    self.refused(operation)
                self.assertEqual(calls, [True])
                self.assertEqual(dict(replacement), original)

    def test_empty_and_absent_blobs_validate_after_the_last_component(self) -> None:
        root, admin, _, head = self.repository()
        real_check = diff._GitOperation.check

        def late_empty(scope, checked_root=None):
            result = real_check(scope, checked_root)
            if checked_root is not None:
                self.transient(admin)
            return result

        with mock.patch.object(diff._GitOperation, "check", late_empty):
            self.refused(lambda: diff._git_blobs(root, head, ()))
        real_git = diff._git

        def late_absent(*args, **kwargs):
            result = real_git(*args, **kwargs)
            if "ls-tree" in args[1]:
                self.transient(admin)
            return result

        with mock.patch.object(diff, "_git", side_effect=late_absent):
            self.refused(lambda: diff._git_blobs(root, head, ("absent",)))
        self.assertFalse(diff._GIT_FORMAT_CACHE)
        self.assertFalse(diff._GIT_COMMIT_CACHE)
        self.assertFalse(diff._GIT_BLOB_CACHE)

    def test_materialization_shares_one_scope_across_all_component_reads(self) -> None:
        from tests.test_architecture_fitness import GitArchitectureRepo, _rules, _system
        repo = GitArchitectureRepo(self)
        repo.model(_system(), _rules())
        head = repo.commit("architecture fixture")
        real_blob = diff._git_blob
        scopes = []

        def component(*args, **kwargs):
            value = real_blob(*args, **kwargs)
            scopes.append(kwargs.get("_scope"))
            if len(scopes) == 2:
                self.transient(repo.root / ".git")
            return value

        with mock.patch.object(diff, "_git_blob", side_effect=component):
            self.refused(lambda: diff._materialized_state(repo.root, head))
        self.assertGreaterEqual(len(scopes), 2)
        self.assertIsNotNone(scopes[0])
        self.assertTrue(all(scope is scopes[0] for scope in scopes))
        self.assertFalse(diff._MATERIALIZED_STATE_CACHE)
        self.assertFalse(diff._GIT_BLOB_CACHE)


class GitOperationCacheCapacityTests(_GuardFixture):
    require_native = False

    def maximum_contract_model(self):
        from tests.test_architecture_fitness import GitArchitectureRepo, _rules, _system
        repo = GitArchitectureRepo(self)
        system = _system()
        system["contracts"] = [
            {"id": f"CONTRACT-CAPACITY-{number:03d}", "kind": "json_schema",
             "path": f"contracts/{number:03d}.json", "version": "1",
             "role": "consumer", "compatibility": "exact"}
            for number in range(256)
        ]
        for contract in system["contracts"]:
            repo.write_json(contract["path"], {"type": "object"})
        repo.model(system, _rules())
        return repo, repo.commit("maximum contract fixture")

    def caches(self):
        return (diff._GIT_FORMAT_CACHE, diff._GIT_COMMIT_CACHE,
                diff._GIT_BLOB_CACHE, diff._MATERIALIZED_STATE_CACHE)

    def test_cold_and_warm_maximum_contract_model_is_admitted(self) -> None:
        repo, head = self.maximum_contract_model()
        for warm in (False, True):
            with self.subTest(warm=warm):
                for cache in self.caches():
                    cache.clear()
                if warm:
                    diff._exact_commit(repo.root, head, label="warmup")
                before = tuple(dict(cache) for cache in self.caches())
                with diff._GitOperation(repo.root) as scope:
                    state = diff._materialized_state(repo.root, head, _scope=scope)
                    self.assertEqual(len(state.contracts), 256)
                    self.assertIs(diff._materialized_state(repo.root, head, _scope=scope), state)
                    self.assertEqual(tuple(dict(cache) for cache in self.caches()), before)
                self.assertIs(diff._materialized_state(repo.root, head), state)

    def test_same_scope_cache_hits_reuse_values_without_rereading_git(self) -> None:
        root, _, _, head = self.repository()
        operations = (
            ("format", lambda scope: diff._git_object_id_length(root, _scope=scope), len(head)),
            ("commit", lambda scope: diff._exact_commit(root, head, label="head", _scope=scope), head),
            ("blobs", lambda scope: diff._git_blobs(root, head, ("value.txt",), _scope=scope),
             {"value.txt": b"original content\n"}),
            ("state", lambda scope: diff._materialized_state(root, head, bootstrap_baseline=True,
                                                            _scope=scope), None),
        )
        for kind, operation, expected in operations:
            with self.subTest(kind=kind):
                for cache in self.caches():
                    cache.clear()
                with diff._GitOperation(root) as scope:
                    self.assertEqual(operation(scope), expected)
                    self.assertTrue(all(not cache for cache in self.caches()))
                    with mock.patch.object(diff, "_run_capped", side_effect=AssertionError("pending result reread")):
                        self.assertEqual(operation(scope), expected)
                    self.assertTrue(all(not cache for cache in self.caches()))

    def test_maximum_contract_model_late_invalidation_discards_pending_caches(self) -> None:
        repo, head = self.maximum_contract_model()
        completed = []

        def operation():
            with diff._GitOperation(repo.root) as scope:
                state = diff._materialized_state(repo.root, head, _scope=scope)
                completed.append(len(state.contracts))
                self.transient(repo.root / ".git")

        self.refused(operation)
        self.assertEqual(completed, [256])
        self.assertTrue(all(not cache for cache in self.caches()))

    def test_pending_unique_entry_limit_rejects_new_key_after_duplicate(self) -> None:
        root, _, _, _ = self.repository()
        reached_new_key = []

        def operation():
            with diff._GitOperation(root) as scope:
                for number in range(512):
                    scope.stage("format", ("bounded", number), 40)
                scope.stage("format", ("bounded", 0), 40)
                reached_new_key.append(True)
                scope.stage("format", ("bounded", 512), 40)

        with self.assertRaisesRegex(ArchitectureError, "Git operation binding cache limit exceeded"):
            operation()
        self.assertEqual(reached_new_key, [True])
        self.assertTrue(all(not cache for cache in self.caches()))


class GitBindingGuardFallbackTests(_GuardFixture):
    require_native = False

    @unittest.skipUnless(sys.platform == "linux", "Linux descriptor capabilities")
    def test_unavailable_directory_capabilities_keep_strict_mutation_checks(self) -> None:
        root, admin, _, head = self.repository()
        real_open = os.open

        def legacy_open(path, flags, *args, **kwargs):
            if kwargs.get("dir_fd") is not None:
                self.fail("unavailable descriptor-relative open was attempted")
            return real_open(path, flags, *args, **kwargs)

        variants = (
            mock.patch.object(native.os, "O_NOFOLLOW", 0),
            mock.patch.object(native.os, "supports_dir_fd", set()),
            mock.patch.object(native.os, "open", side_effect=legacy_open),
        )
        before = len(os.listdir("/proc/self/fd"))
        for index, unavailable in enumerate(variants):
            with self.subTest(capability=index), unavailable:
                with diff._GitOperation(root) as scope:
                    self.assertEqual(scope.mode, "strict")
                    self.assertIsNone(scope.guard)
                    self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                                     (head + "\n").encode())
                binding = diff._git_binding(root)
                self.churn(admin)
                self.refused(binding.verify, "directory")
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    @unittest.skipUnless(os.name == "posix", "POSIX directory aliases")
    def test_ancestor_alias_is_reacquired_with_original_strict_binding(self) -> None:
        root, _, _, head = self.repository()
        alias = self.parent / "alias"
        alias.symlink_to(root.parent, target_is_directory=True)
        named = alias / root.name
        with diff._GitOperation(named) as scope:
            self.assertEqual(scope.mode, "strict")
            self.assertEqual(diff.run_git_bounded(named, ["rev-parse", "HEAD"], _scope=scope),
                             (head + "\n").encode())

    def test_unhandled_symbolic_reference_target_keeps_strict_binding(self) -> None:
        root, _, common, head = self.repository()
        (common / "refs/heads/other").write_bytes(b"ref: outside-covered-refs\n")
        with diff._GitOperation(root) as scope:
            self.assertEqual(scope.mode, "strict")
            self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                             (head + "\n").encode())

    def test_unqualified_backend_reacquires_strict_and_allows_loose_objects(self) -> None:
        root, admin, common, head = self.repository()
        real_run = diff._run_capped

        def add_object(command, **kwargs):
            result = real_run(command, **kwargs)
            if command[-2:] == ["rev-parse", "HEAD"]:
                self.git(root, "hash-object", "-w", "--stdin", input=b"new loose object\n")
            return result

        with mock.patch.object(native, "_native_api", side_effect=native.GuardUnavailable("platform")):
            with diff._GitOperation(root) as scope:
                self.assertEqual(scope.mode, "strict")
                self.assertIsNone(scope.guard)
                self.assertEqual(scope.binding.objects_directory, common / "objects")
            with mock.patch.object(diff, "_run_capped", side_effect=add_object):
                self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"]), (head + "\n").encode())
            binding = diff._git_binding(root)
            self.churn(admin)
            self.refused(binding.verify, "directory")

    def test_unhandled_configuration_uses_git_parsing_and_strict_fallback(self) -> None:
        variants = (
            '[include]\n path = "absent-\\\ninclude"\n',
            '[includeIf "gitdir:/unmatched/"]\n path = absent\n',
            '[extensions]\n worktreeConfig = true\n',
            '[remote "origin"]\n promisor = true\n',
            '[alias]\n sample = status\n',
        )
        for index, extra in enumerate(variants):
            with self.subTest(configuration=index):
                root, admin, _, head = self.repository(name=str(index))
                with (admin / "config").open("a") as stream:
                    stream.write(extra)
                with diff._GitOperation(root) as scope:
                    self.assertEqual(scope.mode, "strict")
                    self.assertIsNone(scope.guard)
                    self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                                     (head + "\n").encode())

    def test_alternate_object_store_keeps_original_strict_behavior(self) -> None:
        root, _, common, head = self.repository()
        _foreign, _, foreign_common, _ = self.repository(name="foreign")
        (common / "objects/info/alternates").write_text(str(foreign_common / "objects") + "\n")
        with diff._GitOperation(root) as scope:
            self.assertEqual(scope.mode, "strict")
            self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                             (head + "\n").encode())

    def test_unknown_filesystem_keeps_strict_binding(self) -> None:
        root, _, _, head = self.repository()
        with mock.patch.object(native.LinuxGitGuard, "_qualified", side_effect=native.GuardUnavailable("filesystem")):
            with diff._GitOperation(root) as scope:
                self.assertEqual(scope.mode, "strict")
                self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                                 (head + "\n").encode())


class GitBindingGuardResourceTests(_GuardFixture):
    def assert_capability_rejected_before_acquisition(self, patch, *, missing: str | None = None) -> None:
        api = native._native_api()
        real_init = api.inotify_init1
        allocated = []

        def observe(flags):
            descriptor = real_init(flags)
            if descriptor >= 0:
                allocated.append(descriptor)
            return descriptor

        before = len(os.listdir("/proc/self/fd"))
        guard = None
        with mock.patch.object(native.ctypes, "CDLL", return_value=api) as load_library, \
                mock.patch.object(api, "inotify_init1", side_effect=observe), patch:
            if missing is not None:
                delattr(native.os, missing)
            try:
                with self.assertRaisesRegex(native.GuardUnavailable, "^directory-capabilities$"):
                    guard = native.LinuxGitGuard()
            finally:
                if guard is not None:
                    guard.close()
        load_library.assert_not_called()
        self.assertEqual(allocated, [])
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_missing_or_zero_directory_flags_refuse_before_native_acquisition(self) -> None:
        for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK", "O_CLOEXEC"):
            for missing in (False, True):
                with self.subTest(flag=flag, missing=missing):
                    self.assert_capability_rejected_before_acquisition(
                        mock.patch.object(native.os, flag, 0),
                        missing=flag if missing else None,
                    )

    def test_unsupported_directory_primitives_refuse_before_native_acquisition(self) -> None:
        for support, primitive in (("supports_dir_fd", os.open), ("supports_dir_fd", os.stat),
                                   ("supports_follow_symlinks", os.stat), ("supports_fd", os.scandir)):
            with self.subTest(support=support, primitive=primitive.__name__):
                self.assert_capability_rejected_before_acquisition(
                    mock.patch.object(native.os, support, getattr(os, support) - {primitive}),
                )

    def test_real_owned_descriptors_are_nonblocking_and_not_inheritable(self) -> None:
        root, _, _, _ = self.repository()
        with diff._GitOperation(root) as scope:
            descriptors = [scope.guard._descriptor]
            descriptors.extend(record.descriptor for record in scope.guard._directories.values())
            self.assertGreater(len(descriptors), 4)
            for descriptor in descriptors:
                self.assertFalse(os.get_inheritable(descriptor))
                self.assertFalse(os.get_blocking(descriptor))

    def test_lost_watch_descriptor_keeps_typed_error_and_releases_directories(self) -> None:
        root, _, _, _ = self.repository()
        before = len(os.listdir("/proc/self/fd"))
        with self.assertRaises(ArchitectureError):
            with diff._GitOperation(root) as scope:
                os.close(scope.guard._descriptor)
                scope.check()
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_constructor_exception_does_not_orphan_a_native_descriptor(self) -> None:
        api = native._native_api()
        real_init = api.inotify_init1
        owned = []

        def observe(flags):
            descriptor = real_init(flags)
            if descriptor >= 0:
                owned.append(descriptor)
            return descriptor

        try:
            with mock.patch.object(native, "_native_api", return_value=api), \
                    mock.patch.object(api, "inotify_init1", side_effect=observe), \
                    mock.patch.object(native.time, "monotonic", side_effect=RuntimeError("clock failed")), \
                    self.assertRaises(RuntimeError):
                native.LinuxGitGuard()
            for descriptor in owned:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        finally:
            for descriptor in owned:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_partial_watch_resource_failure_closes_before_fresh_fallback(self) -> None:
        root, _, _, head = self.repository()
        before = len(os.listdir("/proc/self/fd"))
        real_watch = native.LinuxGitGuard._watch
        calls = []

        def unavailable(guard, descriptor, identity, label):
            calls.append(True)
            if len(calls) == 3:
                raise native.GuardUnavailable("watch-resources")
            return real_watch(guard, descriptor, identity, label)

        with mock.patch.object(native.LinuxGitGuard, "_watch", unavailable):
            with diff._GitOperation(root) as scope:
                self.assertEqual(scope.mode, "strict")
                self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"], _scope=scope),
                                 (head + "\n").encode())
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_direct_commit_and_stream_start_failure_is_fixed_and_typed(self) -> None:
        root, _, _, head = self.repository()
        diff._git_object_id_length(root)
        blob = self.git(root, "rev-parse", "HEAD:value.txt").decode().strip()
        for operation in (lambda scope: diff._exact_commit(root, head, label="head", _scope=scope),
                          lambda scope: diff._stream_git_blob(root, blob, 17, "value.txt", _scope=scope)):
            with diff._GitOperation(root) as scope:
                with mock.patch.object(diff.subprocess, "Popen", side_effect=OSError(errno.EIO, "PRIVATE_FOREIGN_DETAIL")):
                    self.refused(lambda: operation(scope))

    def test_event_errors_are_terminal_and_privacy_safe(self) -> None:
        root, _, _, _ = self.repository()
        for payload in (b"bad", native._EVENT.pack(-1, native._OVERFLOW, 0, 0),
                        native._EVENT.pack(987654, native._CREATE, 0, 0),
                        native._EVENT.pack(1, native._CREATE, 0, 4096),
                        native._EVENT.pack(1, 0x100000, 0, 0)):
            with self.subTest(payload=payload):
                with self.assertRaises(ArchitectureError):
                    with diff._GitOperation(root) as scope:
                        self.refused(lambda: scope.guard._consume(payload))
                        self.refused(scope.check)

    def test_watch_loss_unmount_and_read_failure_are_terminal(self) -> None:
        root, _, _, _ = self.repository()
        for mask in (native._IGNORED, native._UNMOUNT, native._DELETE_SELF):
            with self.subTest(mask=mask), self.assertRaises(ArchitectureError):
                with diff._GitOperation(root) as scope:
                    watch = scope.guard._directories[root].watch
                    scope.guard._consume(native._EVENT.pack(watch, mask, 0, 0))
        with self.assertRaises(ArchitectureError):
            with diff._GitOperation(root) as scope:
                real_read = os.read

                def bad_read(descriptor, size):
                    if descriptor == scope.guard._descriptor:
                        raise OSError(errno.EIO, "PRIVATE_FOREIGN_DETAIL")
                    return real_read(descriptor, size)

                with mock.patch.object(native.os, "read", side_effect=bad_read):
                    self.refused(scope.check)

    def test_real_event_budget_and_overflow_refuse_finitely(self) -> None:
        root, _, _, _ = self.repository()
        with mock.patch.object(native, "MAX_EVENTS", 1), self.assertRaises(ArchitectureError):
            with diff._GitOperation(root) as scope:
                self.churn(root)
                scope.check()
        queue_limit = int(Path("/proc/sys/fs/inotify/max_queued_events").read_text())
        if queue_limit > 32768:
            self.skipTest("real overflow fixture exceeds the finite 32768-record control bound")
        with mock.patch.object(native, "MAX_EVENTS", 100000), self.assertRaisesRegex(ArchitectureError, "overflowed"):
            with diff._GitOperation(root) as scope:
                neighbor = root / "overflow-neighbor"
                for _ in range(queue_limit // 2 + 1):
                    neighbor.touch()
                    neighbor.unlink()
                scope.check()

    def test_setup_directory_and_time_limits_refuse_without_retry(self) -> None:
        root, _, _, _ = self.repository()
        with mock.patch.object(native, "MAX_DIRECTORIES", 1):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))
        with mock.patch.object(native, "SETUP_SECONDS", 0):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))

    def test_setup_failure_closes_capped_input_and_guard_descriptors(self) -> None:
        root, _, _, _ = self.repository()
        real_temporary = tempfile.TemporaryFile
        opened = []

        def temporary(*args, **kwargs):
            result = real_temporary(*args, **kwargs)
            opened.append(result)
            return result

        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(diff.tempfile, "TemporaryFile", side_effect=temporary), \
                mock.patch.object(diff.subprocess, "Popen", side_effect=OSError(errno.EIO, "failed")):
            self.refused(lambda: diff.run_git_bounded(root, ["rev-parse", "HEAD"]))
        self.assertTrue(opened)
        self.assertTrue(all(stream.closed for stream in opened))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_success_timeout_output_nonzero_and_stream_errors_do_not_retain_fds(self) -> None:
        root, _, _, head = self.repository()
        blob = self.git(root, "rev-parse", "HEAD:value.txt").decode().strip()
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(8):
            self.assertEqual(diff.run_git_bounded(root, ["rev-parse", "HEAD"]), (head + "\n").encode())
            self.assertIsNone(diff.run_git_bounded(root, ["rev-parse", "--verify", "missing"], allow_failure=True))
            with self.assertRaises(ArchitectureError):
                diff.run_git_bounded(root, ["cat-file", "blob", blob], limit=1)
            with self.assertRaises(ArchitectureError):
                diff._stream_git_blob(root, blob, 18, "value.txt")
            with mock.patch.object(diff, "_GIT_TIMEOUT_SECONDS", 0.000001), self.assertRaises(ArchitectureError):
                diff.run_git_bounded(root, ["rev-parse", "HEAD"])
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
