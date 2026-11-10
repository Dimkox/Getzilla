import copy
import importlib.util
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_public_check_protection.py"
spec = importlib.util.spec_from_file_location("public_protection", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture_root():
    common = subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=SCRIPT.parents[2], text=True).strip()
    root = Path(common).parent / ".getzilla/runtime/scratch"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.context = "getzilla-security/verified@123456789abc"
        self.before = {
            "url": "https://api.github.com/repos/Dimkox/Getzilla/branches/main/protection",
            "required_status_checks": {
                "strict": True, "contexts": ["linux", "windows", "other"],
                "checks": [{"context": name, "app_id": 15368}
                           for name in ["linux", "windows", "other"]],
                "contexts_url": "https://api.github.com/old",
            },
            "enforce_admins": {"enabled": True},
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "allow_force_pushes": {"enabled": False},
            "restrictions": None,
        }
        self.after = copy.deepcopy(self.before)
        self.after["required_status_checks"]["checks"].append(
            {"context": self.context, "app_id": 42})
        self.after["required_status_checks"]["contexts"].append(self.context)

    def verify(self):
        module.verify_protection(self.before, self.after, self.context, 42)

    def test_addition_preserves_existing_controls(self):
        self.verify()

    def test_metadata_and_check_order_do_not_change_policy(self):
        self.after["required_status_checks"]["contexts_url"] = "https://api.github.com/new"
        self.after["required_status_checks"]["checks"].reverse()
        self.after["required_status_checks"]["contexts"].reverse()
        self.verify()

    def test_wrong_or_wildcard_publisher_refused(self):
        for app in [None, -1, 0, True, "42", 43]:
            with self.subTest(app=app):
                self.after["required_status_checks"]["checks"][-1]["app_id"] = app
                with self.assertRaises(ValueError):
                    self.verify()

    def test_wildcard_new_context_refused(self):
        self.after["required_status_checks"]["checks"][-1]["context"] = "security-*"
        self.after["required_status_checks"]["contexts"][-1] = "security-*"
        with self.assertRaises(ValueError):
            module.verify_protection(self.before, self.after, "security-*", 42)

    def test_lost_existing_check_or_changed_publisher_refused(self):
        for name in ["linux", "windows", "other"]:
            with self.subTest(name=name):
                saved = copy.deepcopy(self.after)
                checks = self.after["required_status_checks"]
                checks["checks"] = [x for x in checks["checks"] if x["context"] != name]
                checks["contexts"].remove(name)
                with self.assertRaises(ValueError):
                    self.verify()
                self.after = copy.deepcopy(saved)
                next(x for x in self.after["required_status_checks"]["checks"]
                     if x["context"] == name)["app_id"] = None
                with self.assertRaises(ValueError):
                    self.verify()
                self.after = saved

    def test_other_policy_changes_refused(self):
        for key, value in [("allow_force_pushes", {"enabled": True}),
                           ("enforce_admins", {"enabled": False}),
                           ("restrictions", {"users": []}),
                           ("required_pull_request_reviews", {"required_approving_review_count": 0})]:
            with self.subTest(key=key):
                saved = copy.deepcopy(self.after)
                self.after[key] = value
                with self.assertRaises(ValueError):
                    self.verify()
                self.after = saved
        self.after["required_status_checks"]["strict"] = False
        with self.assertRaises(ValueError):
            self.verify()

    def test_same_wrong_repository_or_branch_in_both_snapshots_refused(self):
        for endpoint in [
            "https://api.github.com/repos/other/Getzilla/branches/main/protection",
            "https://api.github.com/repos/Dimkox/Getzilla/branches/dev/protection",
        ]:
            with self.subTest(endpoint=endpoint):
                self.before["url"] = self.after["url"] = endpoint
                with self.assertRaises(ValueError):
                    self.verify()

    def test_actions_cannot_be_the_new_security_check_publisher(self):
        self.after["required_status_checks"]["checks"][-1]["app_id"] = 15368
        with self.assertRaises(ValueError):
            module.verify_protection(self.before, self.after, self.context, 15368)

    def test_other_branch_snapshot_refused(self):
        self.after["url"] = "https://api.github.com/repos/owner/other/branches/main/protection"
        with self.assertRaises(ValueError):
            self.verify()

    def test_duplicate_or_inconsistent_check_records_refused(self):
        self.after["required_status_checks"]["checks"].append(
            {"context": self.context, "app_id": 42})
        with self.assertRaises(ValueError):
            self.verify()
        self.after["required_status_checks"]["checks"].pop()
        self.after["required_status_checks"]["contexts"].remove("linux")
        with self.assertRaises(ValueError):
            self.verify()

    def test_snapshot_reader_refuses_malformed_or_unbounded_json(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / "input.json"
            for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{', '[]',
                        '[' * 40 + '0' + ']' * 40, ' ' * (1024 * 1024 + 1)]:
                with self.subTest(size=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        value = module.read_snapshot(path)
                        module.verify_protection(value, self.after, self.context, 42)

    def test_cli_uses_only_supplied_files_and_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            before = Path(directory) / "before.json"
            after = Path(directory) / "after.json"
            before.write_text(json.dumps(self.before))
            after.write_text(json.dumps(self.after))
            command = [sys.executable, str(SCRIPT), str(before), str(after),
                       "--context", self.context, "--app-id", "42"]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(json.loads(result.stdout)["ready"])
            after.write_text('{"message":"Forbidden"}')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["ready"])

    def test_malformed_snapshots_refused(self):
        for bad in [None, [], {}, {"message": "Forbidden"}, float("nan")]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    module.verify_protection(bad, self.after, self.context, 42)


class SnapshotInputTests(unittest.TestCase):
    def test_invalid_cli_arguments_have_fixed_json_errors(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'PRIVATE-BEFORE', 'PRIVATE-AFTER',
            '--context', 'owned', '--app-id', 'PRIVATE-INVALID'], capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('PRIVATE-', result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason'], 'snapshot-invalid')

    def test_safe_open_capability_and_special_files_are_required(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{}')
            with patch.object(os, 'O_NOFOLLOW', 0, create=True), self.assertRaises(ValueError):
                module.read_snapshot(path)
            with self.assertRaises(ValueError):
                module.read_snapshot(directory)
            if hasattr(socket, 'AF_UNIX'):
                with socket.socket(socket.AF_UNIX) as sock:
                    endpoint = Path(directory) / 'owned.sock'
                    sock.bind(str(endpoint))
                    with self.assertRaises(ValueError):
                        module.read_snapshot(endpoint)

    def test_close_error_is_a_fixed_value_error_after_fd_is_closed(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{}')
            native = os.close
            def close(fd):
                native(fd)
                raise OSError('PRIVATE-close-detail')
            with patch.object(os, 'close', side_effect=close):
                with self.assertRaisesRegex(ValueError, '^snapshot-invalid$'):
                    module.read_snapshot(path)

    def test_decoder_recursion_and_nonfinite_numbers_are_fixed_refusals(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            for raw in ['[' * 2000 + '0' + ']' * 2000, '{"a":Infinity}', '{"a":-Infinity}']:
                path.write_text(raw)
                with self.subTest(size=len(raw)), self.assertRaisesRegex(ValueError, '^snapshot-invalid$'):
                    module.read_snapshot(path)

    def test_existing_wildcard_context_cannot_be_admitted_as_a_literal_binding(self):
        fixture = ProtectionTests()
        fixture.setUp()
        for document in (fixture.before, fixture.after):
            document['required_status_checks']['contexts'][2] = 'other*'
            document['required_status_checks']['checks'][2]['context'] = 'other*'
        with self.assertRaises(ValueError):
            fixture.verify()

    def test_direct_values_are_closed_json_with_key_text_and_node_limits(self):
        cycle = []
        cycle.append(cycle)
        for value in [object(), (1, 2), {1: 'bad'}, {'k' * 65537: 1},
                      ['x' * 65536] * 17, list(range(65536)), cycle, float('inf')]:
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                module._bounded(value)

    def test_reader_accepts_regular_json_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{"owned":true}')
            self.assertEqual(module.read_snapshot(path), {'owned': True})
            link = path.with_name('link.json')
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                module.read_snapshot(link)

    def test_reader_never_uses_following_path_open(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{}')
            with patch.object(Path, 'open', side_effect=AssertionError('following open used')):
                self.assertEqual(module.read_snapshot(path), {})

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires POSIX FIFO')
    def test_fifo_cli_refuses_without_blocking_or_leaking_path(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'PRIVATE-FIFO'
            os.mkfifo(path)
            try:
                result = subprocess.run([sys.executable, str(SCRIPT), str(path), str(path),
                    '--context', 'owned', '--app-id', '42'], capture_output=True, text=True, timeout=2)
            except subprocess.TimeoutExpired:
                self.fail('snapshot reader blocked on an owned FIFO')
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(str(path), result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['reason'], 'snapshot-invalid')

    def test_named_replacement_during_read_is_refused(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{}')
            replacement = path.with_name('replacement.json')
            replacement.write_text('{}')
            native = os.read
            changed = False
            def read(fd, count):
                nonlocal changed
                result = native(fd, count)
                if not changed:
                    changed = True
                    os.replace(replacement, path)
                return result
            with patch.object(os, 'read', side_effect=read), self.assertRaises(ValueError):
                module.read_snapshot(path)

    def test_changed_fd_identity_during_read_is_refused(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'owned.json'
            path.write_text('{}')
            native = os.read
            changed = False
            def read(fd, count):
                nonlocal changed
                result = native(fd, count)
                if not changed:
                    changed = True
                    with path.open('ab') as handle:
                        handle.write(b' ')
                return result
            with patch.object(os, 'read', side_effect=read), self.assertRaises(ValueError):
                module.read_snapshot(path)

    def test_cli_errors_do_not_echo_paths_or_snapshot_values(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'PRIVATE-MISSING'
            result = subprocess.run([sys.executable, str(SCRIPT), str(path), str(path),
                '--context', 'owned', '--app-id', '42'], capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(str(path), result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['reason'], 'snapshot-invalid')


if __name__ == "__main__":
    unittest.main()
