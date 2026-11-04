import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_public_check_protection.py"
spec = importlib.util.spec_from_file_location("public_protection", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


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
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[2]) as directory:
            path = Path(directory) / "input.json"
            for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{', '[]',
                        '[' * 40 + '0' + ']' * 40, ' ' * (1024 * 1024 + 1)]:
                with self.subTest(size=len(raw)):
                    path.write_text(raw)
                    with self.assertRaises(ValueError):
                        value = module.read_snapshot(path)
                        module.verify_protection(value, self.after, self.context, 42)

    def test_cli_uses_only_supplied_files_and_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=SCRIPT.parents[2]) as directory:
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


if __name__ == "__main__":
    unittest.main()
