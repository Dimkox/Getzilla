import json
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_main_update_ruleset.py"


def snapshot():
    return {
        "id": 73, "source": "Dimkox/Getzilla", "source_type": "Repository",
        "target": "branch", "enforcement": "active",
        "_links": {"self": {"href": "https://api.github.com/repos/Dimkox/Getzilla/rulesets/73"}},
        "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
        "bypass_actors": [{"actor_type": "Integration", "actor_id": 41, "bypass_mode": "pull_request"}],
        "rules": [{"type": "update", "parameters": {"update_allows_fetch_and_merge": False}}],
    }


def fixture_root():
    common = subprocess.check_output(
        ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
        cwd=SCRIPT.parents[2], text=True).strip()
    root = Path(common).parent / ".getzilla/runtime/scratch"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


class MainUpdateRulesetTests(unittest.TestCase):
    def check(self, document, *, matches=False, merge=41, publisher=42, ruleset=73, raw=False):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as temp:
            path = Path(temp) / "snapshot.json"
            path.write_text(document if raw else json.dumps(document), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), str(path), "--ruleset-id", str(ruleset),
                 "--merge-app-id", str(merge), "--publisher-app-id", str(publisher)],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0 if matches else 1, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertIs(report["matches"], matches)
        self.assertIn("snapshot", report["scope"])

    def test_matching_operator_snapshot(self):
        self.check(snapshot(), matches=True)

    def test_target_repo_and_ruleset_identity(self):
        for field, wrong in [
            ("source", "other/Getzilla"), ("source_type", "Organization"), ("target", "tag"),
            ("enforcement", "evaluate"), ("id", True), ("id", 74), ("_links", {}),
            ("_links", {"self": {"href": "https://api.github.com/repos/other/Getzilla/rulesets/73"}}),
        ]:
            with self.subTest(field=field, wrong=wrong):
                self.check({**snapshot(), field: wrong})

    def test_exact_main_scope(self):
        for ref_name in [
            {"include": ["~ALL"], "exclude": []},
            {"include": ["refs/heads/main", "refs/heads/dev"], "exclude": []},
            {"include": ["refs/heads/main"], "exclude": ["refs/heads/main"]},
        ]:
            with self.subTest(ref_name=ref_name):
                self.check({**snapshot(), "conditions": {"ref_name": ref_name}})

    def test_only_merge_integration_has_pr_only_bypass(self):
        actor = snapshot()["bypass_actors"][0]
        for actors in [
            [], [actor, {**actor, "actor_id": 42}], [{**actor, "actor_type": "Team"}],
            [{**actor, "actor_id": 43}], [{**actor, "actor_id": 41.0}],
            [{**actor, "actor_id": "41"}], [{**actor, "bypass_mode": "always"}],
            [{**actor, "bypass_mode": "exempt"}], [{"actor_type": "Integration", "actor_id": 41}],
        ]:
            with self.subTest(actors=actors):
                self.check({**snapshot(), "bypass_actors": actors})
        redacted = snapshot()
        del redacted["bypass_actors"]
        self.check(redacted)

    def test_pins_from_operator_must_be_positive_and_separate(self):
        for wrong in [dict(publisher=41), dict(publisher=0), dict(merge=-1), dict(ruleset=0)]:
            with self.subTest(wrong=wrong):
                self.check(snapshot(), **wrong)
        github_actions = snapshot()
        github_actions["bypass_actors"][0]["actor_id"] = 15368
        self.check(github_actions, merge=15368)

    def test_actions_cannot_be_the_separate_status_publisher(self):
        self.check(snapshot(), publisher=15368)

    def test_reject_other_rules_or_upstream_merge_exception(self):
        only_update = snapshot()["rules"][0]
        for rules in [
            [], [{"type": "pull_request"}], [only_update, {"type": "required_status_checks"}],
            [{"type": "update", "parameters": {"update_allows_fetch_and_merge": True}}],
            [{"type": "update", "parameters": {"update_allows_fetch_and_merge": 0}}],
            [{"type": "update"}],
        ]:
            with self.subTest(rules=rules):
                self.check({**snapshot(), "rules": rules})

    def test_reject_list_errors_and_duplicate_keys(self):
        for document in [[], [snapshot()], {"message": "Forbidden"}, {"state": snapshot()}]:
            with self.subTest(document=document):
                self.check(document)
        self.check('{"enforcement":"disabled",' + json.dumps(snapshot())[1:], raw=True)


class RulesetInputTests(unittest.TestCase):
    def test_invalid_cli_arguments_have_fixed_json_errors(self):
        result = subprocess.run([sys.executable, str(SCRIPT), 'PRIVATE-PATH', '--ruleset-id',
            'PRIVATE-INVALID', '--merge-app-id', '41', '--publisher-app-id', '42'],
            capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('PRIVATE-', result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['reason'], 'snapshot-invalid')

    def load(self):
        with patch.object(sys, 'path', [str(SCRIPT.parent), *sys.path]):
            spec = importlib.util.spec_from_file_location('owned_ruleset', SCRIPT)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        return module

    def test_direct_ruleset_metadata_cannot_hide_non_json_or_oversized_values(self):
        module = self.load()
        for value in [object(), {'k' * 65537: 0}, ['x' * 65536] * 17, list(range(65536))]:
            document = snapshot()
            document['metadata'] = value
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                module.verify_ruleset(document, 73, 41, 42)

    def test_cli_failure_does_not_echo_missing_path_or_invalid_json(self):
        with tempfile.TemporaryDirectory(dir=fixture_root()) as directory:
            path = Path(directory) / 'PRIVATE-MISSING'
            command = [sys.executable, str(SCRIPT), str(path), '--ruleset-id', '73',
                       '--merge-app-id', '41', '--publisher-app-id', '42']
            result = subprocess.run(command, capture_output=True, text=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(str(path), result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)['reason'], 'snapshot-invalid')


if __name__ == "__main__":
    unittest.main()
