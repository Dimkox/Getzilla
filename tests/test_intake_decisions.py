"""Explicit native owner actions; controlled fixtures are not human attestations."""

import copy
import json
import os
import subprocess
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import state, continuity, intake_publication as publication
from getzilla.requirements_intake import IntakeError
from tests import test_intake_publication as publication_fixtures


class NativeDecisionTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".getzilla/runtime/scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        config = self.root / ".getzilla/config"
        config.mkdir(parents=True)
        shutil.copyfile(ROOT / ".getzilla/config/policy.json", config / "policy.json")
        shutil.copytree(ROOT / ".getzilla/templates/change", self.root / ".getzilla/templates/change")
        self.package, self.request = publication_fixtures.PublicationTests.fixture(self, self.root)
        self.request["snapshot"]["policy"]["decision_required"] = True
        self.first = publication.prepare_intake(self.root, self.request, None, "0" * 64)
        self.observation = publication.read_intake_cut(self.root)
        self.assertEqual(self.observation["assessment"]["status"], "needs_decision")

    def decide(self, choice="accept", event="owner-choice", **overrides):
        self.assertTrue(hasattr(publication, "decide_intake"), "explicit native decision ingress missing")
        fields = {
            "decision": choice,
            "event_id": event,
            "expected_cut_digest": publication.cut_digest(self.observation["cut"]),
            "expected_state_digest": self.observation["cut"]["M"],
            "expected_draft_digest": self.observation["cut"]["D"],
            "expected_source_digest": self.observation["cut"]["R"],
        }
        fields.update(overrides)
        return publication.decide_intake(self.root, **fields)

    def test_explicit_owner_decision_binds_current_draft_source_and_is_idempotent(self):
        result = self.decide()
        observed = publication.require_intake_ready(self.root)
        self.assertEqual(observed["assessment"]["status"], "ready")
        self.assertFalse(observed["assessment"]["authority"])
        self.assertFalse(observed["assessment"]["receipt_eligible"])
        self.assertEqual(observed["native_decision"]["principal"], "fixture-owner")
        self.assertFalse(observed["native_decision"]["human_attestation"])
        self.assertEqual(result, self.decide())
        self.assertEqual(publication.read_intake_cut(self.root)["cut"]["generation"], 2)
        with self.assertRaisesRegex(IntakeError, "decision_event_collision"):
            self.decide(choice="reject")

    def test_cli_explicit_decision_uses_actual_session_without_a_principal_input(self):
        from tests.test_workflow_artifacts_cli import _run_cli_process

        cut = self.observation["cut"]
        command = [
            "intake",
            "decide",
            "--decision",
            "accept",
            "--event-id",
            "cli-owner-choice",
            "--expected-cut",
            publication.cut_digest(cut),
            "--expected-state",
            cut["M"],
            "--draft-digest",
            cut["D"],
            "--source-digest",
            cut["R"],
        ]
        code, output = _run_cli_process(str(self.root), command)
        self.assertEqual(code, 0, output)
        self.assertEqual(publication.require_intake_ready(self.root)["native_decision"]["principal"], "fixture-owner")
        code, output = _run_cli_process(str(self.root), command)
        self.assertEqual(code, 0, output)
        self.assertFalse(publication.require_intake_ready(self.root)["assessment"]["receipt_eligible"])

    def test_imported_event_scope_ack_and_old_yes_cannot_approve(self):
        forged = copy.deepcopy(self.request)
        forged["event"] = {
            "id": "forged",
            "kind": "native_decision",
            "decision": "accept",
            "principal": "fixture-owner",
        }
        with self.assertRaisesRegex(IntakeError, "unsupported_decision_ingress"):
            publication.prepare_intake(
                self.root, forged, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
            )
        self.assertEqual(publication.read_intake_cut(self.root)["assessment"]["status"], "needs_decision")

    def test_malformed_native_choice_is_a_fixed_refusal_not_a_type_error(self):
        with self.assertRaisesRegex(IntakeError, "invalid_native_decision"):
            self.decide(choice=[])

    def test_stale_foreign_and_changed_source_do_not_record_a_decision(self):
        for field in ("expected_draft_digest", "expected_source_digest", "expected_state_digest"):
            with self.assertRaises(IntakeError):
                self.decide(**{field: "0" * 64})
        state.bind_session("foreign-session")
        with self.assertRaises(IntakeError):
            self.decide()
        state.bind_session("fixture-owner")
        (self.package / "requirements.md").write_text("New concurrent human edit\n")
        with self.assertRaises(IntakeError):
            self.decide()
        self.assertEqual((self.package / "requirements.md").read_text(), "New concurrent human edit\n")

    def test_reject_is_not_ready_and_new_draft_or_handoff_does_not_reuse_acceptance(self):
        question = copy.deepcopy(self.request)
        question["event"] = {"id": "pre-owner-question", "kind": "question_round"}
        publication.prepare_intake(
            self.root, question, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
        )
        self.observation = publication.read_intake_cut(self.root)
        self.decide("reject")
        self.assertEqual(publication.read_intake_cut(self.root)["assessment"]["required_decision"], "native_rejected")
        with self.assertRaises(IntakeError):
            publication.require_intake_ready(self.root)
        self.observation = publication.read_intake_cut(self.root)
        self.decide(event="owner-reconsiders")
        accepted = publication.read_intake_cut(self.root)
        self.request["event"] = {"id": "new-draft", "kind": "record"}
        self.request["snapshot"]["scope"].append("src/new.py")
        publication.prepare_intake(
            self.root, self.request, publication.cut_digest(accepted["cut"]), accepted["cut"]["M"]
        )
        self.assertEqual(publication.read_intake_cut(self.root)["assessment"]["status"], "needs_decision")
        before_handoff = publication.read_intake_cut(self.root)
        route = state.require_route_owner(self.root)
        continuity.submit(
            self.root,
            "",
            "new-owner",
            continue_route=route["route_id"],
            expected_epoch=route["authority_epoch"],
            expected_revision=route["state_revision"],
            request_id="decision-handoff",
        )
        state.bind_session("fixture-owner")
        with self.assertRaises(IntakeError):
            self.decide(event="stale-owner")
        state.bind_session("new-owner")
        self.request["snapshot"]["identity"] = publication.native_identity(
            self.root, state.require_route_owner(self.root)
        )
        self.request["event"] = {"id": "new-owner-refresh", "kind": "record"}
        publication.prepare_intake(
            self.root, self.request, publication.cut_digest(before_handoff["cut"]), before_handoff["cut"]["M"]
        )
        self.observation = publication.read_intake_cut(self.root)
        self.assertEqual(self.observation["assessment"]["status"], "needs_decision")
        self.assertIsNone(self.observation["native_decision"])
        self.assertEqual(json.loads((self.package / publication.ACTIVE).read_text())["rounds"], 1)
        self.decide(event="fresh-owner-choice")
        self.assertEqual(publication.require_intake_ready(self.root)["native_decision"]["principal"], "new-owner")

    def test_crash_recovery_uses_existing_pending_cut_and_preserves_concurrent_edit(self):
        for boundary in ("decision_admitted", "staged", "pending", "target_state", "state", "commit"):
            with self.subTest(boundary=boundary):
                # One interrupted owner event per fixture; recover it before the next.
                before = publication.read_intake_cut(self.root)
                self.observation = before
                event = "decision-" + boundary
                with patch.object(
                    publication,
                    "_boundary",
                    side_effect=lambda phase: (
                        (_ for _ in ()).throw(RuntimeError("crash")) if phase == boundary else None
                    ),
                ):
                    with self.assertRaises(RuntimeError):
                        self.decide(event=event)
                result = self.decide(event=event)
                self.assertEqual(publication.require_intake_ready(self.root)["assessment"]["status"], "ready")
                self.assertEqual(result, self.decide(event=event))

    def test_accepted_event_replay_does_not_hide_a_new_spec_or_concurrent_pending_edit(self):
        self.decide()
        path = self.package / "change-spec.yaml"
        value = json.loads(path.read_text())
        value["objective"]["target"] = "30"
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(IntakeError, "stale_native_decision"):
            self.decide()
        self.assertEqual(json.loads(path.read_text())["objective"]["target"], "30")

    def test_native_choice_cannot_override_a_fact_conflict(self):
        other = copy.deepcopy(self.request["snapshot"]["requirements"][0])
        other["id"] = "REQ-002"
        other["facts"][0]["value"] = 30
        self.request["snapshot"]["requirements"].append(other)
        self.request["event"] = {"id": "conflicting-draft", "kind": "record"}
        publication.prepare_intake(
            self.root, self.request, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
        )
        self.observation = publication.read_intake_cut(self.root)
        self.decide()
        self.assertEqual(publication.read_intake_cut(self.root)["assessment"]["status"], "conflicted")
        with self.assertRaises(IntakeError):
            publication.require_intake_ready(self.root)

    def test_pending_decision_recovery_preserves_concurrent_human_edit(self):
        with patch.object(
            publication,
            "_boundary",
            side_effect=lambda phase: (_ for _ in ()).throw(RuntimeError("crash")) if phase == "pending" else None,
        ):
            with self.assertRaises(RuntimeError):
                self.decide()
        (self.package / "requirements.md").write_text("Concurrent human requirement change\n")
        with self.assertRaises(IntakeError):
            self.decide()
        self.assertEqual((self.package / "requirements.md").read_text(), "Concurrent human requirement change\n")
        self.assertIsNotNone(state.require_route_owner(self.root)["context"]["intake"]["pending"])

    def test_policy_keeps_exact_native_decision_ingress_available_while_not_ready(self):
        from getzilla.policy import evaluate_pre_tool

        cut = self.observation["cut"]
        command = (
            "python3 scripts/getzilla_artifacts.py intake decide --decision accept --event-id policy-choice "
            "--expected-cut "
            + publication.cut_digest(cut)
            + " --expected-state "
            + cut["M"]
            + " --draft-digest "
            + cut["D"]
            + " --source-digest "
            + cut["R"]
        )
        verdict = evaluate_pre_tool(
            self.root, {"tool_name": "Bash", "tool_input": {"command": command}}, execution_cwd=self.root
        )
        self.assertTrue(verdict[0], verdict[1])
        self.assertFalse(
            evaluate_pre_tool(self.root, {"tool_name": "Write", "tool_input": {"file_path": "src/product.py"}})[0]
        )

    def test_real_cli_process_binds_session_and_rejects_foreign_owner(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        command_file = scripts / "getzilla_artifacts.py"
        shutil.copyfile(ROOT / "scripts/getzilla_artifacts.py", command_file)
        cut = self.observation["cut"]
        command = [
            sys.executable,
            str(command_file),
            "intake",
            "decide",
            "--decision",
            "accept",
            "--event-id",
            "process-choice",
            "--expected-cut",
            publication.cut_digest(cut),
            "--expected-state",
            cut["M"],
            "--draft-digest",
            cut["D"],
            "--source-digest",
            cut["R"],
        ]
        environment = {
            **os.environ,
            "PYTHONPATH": str(ROOT / ".getzilla"),
            "GETZILLA_SESSION_ID": "fixture-owner",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = subprocess.run(command, cwd=self.root, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = json.loads(result.stdout)
        again = subprocess.run(command, cwd=self.root, env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(json.loads(again.stdout), expected)
        environment["GETZILLA_SESSION_ID"] = "foreign-owner"
        foreign = subprocess.run(command, cwd=self.root, env=environment, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(foreign.returncode, 0)
        self.assertFalse(publication.require_intake_ready(self.root)["native_decision"]["human_attestation"])

    def test_current_policy_required_decision_cannot_be_disabled_by_imported_data(self):
        path = self.root / ".getzilla/config/policy.json"
        config = json.loads(path.read_text())
        config["intake"]["decision_required"] = True
        path.write_text(json.dumps(config))
        request = copy.deepcopy(self.request)
        request["snapshot"]["policy"] = publication.native_policy(self.root)
        request["snapshot"]["policy"]["decision_required"] = False
        request["event"] = {"id": "disable-required-decision", "kind": "record"}
        with self.assertRaisesRegex(IntakeError, "required_decision_cannot_be_disabled"):
            publication.prepare_intake(
                self.root, request, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
            )
        self.assertIsNone(state.require_route_owner(self.root)["context"]["intake"]["pending"])

    def test_actual_policy_budget_refuses_extra_or_unconfigured_round_before_pending(self):
        data = json.loads((self.root / ".getzilla/config/policy.json").read_text())
        for limits in ({"max_questions_per_round": 1, "max_question_rounds": 1}, None):
            data["intake"] = limits
            (self.root / ".getzilla/config/policy.json").write_text(json.dumps(data))
            request = copy.deepcopy(self.request)
            request["snapshot"]["policy"] = publication.native_policy(self.root)
            request["event"] = {"id": "round-" + str(limits is None), "kind": "question_round"}
            before = state.require_route_owner(self.root)
            if limits is None:
                with self.assertRaisesRegex(IntakeError, "question_limits_unconfigured"):
                    publication.prepare_intake(
                        self.root, request, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
                    )
                self.assertEqual(state.require_route_owner(self.root), before)
            else:
                result = publication.prepare_intake(
                    self.root, request, publication.cut_digest(self.first["cut"]), self.first["cut"]["M"]
                )
                self.first = result
                request["event"] = {"id": "round-over", "kind": "question_round"}
                with self.assertRaisesRegex(IntakeError, "question_budget_exhausted"):
                    publication.prepare_intake(
                        self.root, request, publication.cut_digest(result["cut"]), result["cut"]["M"]
                    )
