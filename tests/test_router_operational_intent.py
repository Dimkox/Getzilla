"""Operational intent: release, deploy and publish requests versus descriptive mentions."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.router import (
    build_route,
)


class OperationalIntentTests(unittest.TestCase):
    def test_weak_language_disclosure_survives_operational_route_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'Package.swift').write_text('// not package metadata\n')
            (root / 'main.py').write_text('print("source")\n')
            route = self.route(root, 'Publish the package through a pull request')
            disclosed = route.to_dict()['repo']
            self.assertEqual(disclosed['detected_languages'], ['python', 'swift'])
            self.assertEqual(disclosed['languages'], [])
            self.assertEqual(disclosed['domains'], [])
            self.assertIn('language_scan', disclosed)
            self.assertEqual(route.intent, 'release')
            self.assertIsNone(route.write_agent)
            self.assertNotIn('apple', route.domains)
            self.assertNotIn('python', route.domains)
            self.assert_release_controls(root, 'Publish the package through a pull request')

    def route(self, root: Path, prompt: str):
        return build_route(root, prompt, 'operational-intent',
                           base_commit_override=None,
                           base_fingerprint_override='0' * 64)

    def assert_release_controls(self, root: Path, prompt: str) -> None:
        route = self.route(root, prompt)
        self.assertEqual(route.intent, 'release')
        self.assertEqual(route.risk, 'high')
        self.assertIsNone(route.write_agent)
        self.assertIn('release-readiness', route.workflow_skills)
        self.assertEqual(set(route.review_agents), {
            'code_reviewer', 'test_reviewer', 'security_reviewer', 'release_reviewer',
        })
        self.assertEqual(set(route.required_evidence), {
            'verification', 'code_review', 'test_review', 'security_review', 'release_review',
        })
        self.assertEqual(route.human_gates, [
            'scope_and_design_approval', 'production_action_approval',
        ])

    def test_artifact_history_does_not_negate_a_current_operation(self) -> None:
        # Global historical/past-state vetoes lose the requested publication.
        prompts = (
            'Publish the artifact built yesterday through a pull request',
            "Review yesterday's changes and publish v3 through PR",
            'Publish the artifact reviewed yesterday through a pull request',
            'Опубликуй пакет собранный вчера после ревью',
            'Publish the artifact that was reviewed through a pull request',
            'Deploy the build that has been reviewed through a pull request',
            'Опубликуй пакет который был проверен на ревью',
            'Опубликуй пакет, который был проверен на ревью',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    self.assert_release_controls(Path(tmp), prompt)

    def test_object_and_destination_restrictions_do_not_negate_the_action(self) -> None:
        # Negation belongs to the command prefix, not arbitrary object words.
        prompts = (
            'Опубликуй пакет без README через PR',
            'Выпусти релиз без деплоя через pull request',
            'Publish the package with no need to restart; review the PR',
            'Опубликуй пакет без изменения версии после ревью',
            'Publish the artifact not to production but to staging after review',
            'Review this PR and publish the package',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    self.assert_release_controls(Path(tmp), prompt)
            for prompt in (
                'No need to publish and release; review this PR',
                'Can you not deploy and publish; review this PR',
                'Нужно не опубликовать пакет и развернуть сборку; проверь код',
            ):
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, 'review')
                    self.assertNotIn('release-readiness', route.workflow_skills)

    def test_coordinated_plan_content_and_plural_nouns_remain_descriptive(self) -> None:
        # Splitting infinitives or excluding only singular nouns invents actions.
        cases = (
            ('Review the plan to deploy and publish the build', 'review'),
            ('Review the plans to deploy and publish the build', 'review'),
            ('Review the plan to deploy, then publish the build', 'review'),
            ('Create release plans', 'feature'),
            ('Prepare release checklists', 'feature'),
            ('Review the report; release plans are listed below', 'review'),
            ('Create release workflows', 'feature'),
            ('Prepare release policies', 'feature'),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt, expected in cases:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, expected)
                    self.assertNotIn('release-readiness', route.workflow_skills)
            self.assert_release_controls(
                Path(tmp), 'Review the plan to deploy and publish; publish the build through PR',
            )

    def test_historical_prefix_scopes_coordinated_action_shaped_content(self) -> None:
        # These marker-only examples independently catch removal of history scope.
        prompts = (
            'Review the report; yesterday, publish the artifact',
            'Review the report; last week, deploy the build',
            'Проведи ревью отчета; вчера, опубликуй пакет',
            'Review the report; yesterday, deploy and publish the build',
            'Review the note; release v2 was published',
            'Review the note; publish was requested',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, 'review')
                    self.assertNotIn('release-readiness', route.workflow_skills)

    def test_dotted_versions_and_bounded_historical_subjects_remain_review(self) -> None:
        # Numeric dots and qualified subjects must not sever the past predicate.
        prompts = (
            'Review the note; release v2.1.1 was published yesterday',
            'Review the note; release v2.1.1 was published',
            'Review the note; release candidate v2 was published',
            'Review the note; publish the reviewed artifact was requested',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, 'review')
                    self.assertNotIn('release-readiness', route.workflow_skills)

    def test_russian_coordinated_plan_infinitives_remain_descriptive(self) -> None:
        # Russian plan context must survive both optional colon and coordination.
        prompts = (
            'Проведи ревью плана развернуть сборку и опубликовать пакет',
            'Проведи ревью плана: развернуть сборку и опубликовать пакет',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, 'review')
                    self.assertNotIn('release-readiness', route.workflow_skills)
            self.assert_release_controls(
                Path(tmp), 'Проведи ревью плана развернуть сборку и опубликовать пакет; опубликуй пакет',
            )

    def test_context_exclusion_preserves_raw_domain_and_risk_safety(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            route = self.route(Path(tmp), 'Review "publish SQL auth package in production"')
            self.assertEqual(route.intent, 'review')
            self.assertEqual(set(route.task_domains), {'data', 'security'})
            self.assertEqual(route.risk, 'high')
            self.assertIn('production_action_approval', route.human_gates)
            self.assertNotIn('release-readiness', route.workflow_skills)

    def test_affirmative_operation_survives_pr_review_and_fix_words(self) -> None:
        # A review-first or defect-first ladder loses the requested operation.
        prompts = (
            'Release the artifact through a pull request',
            'Please release v2.1.1 via PR after review',
            'Review this PR, then deploy the build',
            'Fix the bug and publish the package through a pull request',
            'Can you deploy this build after code review?',
            'We need to release v2.1.1 through a pull request',
            'I want you to publish the artifact after review',
            'Prepare the production release through PR',
            'Run the canary rollout after review',
            'Roll back the deployment after review',
            'Выпусти релиз через pull request после review',
            'Проведи ревью PR, затем опубликуй пакет',
            'Исправь баг и выкати релиз через PR',
            'Нужно развернуть сборку после code review',
            'Подготовь production release и canary rollout через PR',
            'Сделай релиз через pull request',
            'Откати сборку после ревью',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, 'release')
                    self.assertEqual(route.risk, 'high')
                    self.assertIsNone(route.write_agent)
                    self.assertIn('release-readiness', route.workflow_skills)
                    self.assertEqual(set(route.review_agents), {
                        'code_reviewer', 'test_reviewer', 'security_reviewer',
                        'release_reviewer',
                    })
                    self.assertEqual(set(route.required_evidence), {
                        'verification', 'code_review', 'test_review',
                        'security_review', 'release_review',
                    })
                    self.assertEqual(route.human_gates, [
                        'scope_and_design_approval', 'production_action_approval',
                    ])

    def test_incidental_and_descriptive_mentions_keep_ordinary_intent(self) -> None:
        # A raw release substring or a generic infinitive would escalate these.
        cases = (
            ('Review this release plan', 'review'),
            ('Review the plan to deploy later', 'review'),
            ('Review the release checklist before we publish', 'review'),
            ('Review the PR deployment report', 'review'),
            ('Проведи ревью плана релиза', 'review'),
            ('Проверь код для публикации релиза', 'review'),
            ('Fix the release installer', 'bugfix'),
            ('Fix the rollback path', 'bugfix'),
            ('Fix prerelease handling', 'bugfix'),
            ('Fix unpublished artifact handling', 'bugfix'),
            ('Update release notes documentation', 'docs'),
            ('Create a release plan', 'feature'),
            ('Prepare release notes', 'feature'),
            ('Создай план релиза', 'feature'),
            ('Сделай релизный checklist', 'feature'),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt, expected in cases:
                with self.subTest(prompt=prompt):
                    route = self.route(Path(tmp), prompt)
                    self.assertEqual(route.intent, expected)
                    self.assertNotIn('release-readiness', route.workflow_skills)
                    if 'deploy' not in prompt:
                        self.assertNotIn('production_action_approval', route.human_gates)

    def test_negated_operations_do_not_mask_code_or_review_tasks(self) -> None:
        cases = (
            ("Don't deploy, fix the code", 'bugfix'),
            ('Do not release or publish; fix the bug', 'bugfix'),
            ('Never deploy and publish; review this PR', 'review'),
            ('Please do not release this build; review the PR', 'review'),
            ('Do not deploy and then publish; fix the code', 'bugfix'),
            ('Не выкатывай релиз, исправь код', 'bugfix'),
            ('Не опубликуй пакет и не разверни сборку; проверь код', 'review'),
            ('Не нужно выпускать релиз; проверь код', 'review'),
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt, expected in cases:
                with self.subTest(prompt=prompt):
                    self.assertEqual(self.route(Path(tmp), prompt).intent, expected)

    def test_negation_is_bounded_before_an_affirmative_operation(self) -> None:
        prompts = (
            'Do not deploy, but release the source through a pull request',
            "Don't publish; release the build via PR",
            'Не выкатывай в production, но опубликуй пакет через PR',
            'Не публикуй; затем выпусти релиз через pull request',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    self.assertEqual(self.route(Path(tmp), prompt).intent, 'release')

    def test_quoted_and_historical_operations_are_context_only(self) -> None:
        prompts = (
            'Review the example "release the artifact through PR"',
            "Review the example 'deploy the build'",
            "Review the example 'don't deploy and publish the package'",
            'Review the example `publish the package`',
            'Review the example "deploy the build\nand publish the package"',
            'Review the incomplete example "deploy the build\nand publish the package',
            'Review the example “release the package”',
            'Проведи ревью примера «опубликуй пакет»',
            'Review the script:\n```\ndeploy the build\npublish the artifact\n```',
            'Review the report; yesterday, deploy the build was the old instruction',
            'Review the report; historically: release the build through PR',
            'Review the note; release v2 was published yesterday',
            'Review the note; on 2026-09-24: publish the artifact was requested',
            'Проведи ревью отчета; вчера, выпусти релиз было старой командой',
            'Проведи ревью отчета; ранее: опубликуй пакет',
        )
        with tempfile.TemporaryDirectory() as tmp:
            for prompt in prompts:
                with self.subTest(prompt=prompt):
                    self.assertEqual(self.route(Path(tmp), prompt).intent, 'review')
            for prompt in (
                'Review "do not release"; release the build via PR',
                'Yesterday we deployed v2; publish v3 through PR',
                'Ранее выпустили релиз; теперь опубликуй пакет через PR',
            ):
                with self.subTest(prompt=prompt):
                    self.assertEqual(self.route(Path(tmp), prompt).intent, 'release')

    def test_incident_priority_retains_explicit_operation_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for prompt in ('Production down; fix the incident and release the patch via PR',
                           'Авария: исправь баг и опубликуй пакет через PR'):
                with self.subTest(prompt=prompt):
                    route = self.route(root, prompt)
                    self.assertEqual(route.intent, 'incident')
                    self.assertEqual(route.write_agent, 'general_implementer')
                    self.assertIn('incident-response', route.workflow_skills)
                    self.assertIn('release-readiness', route.workflow_skills)
                    self.assertIn('production_action_approval', route.human_gates)
            for prompt, expected, owner in (
                ('Review this pull request', 'review', None),
                ('Check the PR', 'review', None),
                ('Fix the bug with a regression test', 'bugfix', 'general_implementer'),
                ('Hotfix the rollback path', 'incident', 'general_implementer'),
            ):
                with self.subTest(prompt=prompt):
                    route = self.route(root, prompt)
                    self.assertEqual(route.intent, expected)
                    self.assertEqual(route.write_agent, owner)
                    self.assertNotIn('release-readiness', route.workflow_skills)


if __name__ == '__main__':
    unittest.main()
