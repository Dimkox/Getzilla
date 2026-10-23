"""The small-change lane is admitted from complete source evidence, never task wording."""
from __future__ import annotations
import sys
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from tests.branch_support import git

class LightLaneTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        git(self.root, 'init', '-q', '-b', 'work')
        (self.root / 'README.md').write_text('base\n')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'base')
        self.base = git(self.root, 'rev-parse', 'HEAD')

    def admit(self, files, *, risk='low', complete=True):
        from getzilla.light_lane import inspect_light_diff
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content if isinstance(content, bytes) else content.encode())
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'change')
        return inspect_light_diff(self.root, [self.base], risk=risk, complete=complete)

    def test_fifty_code_lines_exclude_test_and_document_lines(self):
        result = self.admit({'src/page.py': 'x = 1\n' * 50, 'tests/test_page.py': '# test\n' * 100,
                             'docs/guide.md': 'guide\n' * 100})
        self.assertTrue(result['admitted'], result)
        self.assertEqual(result['code_lines'], 50)

    def test_fifty_one_code_lines_promote_to_full(self):
        self.assertFalse(self.admit({'src/page.py': 'x = 1\n' * 51})['admitted'])

    def test_replacement_counts_both_removed_and_added_code_lines(self):
        from getzilla.light_lane import inspect_light_diff
        path = self.root / 'app.py'
        path.write_text('old_value = 1\n' * 25)
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'replacement baseline')
        base = git(self.root, 'rev-parse', 'HEAD')
        for added, admitted, reason in [(25, True, 'small_diff'), (26, False, 'code_line_limit_exceeded')]:
            with self.subTest(added=added):
                path.write_text('new_value = 2\n' * added)
                git(self.root, 'add', '.')
                git(self.root, 'commit', '-qm', 'replacement')
                result = inspect_light_diff(self.root, [base], risk='low', complete=True)
                self.assertEqual(result['code_lines'], 25 + added)
                self.assertEqual((result['admitted'], result['reason']), (admitted, reason))

    def test_sensitive_docs_paths_and_binary_content_never_qualify(self):
        for path, data in [('docs/AGENTS.md', 'control'), ('docs/requirements.txt', 'dependency'),
                           ('docs/bitrix-local-AGENTS.md', 'installed instructions'),
                           ('scripts/getzilla_approve.py', 'pass\n'), ('trust-ci/tests/test_x.py', 'pass\n'),
                           ('src/blob.py', b'\x00binary')]:
            with self.subTest(path=path):
                self.assertFalse(self.admit({path: data})['admitted'])
                self.base = git(self.root, 'rev-parse', 'HEAD')

    def test_source_below_docs_counts_as_code(self):
        result = self.admit({'docs/tool.py': 'x = 1\n' * 51})
        self.assertFalse(result['admitted'])

    def test_executable_markdown_is_not_excluded_as_documentation(self):
        from getzilla.light_lane import inspect_light_diff
        path = self.root / 'tool.md'
        path.write_text('echo probe\n' * 51)
        git(self.root, 'add', '.')
        git(self.root, 'update-index', '--chmod=+x', 'tool.md')
        git(self.root, 'commit', '-qm', 'executable document')
        # Set the worktree mode too where Git observes it; the admission reads
        # committed modes, so this also exercises Windows with core.filemode=false.
        path.chmod(0o755)
        result = inspect_light_diff(self.root, [self.base], risk='low', complete=True)
        self.assertFalse(result['admitted'])
        self.assertEqual(result['code_lines'], 51)

    def test_medium_risk_and_incomplete_inventory_never_qualify(self):
        self.assertFalse(self.admit({'src/page.py': 'x = 1\n'}, risk='medium')['admitted'])
        self.assertFalse(self.admit({'src/page.py': 'x = 2\n'}, complete=False)['admitted'])

    def test_dirty_inventory_and_renames_do_not_qualify(self):
        from getzilla.light_lane import inspect_light_diff
        (self.root / 'src.py').write_text('x = 1\n')
        self.assertFalse(inspect_light_diff(self.root, [self.base], risk='low', complete=True)['admitted'])
        git(self.root, 'mv', 'README.md', 'guide.md')
        git(self.root, 'add', '.')
        git(self.root, 'commit', '-qm', 'rename')
        self.assertFalse(inspect_light_diff(self.root, [self.base], risk='low', complete=True)['admitted'])

class LightLaneVerificationTests(unittest.TestCase):
    def test_escalation_authorizes_the_required_reviewers_without_changing_writer(self):
        from getzilla.agent_lifecycle import start_agent
        from getzilla.policy import evaluate_pre_tool
        from getzilla.router import build_route
        from getzilla.state import get_active_route, set_active_route
        from getzilla.verification import verify
        from tests._support import project_copy
        for path, content, reason in [('app.py', 'value = 1\n' * 51, 'code_line_limit_exceeded'),
                                      ('.getzilla/getzilla/service.py', 'value = 1\n', 'risk_requires_full_lane')]:
            with self.subTest(path=path), project_copy(git=True) as root:
                base = git(root, 'rev-parse', 'HEAD')
                git(root, 'update-ref', 'refs/remotes/origin/main', base)
                original = build_route(root, 'Fix the greeting text', 'escalation-e2e').to_dict()
                original.update(base_commit=base, quality_profiles=['base'])
                self.assertEqual(original['review_agents'], ['code_reviewer'])
                set_active_route(root, original)
                source = root / path
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(content)
                git(root, 'add', '.')
                git(root, 'commit', '-qm', 'change requiring full review')
                report = verify(root, mode='fast', record=False)
                self.assertEqual(report['light_diff']['reason'], reason)
                self.assertFalse(report['light_diff']['admitted'])
                current = get_active_route(root)
                self.assertEqual(current['write_agent'], original['write_agent'])
                self.assertEqual(current['analysis_agents'], original['analysis_agents'])
                self.assertTrue(set(original['allowed_agents']) <= set(current['allowed_agents']))
                self.assertEqual(current['review_agents'], ['code_reviewer', 'security_reviewer'] if path.startswith('.getzilla/') else ['code_reviewer'])
                reviewer = 'security_reviewer' if path.startswith('.getzilla/') else 'code_reviewer'
                allowed, refusal = evaluate_pre_tool(root, {'tool_name': 'Agent',
                    'tool_input': {'agent_type': reviewer}})
                self.assertTrue(allowed, refusal)
                self.assertEqual(start_agent(root, 'test-review', reviewer)['lifecycle'], 'running')

    def test_fast_verifier_admits_small_code_without_package_then_restores_full_floor(self):
        from getzilla.router import build_route
        from getzilla.state import get_active_route, set_active_route
        from getzilla.verification import verify
        from tests._support import project_copy
        with project_copy(git=True) as root:
            base = git(root, 'rev-parse', 'HEAD')
            git(root, 'update-ref', 'refs/remotes/origin/main', base)
            route = build_route(root, 'Fix the greeting text', 'light-e2e').to_dict()
            route['base_commit'] = base
            route['quality_profiles'] = ['base']
            self.assertEqual(route['delivery_lane'], 'light')
            set_active_route(root, route)
            (root / 'app.py').write_text('def greeting():\n    return "hello"\n')
            (root / 'tests').mkdir()
            (root / 'tests/test_app.py').write_text('import unittest\nfrom app import greeting\nclass Tests(unittest.TestCase):\n    def test_greeting(self):\n        self.assertEqual(greeting(), "hello")\n')
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'small code and regression')
            report = verify(root, mode='fast', record=False)
            self.assertTrue(report['light_diff']['admitted'], report['light_diff'])
            self.assertEqual(report['status'], 'pass', report['checks'])
            self.assertEqual(get_active_route(root)['required_evidence'], ['verification', 'code_review'])
            self.assertFalse((root / '.getzilla/runtime/active-change.json').exists())
            self.assertNotEqual(next(item for item in report['checks'] if item['name'] == 'change-spec')['status'], 'fail')
            (root / 'app.py').write_text('def greeting():\n    return "hello"\n' + 'value = 1\n' * 51)
            git(root, 'add', '.')
            git(root, 'commit', '-qm', 'larger successor')
            report = verify(root, mode='fast', record=False)
            self.assertFalse(report['light_diff']['admitted'])
            self.assertEqual(get_active_route(root)['required_evidence'], ['verification', 'code_review'])
            self.assertEqual(report['status'], 'fail')
            self.assertEqual(next(item for item in report['checks'] if item['name'] == 'light-lane')['status'], 'fail')
