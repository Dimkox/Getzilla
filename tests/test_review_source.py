from __future__ import annotations
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.receipts import write_receipt, validate_evidence
from getzilla.state import set_active_route
from getzilla.util import dump_json


class ReviewSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Test')
        self.git('config', 'user.email', 'test@example.com')
        (self.root / '.gitignore').write_text('.getzilla/runtime/\n')
        (self.root / 'source.py').write_text('value = 1\n')
        self.evidence = 'engineering/changes/test/evidence'
        (self.root / self.evidence).mkdir(parents=True)
        self.report = self.evidence + '/code-review.md'
        (self.root / self.report).write_text('Reviewed source.\n')
        self.commit()
        self.source = self.git('rev-parse', 'HEAD').strip()
        self.route = {'route_id': 'test', 'required_evidence': ['code_review']}
        set_active_route(self.root, self.route)
        dump_json(self.root / '.getzilla/runtime/active-change.json', {'path': 'engineering/changes/test', 'change_id': 'test'})

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.root, text=True)

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'candidate')

    def record(self, source=None, report=None):
        return write_receipt(self.root, 'code_review', 'pass', report or self.report,
                             reviewed_commit=source or self.source)

    def test_micro_route_without_package_admits_global_reports_and_consumption(self):
        (self.root / '.getzilla/runtime/active-change.json').unlink()
        self.route.update(complexity='micro', risk='low')
        set_active_route(self.root, self.route)
        self.report = 'engineering/reviews/code-review.md'
        (self.root / self.report).parent.mkdir(parents=True)
        (self.root / self.report).write_text('Independent micro review.\n')
        self.commit()
        self.source = self.git('rev-parse', 'HEAD').strip()
        (self.root / self.report).write_text('Saved independent micro review.\n')
        self.commit()
        self.record()
        self.assertEqual(validate_evidence(self.root, self.route), [])
        self.assertFalse((self.root / '.getzilla/runtime/active-change.json').exists())
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_review.py'
        result = subprocess.run([sys.executable, str(script), 'code_review', '--status', 'pass',
                                 '--report', self.report, '--reviewed-commit', self.source],
                                cwd=self.root, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_active_package_accepts_documented_global_review_location(self):
        self.report = 'engineering/reviews/code-review.md'
        (self.root / self.report).parent.mkdir(parents=True)
        (self.root / self.report).write_text('Independent report.\n')
        self.commit()
        self.source = self.git('rev-parse', 'HEAD').strip()
        self.record()
        self.assertEqual(validate_evidence(self.root, self.route), [])

    def test_missing_durable_or_malformed_selected_package_fails_closed(self):
        self.report = 'engineering/reviews/code-review.md'
        (self.root / self.report).parent.mkdir(parents=True)
        (self.root / self.report).write_text('Independent report.\n')
        self.commit()
        self.source = self.git('rev-parse', 'HEAD').strip()
        selected = self.root / '.getzilla/runtime/active-change.json'
        for active in (None, {}, {'path': '../escape', 'change_id': 'escape'}, []):
            selected.write_text(json.dumps(active))
            self.route.update(complexity='micro', risk='low')
            set_active_route(self.root, self.route)
            with self.assertRaises((RuntimeError, ValueError)):
                self.record()
        selected.unlink()
        for complexity, risk in (('standard', 'low'), ('high-risk', 'high'), ('micro', 'high')):
            self.route.update(complexity=complexity, risk=risk)
            set_active_route(self.root, self.route)
            with self.assertRaises((RuntimeError, ValueError)):
                self.record()

    def test_micro_unsafe_selected_metadata_does_not_fall_back(self):
        self.route.update(complexity='micro', risk='low')
        set_active_route(self.root, self.route)
        selected = self.root / '.getzilla/runtime/active-change.json'
        selected.unlink()
        try:
            selected.symlink_to(self.root / 'source.py')
        except OSError:
            self.skipTest('symlinks unavailable')
        with self.assertRaises((RuntimeError, ValueError)):
            self.record()

    def test_pass_requires_reviewed_identity(self):
        with self.assertRaisesRegex((ValueError, RuntimeError), 'reviewed'):
            write_receipt(self.root, 'code_review', 'pass', self.report)

    def test_report_only_commit_binds_reviewed_tree(self):
        (self.root / self.report).write_text('Saved final review.\n')
        self.commit()
        receipt = json.loads(self.record().read_text())
        self.assertEqual(receipt['review_source']['reviewed_commit'], self.source)
        self.assertEqual(receipt['review_source']['reviewed_tree'], self.git('rev-parse', self.source + '^{tree}').strip())
        self.assertEqual(validate_evidence(self.root, self.route), [])

    def test_rejects_source_delta_and_dirty_or_untracked_candidate(self):
        for mode in ('dirty', 'untracked', 'committed'):
            with self.subTest(mode=mode):
                path = self.root / ('extra.py' if mode == 'untracked' else 'source.py')
                path.write_text('value = 2\n')
                if mode == 'committed':
                    self.commit()
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    self.record()
                if mode == 'untracked':
                    path.unlink()
                else:
                    self.git('restore', 'source.py')

    def test_rejects_unsafe_revisions_and_report_paths(self):
        for source in ('HEAD', '--help', self.source + '~0', 'f' * 40,
                       self.git('rev-parse', 'HEAD^{tree}').strip()):
            with self.subTest(source=source), self.assertRaises((RuntimeError, ValueError, OSError)):
                self.record(source=source)
        for report in ('../outside.md', '/tmp/report.md', self.evidence + '/../brief.md', 'source.py'):
            with self.subTest(report=report), self.assertRaises((RuntimeError, ValueError, OSError)):
                self.record(report=report)

    def test_rejects_staged_source_and_symlink_report_parent(self):
        (self.root / 'source.py').write_text('staged source delta\n')
        self.git('add', 'source.py')
        with self.assertRaises((RuntimeError, ValueError)):
            self.record()
        self.git('restore', '--staged', 'source.py')
        self.git('restore', 'source.py')
        directory = self.root / self.evidence
        saved = self.root / 'saved-evidence'
        directory.rename(saved)
        try:
            directory.symlink_to(saved, target_is_directory=True)
        except OSError:
            self.skipTest('directory symlinks unavailable')
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.record()

    def test_rejects_nonancestor(self):
        self.git('checkout', '--orphan', 'other')
        (self.root / 'source.py').write_text('other history\n')
        self.commit()
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.record()

    def test_rejects_deleted_renamed_executable_or_symlink_evidence(self):
        for mode in ('delete', 'rename', 'executable', 'symlink'):
            with self.subTest(mode=mode):
                report = self.root / self.report
                if mode == 'delete':
                    report.unlink()
                elif mode == 'rename':
                    report.rename(report.with_name('renamed.md'))
                elif mode == 'executable':
                    report.chmod(0o755)
                    if not report.stat().st_mode & 0o111:
                        continue
                else:
                    report.unlink()
                    try:
                        report.symlink_to(self.root / 'source.py')
                    except OSError:
                        self.skipTest('symlinks unavailable')
                self.commit()
                with self.assertRaises((RuntimeError, ValueError, OSError)):
                    self.record()
                self.git('checkout', self.source, '--', self.evidence)
                self.commit()

    def test_git_executable_report_mode_is_rejected_even_without_fs_mode_tracking(self):
        self.git('config', 'core.filemode', 'false')
        self.git('update-index', '--chmod=+x', self.report)
        self.git('commit', '-qm', 'executable Git report')
        with self.assertRaisesRegex(RuntimeError, 'Git entry'):
            self.record()

    def test_consumption_rejects_missing_and_forged_binding(self):
        for mutation in ('missing', 'tree', 'commit', 'report_digest'):
            with self.subTest(mutation=mutation):
                path = self.record()
                data = json.loads(path.read_text())
                if mutation == 'missing':
                    data.pop('review_source')
                else:
                    field = {'tree': 'reviewed_tree', 'commit': 'reviewed_commit', 'report_digest': 'report_sha256'}[mutation]
                    data['review_source'][field] = '0' * 40
                path.write_text(json.dumps(data))
                self.assertTrue(any('review source' in gap for gap in validate_evidence(self.root, self.route)))

    def test_index_and_analysis_cannot_be_supplied_as_review_report(self):
        for name in ('README.md', 'analysis-code-review.md', 'checkpoint.md'):
            report = self.evidence + '/' + name
            (self.root / report).write_text('Not an independent report.\n')
            self.commit()
            with self.assertRaises((RuntimeError, ValueError)):
                self.record(source=self.git('rev-parse', 'HEAD').strip(), report=report)

    def test_supported_cyrillic_change_identity(self):
        destination = 'engineering/changes/тест-проверка'
        (self.root / 'engineering/changes/test').rename(self.root / destination)
        self.report = destination + '/evidence/code-review.md'
        self.commit()
        self.source = self.git('rev-parse', 'HEAD').strip()
        dump_json(self.root / '.getzilla/runtime/active-change.json',
                  {'path': destination, 'change_id': 'тест-проверка'})
        self.assertEqual(validate_evidence(self.root, self.route), ['code_review: missing receipt'])
        self.record()
        self.assertEqual(validate_evidence(self.root, self.route), [])

    def test_cli_requires_identity_and_preserves_failure_observation(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/getzilla_review.py'
        args = [sys.executable, str(script), 'code_review', '--report', self.report]
        missing = subprocess.run(args + ['--status', 'pass'], cwd=self.root,
                                 capture_output=True, text=True)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('--reviewed-commit is required for pass', missing.stderr)
        # No selected package is needed for a failed observation in this minimal fixture.
        (self.root / '.getzilla/runtime/active-change.json').unlink()
        failed = subprocess.run(args + ['--status', 'fail'], cwd=self.root,
                                capture_output=True, text=True)
        self.assertEqual(failed.returncode, 0, failed.stderr)

    def test_rejects_other_report_directory_and_executable_evidence_delta(self):
        for path in ('engineering/reviews/other.md', self.evidence + '/probe.py',
                     self.evidence + '/analysis-architect.md', self.evidence + '/README.md',
                     self.evidence + '/checkpoint.md'):
            with self.subTest(path=path):
                target = self.root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('Unreviewed delta.\n')
                self.commit()
                with self.assertRaises((RuntimeError, ValueError)):
                    self.record()
                self.git('rm', path)
                self.commit()

    def test_fail_does_not_require_reviewed_identity(self):
        path = write_receipt(self.root, 'code_review', 'fail')
        self.assertEqual(json.loads(path.read_text())['status'], 'fail')
