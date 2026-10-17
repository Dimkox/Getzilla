"""S01: stacks come from the registry; a detected stack without checks is never a silent pass."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.quality_gates import required_check_refused  # noqa: E402
from getzilla.stacks import NOT_VERIFIED, Stack, detect_stacks, load_registry, stack_checks, tree_files  # noqa: E402
from getzilla.verification import CheckResult, verify  # noqa: E402

OFFICIAL_HOSTS = ('https://nodejs.org/', 'https://static.rust-lang.org/', 'https://builds.dotnet.microsoft.com/',
                  'https://www.powershellgallery.com/')
DIGEST_LENGTH = {'sha256': 64, 'sha512': 128, 'sha512-base64': 88}


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


def _git(root: Path, *args: str) -> None:
    subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)


def _no_command(*_args, **_kwargs):
    raise AssertionError('a not-verified stack must not run commands')


class RegistryTests(unittest.TestCase):
    def test_registry_entries_are_complete_and_sources_official(self) -> None:
        data = json.loads((ROOT / '.getzilla' / 'config' / 'stacks.json').read_text(encoding='utf-8'))
        self.assertEqual(data['schema_version'], 'getzilla-stacks-v1')
        for stack_id, item in data['stacks'].items():
            with self.subTest(stack=stack_id):
                self.assertTrue(item['markers'])
                self.assertTrue(item['extensions'])
                toolchain = item.get('toolchain')
                if not toolchain:
                    continue
                source = toolchain['source']
                urls = [value for key, value in source.items() if key.endswith('url')]
                urls += [value['url'] for value in source.values() if isinstance(value, dict) and 'url' in value]
                for url in urls:
                    self.assertTrue(url.startswith(OFFICIAL_HOSTS), url)
                length = DIGEST_LENGTH[source['algorithm']]
                pinned = [digest for per_version in source.get('pinned', {}).values() for digest in per_version.values()]
                pinned += [module['hash'] for module in source.get('modules', {}).values()]
                self.assertTrue(pinned, 'a toolchain without a pinned digest cannot be checked offline')
                for digest in pinned:
                    self.assertEqual(len(digest), length, digest)
                    if not source['algorithm'].endswith('-base64'):
                        self.assertRegex(digest, r'^[0-9a-f]+$')
                if 'pinned' in source:
                    self.assertIn(toolchain['default_version'] if source['kind'] != 'rustup' else source['rustup_version'],
                                  source['pinned'])

    def test_recorded_node_manifest_matches_the_pinned_digests(self) -> None:
        recorded = (ROOT / 'tests' / 'fixtures' / 'stacks' / 'node' / 'SHASUMS256-v24.22.0.txt').read_text(encoding='utf-8')
        published = {name: digest for digest, name in (line.split() for line in recorded.splitlines() if line.strip())}
        node = load_registry(ROOT)['node'].toolchain
        assert node is not None
        for key, digest in node['source']['pinned']['24.22.0'].items():
            self.assertEqual(published[node['source']['archives'][key].format(version='24.22.0')], digest, key)


class DetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_detects_by_marker_and_ignores_fixtures_and_dependencies(self) -> None:
        _write(self.root, {'Cargo.toml': '[package]\nname = "x"\n', 'src/main.rs': 'fn main() {}\n',
                           'tests/fixtures/go/go.mod': 'module x\n', 'node_modules/a/package.json': '{}',
                           'tools/build.ps1': 'Write-Output 1\n'})
        found = {stack.id for stack in detect_stacks(self.root)}
        self.assertEqual(found, {'rust', 'powershell'})
        self.assertNotIn('node_modules/a/package.json', tree_files(self.root))

    def test_git_tree_skips_ignored_files(self) -> None:
        _write(self.root, {'go.mod': 'module x\n', '.gitignore': 'gen/\n', 'gen/Gemfile': ''})
        _git(self.root, 'init', '-q')
        self.assertEqual({stack.id for stack in detect_stacks(self.root)}, {'go'})


class NotVerifiedTests(unittest.TestCase):
    REGISTRY = {'cobol': Stack('cobol', ('*.cbl',), ('.cbl', '.cpy'))}

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        _write(self.root, {'pay.cbl': 'IDENTIFICATION DIVISION.\n', 'copy/rec.cpy': ''})

    def _checks(self, mode: str, changed: list[str]):
        return stack_checks(self.root, mode, changed, make=CheckResult, command=_no_command, registry=self.REGISTRY, runners={})

    def test_pr_with_changed_files_of_an_unchecked_stack_fails(self) -> None:
        results, metadata = self._checks('pr', ['pay.cbl'])
        self.assertEqual([(check.name, check.status) for check in results], [('stack:cobol', 'fail')])
        self.assertEqual(results[0].details[0]['code'], f'{NOT_VERIFIED}:cobol')
        self.assertTrue(required_check_refused(results[0], mode='pr'))
        self.assertEqual(metadata['not_verified'], ['cobol'])

    def test_untouched_stack_is_reported_but_does_not_refuse(self) -> None:
        results, metadata = self._checks('pr', ['README.md'])
        self.assertEqual(results[0].status, 'skip')
        self.assertEqual(results[0].details[0]['code'], f'{NOT_VERIFIED}:cobol')
        self.assertFalse(required_check_refused(results[0], mode='pr'))
        self.assertEqual(metadata['untouched'], ['cobol'])

    def test_fast_mode_warns_instead_of_refusing(self) -> None:
        results, _ = self._checks('fast', ['copy/rec.cpy'])
        self.assertEqual(results[0].status, 'skip')
        self.assertEqual(results[0].details[0]['severity'], 'warning')

    def test_registered_runner_replaces_the_not_verified_line(self) -> None:
        def runner(context):
            return [context.make('cobol-compile', 'pass', 'exit=0')]
        results, metadata = stack_checks(self.root, 'pr', ['pay.cbl'], make=CheckResult, command=_no_command,
                                         registry=self.REGISTRY, runners={'cobol': runner})
        self.assertEqual([check.name for check in results], ['cobol-compile'])
        self.assertEqual(metadata['checked'], ['cobol'])

    def test_verify_pr_report_carries_the_marker(self) -> None:
        _write(self.root, {'go.mod': 'module example.com/x\n\ngo 1.22\n', 'main.go': 'package main\n'})
        _git(self.root, 'init', '-q', '-b', 'main')
        _git(self.root, 'add', '-A')
        _git(self.root, '-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'base')
        (self.root / 'main.go').write_text('package main\n\nfunc main() {}\n', encoding='utf-8')
        report = verify(self.root, mode='fast', record=False, keep_going=True)
        stack = next(check for check in report['checks'] if check['name'] == 'stack:go')
        self.assertEqual(stack['details'][0]['code'], f'{NOT_VERIFIED}:go')
        self.assertIn('go', report['stacks']['not_verified'])


if __name__ == '__main__':
    unittest.main()
