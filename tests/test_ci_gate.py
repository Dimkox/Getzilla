"""CI gate by repository visibility: public -> GitHub Actions, private -> Trust CI.

Every process and network call is injected, so these tests run offline and on
Windows. One test drives the real ``git`` binary when it is installed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import ci_gate  # noqa: E402
from getzilla.ci_gate import CommandResult, HttpResponse  # noqa: E402
from tests._support import project_copy, run_hook  # noqa: E402

TEMPLATE = ROOT / ci_gate.TEMPLATE_PATH
REMOTE = 'https://github.com/example-owner/example-repo.git'
SLUG = 'example-owner/example-repo'
PINNED_USES = re.compile(r'^\s*(?:-\s+)?uses:\s+(\S+)@([0-9a-f]{40}) # v\d+(?:\.\d+)*\s*$')


def _load_cli():
    spec = importlib.util.spec_from_file_location('getzilla_ci_under_test', ROOT / 'scripts/getzilla_ci.py')
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


CLI = _load_cli()


def fake_runner(
    *, remote: str | None = REMOTE, head: str | None = 'refs/remotes/origin/main', gh: CommandResult | None = None,
):
    calls: list[list[str]] = []

    def runner(args, cwd):
        argv = list(args)
        calls.append(argv)
        if argv[:3] == ['git', 'remote', 'get-url']:
            return CommandResult(0, remote + '\n', '') if remote else CommandResult(2, '', 'error: No such remote')
        if argv[:2] == ['git', 'rev-parse']:
            return CommandResult(0, f'{cwd}\n', '')
        if argv[:2] == ['git', 'symbolic-ref']:
            return CommandResult(0, head + '\n', '') if head else CommandResult(1, '', '')
        if len(argv) > 1 and argv[1] == 'api':
            if gh is None:
                raise AssertionError('gh must not be called')
            return gh
        raise AssertionError(f'unexpected command: {argv}')

    runner.calls = calls  # type: ignore[attr-defined]
    return runner


def no_network(url: str) -> HttpResponse:
    raise AssertionError(f'unexpected network request: {url}')


def no_gh(name: str) -> None:
    return None


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob('*'))
        if path.is_file()
    }


class SlugParsingTests(unittest.TestCase):
    def test_github_https_and_ssh_remotes(self) -> None:
        for url in (
            'https://github.com/Dimkox/Getzilla',
            'https://github.com/Dimkox/Getzilla.git',
            'https://github.com/Dimkox/Getzilla/',
            'http://github.com/Dimkox/Getzilla.git',
            'https://x-access-token:secret@github.com/Dimkox/Getzilla.git',
            'https://GitHub.com/Dimkox/Getzilla.git',
            'git@github.com:Dimkox/Getzilla.git',
            'git@github.com:Dimkox/Getzilla',
            'ssh://git@github.com/Dimkox/Getzilla.git',
            'ssh://git@ssh.github.com:443/Dimkox/Getzilla.git',
            '  https://github.com/Dimkox/Getzilla.git\n',
        ):
            with self.subTest(url=url):
                self.assertEqual(ci_gate.parse_github_remote(url), 'Dimkox/Getzilla')
        self.assertEqual(ci_gate.parse_github_remote('git@github.com:a-b/c.d_e-f.git'), 'a-b/c.d_e-f')

    def test_non_github_or_malformed_remotes_have_no_slug(self) -> None:
        for url in (
            '',
            'https://gitlab.com/Dimkox/Getzilla.git',
            'https://github.com.evil.example/Dimkox/Getzilla.git',
            'https://evilgithub.com/Dimkox/Getzilla.git',
            'git@gitlab.com:Dimkox/Getzilla.git',
            'https://github.example.com/Dimkox/Getzilla.git',
            'https://github.com/Dimkox',
            'https://github.com/Dimkox/Getzilla/tree/main',
            'https://github.com/-bad/Getzilla.git',
            'https://github.com/Dimkox/..',
            '/home/user/Getzilla',
            'file:///srv/git/Getzilla.git',
        ):
            with self.subTest(url=url):
                self.assertIsNone(ci_gate.parse_github_remote(url))

    def test_repository_slug_reads_origin_and_never_needs_the_network(self) -> None:
        runner = fake_runner()
        self.assertEqual(ci_gate.repository_slug(Path('.'), runner=runner), SLUG)
        self.assertEqual(runner.calls, [['git', 'remote', 'get-url', 'origin']])
        self.assertIsNone(ci_gate.repository_slug(Path('.'), runner=fake_runner(remote=None)))
        self.assertIsNone(
            ci_gate.repository_slug(Path('.'), runner=fake_runner(remote='https://gitlab.com/a/b.git'))
        )

    @unittest.skipUnless(shutil.which('git'), 'git is not installed')
    def test_repository_slug_with_real_git(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            self.assertIsNone(ci_gate.repository_slug(root))
            subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'git@github.com:o/r.git'], check=True)
            self.assertEqual(ci_gate.repository_slug(root), 'o/r')


class VisibilityDetectionTests(unittest.TestCase):
    def test_gh_answer_is_used_and_pinned_to_github_com(self) -> None:
        for answer, expected in (('false', ci_gate.PUBLIC), ('true', ci_gate.PRIVATE)):
            with self.subTest(answer=answer):
                runner = fake_runner(gh=CommandResult(0, answer + '\n', ''))
                found = ci_gate.detect_visibility(
                    SLUG, runner=runner, fetch=no_network, which=lambda name: '/usr/bin/gh',
                )
                self.assertEqual((found.visibility, found.source), (expected, 'gh'))
                self.assertEqual(
                    runner.calls,
                    [['/usr/bin/gh', 'api', '--hostname', 'github.com', f'repos/{SLUG}', '--jq', '.private']],
                )

    def test_https_without_gh(self) -> None:
        seen: list[str] = []

        def fetch(body: bytes, status: int = 200):
            def inner(url: str) -> HttpResponse:
                seen.append(url)
                return HttpResponse(status, body)
            return inner

        public = ci_gate.detect_visibility(SLUG, runner=fake_runner(), fetch=fetch(b'{"private": false}'), which=no_gh)
        self.assertEqual((public.visibility, public.source), (ci_gate.PUBLIC, 'https'))
        self.assertEqual(seen, [f'https://api.github.com/repos/{SLUG}'])
        private = ci_gate.detect_visibility(SLUG, runner=fake_runner(), fetch=fetch(b'{"private": true}'), which=no_gh)
        self.assertEqual(private.visibility, ci_gate.PRIVATE)
        for body in (b'{}', b'{"private": "false"}', b'[]', b'not json', b'\xff'):
            with self.subTest(body=body):
                found = ci_gate.detect_visibility(SLUG, runner=fake_runner(), fetch=fetch(body), which=no_gh)
                self.assertEqual(found.visibility, ci_gate.UNKNOWN)

    def test_404_and_other_failures_are_unknown_not_private(self) -> None:
        for response in (HttpResponse(404, b''), HttpResponse(403, b''), HttpResponse(500, b''),
                         HttpResponse(0, b'', 'timed out')):
            with self.subTest(status=response.status):
                found = ci_gate.detect_visibility(
                    SLUG, runner=fake_runner(), fetch=lambda url, r=response: r, which=no_gh,
                )
                self.assertEqual(found.visibility, ci_gate.UNKNOWN)
                self.assertIsNone(ci_gate.select_gate(found.visibility))
        not_found = ci_gate.detect_visibility(
            SLUG, runner=fake_runner(), fetch=lambda url: HttpResponse(404, b''), which=no_gh,
        )
        self.assertIn('private or does not exist', not_found.detail)

    def test_failed_gh_falls_back_to_https(self) -> None:
        for gh in (CommandResult(1, '', 'gh: Not Found (HTTP 404)'), CommandResult(0, 'null\n', ''),
                   CommandResult(4, '', 'not logged in')):
            with self.subTest(gh=gh):
                found = ci_gate.detect_visibility(
                    SLUG,
                    runner=fake_runner(gh=gh),
                    fetch=lambda url: HttpResponse(200, b'{"private": false}'),
                    which=lambda name: 'gh',
                )
                self.assertEqual((found.visibility, found.source), (ci_gate.PUBLIC, 'https'))
                self.assertIn('gh api gave no answer', found.detail)

    def test_invalid_slug_makes_no_call(self) -> None:
        for slug in (None, '', 'just-owner', 'a/b/c', '../x'):
            with self.subTest(slug=slug):
                found = ci_gate.detect_visibility(
                    slug, runner=fake_runner(), fetch=no_network, which=lambda name: 'gh',
                )
                self.assertEqual((found.visibility, found.source), (ci_gate.UNKNOWN, 'none'))

    def test_https_get_sends_no_credentials_and_stays_on_the_api_host(self) -> None:
        with self.assertRaises(ci_gate.CiGateError):
            ci_gate.https_get('https://example.com/repos/o/r')
        with self.assertRaises(ci_gate.CiGateError):
            ci_gate.https_get('http://api.github.com/repos/o/r')
        captured = []

        class Response(io.BytesIO):
            status = 200

        class Opener:
            def open(self, request, timeout):
                captured.append((request, timeout))
                return Response(b'{"private": false}')

        with mock.patch.object(ci_gate.urllib.request, 'build_opener', return_value=Opener()), \
                mock.patch.dict('os.environ', {'GITHUB_TOKEN': 'must-not-leak', 'GH_TOKEN': 'must-not-leak'}):
            response = ci_gate.https_get('https://api.github.com/repos/o/r')
        self.assertEqual((response.status, response.body), (200, b'{"private": false}'))
        request, timeout = captured[0]
        self.assertEqual(request.full_url, 'https://api.github.com/repos/o/r')
        self.assertEqual(request.get_method(), 'GET')
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertNotIn('authorization', headers)
        self.assertNotIn('must-not-leak', json.dumps(headers))
        self.assertLessEqual(timeout, 30)


class CiGateArchitectureTests(unittest.TestCase):
    def test_selector_has_specific_network_ownership_without_changing_local_policy(self):
        from getzilla.architecture import load_architecture
        from getzilla.architecture_fitness import _owner_for_path
        snapshot = load_architecture(ROOT)
        owner = _owner_for_path(snapshot, '.getzilla/getzilla/ci_gate.py')
        self.assertIsNotNone(owner)
        self.assertEqual(owner['id'], 'NODE-LOCAL-CI-GATE')
        self.assertEqual(owner['repository_paths'], ['.getzilla/getzilla/ci_gate.py'])
        self.assertEqual(owner['runtime']['network'], 'declared_egress')
        policy = next(node for node in snapshot.system['nodes'] if node['id'] == 'NODE-LOCAL-ROUTE-POLICY')
        self.assertEqual(policy['runtime']['network'], 'none')

    def test_actual_https_import_requires_the_specific_declared_github_edge(self):
        import ast
        import copy
        from dataclasses import replace
        from types import SimpleNamespace
        from getzilla.architecture import load_architecture
        from getzilla import architecture_fitness as fitness
        source = '.getzilla/getzilla/ci_gate.py'
        snapshot = load_architecture(ROOT)
        tree = ast.parse((ROOT / source).read_bytes(), filename=source)
        diff = SimpleNamespace(artifacts=(SimpleNamespace(path=source, status='modified'),))
        inventory = SimpleNamespace(root=ROOT, tree=lambda path: tree if path == source else None)
        # Only this actual source is in this bounded rule contrast. Do not load
        # the whole repository's unrelated import-root inventory or run HTTP.
        with mock.patch.object(fitness, '_repository_paths', return_value=(source,)):
            result = fitness._network_clients(snapshot, diff, inventory)
            self.assertEqual(result.status, 'pass', result.findings)
            changed = copy.deepcopy(snapshot.system)
            edge = next(edge for edge in changed['edges'] if edge['id'] == 'EDGE-LOCAL-CI-GITHUB-VISIBILITY')
            self.assertEqual((edge['from'], edge['to'], edge['protocol'], edge['authentication']),
                             ('NODE-LOCAL-CI-GATE', 'NODE-GITHUB', 'https', 'none'))
            self.assertEqual(edge['failure_behavior']['timeout_ms'], int(ci_gate.HTTP_TIMEOUT_SECONDS * 1000))
            self.assertEqual(edge['failure_behavior']['max_retries'], 0)
            changed['edges'].remove(edge)
            denied = fitness._network_clients(replace(snapshot, system=changed), diff, inventory)
        self.assertEqual(denied.status, 'fail')
        self.assertTrue(any('undeclared network client https' in finding for finding in denied.findings))


class GateSelectionTests(unittest.TestCase):
    def test_visibility_selects_the_gate(self) -> None:
        self.assertEqual(ci_gate.select_gate('public'), 'github-actions')
        self.assertEqual(ci_gate.select_gate('private'), 'trust-ci')
        self.assertIsNone(ci_gate.select_gate('unknown'))
        with self.assertRaises(ci_gate.CiGateError):
            ci_gate.select_gate('internal')

    def test_explicit_visibility_skips_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for visibility, gate in (('public', 'github-actions'), ('private', 'trust-ci')):
                with self.subTest(visibility=visibility):
                    plan = ci_gate.plan_gate(
                        Path(tmp), ROOT, visibility=visibility,
                        runner=fake_runner(), fetch=no_network, which=lambda name: 'gh',
                    )
                    self.assertEqual((plan['gate'], plan['visibility_source']), (gate, 'explicit'))
            with self.assertRaises(ci_gate.CiGateError):
                ci_gate.plan_gate(Path(tmp), ROOT, visibility='unknown', runner=fake_runner())

    def test_the_getzilla_source_repository_keeps_its_own_workflow(self) -> None:
        plan = ci_gate.plan_gate(ROOT, ROOT, visibility='public', runner=fake_runner(), fetch=no_network)
        self.assertEqual(plan['writes'][0]['state'], 'source-repository')
        self.assertFalse((ROOT / ci_gate.WORKFLOW_PATH).exists())


class WorkflowTemplateTests(unittest.TestCase):
    def test_explicit_platforms_render_native_matrix_and_reject_unknown_before_write(self) -> None:
        rendered = ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main',
                                         platforms=['linux-x64', 'macos-arm64', 'windows-x64']).decode()
        self.assertIn('runner.os', rendered)
        self.assertIn('macos-15', rendered)
        self.assertIn('windows-2025', rendered)
        self.assertIn('fail-fast: false', rendered)
        self.assertIn('needs: getzilla-verify-platform', rendered)
        self.assertIn('if: always()', rendered)
        self.assertIn('python scripts/getzilla_update.py --only opengrep', rendered)
        for names in ([], ['unknown'], ['windows-arm64'], ['linux-x64', 'linux-x64']):
            with self.subTest(names=names), self.assertRaises(ci_gate.CiGateError):
                ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main', platforms=names)
        altered = TEMPLATE.read_bytes().replace(b'Install OpenGrep for taint analysis', b'Changed unsupported bootstrap')
        with self.assertRaises(ci_gate.CiGateError):
            ci_gate.render_workflow(altered, 'main', platforms=['linux-x64'])

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML not installed')
    def test_generated_client_aggregate_executes_failure_and_skip_controls(self) -> None:
        import yaml
        document = yaml.safe_load(ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main',
                                                        platforms=['linux-x64', 'windows-x64']))
        final = document['jobs']['getzilla-verify']
        steps = document['jobs']['getzilla-verify-platform']['steps']
        native = next(step for step in steps if step.get('name', '').startswith('Verify native runner'))
        self.assertEqual(native['shell'], 'bash')
        guard = final['steps'][0]
        self.assertEqual(guard['shell'], 'python')
        for result, expected in [('success', 0), ('failure', 1), ('skipped', 1), ('cancelled', 1), ('', 1)]:
            process = subprocess.run([sys.executable, '-c', guard['run']],
                                     env={**os.environ, 'GETZILLA_PLATFORM_RESULT': result},
                                     capture_output=True, timeout=5)
            self.assertEqual(process.returncode, expected, result)

    @unittest.skipUnless(importlib.util.find_spec('yaml') and shutil.which('bash') and os.name != 'nt',
                         'requires POSIX executable fixture and YAML')
    def test_native_identity_failure_prevents_the_following_download(self) -> None:
        import yaml
        document = yaml.safe_load(ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main', platforms=['windows-x64']))
        step = next(step for step in document['jobs']['getzilla-verify-platform']['steps']
                    if step.get('name', '').startswith('Verify native runner'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            interpreter = root/'python'
            marker = root/'download-ran'
            interpreter.write_text('#!/bin/sh\nif [ "$2" = "--check-platform" ]; then exit 3; fi\nprintf bad > "$MARKER"\n')
            interpreter.chmod(0o755)
            program = step['run'].replace('${{ matrix.platform }}', 'windows-x64')
            process = subprocess.run([step['shell'], '-c', program],
                        env={**os.environ, 'PATH': str(root)+os.pathsep+os.environ.get('PATH', ''), 'MARKER': str(marker)},
                        capture_output=True, timeout=5)
            self.assertEqual(process.returncode, 3)
            self.assertFalse(marker.exists())

    def test_template_is_minimal_pinned_and_runs_the_pr_gate(self) -> None:
        text = TEMPLATE.read_text(encoding='utf-8')
        self.assertEqual(text.count(ci_gate.BRANCH_PLACEHOLDER), 1)
        self.assertIn('\non:\n  pull_request:\n  push:\n    branches:\n', text)
        self.assertIn('\npermissions:\n  contents: read\n', text)
        self.assertNotIn(': write', text)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('pull_request_target', text)
        self.assertIn('runs-on: ubuntu-latest', text)
        self.assertIn('python-version: "3.13"', text)
        self.assertIn('fetch-depth: 0', text)
        self.assertIn('if [ -f .getzilla/config/python-test-requirements.txt ]; then', text)
        self.assertIn('run: python scripts/getzilla_verify.py --mode pr', text)
        self.assertIn(f'  {ci_gate.CHECK_NAME}:\n', text)
        uses = [line for line in text.splitlines() if 'uses:' in line]
        self.assertEqual(len(uses), 3)
        for line in uses:
            with self.subTest(line=line):
                self.assertRegex(line, PINNED_USES)
        self.assertEqual(
            sorted(PINNED_USES.match(line).group(1) for line in uses),
            ['actions/checkout', 'actions/setup-python', 'actions/upload-artifact'],
        )

    def test_rendering_fills_the_push_branch_and_normalizes_newlines(self) -> None:
        template = TEMPLATE.read_bytes()
        rendered = ci_gate.render_workflow(template.replace(b'\n', b'\r\n'), 'develop')
        self.assertNotIn(b'\r\n', rendered)
        self.assertIn(b'      - "develop"\n', rendered)
        self.assertNotIn(ci_gate.BRANCH_PLACEHOLDER.encode(), rendered)
        self.assertEqual(rendered, ci_gate.render_workflow(template, 'develop'))
        for bad in ('', '-x', 'a..b', 'a b', 'a"b', 'x.lock', 'a/', 'new\nline'):
            with self.subTest(branch=bad), self.assertRaises(ci_gate.CiGateError):
                ci_gate.render_workflow(template, bad)
        with self.assertRaises(ci_gate.CiGateError):
            ci_gate.render_workflow(b'name: x\n', 'main')

    def test_default_branch_comes_from_origin_head(self) -> None:
        self.assertEqual(ci_gate.default_branch(Path('.'), runner=fake_runner()), ('main', 'origin/HEAD'))
        self.assertEqual(
            ci_gate.default_branch(Path('.'), runner=fake_runner(head='refs/remotes/origin/release/2')),
            ('release/2', 'origin/HEAD'),
        )
        self.assertEqual(ci_gate.default_branch(Path('.'), runner=fake_runner(head=None)), ('main', 'fallback'))

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_rendered_template_parses_as_yaml(self) -> None:
        import yaml

        document = yaml.safe_load(ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main'))
        triggers = document.get('on', document.get(True))
        self.assertEqual(triggers['push'], {'branches': ['main']})
        self.assertIn('pull_request', triggers)
        self.assertEqual(document['permissions'], {'contents': 'read'})
        steps = document['jobs'][ci_gate.CHECK_NAME]['steps']
        self.assertIn('python scripts/getzilla_verify.py --mode pr', [step.get('run') for step in steps])
        self.assertEqual(steps[-1]['with']['retention-days'], 30)
        self.assertNotIn('.getzilla/runtime', steps[-1]['with']['path'])


class SourceWorkflowSmokeTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('yaml') and os.name == 'posix', 'requires YAML and POSIX')
    def test_own_native_macos_probe_uses_separate_artifact_path(self):
        import yaml
        document = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())
        steps = document['jobs']['platform-install']['steps']
        probes = [s for s in steps if s.get('name') == 'Observe canonical public fixture startup on macOS']
        self.assertEqual(len(probes), 1)
        probe = probes[0]
        self.assertEqual(probe['if'], "${{ always() && matrix.os == 'macos' }}")
        self.assertGreater(steps.index(probe), next(i for i, s in enumerate(steps) if s['name'].startswith('Exercise the real user installer')))
        retention = next(s for s in steps if s['name'] == 'Retain actual install and upgrade observations')
        self.assertGreater(steps.index(retention), steps.index(probe))
        self.assertEqual(retention['if'], 'always()')
        self.assertIn('/*.log', retention['with']['path'])
        target = 'tests.test_public_fixture_startup.PublicFixtureStartupTests.test_canonical_startup_is_observed_before_environment_clear'
        self.assertNotIn(target.encode(), ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main'))
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', probe['run']], cwd=ROOT,
                                    env={'RUNNER_TEMP': tmp, 'GETZILLA_PLATFORM_CELL': 'public-macos'},
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            log = Path(tmp) / 'public-fixture-startup-public-macos/public-fixture-startup.log'
            rows = [json.loads(line.split('public-fixture-startup ', 1)[1])
                    for line in log.read_text().splitlines() if 'public-fixture-startup {' in line]
            self.assertEqual(len(rows), 1)
            self.assertEqual([r['case'] for r in rows[0]['cases']],
                             ['exact-direct', 'diagnostic-direct', 'diagnostic-after-startup-clear'])
            self.assertEqual([r['returncode'] for r in rows[0]['cases']], [0, 0, 0])

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'requires YAML')
    def test_own_native_macos_probe_preserves_failure_and_timeout(self):
        import yaml
        document = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())
        steps = document['jobs']['platform-install']['steps']
        probes = [s for s in steps if s.get('name') == 'Observe canonical public fixture startup on macOS']
        self.assertEqual(len(probes), 1)
        for failure, expected in [('exit', 9), ('timeout', 1)]:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                def run(command, **kwargs):
                    self.assertEqual(command[1:5], ['-I', '-S', '-B', '-c'])
                    self.assertEqual(command[-1], 'tests.test_public_fixture_startup.PublicFixtureStartupTests.test_canonical_startup_is_observed_before_environment_clear')
                    self.assertEqual(kwargs['timeout'], 15)
                    self.assertEqual(set(kwargs['env']), {'TMPDIR'})
                    self.assertEqual(kwargs['stderr'], subprocess.STDOUT)
                    kwargs['stdout'].write(b'bounded public child observation\n')
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired(command, 15)
                    return subprocess.CompletedProcess(command, 9)
                with mock.patch.dict(os.environ, {'RUNNER_TEMP': tmp, 'GETZILLA_PLATFORM_CELL': 'public-macos'}, clear=True), \
                        mock.patch.object(subprocess, 'run', side_effect=run), self.assertRaises(SystemExit) as stopped:
                    exec(compile(probes[0]['run'], '<own-workflow-public-probe>', 'exec'), {})
                self.assertEqual(stopped.exception.code, expected)
                self.assertTrue((Path(tmp) / 'public-fixture-startup-public-macos/public-fixture-startup.log').is_file())

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_source_and_generated_evidence_require_a_successful_checkout(self) -> None:
        import yaml
        workflow = yaml.safe_load((ROOT/'.github/workflows/getzilla.yml').read_text())
        steps = workflow['jobs']['linux']['steps']
        checkout = next(s for s in steps if s.get('uses', '').startswith('actions/checkout@'))
        self.assertEqual(checkout.get('id'), 'source_checkout')
        self.assertEqual(checkout.get('if'), 'always()')
        for step in steps:
            condition = step.get('if', '')
            if step.get('run') and ('failure()' in condition or 'always()' in condition):
                self.assertIn("steps.source_checkout.outcome == 'success'", condition, step['name'])
        template = yaml.safe_load((ROOT/'.getzilla/templates/ci/github-actions-verify.yml').read_text())
        generated = template['jobs']['getzilla-verify']['steps']
        self.assertEqual(generated[0].get('id'), 'source_checkout')
        export = next(s for s in generated if s.get('id') == 'export_evidence')
        self.assertIn("steps.source_checkout.outcome == 'success'", export['if'])

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_own_linux_host_keeps_the_required_namespace_admission(self) -> None:
        import yaml
        current = yaml.safe_load((ROOT/ci_gate.SOURCE_WORKFLOW_PATH).read_text())['jobs']['linux']
        self.assertEqual(current['runs-on'], 'ubuntu-22.04')
        frozen = subprocess.check_output(['git','show',
            'a927eac9a5170941eca0d167741dab619e550f2b:'+ci_gate.SOURCE_WORKFLOW_PATH],cwd=ROOT)
        previous = yaml.safe_load(frozen)['jobs']['linux']
        def admission(job):
            return next(step for step in job['steps'] if '/usr/bin/bwrap --unshare-all' in step.get('run',''))
        self.assertEqual(admission(current),admission(previous))
        self.assertFalse(admission(current).get('continue-on-error',False))
        self.assertFalse(current.get('continue-on-error',False))

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_own_linux_admits_fixed_node_before_the_real_profile_and_core(self) -> None:
        import yaml
        job = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())['jobs']['linux']
        steps = job['steps']
        by_id = {step['id']: step for step in steps if 'id' in step}
        self.assertIn('node_setup', by_id)
        setup = by_id['node_setup']
        self.assertEqual(setup['uses'], 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1')
        self.assertEqual(setup['with'], {'node-version': '24.22.2', 'architecture': 'x64',
                                         'package-manager-cache': False})
        runtime = by_id['node_runtime']
        self.assertIn("steps.node_setup.outcome == 'success'", runtime['if'])
        self.assertEqual(runtime['shell'], 'python')
        # Bind this CI-only physical admission, not a PATH-only setup or a link.
        for requirement in ("'node' / '24.22.2' / 'x64' / 'bin' / 'node'",
                            "selected != expected", "['sudo', 'install', '-T', '-m', '0755', '--'",
                            "node = pathlib.Path('/usr/bin/node')", "node.is_symlink()",
                            "stat.S_ISREG(info.st_mode)", "stat.S_IMODE(info.st_mode) != 0o755",
                            "digest(node) != selected_digest", "'/usr/bin/node', '--version'",
                            "!= 'v24.22.2'"):
            self.assertIn(requirement, runtime['run'])
        admission = by_id['node_profile_admission']
        self.assertEqual(admission['run'].split(), ['python', '-m', 'unittest',
            'tests.test_skill_sandbox.BmadDependencyGraft.test_synthetic_cjs_esm_load_and_all_input_mounts_are_read_only'])
        self.assertEqual(admission['if'], "success() && steps.source_checkout.outcome == 'success' && steps.node_runtime.outcome == 'success'")
        bubblewrap = next(step for step in steps if '/usr/bin/bwrap --unshare-all' in step.get('run', ''))
        requirements = next(step for step in steps if step.get('name') == 'Install test requirements')
        for dependency in (runtime, bubblewrap, requirements):
            self.assertLess(steps.index(dependency), steps.index(admission))
        core = next(step for step in steps if step.get('name') == 'Core tests')
        self.assertLess(steps.index(admission), steps.index(core))
        for step in (setup, runtime, admission, core, job):
            self.assertFalse(step.get('continue-on-error', False))

    @unittest.skipUnless(importlib.util.find_spec('yaml') and shutil.which('bash'), 'requires YAML and bash')
    def test_own_core_requires_successful_node_admission_not_missing_or_failed(self) -> None:
        import yaml
        steps = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())['jobs']['linux']['steps']
        core = next(step for step in steps if step.get('name') == 'Core tests')
        self.assertEqual(core['if'], "(success() || failure()) && steps.source_checkout.outcome == 'success' && steps.node_profile_admission.outcome == 'success'")
        condition = core['if'].replace('(success() || failure())', 'true')
        condition = condition.replace("steps.source_checkout.outcome == 'success'", '[[ "$CHECKOUT" == success ]]')
        condition = condition.replace("steps.node_profile_admission.outcome == 'success'", '[[ "$ADMISSION" == success ]]')
        for checkout, admission, expected in (('success', 'success', 0), ('success', 'failure', 1),
                ('success', 'skipped', 1), ('success', 'cancelled', 1), ('success', '', 1), ('', 'success', 1)):
            with self.subTest(checkout=checkout, admission=admission):
                result = subprocess.run(['bash', '-c', condition],
                    env={'CHECKOUT': checkout, 'ADMISSION': admission}, capture_output=True, timeout=3)
                self.assertEqual(result.returncode, expected)

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_required_linux_core_uses_full_measured_parallel_runner(self) -> None:
        import yaml
        steps = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())['jobs']['linux']['steps']
        core = next(step for step in steps if step.get('name') == 'Core tests')
        script = core['run']
        self.assertIn('set -euo pipefail', script)
        self.assertIn("cli.project_python(cli.HOME), '-c', 'import pytest, xdist'", script)
        self.assertIn('check=True', script)
        self.assertIn('python scripts/getzilla_cli.py test tests --max-worker-restart=0 --durations=20', script)
        self.assertNotIn('unittest discover', script)
        self.assertNotIn('continue-on-error', core)

    @unittest.skipUnless(os.name == 'posix' and importlib.util.find_spec('yaml') and shutil.which('bash'),
                         'requires POSIX, YAML and bash')
    def test_required_linux_core_preserves_preflight_and_parallel_failure_status(self) -> None:
        import yaml
        steps = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text())['jobs']['linux']['steps']
        script = next(step for step in steps if step.get('name') == 'Core tests')['run']
        # Execute only an inert public shim, never the represented repository tests.
        for preflight, runner, expected, calls in ((7, 0, 7, 1), (0, 0, 0, 2),
                (0, 1, 1, 2), (0, 2, 2, 2), (0, 3, 3, 2), (0, 5, 5, 2)):
            with self.subTest(preflight=preflight, runner=runner), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shim = root / 'python'
                shim.write_text(f'#!{sys.executable}\n' +
                    "import os, pathlib, sys\n"
                    "with pathlib.Path(os.environ['CALL_LOG']).open('a') as stream:\n"
                    "    stream.write('preflight\\n' if sys.argv[1:] == ['-'] else 'runner\\n')\n"
                    "if sys.argv[1:] == ['-']:\n"
                    "    sys.stdin.read()\n"
                    "    raise SystemExit(int(os.environ['PREFLIGHT_RC']))\n"
                    "expected = ['scripts/getzilla_cli.py', 'test', 'tests', '--max-worker-restart=0', '--durations=20']\n"
                    "if sys.argv[1:] != expected:\n"
                    "    raise SystemExit(91)\n"
                    "raise SystemExit(int(os.environ['RUNNER_RC']))\n", encoding='utf-8')
                shim.chmod(0o755)
                log = root / 'calls'
                environment = {**os.environ, 'PATH': str(root) + os.pathsep + os.defpath,
                    'RUNNER_TEMP': str(root), 'CALL_LOG': str(log),
                    'PREFLIGHT_RC': str(preflight), 'RUNNER_RC': str(runner)}
                result = subprocess.run(['bash', '-c', script], cwd=ROOT, env=environment,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected)
                self.assertEqual(log.read_text().splitlines(), ['preflight', 'runner'][:calls])

    @unittest.skipUnless(importlib.util.find_spec('yaml') and shutil.which('bash'), 'requires YAML and bash')
    def test_required_linux_status_fails_for_missing_or_cancelled_platform_results(self) -> None:
        import yaml
        document = yaml.safe_load((ROOT/ci_gate.SOURCE_WORKFLOW_PATH).read_text())
        linux = document['jobs']['linux']
        self.assertEqual(linux['if'], 'always()')
        self.assertIn('platform-install-results', linux['needs'])
        guard = next(step for step in linux['steps'] if 'GETZILLA_PLATFORM_RESULT' in step.get('env', {}))
        self.assertEqual(guard['env']['GETZILLA_PLATFORM_RESULT'], '${{ needs.platform-install-results.result }}')
        for result, expected in [('success', 0), ('failure', 1), ('skipped', 1), ('cancelled', 1), ('', 1)]:
            process = subprocess.run(['bash', '-c', guard['run']],
                                     env={**os.environ, 'GETZILLA_PLATFORM_RESULT': result},
                                     capture_output=True, timeout=5)
            self.assertEqual(process.returncode, expected, result)

    @unittest.skipUnless(importlib.util.find_spec('yaml'), 'PyYAML is not installed')
    def test_smoke_environment_preserves_hook_owner_for_cli_package_start(self) -> None:
        import yaml

        workflow = yaml.safe_load((ROOT / ci_gate.SOURCE_WORKFLOW_PATH).read_text(encoding='utf-8'))
        for job_name in ('windows', 'macos'):
            job = workflow['jobs'][job_name]
            step = next(item for item in job['steps'] if item['name'].startswith('Hooks and CLI smoke'))
            with self.subTest(job=job_name), project_copy(git=True) as root:
                scripts = root / 'scripts'
                scripts.mkdir()
                for name in ('getzilla_cli.py', 'getzilla_change.py'):
                    shutil.copy2(ROOT / 'scripts' / name, scripts / name)
                shutil.copytree(ROOT / 'schemas', root / 'schemas')
                code, _, stderr = run_hook(root, 'user_prompt_submit.py', {
                    'cwd': str(root), 'session_id': 'ci', 'hook_event_name': 'UserPromptSubmit',
                    'prompt': 'Add a health endpoint to the API',
                })
                self.assertEqual(code, 0, stderr)
                route_path = root / '.getzilla/runtime/active-route.json'
                before = json.loads(route_path.read_text(encoding='utf-8'))
                environment = {key: value for key, value in os.environ.items()
                               if key not in {'GETZILLA_SESSION_ID', 'CLAUDE_CODE_SESSION_ID'}}
                environment.update(workflow.get('env', {}))
                environment.update(job.get('env', {}))
                environment.update(step.get('env', {}))
                command = [sys.executable, str(scripts / 'getzilla_cli.py'),
                           'change', 'start', '--title', 'Health endpoint']
                for owner in (None, 'foreign-session'):
                    rejected_env = dict(environment)
                    rejected_env.pop('GETZILLA_SESSION_ID', None)
                    rejected_env.pop('CLAUDE_CODE_SESSION_ID', None)
                    if owner is not None:
                        rejected_env['GETZILLA_SESSION_ID'] = owner
                    refused = subprocess.run(command, cwd=root, env=rejected_env, capture_output=True,
                                             text=True, timeout=30)
                    self.assertNotEqual(refused.returncode, 0, refused.stdout)
                    self.assertFalse((root / '.getzilla/runtime/active-change.json').exists())
                    self.assertFalse(list((root / '.getzilla/runtime/changes').glob('*/state.json')))
                started = subprocess.run(command, cwd=root, env=environment, capture_output=True,
                                         text=True, timeout=30)
                self.assertEqual(started.returncode, 0, started.stdout + started.stderr)
                self.assertEqual(json.loads(started.stdout)['route_id'], before['route_id'])
                after = json.loads(route_path.read_text(encoding='utf-8'))
                for field in ('route_id', 'logical_task_id', 'session_id', 'authority_epoch'):
                    self.assertEqual(after[field], before[field], field)


class CliTests(unittest.TestCase):
    def run_cli(self, *argv: str, **dependencies) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        dependencies.setdefault('runner', fake_runner())
        dependencies.setdefault('fetch', no_network)
        dependencies.setdefault('which', no_gh)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = CLI.main(list(argv), **dependencies)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_client_example_writes_selected_platforms_idempotently_and_refuses_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            arguments = ('--write', '--json', '--target', tmp, '--visibility', 'public',
                         '--platform', 'linux-x64', '--platform', 'windows-x64')
            code, output, _ = self.run_cli(*arguments)
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output)['result'], 'written')
            before = _snapshot(target)
            workflow = (target / ci_gate.WORKFLOW_PATH).read_text()
            self.assertIn('windows-2025', workflow)
            self.assertIn('needs: getzilla-verify-platform', workflow)
            code, output, _ = self.run_cli(*arguments)
            self.assertEqual((code, json.loads(output)['result']), (0, 'unchanged'))
            code, _, _ = self.run_cli('--write', '--target', tmp, '--visibility', 'public',
                                      '--platform', 'unknown')
            self.assertEqual(code, 2)
            self.assertEqual(_snapshot(target), before)

    def test_plan_json_reports_visibility_gate_and_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            before = _snapshot(target)
            code, out, _ = self.run_cli(
                '--plan', '--json', '--target', tmp,
                which=lambda name: 'gh', runner=fake_runner(gh=CommandResult(0, 'false\n', '')),
            )
            self.assertEqual(code, 0)
            plan = json.loads(out)
            self.assertEqual(plan['repository'], SLUG)
            self.assertEqual((plan['visibility'], plan['visibility_source']), ('public', 'gh'))
            self.assertEqual(plan['gate'], 'github-actions')
            [entry] = plan['writes']
            self.assertEqual(entry['path'], '.github/workflows/getzilla-verify.yml')
            self.assertEqual(entry['template'], '.getzilla/templates/ci/github-actions-verify.yml')
            self.assertEqual((entry['state'], entry['push_branch']), ('create', 'main'))
            import hashlib
            self.assertEqual(
                entry['sha256'],
                hashlib.sha256(ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main')).hexdigest(),
            )
            self.assertEqual(_snapshot(target), before)

    def test_plan_for_private_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_cli('--plan', '--json', '--target', tmp, '--visibility', 'private')
            self.assertEqual(code, 0)
            plan = json.loads(out)
            self.assertEqual((plan['gate'], plan['writes']), ('trust-ci', []))
            steps = '\n'.join(plan['next_steps'])
            self.assertIn(ci_gate.ONBOARDING_RUNBOOK, steps)
            self.assertIn('owner profile for example-owner', steps)
            self.assertIn('paid service', steps)
            self.assertIn(ci_gate.TRUST_CI_ACCESS_URL, steps)
            code, out, _ = self.run_cli(
                '--plan', '--json', '--target', tmp, fetch=lambda url: HttpResponse(404, b''),
            )
            self.assertEqual(code, 2)
            plan = json.loads(out)
            self.assertEqual((plan['visibility'], plan['gate'], plan['writes']), ('unknown', None, []))
            code, out, _ = self.run_cli('--plan', '--target', tmp, '--visibility', 'public')
            self.assertEqual(code, 0)
            self.assertIn('gate: github-actions', out)

    def test_write_public_creates_then_is_a_no_op_then_refuses_a_different_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            workflow = target / '.github' / 'workflows' / 'getzilla-verify.yml'
            code, out, _ = self.run_cli('--write', '--json', '--target', tmp, '--visibility', 'public')
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out)['result'], 'written')
            expected = ci_gate.render_workflow(TEMPLATE.read_bytes(), 'main')
            self.assertEqual(workflow.read_bytes(), expected)
            before = _snapshot(target)
            code, out, _ = self.run_cli('--write', '--json', '--target', tmp, '--visibility', 'public')
            self.assertEqual(code, 0)
            report = json.loads(out)
            self.assertEqual((report['result'], report['writes'][0]['state']), ('unchanged', 'identical'))
            self.assertEqual(_snapshot(target), before)
            workflow.write_bytes(expected.replace(b'\n', b'\r\n'))
            code, out, _ = self.run_cli('--write', '--json', '--target', tmp, '--visibility', 'public')
            self.assertEqual((code, json.loads(out)['result']), (0, 'unchanged'))
            workflow.write_bytes(b'name: local\n')
            before = _snapshot(target)
            code, out, err = self.run_cli('--write', '--json', '--target', tmp, '--visibility', 'public')
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)['result'], 'refused')
            self.assertIn('refused to overwrite', err)
            self.assertEqual(_snapshot(target), before)

    def test_write_public_uses_the_named_default_branch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            code, _, _ = self.run_cli(
                '--write', '--target', tmp, '--visibility', 'public', '--default-branch', 'trunk',
            )
            self.assertEqual(code, 0)
            text = (Path(tmp) / '.github/workflows/getzilla-verify.yml').read_text(encoding='utf-8')
            self.assertIn('      - "trunk"\n', text)
            code, _, err = self.run_cli(
                '--write', '--target', tmp, '--visibility', 'public', '--default-branch', 'a..b',
            )
            self.assertEqual(code, 2)
            self.assertIn('unsupported default branch', err)

    def test_write_refuses_a_non_directory_workflow_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / '.github').write_text('not a directory\n', encoding='utf-8')
            before = _snapshot(Path(tmp))
            code, out, _ = self.run_cli('--write', '--json', '--target', tmp, '--visibility', 'public')
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)['writes'][0]['state'], 'conflict')
            self.assertEqual(_snapshot(Path(tmp)), before)

    def test_write_private_and_unknown_write_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / 'README.md').write_text('consumer\n', encoding='utf-8')
            before = _snapshot(target)
            code, out, _ = self.run_cli('--write', '--target', tmp, '--visibility', 'private')
            self.assertEqual(code, 0)
            self.assertIn('result: nothing-to-write', out)
            self.assertIn('adaptive-trust-ci', out)
            self.assertIn(ci_gate.ONBOARDING_RUNBOOK, out)
            self.assertEqual(_snapshot(target), before)
            code, out, err = self.run_cli(
                '--write', '--json', '--target', tmp, fetch=lambda url: HttpResponse(404, b''),
            )
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)['result'], 'undetermined')
            self.assertIn('--visibility', err)
            self.assertEqual(_snapshot(target), before)

    def test_mode_is_required_and_exclusive(self) -> None:
        for argv in ((), ('--plan', '--write')):
            with self.subTest(argv=argv), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                CLI.main(list(argv))

    def test_script_runs_as_a_program(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/getzilla_ci.py'), '--plan', '--json',
                 '--target', tmp, '--visibility', 'private'],
                capture_output=True, text=True, check=False, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['gate'], 'trust-ci')
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
