"""CI gate by repository visibility: public -> GitHub Actions, private -> Trust CI.

Every process and network call is injected, so these tests run offline and on
Windows. One test drives the real ``git`` binary when it is installed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
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
        self.assertEqual(len(uses), 2)
        for line in uses:
            with self.subTest(line=line):
                self.assertRegex(line, PINNED_USES)
        self.assertEqual(
            sorted(PINNED_USES.match(line).group(1) for line in uses),
            ['actions/checkout', 'actions/setup-python'],
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
        self.assertEqual(steps[-1]['run'], 'python scripts/getzilla_verify.py --mode pr')


class CliTests(unittest.TestCase):
    def run_cli(self, *argv: str, **dependencies) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        dependencies.setdefault('runner', fake_runner())
        dependencies.setdefault('fetch', no_network)
        dependencies.setdefault('which', no_gh)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = CLI.main(list(argv), **dependencies)
        return code, stdout.getvalue(), stderr.getvalue()

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
