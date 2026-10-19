"""S06-S07: Go and Java/Kotlin are checked with pinned toolchains, or say exactly why not."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla import stack_runners  # noqa: E402,F401  registers the runners
from getzilla.known_vulns import _pairs_from_gradle_lockfile  # noqa: E402
from getzilla.stack_toolchains import Toolchain, _manifest_digest, _toolchain, ensure_toolchain, resolve_version, template_fields  # noqa: E402
from getzilla.stacks import RUNNERS, StackContext, load_registry  # noqa: E402
from getzilla.verification import CheckResult  # noqa: E402

REGISTRY = load_registry(ROOT)
E2E = os.environ.get('GETZILLA_E2E_TOOLCHAINS') == '1'


def _write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')


class Recorder:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[tuple[Path, str, list[str], dict[str, str]]] = []
        self.outputs = outputs or {}

    def __call__(self, cwd, name, command, timeout=300, *, env=None):
        self.calls.append((Path(cwd), name, list(command), dict(env or {})))
        return CheckResult(name, 'pass', 'exit=0', command=command, stdout=self.outputs.get(name.split(':')[0], ''))


class Case(unittest.TestCase):
    stack = ''

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.home = self.root / '.tc'
        self.toolchain = Toolchain(self.stack, '1', self.home, (self.home / 'bin',), {'X': '1'})

    def run_stack(self, mode: str, files: list[str], outputs=None):
        recorder = Recorder(outputs)
        context = StackContext(self.root, mode, REGISTRY[self.stack], files, CheckResult, recorder,
                               lambda _stack, _version: self.toolchain)
        return RUNNERS[self.stack](context), recorder, context


class GoTests(Case):
    stack = 'go'

    def test_fast_and_pr_commands(self) -> None:
        _write(self.root, {'go.mod': 'module example.com/x\n\ngo 1.27\n', 'main.go': 'package main\n'})
        results, recorder, context = self.run_stack('fast', ['main.go'])
        self.assertEqual([check.name for check in results], ['gofmt', 'go-vet'])
        self.assertEqual(recorder.calls[0][2], ['gofmt', '-l', '.'])
        self.assertTrue(all(call[3]['PATH'].startswith(str(self.home / 'bin')) for call in recorder.calls))
        results, recorder, _ = self.run_stack('pr', ['main.go'])
        self.assertEqual([check.name for check in results], ['gofmt', 'go-vet', 'go-build', 'go-test'])
        self.assertEqual(recorder.calls[-1][2], ['go', 'test', './...'])

    def test_unformatted_files_fail_gofmt(self) -> None:
        _write(self.root, {'go.mod': 'module x\n', 'a.go': 'package a\n'})
        results, _, _ = self.run_stack('fast', ['a.go'], outputs={'gofmt': 'a.go\nb/b.go\n'})
        gofmt = results[0]
        self.assertEqual((gofmt.status, gofmt.summary), ('fail', '2 file(s) need gofmt'))
        self.assertEqual([item['path'] for item in gofmt.details], ['a.go', 'b/b.go'])

    def test_toolchain_directive_pins_the_version(self) -> None:
        spec = REGISTRY['go'].toolchain
        _write(self.root, {'go.mod': 'module x\n\ngo 1.26\n'})
        self.assertEqual(resolve_version(self.root, spec), (spec['default_version'], 'stacks.json'))
        _write(self.root, {'go.mod': 'module x\n\ngo 1.26\ntoolchain go1.26.4\n'})
        self.assertEqual(resolve_version(self.root, spec), ('1.26.4', 'go.mod'))
        env = _toolchain('go', '1.27.2', self.home, spec, 'linux-x64', fetched=False).env
        self.assertEqual(env['GOTOOLCHAIN'], 'local')  # never let go download another toolchain itself

    def test_go_dev_manifest_is_read_by_file_name(self) -> None:
        source = REGISTRY['go'].toolchain['source']
        manifest = json.dumps([{'version': 'go1.27.2', 'files': [
            {'filename': 'go1.27.2.linux-amd64.tar.gz', 'sha256': 'ab' * 32}, {'filename': 'go1.27.2.src.tar.gz', 'sha256': 'cd' * 32}]}])

        def fetch(_url: str, destination: Path) -> None:
            destination.write_text(manifest, encoding='utf-8')

        self.assertEqual(_manifest_digest(source, '1.27.2', 'go1.27.2.linux-amd64.tar.gz', fetch), 'ab' * 32)

    @unittest.skipUnless(E2E, 'downloads Go from go.dev')
    def test_real_go_toolchain_checks_a_module(self) -> None:
        from getzilla.verification import _command_check
        _write(self.root, {'go.mod': 'module example.com/demo\n\ngo 1.27\n',
                           'add.go': 'package demo\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n',
                           'add_test.go': 'package demo\n\nimport "testing"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal("bad")\n\t}\n}\n'})
        context = StackContext(self.root, 'pr', REGISTRY['go'], ['add.go'], CheckResult, _command_check,
                               lambda stack, version: ensure_toolchain(stack.id, stack.toolchain, version))
        results = RUNNERS['go'](context)
        self.assertEqual([(check.name, check.status) for check in results],
                         [('gofmt', 'pass'), ('go-vet', 'pass'), ('go-build', 'pass'), ('go-test', 'pass')],
                         [check.stderr[-400:] for check in results])


class JavaTests(Case):
    stack = 'java'

    def test_gradle_and_maven_run_only_through_the_project_wrapper(self) -> None:
        _write(self.root, {'build.gradle.kts': '', 'gradlew': '#!/bin/sh\n', 'gradle.lockfile': 'empty=\n',
                           'svc/pom.xml': '<project/>', 'svc/mvnw': '#!/bin/sh\n', 'src/A.kt': ''})
        results, recorder, _ = self.run_stack('pr', ['src/A.kt'])
        commands = {call[1]: call[2] for call in recorder.calls}
        self.assertEqual(commands['gradle-build'][1:], ['check', '--no-daemon'])
        self.assertTrue(all(call[3]['PATH'].startswith(str(self.home / 'bin')) for call in recorder.calls))
        self.assertNotIn('maven-build:svc', commands, 'svc is inside the Gradle root project')

    def test_missing_wrapper_and_unknown_maven_dependencies_fail_pr(self) -> None:
        _write(self.root, {'pom.xml': '<project/>', 'src/main/java/A.java': ''})
        results, recorder, _ = self.run_stack('pr', ['src/main/java/A.java'])
        self.assertEqual([(check.name, check.status, check.summary) for check in results],
                         [('java-wrapper', 'fail', 'BUILD_WRAPPER_MISSING'),
                          ('maven-dependencies', 'fail', 'MAVEN_DEPENDENCIES_UNKNOWN')])
        self.assertEqual(recorder.calls, [])

    def test_fast_mode_says_builds_run_in_pr(self) -> None:
        _write(self.root, {'pom.xml': '<project/>', 'mvnw': ''})
        results, recorder, _ = self.run_stack('fast', ['pom.xml'])
        self.assertEqual((results[0].name, results[0].status), ('java', 'skip'))
        self.assertEqual(recorder.calls, [])

    def test_versions_archives_and_macos_layout(self) -> None:
        spec = REGISTRY['java'].toolchain
        _write(self.root, {'.java-version': '21\n'})
        self.assertEqual(resolve_version(self.root, spec), ('21.0.12.1+1', '.java-version'))
        fields = template_fields('21.0.12.1+1')
        self.assertEqual(spec['source']['archives']['linux-x64'].format(**fields),
                         'OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz')
        self.assertIn('/jdk-21.0.12.1%2B1/', spec['source']['url'].format(**fields, archive='x'))
        mac = _toolchain('java', '21.0.12.1+1', self.home, spec, 'darwin-arm64', fetched=False)
        self.assertEqual(mac.bin_dirs, (self.home / 'Contents/Home/bin',))
        self.assertEqual(mac.env['JAVA_HOME'], str(self.home / 'Contents/Home'))
        linux = _toolchain('java', '21.0.12.1+1', self.home, spec, 'linux-x64', fetched=False)
        self.assertEqual(linux.env['JAVA_HOME'], str(self.home))

    def test_gradle_lockfile_feeds_osv(self) -> None:
        text = ('# This is a Gradle generated file\ncom.google.guava:guava:31.1-jre=compileClasspath\n'
                'org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=annotationProcessor\n')
        self.assertEqual(list(_pairs_from_gradle_lockfile(text)),
                         [('com.google.guava:guava', '31.1-jre'), ('org.apache.logging.log4j:log4j-core', '2.14.1')])

    @unittest.skipUnless(E2E and shutil.which('curl'), 'downloads Temurin JDK 21 from GitHub')
    def test_real_jdk_is_verified_and_runs(self) -> None:
        spec = REGISTRY['java'].toolchain
        toolchain = ensure_toolchain('java', spec, spec['default_version'])
        assert isinstance(toolchain, Toolchain), toolchain
        out = subprocess.run(['java', '-version'], env=toolchain.process_env(), capture_output=True, text=True, check=True)
        self.assertIn('21.0.12', out.stderr)


if __name__ == '__main__':
    unittest.main()
