"""Synthetic repositories and output producer. These are not language SDK tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess

from getzilla.language_quality.core import TOOLS, _read_inputs, discover_packages
from getzilla.language_quality.models import ToolOutput
from getzilla.language_quality.sandbox import Execution


def make_fixture(root: Path, *, stack: str, files: int, packages: int, scope: str, typed: bool) -> dict:
    if stack not in {'javascript', 'kotlin', 'dart', 'flutter', 'swift', 'mixed', 'python'} or not 1 <= files <= 1000 or not 1 <= packages <= 8:
        raise ValueError('fixture bounds exceeded')
    sources = []
    written = {}
    languages = ['javascript', 'kotlin', 'dart', 'swift'] if stack == 'mixed' else ['dart' if stack == 'flutter' else stack]
    def write(name, text):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        written[name] = text
    for package in range(packages):
        for language in languages:
            prefix = f'pkg{package:02}/{language}' if packages > 1 or stack == 'mixed' else '.'
            configs = {
                'javascript': {'package.json': '{"private":true}', 'eslint.config.js': 'export default [];\n'},
                'kotlin': {'build.gradle.kts': '// synthetic Gradle marker\n', 'detekt.yml': 'build:\n  maxIssues: 0\n', '.editorconfig': 'root=true\n'},
                'dart': {'pubspec.yaml': 'name: fixture\nenvironment:\n  sdk: ">=3.0.0 <4.0.0"\n', 'analysis_options.yaml': '{}\n'},
                'swift': {'Package.swift': '// swift-tools-version: 6.0\nimport PackageDescription\nlet package = Package(name: "Fixture")\n', '.swiftlint.yml': 'disabled_rules: []\n', '.swiftformat': '--swiftversion 6.0\n'},
                'python': {},
            }[language]
            for name, content in configs.items():
                write((PurePosixPath(prefix) / name).as_posix(), content)
            for index in range(files):
                extension = {'javascript': 'ts' if typed else 'js', 'kotlin': 'kt', 'dart': 'dart', 'swift': 'swift', 'python': 'py'}[language]
                name = (PurePosixPath(prefix) / f'src/file{index:04}.{extension}').as_posix()
                content = {'javascript': f'export const value{index}' + (': number' if typed else '') + f' = {index};\n',
                           'kotlin': f'val value{index} = {index}\n', 'dart': f'void function{index}() {{}}\n',
                           'swift': f'let value{index} = {index}\n', 'python': f'value{index} = {index}\n'}[language]
                write(name, content)
                if index == 0:
                    sources.append(name)
    tools = {tool: {'mode': 'auto', 'launcher': ['/fixture/' + tool], 'version': 'synthetic-1',
                   'driver': 'flutter' if stack == 'flutter' and tool == 'dart_analyzer' else 'dart' if language == 'dart' else 'cli'}
             for tool, (language, _) in TOOLS.items() if language in languages}
    section = {'scope': scope, 'sandbox': {'image': 'synthetic@sha256:' + 'a' * 64, 'cpus': 1}, 'tools': tools}
    write('.getzilla/config/policy.json', json.dumps({'language_quality_gates': section}, sort_keys=True))
    write('.gitignore', '.getzilla/runtime/\n')
    command = ['git', '-c', 'core.hooksPath=', '-c', 'core.autocrlf=false', '-c', 'user.name=Fixture',
               '-c', 'user.email=fixture@example.invalid', '-C', str(root)]
    subprocess.run([*command, 'init', '-q'], check=True, capture_output=True)
    subprocess.run([*command, 'add', '.'], check=True, capture_output=True)
    subprocess.run([*command, 'commit', '-qm', 'synthetic baseline'], check=True, capture_output=True)
    base = subprocess.check_output([*command, 'rev-parse', 'HEAD'], text=True).strip()
    for name in sources:
        write(name, written[name] + ('# dirty fixture\n' if name.endswith('.py') else '// dirty fixture\n'))
    content = json.dumps(written, sort_keys=True, separators=(',', ':')).encode()
    return {'base': base, 'fixture_digest': hashlib.sha256(content).hexdigest(), 'dirty_files': sources,
            'files_per_package': files, 'packages': packages, 'stack': stack, 'typed': typed}


class FixtureExecutor:
    """Trusted test seam; measures Python orchestration with deterministic tool output."""
    def __init__(self):
        self.calls = 0
        self.identity = 'synthetic-output-producer-v1'

    def cache_identity(self, root, *, cancellation=None):
        return self.identity

    def execute(self, root, package, files, argv, *, cancellation=None, expected_digest=None):
        self.calls += 1
        if cancellation and cancellation():
            return Execution('CANCELLED', ToolOutput(-1, '', ''), 'fixture cancelled')
        if _read_inputs(root, files)[0] != expected_digest:
            return Execution('ERROR', ToolOutput(-1, '', ''), 'fixture source changed')
        tool = PurePosixPath(argv[0]).name
        if tool not in TOOLS:
            raise AssertionError('unexpected fixture command')
        source = next(p for p in discover_packages(files) if p.path == package and p.language == TOOLS[tool][0])
        names = source.files
        if '--' in argv and '.' not in argv[argv.index('--') + 1:]:
            names = tuple(name.removeprefix('./') for name in argv[argv.index('--') + 1:])
        if tool == 'eslint':
            stdout = json.dumps([{'filePath': '/workspace/' + (PurePosixPath(package) / name).as_posix(),
                                 'messages': [], 'errorCount': 0, 'warningCount': 0, 'fatalErrorCount': 0} for name in names])
        elif tool in {'ktlint', 'swiftlint', 'swiftformat'}:
            stdout = '[]'
        elif tool == 'dart_analyzer':
            stdout = 'No issues found! (ran in 0.1s)\n' if '--no-pub' in argv else ''
        elif tool == 'dart_format':
            stdout = f'Formatted {len(names)} files (0 changed) in 0.01 seconds.\n'
        else:
            stdout = ''
        return Execution('COMPLETED', ToolOutput(0, stdout, ''), identity=self.identity)
