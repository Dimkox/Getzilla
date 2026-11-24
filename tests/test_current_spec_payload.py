"""Owned inert source data; no upstream script or generator is executed."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tomllib
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import current_workflows as workflows


class SpecPayloadTests(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        for port in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen', 'subprocess.run'):
            effects.enter_context(mock.patch(port, side_effect=AssertionError('outside effects forbidden')))

    def source(self):
        source = {
            'templates/constitution-template.md': b'Owned constitution\n',
            'templates/plan-template.md': b'Owned plan\n',
            'workflows/speckit/workflow.yml': b'schema_version: "1.0"\nworkflow:\n  id: "speckit"\n  version: "1.0.2"\n',
            'scripts/bash/check-prerequisites.sh': b'owned shell bytes\n',
            'scripts/powershell/check-prerequisites.ps1': b'owned powershell bytes\r\n',
            'scripts/python/check_prerequisites.py': b'owned python data\n',
        }
        for name in ('analyze', 'checklist', 'clarify', 'constitution', 'converge', 'implement', 'plan', 'specify', 'tasks'):
            indent = '   ' if name == 'clarify' else '  '
            source['templates/commands/' + name + '.md'] = (
                '---\ndescription: Owned template.\nscripts:\n'
                + indent + 'sh: scripts/bash/check-prerequisites.sh --json\n'
                + indent + 'ps: scripts/powershell/check-prerequisites.ps1 -Json\n'
                + indent + 'py: scripts/python/check_prerequisites.py --json\n'
                + '---\nRun `{SCRIPT}`. Then __SPECKIT_COMMAND_PLAN__.\n'
                + 'Context: {ARGS}\nInput: $ARGUMENTS\nLiteral triple: """ and slash: \\\n'
            ).encode()
        return source

    def payload(self, source, agent='qwen', windows=False):
        result = workflows.spec_payload(source, agent, '1.4.2', 'a' * 40, windows=windows)
        return {name: (body, mode) for name, body, mode in result.files}

    def complete_payload(self, source, agent='qwen', windows=False):
        try:
            return self.payload(source, agent, windows)
        except ValueError as error:
            self.fail('Observed source layout must generate data: ' + str(error))

    def test_observed_layout_registers_native_commands_for_all_agents_and_platforms(self):
        expected = {
            'qwen': ('.qwen/commands/speckit.plan.md', '/speckit.plan', '$ARGUMENTS'),
            'gemini': ('.gemini/commands/speckit.plan.toml', '/speckit.plan', '{{args}}'),
            'codex': ('.agents/skills/speckit-plan/SKILL.md', '$speckit-plan', '$ARGUMENTS'),
            'claude': ('.claude/skills/speckit-plan/SKILL.md', '/speckit-plan', '$ARGUMENTS'),
            'grok': ('.grok/skills/speckit-plan/SKILL.md', '/speckit-plan', '$ARGUMENTS'),
            'copilot': ('.github/skills/speckit-plan/SKILL.md', '/speckit-plan', '$ARGUMENTS'),
        }
        source = self.source()
        for agent, (path, invoke, arguments) in expected.items():
            for windows in (False, True):
                with self.subTest(agent=agent, windows=windows):
                    files = self.complete_payload(source, agent, windows)
                    text = files[path][0].decode()
                    if agent == 'gemini':
                        document = tomllib.loads(text)
                        self.assertEqual(document['description'], 'Owned template.')
                        text = document['prompt']
                    self.assertIn(invoke, text)
                    self.assertIn('Context: ' + arguments, text)
                    self.assertIn('Input: ' + arguments, text)
                    self.assertIn('Literal triple: """', text)
                    self.assertNotIn('{SCRIPT}', text)
                    self.assertNotIn('__SPECKIT_COMMAND_', text)
                    self.assertNotIn('{ARGS}', text)
                    lane, suffix, mode = ('powershell', '.ps1', 0o644) if windows else ('bash', '.sh', 0o755)
                    script = 'scripts/' + lane + '/check-prerequisites' + suffix
                    self.assertEqual(files['.specify/' + script], (source[script], mode))
                    self.assertIn('.specify/' + script, text)
                    self.assertFalse(any(name.startswith('.specify/scripts/python/') for name in files))
                    manifest = json.loads(files['.specify/integrations/' + agent + '.manifest.json'][0])
                    self.assertEqual(len(manifest['files']), 9)
                    for name, digest in manifest['files'].items():
                        self.assertEqual(digest, hashlib.sha256(files[name][0]).hexdigest())
                    registry = json.loads(files['.specify/workflows/workflow-registry.json'][0])
                    self.assertEqual(registry['workflows']['speckit']['version'], '1.0.2')

    def test_unique_legacy_root_version_remains_supported(self):
        source = self.source()
        source['workflows/speckit/workflow.yml'] = b'version: 1.0.0\n'
        files = self.complete_payload(source)
        registry = json.loads(files['.specify/workflows/workflow-registry.json'][0])
        self.assertEqual(registry['workflows']['speckit']['version'], '1.0.0')

    def test_missing_duplicate_unknown_and_mixed_script_bindings_refuse(self):
        name = 'templates/commands/clarify.md'
        original = self.source()[name]
        rows = (
            original.replace(b'   sh:', b'   bad:'),
            original.replace(b'   ps:', b'  ps:'),
            original.replace(b'   sh:', b'\tsh:'),
            original.replace(b'   sh: scripts/bash/check-prerequisites.sh --json\n', b''),
            original.replace(b'   sh:', b'   sh: scripts/bash/check-prerequisites.sh --json\n   sh:'),
            original.replace(b'---\nRun', b'scripts:\n  sh: scripts/bash/check-prerequisites.sh\n---\nRun'),
            original.replace(b'---\nRun', b'scripts: {sh: scripts/bash/check-prerequisites.sh}\n---\nRun'),
            original.replace(b'scripts/bash/check-prerequisites.sh', b'scripts/bash/missing.sh'),
            original.replace(b'scripts/bash/check-prerequisites.sh', b'scripts/powershell/check-prerequisites.ps1'),
        )
        for changed in rows:
            source = self.source()
            source[name] = changed
            with self.subTest(changed=changed[:80]), self.assertRaises(ValueError):
                self.payload(source)

    def test_unmapped_dispatch_references_refuse(self):
        for replacement in (b'__SPECKIT_COMMAND_UNKNOWN__', b'__SPECKIT_COMMAND_plan__', b'__SPECKIT_COMMAND_PLAN_'):
            source = self.source()
            name = 'templates/commands/plan.md'
            source[name] = source[name].replace(b'__SPECKIT_COMMAND_PLAN__', replacement)
            with self.subTest(marker=replacement), self.assertRaises(ValueError):
                self.payload(source)
        source = self.source()
        del source['templates/commands/analyze.md']
        source['templates/commands/plan.md'] += b'__SPECKIT_COMMAND_ANALYZE__\n'
        with self.assertRaises(ValueError):
            self.payload(source)
        source = self.source()
        source['templates/commands/plan.md'] += b'{ARGS_UNKNOWN}\n'
        with self.assertRaises(ValueError):
            self.payload(source)

    def test_ambiguous_missing_or_unsupported_workflow_version_refuses(self):
        for value in (
            b'workflow:\n  id: "speckit"\n',
            b'workflow:\n  id: "speckit"\n  version: "wrong"\n',
            b'workflow:\n  id: "speckit"\n  version: "1.0.2"\n  version: "1.0.3"\n',
            b'version: 1.0.0\nversion: 1.0.1\n',
            b'version: 1.0.0\nworkflow:\n  id: "speckit"\n  version: "1.0.2"\n',
            b'workflow:\n  id: "speckit"\n  version: "1.0.2"\nworkflow: {version: 1.0.3}\n',
        ):
            source = self.source()
            source['workflows/speckit/workflow.yml'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.payload(source)
