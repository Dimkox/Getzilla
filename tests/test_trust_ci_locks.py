"""Trust CI installs consume committed, complete, hash-verified dependency profiles."""
from __future__ import annotations
import importlib.util
import unittest
import json
import re
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class TrustCILockTests(unittest.TestCase):
    def _assert_frozen_commands(self, text):
        text = '\n'.join(line for line in text.splitlines() if not line.strip().startswith('#'))
        text = text.replace('\\\n', ' ')
        commands = re.findall(r'python(?:3)? -m pip install ([^&\n]+)', text)
        self.assertTrue(commands)
        for command in commands:
            if ' -r ' in command:
                self.assertIn('--require-hashes', command)
                self.assertIn('--only-binary=:all:', command)
                self.assertIn('--no-deps', command)
                self.assertRegex(command, r'-r (?:trust-ci/)?requirements-(?:runtime|test|runner)\.txt\s*$')
            else:
                self.assertIn('--no-deps', command)
                self.assertIn('--no-build-isolation', command)
                self.assertNotIn('[test]', command)

    def test_detached_or_extra_resolver_install_is_rejected(self):
        text = (ROOT / 'trust-ci/runner.Dockerfile').read_text()
        for mutant in (text.replace('--require-hashes', ''), text + '\nRUN python -m pip install .\n'):
            with self.assertRaises(AssertionError):
                self._assert_frozen_commands(mutant)

    def test_lock_profiles_and_install_consumers_are_bound(self):
        self.assertTrue((ROOT / 'trust-ci/uv.lock').is_file(), 'Trust CI lock is missing')
        for name in ('runtime', 'test', 'runner'):
            content = (ROOT / f'trust-ci/requirements-{name}.txt').read_text()
            self.assertIn('--hash=sha256:', content)
            self.assertIn('starlette==', content)
            self.assertIn('setuptools==84.0.0', content)
        for filename in ('Dockerfile.api', 'Dockerfile.worker', 'Dockerfile.test', 'runner.Dockerfile'):
            content = (ROOT / 'trust-ci' / filename).read_text()
            self._assert_frozen_commands(content)
            self.assertIn('--require-hashes', content, filename)
            self.assertIn('--no-deps --no-build-isolation', content, filename)
            self.assertIn('--only-binary=:all:', content, filename)
            self.assertNotIn('".[test]"', content)
        workflow = (ROOT / '.github/workflows/getzilla.yml').read_text()
        self._assert_frozen_commands(workflow)
        self.assertEqual(workflow.count('--require-hashes'), 1)
        self.assertEqual(workflow.count('--no-deps --no-build-isolation'), 1)

    def _module(self):
        spec = importlib.util.spec_from_file_location('trust_lock_profiles', ROOT / 'trust-ci/lock_profiles.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_corrupt_or_stale_profiles_fail_closed(self):
        module = self._module()
        for mutation in ('missing-lock', 'removed-transitive', 'wrong-hash', 'marker-drift', 'backend-drift', 'unknown-profile'):
            with tempfile.TemporaryDirectory() as temporary, self.subTest(mutation=mutation):
                root = Path(temporary)
                for name in ('uv.lock', 'pyproject.toml', 'lock-profiles.json',
                             'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                    shutil.copyfile(ROOT / 'trust-ci' / name, root / name)
                binding = json.loads((root / 'lock-profiles.json').read_text())
                profile = root / 'requirements-runner.txt'
                if mutation == 'missing-lock':
                    (root / 'uv.lock').unlink()
                elif mutation == 'removed-transitive':
                    text = profile.read_text()
                    text = re.sub(r'starlette==[^\n]+\n(?:    --hash[^\n]+\n)+', '', text)
                    profile.write_text(text)
                    binding['profiles']['runner'] = module.digest(profile)
                elif mutation == 'wrong-hash':
                    profile.write_text(profile.read_text().replace('--hash=sha256:', '--hash=sha256:' + '0' * 64 + ' #', 1))
                    binding['profiles']['runner'] = module.digest(profile)
                elif mutation == 'marker-drift':
                    profile.write_text(profile.read_text().replace("sys_platform == 'win32'", "sys_platform == 'linux'"))
                elif mutation == 'backend-drift':
                    path = root / 'pyproject.toml'
                    path.write_text(path.read_text().replace('setuptools==84.0.0', 'setuptools==75.8.0'))
                    binding['inputs']['pyproject.toml'] = module.digest(path)
                else:
                    binding['profiles']['unsupported'] = '0' * 64
                (root / 'lock-profiles.json').write_text(json.dumps(binding))
                self.assertTrue(module.check(root), mutation)

    def test_refresh_recipe_checks_then_exports_frozen_offline_profiles(self):
        from unittest.mock import patch
        module = self._module()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('uv.lock', 'pyproject.toml', 'lock-profiles.json',
                         'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                shutil.copyfile(ROOT / 'trust-ci' / name, root / name)
            with patch.object(module.subprocess, 'run') as run:
                module.refresh(root)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertIn('--check', commands[0])
            self.assertIn('--offline', commands[0])
            self.assertEqual(len(commands), 4)
            for command in commands[1:]:
                self.assertIn('--frozen', command)
                self.assertIn('--offline', command)
                self.assertIn('--no-emit-project', command)
                self.assertNotIn('--no-hashes', command)

    def test_core_tools_and_supported_platform_markers_are_preserved(self):
        import tomllib
        project = tomllib.loads((ROOT / 'trust-ci/pyproject.toml').read_text())
        tools = {line for line in (ROOT / '.getzilla/config/python-test-requirements.txt').read_text().splitlines()
                 if line and not line.startswith('#')}
        self.assertTrue(tools <= set(project['dependency-groups']['runner']))
        runner = (ROOT / 'trust-ci/requirements-runner.txt').read_text()
        self.assertIn("colorama==0.4.6 ; sys_platform == 'win32'", runner)
        self.assertIn("tzdata==2026.3 ; sys_platform == 'win32'", runner)
        self.assertEqual(project['project']['requires-python'], '>=3.11')

    def test_scanner_collects_transitives_from_the_lock_and_profiles(self):
        import sys
        import subprocess
        sys.path.insert(0, str(ROOT / '.getzilla'))
        from getzilla.known_vulns import collect_dependencies
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'trust-ci').mkdir()
            for name in ('uv.lock', 'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                shutil.copyfile(ROOT / 'trust-ci' / name, root / 'trust-ci' / name)
            subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            dependencies, manifests = collect_dependencies(root)
            for name in ('uv.lock', 'requirements-runtime.txt', 'requirements-test.txt', 'requirements-runner.txt'):
                self.assertIn('trust-ci/' + name, manifests)
            self.assertTrue(any(item.name == 'starlette' and item.manifest == 'trust-ci/uv.lock' for item in dependencies))
            self.assertEqual(len([item for item in dependencies if item.manifest == 'trust-ci/uv.lock']), 42)

    def test_profile_integrity_and_graph_closure(self):
        path = ROOT / 'trust-ci/lock_profiles.py'
        self.assertTrue(path.is_file())
        spec = importlib.util.spec_from_file_location('trust_lock_profiles', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.check(ROOT / 'trust-ci'), [])

if __name__ == '__main__':
    unittest.main()
