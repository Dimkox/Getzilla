"""Cargo sources cannot disappear from the inactive checker's input scope."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from getzilla import security_osv_snapshot as strict
from getzilla.security_inventory import collect_inventory

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'


class CargoCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cargo-security-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def fixture(self, declaration, source, *, workspace=False):
        manifest = ('[workspace]\nmembers=["member"]\n' if workspace else
                    '[package]\nname="app"\nversion="0.1.0"\n')
        manifest += '[dependencies]\ndemo=' + declaration + '\n'
        (self.root / 'Cargo.toml').write_text(manifest)
        (self.root / 'Cargo.lock').write_text('version=3\n[[package]]\nname="demo"\nversion="1.0.0"\n' +
                                               (f'source="{source}"\n' if source else ''))

    def test_git_path_workspace_and_unknown_registry_sources_are_explicit_gaps(self):
        cases = [('{git="https://example.invalid/demo",rev="'+'a'*40+'"}', 'git+https://example.invalid/demo#'+'a'*40, False),
                 ('{path="../demo"}', None, False), ('{workspace=true}', REGISTRY, True),
                 ('{version="1",registry="private"}', 'registry+https://example.invalid/index', False)]
        for declaration, source, workspace in cases:
            with self.subTest(declaration=declaration):
                self.fixture(declaration, source, workspace=workspace)
                inventory = collect_inventory(self.root)
                self.assertFalse(inventory['complete'], inventory)
                self.assertTrue(inventory['gaps'])
                with self.assertRaises(strict.VulnerabilityError):
                    strict.collect_dependencies(self.root)

    def test_registry_packages_and_the_exact_local_project_are_retained(self):
        self.fixture('"1"', REGISTRY)
        with (self.root / 'Cargo.lock').open('a') as stream:
            stream.write('[[package]]\nname="app"\nversion="0.1.0"\n')
        inventory = collect_inventory(self.root)
        self.assertTrue(inventory['complete'], inventory)
        self.assertEqual([(d['ecosystem'], d['name'], d['version']) for d in inventory['dependencies']],
                         [('crates.io', 'demo', '1.0.0')])
        dependencies, _ = strict.collect_dependencies(self.root)
        self.assertEqual([(d.ecosystem, d.name, d.version) for d in dependencies], [('crates.io', 'demo', '1.0.0')])

    def test_mixed_lock_and_missing_declared_entry_remain_incomplete(self):
        self.fixture('"1"', REGISTRY)
        with (self.root / 'Cargo.lock').open('a') as stream:
            stream.write('[[package]]\nname="unqualified"\nversion="2.0.0"\nsource="git+https://example.invalid/source#'+'b'*40+'"\n')
        self.assertFalse(collect_inventory(self.root)['complete'])
        self.fixture('"1"', REGISTRY)
        with (self.root / 'Cargo.toml').open('a') as stream:
            stream.write('missing="2"\n')
        self.assertFalse(collect_inventory(self.root)['complete'])

    def run_cli(self):
        parent = self.root.parent
        with tempfile.TemporaryDirectory(prefix='cargo-checker-', dir=parent) as folder:
            checker = Path(folder)
            shutil.copytree(ROOT / '.getzilla/getzilla', checker / '.getzilla/getzilla',
                            ignore=shutil.ignore_patterns('__pycache__'))
            (checker / 'scripts').mkdir()
            shutil.copyfile(ROOT / 'scripts/getzilla_security.py', checker / 'scripts/getzilla_security.py')
            for project in (checker, self.root):
                for args in (['init','-q'], ['remote','add','origin','https://github.com/Dimkox/Getzilla.git'],
                             ['add','.'], ['-c','user.name=test','-c','user.email=test@example.invalid','commit','-qm','fixture']):
                    subprocess.run(['git','-C',str(project),*args],check=True,capture_output=True)
            output = checker.parent / (checker.name + '-report.json')
            self.addCleanup(output.unlink, missing_ok=True)
            result = subprocess.run([sys.executable,str(checker/'scripts/getzilla_security.py'),
                '--root',str(self.root),'--database',str(checker.parent/(checker.name+'-db')),
                '--artifacts',str(checker.parent/(checker.name+'-artifacts')),
                '--tools',str(checker.parent/(checker.name+'-tools')),'--json-out',str(output)],
                capture_output=True,text=True,timeout=30,check=False,
                env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})
            for suffix in ('-db','-artifacts','-tools'):
                self.addCleanup(shutil.rmtree,checker.parent/(checker.name+suffix),ignore_errors=True)
            report=json.loads(output.read_bytes())
            return result, report

    def test_real_cli_blocks_git_dependency_in_clean_source(self):
        self.fixture('{git="https://example.invalid/demo",rev="'+'a'*40+'"}',
                     'git+https://example.invalid/demo#'+'a'*40)
        result,report=self.run_cli()
        self.assertEqual(result.returncode,1,result.stdout)
        self.assertEqual(report['status'],'fail')
        inventory=next(c for c in report['checks'] if c['name']=='security-inventory')
        self.assertEqual(inventory['details'][0]['outcome'],'blocked')

    def test_real_cli_preserves_complete_first_party_only_absence(self):
        (self.root/'Cargo.toml').write_text('[package]\nname="app"\nversion="0.1.0"\n')
        (self.root/'Cargo.lock').write_text('version=3\n[[package]]\nname="app"\nversion="0.1.0"\n')
        result,report=self.run_cli()
        self.assertEqual(result.returncode,0,result.stdout)
        self.assertEqual(report['status'],'pass')
