"""Normal supported commands must not turn a clean consumer into source changes."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class EntrypointBytecodeTests(unittest.TestCase):
    def setUp(self):
        scratch=Path(os.environ.get('GETZILLA_TEST_SCRATCH',ROOT/'.getzilla/runtime/scratch'))
        scratch.mkdir(parents=True,exist_ok=True,mode=0o700)
        temporary=tempfile.TemporaryDirectory(prefix='owned-bytecode-',dir=scratch)
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.environment={k:v for k,v in os.environ.items() if not k.startswith(('GIT_','GETZILLA_'))
            and k not in {'PYTHONDONTWRITEBYTECODE','PYTHONPYCACHEPREFIX','PYTHONPATH'}}
        self.environment.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL=os.devnull,
            GIT_AUTHOR_NAME='Owned fixture',GIT_AUTHOR_EMAIL='owned@example.invalid',
            GIT_COMMITTER_NAME='Owned fixture',GIT_COMMITTER_EMAIL='owned@example.invalid')
        for source in ('scripts','bin','.getzilla/getzilla','.getzilla/config','.getzilla/hooks'):
            shutil.copytree(ROOT/source,self.root/source,ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        self.git('init','-q','-b','work')
        # Isolate cache pollution from workflow state. There is deliberately no
        # .gitignore or Python-cache exclusion in this fresh source consumer.
        (self.root/'.git/info/exclude').write_text('.getzilla/runtime/\n')
        self.git('add','.')
        self.git('commit','-qm','owned installed source payload')
        self.git('update-ref','refs/remotes/origin/main',self.git('rev-parse','HEAD').strip())
        self.assertEqual(self.git('status','--porcelain=v1','--untracked-files=all'),'')

    def git(self,*arguments):
        result=subprocess.run(['git','-C',str(self.root),*arguments],capture_output=True,text=True,
            env=self.environment,timeout=15,check=True)
        return result.stdout

    def command(self,script,*arguments,stdin=None):
        argv=[str(self.root/script),*arguments] if script=='bin/getzilla' else [sys.executable,str(self.root/script),*arguments]
        result=subprocess.run(argv,cwd=self.root,
            env=self.environment,input=stdin,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        return result

    def route(self,launcher='scripts/getzilla_route.py'):
        prefix=('route',) if launcher.endswith('getzilla_cli.py') or launcher=='bin/getzilla' else ()
        self.command(launcher,*prefix,'Fix owned ordinary application behavior','--session','owned-bytecode','--json')
        return json.loads(self.command(launcher,*prefix,'--reconcile','--session','owned-bytecode','--json').stdout)

    def test_normal_route_and_reconcile_leave_no_bytecode_or_inventory_gap(self):
        for _ in range(2):
            result=self.route()
            self.assertNotIn('UNCOMMITTED_INVENTORY',result['risk_assessment']['gaps'],self.git('status','--porcelain=v1','--untracked-files=all'))
            self.assertEqual(self.git('status','--porcelain=v1','--untracked-files=all'),'')
            self.assertFalse(list((self.root/'.getzilla').rglob('*.pyc')))

    def test_cli_dispatch_and_direct_hook_leave_no_bytecode(self):
        self.route('scripts/getzilla_cli.py')
        if os.name!='nt':self.route('bin/getzilla')
        self.command('.getzilla/hooks/user_prompt_submit.py',stdin='{}')
        self.assertFalse(list((self.root/'.getzilla').rglob('*.pyc')))
        self.assertEqual(self.git('status','--porcelain=v1','--untracked-files=all'),'')

    def test_fresh_actual_archived_install_with_no_cache_ignore_stays_clean(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        import install_into
        target=self.root/'lean-consumer'
        install_into.materialize_new(ROOT,target,selection=install_into.PayloadSelection(('codex',),engine_archive=True))
        self.root=target
        # Remove only this owned fixture's generated ignore file, not any user
        # content. Keep workflow state excluded through Git's private info file.
        (target/'.gitignore').unlink(missing_ok=True)
        self.git('init','-q','-b','work')
        (target/'.git/info/exclude').write_text('.getzilla/runtime/\n')
        self.git('add','.')
        self.git('commit','-qm','owned fresh archived installation')
        self.git('update-ref','refs/remotes/origin/main',self.git('rev-parse','HEAD').strip())
        self.assertTrue((target/'.getzilla/getzilla.zip').is_file())
        for _ in range(2):
            result=self.route()
            self.assertNotIn('UNCOMMITTED_INVENTORY',result['risk_assessment']['gaps'])
            self.assertFalse(list((target/'.getzilla').rglob('*.pyc')))
            self.assertEqual(self.git('status','--porcelain=v1','--untracked-files=all'),'')

    def test_real_untracked_source_and_existing_caller_cache_file_stay_visible(self):
        for path in ('new_feature.py','.getzilla/getzilla/__pycache__/caller-owned.txt'):
            target=self.root/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(b'owned source must remain unchanged\n')
        result=self.route()
        self.assertIn('UNCOMMITTED_INVENTORY',result['risk_assessment']['gaps'])
        status=self.git('status','--porcelain=v1','--untracked-files=all')
        for path in ('new_feature.py','.getzilla/getzilla/__pycache__/caller-owned.txt'):
            self.assertIn(path,status)
            self.assertEqual((self.root/path).read_bytes(),b'owned source must remain unchanged\n')


class EntrypointCoverageTests(unittest.TestCase):
    def test_every_source_entrypoint_disables_cache_before_project_imports(self):
        scripts=[]
        for path in (ROOT/'scripts').glob('*.py'):
            text=path.read_text()
            if path.name.startswith('getzilla_') or 'from getzilla' in text or 'import getzilla' in text:scripts.append(path)
        hooks=[path for path in (ROOT/'.getzilla/hooks').glob('*.py') if path.name!='_lib.py']
        self.assertGreater(len(scripts),50)
        self.assertGreater(len(hooks),5)
        for path in sorted(scripts+hooks):
            with self.subTest(path=str(path.relative_to(ROOT))):
                module=ast.parse(path.read_text())
                assignments=[node for node in module.body if isinstance(node,ast.Assign)
                    and any(isinstance(target,ast.Attribute) and isinstance(target.value,ast.Name)
                        and target.value.id=='sys' and target.attr=='dont_write_bytecode' for target in node.targets)
                    and isinstance(node.value,ast.Constant) and node.value.value is True]
                self.assertTrue(assignments,'entrypoint has no unconditional pre-import bytecode guard')
                first=min(node.lineno for node in assignments)
                imports=[node.lineno for node in ast.walk(module) if
                    isinstance(node,ast.ImportFrom) and (node.module or '').startswith(('getzilla','_lib'))
                    or isinstance(node,ast.Import) and any(alias.name.startswith('getzilla') for alias in node.names)]
                self.assertTrue(not imports or first<min(imports))
