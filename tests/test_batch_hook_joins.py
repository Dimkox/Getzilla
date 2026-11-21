"""Bounded joins for the hook dispatcher and combined policy ownership."""
import ast
import codecs
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import getzilla
from getzilla import harnesses, verification_plan, verification_tool_workspace, verification_policy_source
from getzilla import security_research_catalog
from tests.test_batch_composition_joins import _Registry, pure

ROOT = Path(__file__).resolve().parents[1]
codecs.lookup('utf-16le')  # Preload stdlib encoding before the pure effect boundary.


class HookCompositionJoinTests(unittest.TestCase):
    def test_hook_and_managed_installer_commands_both_survive_dispatch_merge(self):
        tree = ast.parse((ROOT/'scripts/getzilla_cli.py').read_bytes())
        commands = next(ast.literal_eval(node.value) for node in tree.body
                        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
                        and node.target.id == 'COMMANDS')
        with pure():
            self.assertEqual(commands['hook'][0], 'getzilla_hook.py')
            self.assertEqual(commands['install-managed'][0], 'getzilla_install_managed.py')
            self.assertTrue({'route', 'verify', 'vulns', 'harness', 'update', 'baseline'} <= commands.keys())

    def test_hook_interpreters_and_dispatch_bytes_change_actual_policy_binding(self):
        sources = {'scripts/getzilla_cli.py':b'owned dispatcher', 'scripts/getzilla_hook.py':b'owned hook'}
        modules = {'harnesses.py':b'owned renderer'}
        catalogs = {'catalog': b'owned research conditions', 'image': b'owned image conditions'}
        class Source:
            def __init__(self, name): self.name = name
            def exists(self): return self.name in sources
            def is_file(self): return True
            def stat(self): return SimpleNamespace(st_size=len(sources[self.name]))
            def read_bytes(self): return sources[self.name]
        with mock.patch.object(verification_tool_workspace, 'checked_path', side_effect=lambda root, name:Source(name)), \
                mock.patch.object(verification_policy_source.importlib, 'import_module',
                                  side_effect=lambda name, package:SimpleNamespace(filename=name.removeprefix('.')+'.py')), \
                mock.patch.object(verification_policy_source, '_module_source',
                                  side_effect=lambda module:modules.get(module.filename,module.filename.encode())), \
                pure(), mock.patch.object(security_research_catalog, 'catalog_bytes', side_effect=lambda: catalogs['catalog']), \
                mock.patch.object(security_research_catalog, 'image_conditions_bytes', side_effect=lambda: catalogs['image']), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()):
            baseline = verification_plan.policy_binding(Path('owned-hook-root'))
            self.assertTrue(set(sources) <= baseline['inputs'].keys())
            self.assertIn('harnesses.py', baseline['implementation'])
            for name in sources:
                old=sources[name]
                sources[name]+=b' changed'
                self.assertNotEqual(verification_plan.policy_binding(Path('owned-hook-root'))['digest'],baseline['digest'])
                sources[name]=old
            modules['harnesses.py']+=b' changed'
            self.assertNotEqual(verification_plan.policy_binding(Path('owned-hook-root'))['digest'],baseline['digest'])
            modules['harnesses.py']=b'owned renderer'
            for name in catalogs:
                old = catalogs[name]
                catalogs[name] += b' changed'
                self.assertNotEqual(verification_plan.policy_binding(Path('owned-hook-root'))['digest'],baseline['digest'])
                catalogs[name] = old

    def test_hook_dispatcher_has_exact_native_policy_owner(self):
        model=json.loads((ROOT/'architecture/system.yaml').read_bytes())
        with pure():
            owners=[node['id'] for node in model['nodes'] if 'scripts/getzilla_hook.py' in node['repository_paths']]
            self.assertEqual(owners,['NODE-LOCAL-ROUTE-POLICY'])
            updater=next(node for node in model['nodes'] if node['id']=='NODE-LOCAL-SUPPLY-CHAIN-UPDATER')
            self.assertIn('.getzilla/getzilla/current_workflows.py',updater['repository_paths'])

    def test_platform_transform_keeps_custom_overlay_and_generated_policy_conflict(self):
        original={'hooks':{'BeforeTool':[{'hooks':[{'command':harnesses._source_hook_command('pre_tool_use.py','gemini')},
                                                        {'command':'owned-custom.exe'}]}]},'owner':'retained'}
        with pure():
            transformed=json.loads(harnesses.platform_hook_payload('.gemini/settings.json',json.dumps(original).encode(),windows=True))
            hooks=transformed['hooks']['BeforeTool'][0]['hooks']
            self.assertEqual(hooks[0]['command'],harnesses._command('pre_tool_use.py','gemini',windows=True))
            self.assertEqual(hooks[1]['command'],'owned-custom.exe')
            self.assertEqual(transformed['owner'],'retained')
            current=SimpleNamespace(content=b'old role',mode=0o644)
            self.assertTrue(harnesses.policy_reconciliation_required('.codex/agents/owned.toml',current,b'new role',0o644))
            self.assertTrue(harnesses.is_generated_policy('.grok/config.toml'))
