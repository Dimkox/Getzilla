"""Closed consumer joins for merged installer policy and alias rendering."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import getzilla
from getzilla import release_transport
from getzilla import baseline, verification, verification_plan, verification_policy_source
from tests.test_batch_composition_joins import _Registry, pure

POLICY = ('baseline.py', 'baseline_assets.py', 'toolchain.py', 'updater.py',
          'current_workflows.py', 'latest_releases.py', 'managed_runtime.py', 'managed_source_build.py',
          'managed_environment.py', 'managed_npm.py', 'managed_software.py', 'opengrep_releases.py')


class InstallerCompositionJoinTests(unittest.TestCase):
    def test_engine_toolchain_metadata_is_bound_with_current_workflow_policy(self):
        contents = {'stacks.json': b'{}', 'toolchain.json': b'{"owned":"one"}'}
        class Registry:
            def __truediv__(self, name):
                if name == 'config':
                    return self
                return SimpleNamespace(is_file=lambda: True, is_symlink=lambda: False,
                    stat=lambda: SimpleNamespace(st_size=len(contents[name])), read_bytes=lambda: contents[name])
        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_policy_source.importlib, 'import_module',
                                  side_effect=lambda name, package: SimpleNamespace(filename=name)), \
                mock.patch.object(verification_policy_source, '_module_source', side_effect=lambda module: module.filename.encode()), \
                mock.patch.object(getzilla, 'STACK_DIR', Registry()), pure():
            before = verification_plan.policy_binding(Path('owned-installer'))
            self.assertIn('toolchain.json', before['implementation'])
            contents['toolchain.json'] = b'{"owned":"two"}'
            after = verification_plan.policy_binding(Path('owned-installer'))
            self.assertNotEqual(before['digest'], after['digest'])

    def test_current_installer_interpreters_change_actual_policy_binding(self):
        content = {name: b'owned implementation one' for name in POLICY}
        def imported(name, package):
            return SimpleNamespace(filename=name.removeprefix('.')+'.py')
        with mock.patch.object(verification_plan, '_POLICY_PATHS', ()), \
                mock.patch.object(verification_policy_source.importlib, 'import_module', side_effect=imported), \
                mock.patch.object(verification_policy_source, '_module_source',
                                  side_effect=lambda module: content.get(module.filename, module.filename.encode())), \
                mock.patch.object(getzilla, 'STACK_DIR', _Registry()), pure():
            initial = verification_plan.policy_binding(Path('owned-installer'))
            self.assertTrue(set(POLICY) <= set(initial['implementation']))
            for name in POLICY:
                content[name] = b'owned changed implementation'
                current = verification_plan.policy_binding(Path('owned-installer'))
                self.assertNotEqual(current['digest'], initial['digest'], name)
                self.assertNotEqual(current['implementation'][name], initial['implementation'][name])
                content[name] = b'owned implementation one'

    def test_new_installer_model_and_existing_live_transport_guards_coexist(self):
        model = json.loads((Path(__file__).resolve().parents[1]/'architecture/system.yaml').read_bytes())
        with pure():
            edges = {row['id']: row for row in model['edges']}
            self.assertTrue({'EDGE-LOCAL-CURRENT-ARTIFACT-REVALIDATION',
                             'EDGE-LIVE-OBSERVER-DOCKER', 'EDGE-LIVE-OBSERVER-POSTGRES',
                             'EDGE-PUBLIC-PRODUCER-SOURCE'} <= set(edges))
            self.assertEqual(edges['EDGE-LOCAL-CURRENT-ARTIFACT-REVALIDATION']['network_policy'], 'no_network')
            self.assertTrue({'DATA-ATTESTATION', 'DATA-PACKAGE-IDENTITY', 'DATA-REPOSITORY-SOURCE'}
                            <= set(edges['EDGE-LOCAL-SUPPLY-CHAIN-FETCH']['allowed_data']))
            updater_node = next(row for row in model['nodes'] if row['id']=='NODE-LOCAL-SUPPLY-CHAIN-UPDATER')
            self.assertTrue({'.getzilla/getzilla/'+name for name in POLICY
                             if name not in {'baseline.py', 'baseline_assets.py', 'toolchain.py'}}
                            <= set(updater_node['repository_paths']))
            worker = next(row for row in model['nodes'] if row['id']=='NODE-TRUST-CI-WORKER')
            self.assertIn('trust-ci/src/adaptive_trust_ci/http_response.py', worker['repository_paths'])

    def test_alias_escaped_text_and_current_baseline_freshness_are_both_retained(self):
        status = baseline.BaselineStatus(True, [], {'freshness': 'official-current', 'warnings': ['owned warning']})
        with mock.patch.dict(os.environ, {'CI':'false', 'GITHUB_ACTIONS':'false'}), \
                mock.patch.object(Path, 'is_file', return_value=True), \
                mock.patch.object(baseline, 'detect_agent', return_value='codex'), \
                mock.patch.object(baseline, 'inspect', return_value=status), \
                mock.patch.object(release_transport, 'home_dir', return_value=Path('owned-home')), pure():
            result, metadata = verification._workflow_baseline_check(Path('owned-project'), 'pr')
            text = verification._vulnerability_detail({'id':'OSV-owned', 'aliases':['GHSA-owned'],
                'raw_aliases':['provider\x1b[31mtext'], 'package':'owned', 'version':'1'})
        self.assertEqual(result.status, 'pass')
        self.assertIn('freshness=official-current', result.summary)
        self.assertEqual(metadata['details']['warnings'], ['owned warning'])
        self.assertNotIn('\x1b', text['raw_aliases'])
        self.assertIn('\\u001b', text['raw_aliases'])
