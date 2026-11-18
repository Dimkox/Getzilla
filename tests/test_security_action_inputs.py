"""Owned Git/Node data with actual pinned metadata; no upstream program runs."""
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_artifacts as artifacts

FIXTURE = json.loads((ROOT / 'tests/fixtures/security-action-node-metadata.json').read_text())
NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)
PIN = '3d3c42e5aac5ba805825da76410c181273ba90b1'
REFERENCE = 'actions/checkout@' + PIN


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class ActionInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.module = None

    def adapter(self):
        import importlib.util
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_action_inputs'), 'missing Action data adapter')
        from getzilla import security_action_inputs
        return security_action_inputs

    def world(self, uses=1, *, link=False, term_change=None):
        module = self.adapter()
        mit = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())['MIT']['text'].encode()
        metadata = FIXTURE['action']['text'].encode()
        cache = FIXTURE['licensed']['text'].encode()
        self.assertEqual(sha(metadata), FIXTURE['action']['sha256'])
        self.assertEqual(sha(cache), FIXTURE['licensed']['sha256'])
        if term_change == 'restriction':
            cache = cache.replace(b'    Permission is hereby granted', b'    Additional restriction: commercial use is forbidden.\n\n    Permission is hereby granted')
        elif term_change == 'truncated':
            cache = cache.split(b'    THE SOFTWARE IS PROVIDED')[0] + b'notices: []\n'
        elif term_change == 'altered':
            cache = cache.replace(b'without restriction', b'only for non-commercial use')
        files = {'action.yml': metadata, 'dist/index.js': b'/* owned inert bundle, never executed */\n',
                 'LICENSE': mit, '.licenses/npm/@actions/core.dep.yml': cache,
                 'package.json': encoded(dict(name='checkout', version='7.0.1', license='MIT', dependencies={'@actions/core': '3.0.1'})),
                 'package-lock.json': encoded(dict(lockfileVersion=3, packages={'': {}, 'node_modules/@actions/core': {'version': '3.0.1'}}))}
        modes = {name: '100644' for name in files}
        if link:
            files['escape'] = b'/tmp/foreign'
            modes['escape'] = '120000'
        rows = {name: dict(path=name, type='blob', mode=modes[name], size=len(raw),
                          sha=hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()) for name, raw in files.items()}
        tree_id = artifacts._git_tree(rows)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            for name, raw in files.items():
                item = zipfile.ZipInfo('source/' + name)
                item.create_system = 0
                item.external_attr = 0x20  # Actual GitHub omitted Unix regular-file mode.
                archive.writestr(item, raw)
        payload = stream.getvalue()
        commit = encoded(dict(sha=PIN, tree=dict(sha=tree_id)))
        tree = encoded(dict(sha=tree_id, truncated=False, tree=list(rows.values())))
        licensed = module.licensed_text(cache, 'licenses/0/text')
        proof = dict(schema_version=1, kind='action-source-components/v1', artifact_sha256=sha(payload),
                     metadata_sha256=sha(metadata), entrypoints={'dist/index.js': sha(files['dist/index.js'])},
                     bundles=[dict(path='dist/index.js', sha256=sha(files['dist/index.js']), components=['action', 'core'])],
                     components=[dict(id='action', name='checkout', version='7.0.1', expression='MIT', requires=['core'],
                                      terms=[dict(path='LICENSE', sha256=sha(mit), selector=None, text_sha256=sha(mit))], notices=[]),
                                 dict(id='core', name='@actions/core', version='3.0.1', expression='MIT', requires=[],
                                      terms=[dict(path='.licenses/npm/@actions/core.dep.yml', sha256=sha(cache), selector='licenses/0/text', text_sha256=sha(licensed.encode()))], notices=[])])
        path = self.root / 'maps/owned.json'
        path.parent.mkdir()
        path.write_bytes(encoded(proof))
        descriptor = dict(path='maps/owned.json', sha256=sha(encoded(proof)))
        subjects = [dict(kind='github-action', reference=REFERENCE, manifest='.github/workflows/owned.yml',
                         line=index + 1, source_sha256='a' * 64, usage='build-ci') for index in range(uses)]
        urls = {'https://api.github.com/repos/actions/checkout/git/commits/' + PIN: commit,
                'https://api.github.com/repos/actions/checkout/git/trees/' + tree_id + '?recursive=1': tree,
                'https://codeload.github.com/actions/checkout/zip/' + PIN: payload}
        calls = []
        def fetch(url, *, maximum):
            calls.append(url)
            value = urls[url]
            if len(value) > maximum:
                raise artifacts.ArtifactError("artifact-size", "injected bounded transport refusal")
            return value
        return module, dict(digest='a' * 64, tools=subjects), descriptor, proof, fetch, calls

    def test_real_node_metadata_and_embedded_terms_qualify_owned_closed_map(self):
        module, inventory, descriptor, proof, fetch, calls = self.world(33)
        with patch('subprocess.Popen', side_effect=AssertionError('execution denied')), \
             patch('socket.socket', side_effect=AssertionError('network denied')):
            report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                             component_maps={REFERENCE: descriptor})
            self.assertEqual(report['gaps'], [], report)
            self.assertEqual(len(report['records']), 33)
            self.assertEqual(len(calls), 3)
            self.assertEqual(len({row['subject']['line'] for row in report['records']}), 33)
            evidence = artifacts.family_evidence(self.root, report['records'][0])
        self.assertEqual(len(evidence['components']), 2)
        self.assertTrue(any(row.get('selector') == 'licenses/0/text' for row in evidence['binding']['proofs']))
        self.assertGreater(report['bound_bytes'], report['source_facts'][0]['bound_bytes'])

    def test_missing_map_retains_source_facts_and_all_unresolved_uses(self):
        module, inventory, descriptor, proof, fetch, calls = self.world(3)
        report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW)
        self.assertEqual(report['records'], [])
        self.assertEqual(len(report['gaps']), 3)
        self.assertEqual(report['gaps'][0]['code'], 'action-bundle-map-missing')
        self.assertEqual(len(report['source_facts']), 1)
        self.assertEqual(len(calls), 3)

    def test_bundle_component_selector_or_term_changes_cannot_gain_credit(self):
        module, inventory, descriptor, proof, fetch, calls = self.world()
        mutants = []
        for field in ('bundles', 'components'):
            value = copy.deepcopy(proof)
            value[field] = value[field][:1] if field == 'components' else []
            mutants.append(value)
        for change in ('hash', 'selector', 'expression', 'root-only', 'root-term', 'component-identity'):
            value = copy.deepcopy(proof)
            if change == 'hash':
                value['components'][1]['terms'][0]['text_sha256'] = '0' * 64
            elif change == 'selector':
                value['components'][1]['terms'][0]['selector'] = 'licenses/0/text/unknown'
            elif change == 'expression':
                value['components'][1]['expression'] = 'BlueOak-1.0.0'
            elif change == 'root-only':
                value['bundles'][0]['components'] = ['action']
            elif change == 'root-term':
                value['components'][1]['terms'] = copy.deepcopy(value['components'][0]['terms'])
            else:
                value['components'][1]['name'] = '@actions/foreign'
            mutants.append(value)
        for value in mutants:
            raw = encoded(value)
            (self.root / descriptor['path']).write_bytes(raw)
            selected = dict(descriptor, sha256=sha(raw))
            with self.subTest(value=value):
                report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                                 component_maps={REFERENCE: selected})
                self.assertEqual(report['records'], [])
                self.assertTrue(report['gaps'])

    def test_unknown_links_unsupported_nodes_and_origin_refusals_stay_gaps(self):
        module, inventory, descriptor, proof, fetch, calls = self.world(link=True)
        report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                         component_maps={REFERENCE: descriptor})
        self.assertEqual(report['records'], [])
        self.assertEqual(report['gaps'][0]['code'], 'artifact-action-link')
        self.assertFalse(module.source_url('https://codeload.github.com/evil/repo/zip/' + PIN, 'actions/checkout', PIN, 'zip'))
        with self.assertRaises(artifacts.ArtifactError):
            module.node_metadata(b'runs:\n  using: docker\n  image: Dockerfile\n', {'Dockerfile': {}})

    def test_rehashed_restricted_truncated_or_altered_real_terms_remain_refused(self):
        for change in ('restriction', 'truncated', 'altered'):
            with self.subTest(change=change):
                # Each mutation gets coherent new Git/blob/ZIP/container/map
                # hashes; refusal must come from actual complete-term review.
                module, inventory, descriptor, proof, fetch, calls = self.world(term_change=change)
                report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                                 component_maps={REFERENCE: descriptor})
                self.assertEqual(report['records'], [])
                self.assertTrue(any(row['code'] == 'license-text-review' for row in report['gaps']), report)
                (self.root / descriptor['path']).unlink()
                (self.root / 'maps').rmdir()

    def test_actual_api_failure_retains_received_commit_without_retry_or_credit(self):
        module, inventory, descriptor, proof, fetch, calls = self.world(2)
        def refused(url, *, maximum):
            if '/git/trees/' in url:
                calls.append(url)
                raise artifacts.ArtifactError('artifact-action-transport', 'actual API403 remains unavailable')
            return fetch(url, maximum=maximum)
        report = module.prepare_actions(inventory, self.root, fetch=refused, now=NOW)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report['records'], [])
        self.assertEqual(len(report['gaps']), 2)
        self.assertEqual(len(report['source_facts'][0]['responses']), 1)
        response = report['source_facts'][0]['responses'][0]
        self.assertEqual(sha((self.root / response['path']).read_bytes()), response['sha256'])
        self.assertEqual(report['bound_bytes'], response['bytes'] * 2)

    def test_existing_license_consumer_accepts_only_owned_proved_node_family(self):
        module, inventory, descriptor, proof, fetch, calls = self.world()
        inventory.update(schema_version=1, complete=True, gaps=[], dependencies=[], images=[])
        report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                         component_maps={REFERENCE: descriptor})
        manifest = dict(schema_version=1, inventory_digest=inventory['digest'],
                        last_verified_sync_utc=NOW.isoformat(), records=report['records'], gaps=[])
        (self.root / 'manifest.json').write_bytes(encoded(manifest))
        from getzilla.security_licenses import evaluate_artifacts, artifact_catalog_source
        policy = dict(schema_version=1, project_repository='github.com/owned/project',
                      auto_allow=['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD'],
                      usage_distribution={'build-ci': 'internal'})
        evaluated = evaluate_artifacts(inventory, self.root, policy, now=NOW)
        self.assertEqual(evaluated['status'], 'pass', evaluated)
        catalog = artifact_catalog_source(inventory, self.root, policy, now=NOW)
        self.assertTrue(catalog['coverage']['complete'])
        self.assertEqual(len(evaluated['details'][0]['license_files']), 2)

    def test_stale_family_and_low_shared_budget_refuse_without_extra_fetches(self):
        module, inventory, descriptor, proof, fetch, calls = self.world()
        report = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW,
                                         component_maps={REFERENCE: descriptor})
        record = copy.deepcopy(report['records'][0])
        for acquired in (NOW - timedelta(hours=73), NOW + timedelta(seconds=1)):
            record['acquired_at'] = acquired.isoformat()
            with self.assertRaises(artifacts.ArtifactError):
                module.verify_family(self.root, record, now=NOW)
        calls.clear()
        refused = module.prepare_actions(inventory, self.root, fetch=fetch, now=NOW, byte_budget=1)
        self.assertEqual(refused['records'], [])
        self.assertTrue(refused['gaps'])
