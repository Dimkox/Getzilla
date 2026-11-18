"""Possible source closure is a distinct, honest assurance from exact inclusion."""
import base64
import copy
import hashlib
import io
import json
import tarfile
import unittest

from tests import test_security_action_inputs as owned
from getzilla import security_action_inputs as actions


class PossibleClosureTests(unittest.TestCase):
    setUp = owned.ActionInputsTests.setUp
    adapter = owned.ActionInputsTests.adapter
    world = owned.ActionInputsTests.world

    def sources(self):
        body = json.loads((owned.ROOT / 'tests/fixtures/security-license-texts.json').read_text())['MIT']['text'].encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, raw in {'package/package.json': b'{"name":"@actions/core","version":"3.0.1","license":"MIT"}',
                              'package/LICENSE': body, 'package/index.js': b'/* inert owned package */'}.items():
                item = tarfile.TarInfo(name)
                item.size = len(raw)
                archive.addfile(item, io.BytesIO(raw))
        raw = stream.getvalue()
        (self.root / 'core.tgz').write_bytes(raw)
        url = 'https://registry.npmjs.org/@actions/core/-/core-3.0.1.tgz'
        sri = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()
        source = dict(url=url, path='core.tgz', sha256=owned.sha(raw), bytes=len(raw), strong_metadata=None, acquired_at="2026-11-18T00:00:00+00:00")
        return source, dict(version='3.0.1', resolved=url, integrity=sri)

    def test_owned_possible_closure_qualifies_without_exact_membership_claim(self):
        source, locked = self.sources()
        module, inventory, descriptor, proof, fetch, calls = self.world(2, npm_lock=locked)
        report = actions.prepare_actions(inventory, self.root, fetch=fetch, now=owned.NOW,
                                         npm_sources={source['url']: source})
        self.assertEqual(report['gaps'], [], report)
        self.assertEqual(len(report['records']), 2)
        evidence = actions.verify_family(self.root, report['records'][0], now=owned.NOW)
        self.assertEqual(evidence['binding']['composition_assurance'], 'source-declared-possible-runtime-components')
        self.assertFalse(evidence['binding']['exact_runtime_membership_proved'])
        self.assertEqual(len(evidence['components']), 2)
        mapping = evidence['binding']['possible_components_by_bundle']
        self.assertEqual(set(mapping), {'dist/index.js'})
        self.assertEqual(set(mapping['dist/index.js']), {c['id'] for c in evidence['components']})

    def test_hosted_default_acquires_original_npm_bytes_and_reuses_verified_cache(self):
        source, locked = self.sources()
        module, inventory, descriptor, proof, fetch, calls = self.world(2, npm_lock=locked)
        from getzilla.security_inventory import canonical_digest
        inventory['digest'] = canonical_digest({key: value for key, value in inventory.items() if key != 'digest'})
        raw = (self.root / source['path']).read_bytes()
        requests = []
        def npm_fetch(url, *, maximum):
            requests.append(url)
            self.assertEqual(url, source['url'])
            self.assertLessEqual(len(raw), maximum)
            return raw
        report = actions.prepare_actions(inventory, self.root, fetch=fetch, npm_fetch=npm_fetch, now=owned.NOW)
        self.assertEqual(report['gaps'], [], report)
        self.assertEqual(len(requests), 1)
        checked = actions.validate_source_facts(self.root, report, now=owned.NOW,
                                                inventory_digest=inventory['digest'], records=report['records'])
        self.assertEqual(checked['gaps'], [], checked)
        self.assertEqual(checked['bound_bytes'], 0)
        repeated = actions.prepare_actions(inventory, self.root, fetch=fetch,
            npm_fetch=lambda *a, **k: self.fail('unexpected npm cache renewal'), now=owned.NOW)
        self.assertEqual(repeated['gaps'], [], repeated)
        self.assertEqual(repeated['records'][0]['acquired_at'], report['records'][0]['acquired_at'])

    def test_failed_default_npm_response_still_pays_every_unresolved_source_use(self):
        source, locked = self.sources()
        module, inventory, descriptor, proof, fetch, calls = self.world(2, npm_lock=locked)
        from getzilla.security_inventory import canonical_digest
        inventory['digest'] = canonical_digest({key: value for key, value in inventory.items() if key != 'digest'})
        report = actions.prepare_actions(inventory, self.root, fetch=fetch, now=owned.NOW,
                                         npm_fetch=lambda *a, **k: (b'official unavailable response', 403))
        self.assertEqual(report['records'], [])
        self.assertTrue(report['gaps'])
        fact = report['source_facts'][0]
        expected = sum(row['bytes'] for row in fact['responses'] + fact['npm_responses']) * 2
        report['bound_bytes'] = fact['bound_bytes'] = 0
        checked = actions.validate_source_facts(self.root, report, now=owned.NOW,
                                                inventory_digest=inventory['digest'], records=[])
        self.assertEqual(checked['bound_bytes'], expected)
        self.assertTrue(checked['gaps'])

    def test_missing_package_changed_lock_or_exact_claim_refuses(self):
        source, locked = self.sources()
        module, inventory, descriptor, proof, fetch, calls = self.world(npm_lock=locked)
        report = actions.prepare_actions(inventory, self.root, fetch=fetch, now=owned.NOW,
                                         npm_sources={source['url']: source})
        record = report['records'][0]
        original = json.loads((self.root / record['components']['path']).read_bytes())
        for mutation in ('missing-package', 'lock', 'exact-claim', 'unqualified-basis'):
            value = copy.deepcopy(original)
            if mutation == 'missing-package':
                value['npm_sources'] = []
            elif mutation == 'lock':
                value['lock_sha256'] = '0' * 64
            elif mutation == 'exact-claim':
                value['exact_runtime_membership_proved'] = True
            else:
                value['coverage_basis'] = 'exact-runtime-membership'
            raw = owned.encoded(value)
            (self.root / record['components']['path']).write_bytes(raw)
            changed = copy.deepcopy(record)
            changed['components']['sha256'] = owned.sha(raw)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                actions.verify_family(self.root, changed, now=owned.NOW)
