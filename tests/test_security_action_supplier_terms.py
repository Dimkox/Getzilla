"""Fixed supplier custody never grants credit from metadata alone."""
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))


class SupplierTermsTests(unittest.TestCase):
    def test_profiles_require_original_archive_and_complete_dep5(self):
        from getzilla.security_action_supplier_terms import PROFILES
        self.assertEqual({p['name'] for p in PROFILES.values()}, {'buffers', 'chainsaw'})
        for digest, profile in PROFILES.items():
            self.assertEqual(profile['source_sha256'], digest)
            self.assertEqual(profile['source_identity_basis'], 'supplier-upstream-grant+all-published-members-at-fixed-version')
            self.assertTrue(profile['copyright_url'].startswith('https://sources.debian.org/data/main/'))

    def test_complete_original_dep5_and_scope_are_not_generic_mit(self):
        from getzilla.security_action_supplier_terms import project_dep5
        raw = (b'Files: *\nCopyright: 2015 Original Holder\nLicense: MIT\n\n'
               b'Files: debian/*\nCopyright: Packaging Holder\nLicense: MIT\n\n'
               b'License: MIT\n Full permission and disclaimer.\n .\n Extra name restriction.\n')
        expected = b'Copyright 2015 Original Holder\n\nFull permission and disclaimer.\n\nExtra name restriction.\n'
        profile = {'copyright_sha256': hashlib.sha256(raw).hexdigest(),
                   'term_sha256': hashlib.sha256(expected).hexdigest(), 'term_bytes': len(expected)}
        self.assertEqual(project_dep5(raw, profile), expected)
        for changed in (raw.replace(b'Files: *', b'Files: index.js'), raw.replace(b'Original Holder', b'Other Holder'), raw[:-25]):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                project_dep5(changed, profile)
        # Even a re-pinned container cannot silently drop any final condition.
        changed = raw.replace(b' Extra name restriction.\n', b'')
        profile['copyright_sha256'] = hashlib.sha256(changed).hexdigest()
        with self.assertRaises(ValueError):
            project_dep5(changed, profile)

    def test_supplier_custody_checks_every_member_clock_and_original_grant(self):
        import copy
        from unittest.mock import patch
        from tests import test_security_action_supplements as helpers
        from getzilla import security_action_supplements as supplements
        from getzilla.security_action_npm import source_custody
        helper = helpers.SupplementalSourceTests()
        helper.setUp()
        self.addCleanup(helper.doCleanups)
        _, source, profile, expected = helper.world()
        raw = (b'Files: *\nCopyright: 2015 Original Holder\nLicense: MIT\n\n'
               b'Files: debian/*\nCopyright: Packaging Holder\nLicense: MIT\n\n'
               b'License: MIT\n Complete permission.\n .\n Full disclaimer.\n')
        term = b'Copyright 2015 Original Holder\n\nComplete permission.\n\nFull disclaimer.\n'
        profile.update(supplier_version='1', copyright_url='https://sources.debian.org/data/main/n/owned/1/debian/copyright',
                       copyright_sha256=helpers.sha(raw), term_sha256=helpers.sha(term), term_bytes=len(term),
                       source_identity_basis='supplier-upstream-grant+all-published-members-at-fixed-version')
        (helper.root / 'copyright').write_bytes(raw)
        source['term_supplement']['copyright'] = dict(url=profile['copyright_url'], path='copyright',
            sha256=helpers.sha(raw), bytes=len(raw), acquired_at=helpers.NOW.isoformat())
        with patch.dict(supplements.PROFILES, {source['sha256']: profile}, clear=True):
            result = source_custody(helper.root, source, expected, now=helpers.NOW)
            self.assertEqual(result['supplemental_terms'][0][1], term)
            proof = result['proofs'][-1]
            self.assertEqual(len(proof['published_member_matches']), 2)
            self.assertEqual(proof['physical_bytes'], 0)
            self.assertEqual(proof['artifact_path'], 'copyright')
            self.assertEqual(len(supplements.source_receipts(source)), 4)
            from getzilla.security_action_npm_fetch import acquire_sources
            payloads = {row['url']: (helper.root / row['path']).read_bytes()
                        for row in supplements.source_receipts(source)}
            calls = []
            def fetch(url, *, maximum):
                calls.append(url)
                self.assertLessEqual(len(payloads[url]), maximum)
                return payloads[url]
            first = acquire_sources({source['url']: expected}, helper.root, fetch=fetch, now=helpers.NOW)
            self.assertEqual(first['gaps'], [], first)
            self.assertEqual(set(calls), set(payloads))
            self.assertEqual(first['received_bytes'], sum(map(len, payloads.values())))
            second = acquire_sources({source['url']: expected}, helper.root,
                fetch=lambda *a, **k: self.fail('supplier clock renewed on cache hit'), now=helpers.NOW)
            self.assertEqual(second['gaps'], [], second)
            self.assertEqual(first['sources'], second['sources'])
            for variant in ('scope', 'clock', 'origin', 'missing', 'archive'):
                changed = copy.deepcopy(source)
                if variant == 'clock':
                    changed['term_supplement']['copyright']['acquired_at'] = '2026-11-18T00:00:00+00:00'
                elif variant == 'origin':
                    changed['term_supplement']['copyright']['url'] += '?guess=1'
                elif variant == 'missing':
                    changed['term_supplement'].pop('copyright')
                elif variant == 'archive':
                    changed['term_supplement']['archive']['sha256'] = '0' * 64
                else:
                    (helper.root / 'copyright').write_bytes(raw.replace(b'Files: *', b'Files: test/*'))
                with self.subTest(variant=variant), self.assertRaises(ValueError):
                    source_custody(helper.root, changed, expected, now=helpers.NOW)
                (helper.root / 'copyright').write_bytes(raw)

    def test_real_complete_terms_and_closed_legacy_metadata_interpretation(self):
        import copy
        import json
        from getzilla.security_action_supplier_terms import PROFILES, effective_metadata, project_dep5
        fixture = json.loads((Path(__file__).parent / 'fixtures/security-license-debian-supplier-terms.json').read_text())
        for record in fixture['files']:
            digest = record['npm_sha256']
            profile = PROFILES[digest]
            term = project_dep5(record['original_dep5'].encode(), profile)
            self.assertEqual(term, record['projected_term'].encode())
            path = 'derived/npm/' + digest + '/supplier/LICENSE'
            source = {'sha256': digest, 'url': profile['npm_url'], 'term_supplement': {
                'profile': profile['id'], 'archive': {'url': profile['source_url'], 'sha256': digest},
                'copyright': {'url': profile['copyright_url'], 'sha256': profile['copyright_sha256']}}}
            package = {'name': profile['name'], 'version': profile['version']}
            if profile['name'] == 'chainsaw':
                package['license'] = 'MIT/X11'
            terms = [(path, term)]
            proof = {'container_kind': 'supplier-dep5-upstream-grant', 'sha256': profile['term_sha256'],
                     'derived_path': path, 'artifact_sha256': profile['copyright_sha256'],
                     'source_identity_basis': profile['source_identity_basis'], 'supplier_version': profile['supplier_version'],
                     'published_member_matches': {str(i): {} for i in range(profile['published_members'])}}
            original = copy.deepcopy(package)
            interpreted = effective_metadata(source, package, terms, [proof])
            self.assertEqual(package, original)
            from getzilla.security_licenses import ALLOWED
            self.assertNotIn('X11', ALLOWED)
            self.assertEqual(interpreted['expression'], 'MIT' if profile['name'] == 'buffers' else 'X11')
            self.assertEqual(interpreted['declared_expression'], package.get('license'))
            for variant in ('profile', 'archive', 'copyright', 'terms', 'proof', 'metadata', 'inventory'):
                changed, meta, bodies, proofs = copy.deepcopy(source), copy.deepcopy(package), list(terms), [copy.deepcopy(proof)]
                if variant == 'profile':
                    changed['term_supplement']['profile'] += '-guessed'
                elif variant in {'archive', 'copyright'}:
                    changed['term_supplement'][variant]['sha256'] = '0' * 64
                elif variant == 'terms':
                    bodies = [(path, term[:-1])]
                elif variant == 'proof':
                    proofs = []
                elif variant == 'inventory':
                    proofs[0]['published_member_matches'].pop('0')
                else:
                    meta['license'] = 'MIT'
                with self.subTest(name=profile['name'], variant=variant), self.assertRaises(ValueError):
                    effective_metadata(changed, meta, bodies, proofs)
            # A different artifact cannot inherit these interpretations.
            source['sha256'] = '0' * 64
            self.assertIsNone(effective_metadata(source, package, terms, [proof]))
