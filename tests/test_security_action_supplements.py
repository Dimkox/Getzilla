"""Closed immutable source supplements; no local research index is authority."""
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
NOW = datetime(2026, 11, 19, tzinfo=timezone.utc)
MIT = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())['MIT']['text'].encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            tar.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class SupplementalSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def world(self):
        self.assertIsNotNone(importlib.util.find_spec('getzilla.security_action_supplements'), 'missing immutable supplemental source verifier')
        from getzilla import security_action_supplements as supplements
        package = dict(name='@nodable/entities', version='2.1.0', license='MIT')
        members = {'package.json': json.dumps(package).encode(), 'index.js': b'/* owned inert source */'}
        npm = archive({'package/' + k: v for k, v in members.items()})
        source_files = {'source/Entity/' + k: v for k, v in members.items()}
        source_files['source/LICENSE'] = MIT
        upstream = archive(source_files)
        url = 'https://registry.npmjs.org/@nodable/entities/-/entities-2.1.0.tgz'
        git_head = 'a' * 40
        registry_url = 'https://registry.npmjs.org/@nodable%2Fentities/2.1.0'
        source_url = 'https://codeload.github.com/nodable/val-parsers/tar.gz/' + git_head
        registry = json.dumps(dict(name=package['name'], version=package['version'], gitHead=git_head,
            dist=dict(tarball=url, integrity='sha512-' + base64.b64encode(hashlib.sha512(npm).digest()).decode()))).encode()
        def saved(name, raw, origin):
            (self.root / name).write_bytes(raw)
            return dict(url=origin, path=name, bytes=len(raw), sha256=sha(raw), acquired_at=NOW.isoformat())
        descriptor = saved('npm.tgz', npm, url)
        descriptor['strong_metadata'] = None
        descriptor['term_supplement'] = dict(profile='owned-source-mit-v1',
            registry=saved('registry.json', registry, registry_url), archive=saved('source.tgz', upstream, source_url))
        profile = dict(id='owned-source-mit-v1', name=package['name'], version=package['version'], npm_url=url,
            registry_url=registry_url, git_head=git_head, source_url=source_url, source_sha256=sha(upstream),
            package_prefix='Entity', published_members=len(members), term_path='LICENSE', term_sha256=sha(MIT), term_bytes=len(MIT))
        expected = [dict(name=package['name'], version=package['version'], resolved=url,
            integrity='sha512-' + base64.b64encode(hashlib.sha512(npm).digest()).decode())]
        return supplements, descriptor, profile, expected

    def test_complete_source_term_with_every_published_member_qualifies(self):
        supplements, source, profile, expected = self.world()
        from getzilla.security_action_npm import verify_source
        with patch.dict(supplements.PROFILES, {source['sha256']: profile}, clear=True):
            result = verify_source(self.root, source, expected, now=NOW)
        self.assertEqual(result['components'][0]['expression'], 'MIT')
        self.assertTrue(any(row.get('container_kind') == 'supplemental-source-archive-member' for row in result['proofs']))
        self.assertTrue(any(body == MIT for body in result['files'].values()))

    def test_default_acquisition_fetches_fixed_objects_then_preserves_cache_times(self):
        supplements, source, profile, expected = self.world()
        from getzilla.security_action_npm_fetch import acquire_sources
        payloads = {source['url']: (self.root / source['path']).read_bytes()}
        payloads.update({row['url']: (self.root / row['path']).read_bytes()
                         for row in source['term_supplement'].values() if isinstance(row, dict)})
        calls = []
        def fetch(url, *, maximum):
            calls.append(url)
            self.assertLessEqual(len(payloads[url]), maximum)
            return payloads[url]
        with patch.dict(supplements.PROFILES, {source['sha256']: profile}, clear=True):
            first = acquire_sources({source['url']: expected}, self.root, fetch=fetch, now=NOW)
            self.assertEqual(first['gaps'], [], first)
            self.assertEqual(set(calls), set(payloads))
            self.assertEqual(len(calls), 3)
            self.assertIn('term_supplement', first['sources'][source['url']])
            second = acquire_sources({source['url']: expected}, self.root,
                fetch=lambda *a, **k: self.fail('cached source was relabelled/refetched'), now=NOW)
        self.assertEqual(second['gaps'], [], second)
        self.assertEqual(first['sources'], second['sources'])

    def test_coherent_source_change_or_truncated_full_term_cannot_qualify(self):
        supplements, source, profile, expected = self.world()
        from getzilla.security_action_npm import verify_source
        import copy
        npm = (self.root / source['path']).read_bytes()
        with tarfile.open(fileobj=io.BytesIO(npm), mode='r:gz') as tar:
            published = {m.name.split('/', 1)[1]: tar.extractfile(m).read() for m in tar if m.isfile()}
        for variant in ('published-member', 'truncated-term'):
            files = {'source/Entity/' + name: body for name, body in published.items()}
            files['source/LICENSE'] = MIT if variant == 'published-member' else MIT[:-80]
            if variant == 'published-member':
                files['source/Entity/index.js'] = b'/* coherent source mismatch */'
            raw = archive(files)
            (self.root / 'changed-source.tgz').write_bytes(raw)
            changed, reviewed = copy.deepcopy(source), copy.deepcopy(profile)
            changed['term_supplement']['archive'].update(path='changed-source.tgz', sha256=sha(raw), bytes=len(raw))
            reviewed['source_sha256'] = sha(raw)
            if variant == 'truncated-term':
                reviewed['term_sha256'] = sha(files['source/LICENSE'])
                reviewed['term_bytes'] = len(files['source/LICENSE'])
            with self.subTest(variant=variant), patch.dict(supplements.PROFILES, {source['sha256']: reviewed}, clear=True), self.assertRaises(ValueError):
                verify_source(self.root, changed, expected, now=NOW)

    def test_fixed_source_with_no_registry_githead_uses_all_published_members(self):
        supplements, source, profile, expected = self.world()
        from getzilla.security_action_npm import verify_source
        import copy
        npm = (self.root / source['path']).read_bytes()
        with tarfile.open(fileobj=io.BytesIO(npm), mode='r:gz') as tar:
            published = {m.name.split('/', 1)[1]: tar.extractfile(m).read() for m in tar if m.isfile()}
        upstream = archive({**{'source/' + name: body for name, body in published.items()}, 'source/LICENSE': MIT})
        (self.root / 'root-source.tgz').write_bytes(upstream)
        changed, reviewed = copy.deepcopy(source), copy.deepcopy(profile)
        changed['term_supplement']['archive'].update(path='root-source.tgz', sha256=sha(upstream), bytes=len(upstream))
        registry = json.loads((self.root / 'registry.json').read_bytes())
        registry.pop('gitHead')
        raw = json.dumps(registry).encode()
        (self.root / 'headless-registry.json').write_bytes(raw)
        changed['term_supplement']['registry'].update(path='headless-registry.json', sha256=sha(raw), bytes=len(raw))
        reviewed.update(git_head=None, package_prefix='', source_sha256=sha(upstream),
                        source_identity_basis='all-published-members-at-fixed-source-commit', source_commit='a' * 40)
        with patch.dict(supplements.PROFILES, {source['sha256']: reviewed}, clear=True):
            result = verify_source(self.root, changed, expected, now=NOW)
        proof = next(row for row in result['proofs'] if row.get('container_kind') == 'supplemental-source-archive-member')
        self.assertIsNone(proof['registry_gitHead'])
        self.assertEqual(proof['source_identity_basis'], 'all-published-members-at-fixed-source-commit')
        self.assertEqual(proof['physical_bytes'], 0)
        self.assertEqual(len(proof['published_member_matches']), len(published))

    def test_wrong_githead_source_hash_component_or_omitted_term_refuses(self):
        supplements, source, profile, expected = self.world()
        from getzilla.security_action_npm import verify_source
        import copy
        for variant in ('gitHead', 'archive', 'profile', 'missing'):
            changed = copy.deepcopy(source)
            if variant == 'gitHead':
                body = json.loads((self.root / 'registry.json').read_bytes())
                body['gitHead'] = 'b' * 40
                raw = json.dumps(body).encode()
                (self.root / 'bad-registry.json').write_bytes(raw)
                changed['term_supplement']['registry'].update(path='bad-registry.json', sha256=sha(raw), bytes=len(raw))
            elif variant == 'archive':
                changed['term_supplement']['archive']['sha256'] = '0' * 64
            elif variant == 'profile':
                changed['term_supplement']['profile'] = 'label-only-success'
            else:
                changed.pop('term_supplement')
            with self.subTest(variant=variant), patch.dict(supplements.PROFILES, {source['sha256']: profile}, clear=True), self.assertRaises(ValueError):
                verify_source(self.root, changed, expected, now=NOW)
