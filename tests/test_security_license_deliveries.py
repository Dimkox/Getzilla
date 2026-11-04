"""Exact target/use evidence and real Factory extracted-output custody."""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from getzilla import security_license_acquisition as acquisition
from getzilla import security_licenses as licenses
from tests.test_security_licenses import NOW, POLICY, ROOT, artifact, dependency, inventory, manifest, wheel

PROFILE = 'ubuntu-24.04-x86_64-cpython312'
CONTEXT = 'factory-offline-linux312'
NOTICE = b'Example attribution retained verbatim.\n'


def sha(body):
    return hashlib.sha256(body).hexdigest()


def use_context(dep):
    return {key: dep[key] for key in ('manifest', 'usage', 'distribution', 'delivery_context', 'delivery_kind') if key in dep}


def component_id(record):
    # The public identity is a canonical projection, independent of local cache paths.
    value = {key: record[key] for key in ('ecosystem', 'name', 'version', 'filename', 'sha256', 'context')}
    value['origin'] = {key: record['origin'][key] for key in ('index_url', 'index_sha256', 'artifact_url')}
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


class ArtifactFixture(unittest.TestCase):
    def setUp(self):
        runtime = ROOT / '.getzilla/runtime'
        runtime.mkdir(exist_ok=True)
        tmp = tempfile.TemporaryDirectory(dir=runtime)
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)


class ExactArtifactContextTests(ArtifactFixture):
    def test_named_standalone_wheel_delivery_stays_separate_from_extracted_output(self):
        dep = dependency(distribution='redistributed', delivery_context='factory-standalone-wheel',
                         delivery_kind='unchanged-artifact')
        inv = inventory(dep)
        record = artifact(self.root, dep, wheel())
        record['context'] = use_context(dep)
        record['redistributed_path'] = record['path']
        manifest(self.root, inv, [record])
        result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
        self.assertEqual(result['status'], 'pass', result)
        self.assertNotIn('delivery', result['details'][0])

    def test_acquisition_keeps_two_abi_targets_and_separate_use_contexts(self):
        payloads = {
            'example-1.0.0-cp312-cp312-manylinux_2_17_x86_64.whl': wheel(extra_files={'example/native.so': b'312'}),
            'example-1.0.0-cp313-cp313-manylinux_2_17_x86_64.whl': wheel(extra_files={'example/native.so': b'313'}),
        }
        deps = [dependency(artifact_filename=name, artifact_sha256=sha(body), manifest=f'{abi}/requirements.txt',
                           delivery_context=f'trust-ci-{abi}')
                for abi, (name, body) in zip(('312', '313'), payloads.items())]
        deps.append({**deps[0], 'manifest': 'factory/separate-package.txt', 'delivery_context': 'factory-package'})
        inv = inventory(*deps)
        urls = [{'filename': name, 'url': f'https://files.pythonhosted.org/packages/aa/{name}',
                 'digests': {'sha256': sha(body)}, 'packagetype': 'bdist_wheel', 'yanked': False}
                for name, body in payloads.items()]
        index = json.dumps({'info': {'name': 'example', 'version': '1.0.0'}, 'urls': urls}).encode()
        def fetch(url, *, maximum):
            return index if url.endswith('/json') else payloads[url.rsplit('/', 1)[1]]
        bundle = acquisition.acquire_pypi(deps, self.root, inventory_digest=inv['digest'], fetch=fetch, now=NOW)
        self.assertEqual(len(bundle['records']), 3)
        self.assertEqual({r['context']['delivery_context'] for r in bundle['records']},
                         {'trust-ci-312', 'trust-ci-313', 'factory-package'})
        result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
        self.assertEqual(result['status'], 'pass', result)
        self.assertEqual(len(result['details']), 3)
        source = licenses.artifact_catalog_source(inv, self.root, POLICY, now=NOW)
        self.assertEqual(source['coverage']['record_count'], 3)

    def test_context_prevents_other_use_from_covering_a_transitive_requirement(self):
        parent = dependency(name='parent', artifact_filename='parent-1.0.0-py3-none-any.whl',
                            delivery_context='factory-package')
        child = dependency(delivery_context='trust-ci')
        inv = inventory(parent, child)
        records = [artifact(self.root, parent, wheel(name='parent', requires=['example>=1'])),
                   artifact(self.root, child, wheel())]
        for dep, record in zip((parent, child), records):
            record['context'] = use_context(dep)
        manifest(self.root, inv, records)
        result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
        self.assertIn('license-transitive-coverage', {gap['code'] for gap in result['gaps']}, result)


class FactoryArchiveCustodyTests(ArtifactFixture):
    def prepare(self, *, expression='MIT', filename='example-1.0.0-py3-none-any.whl'):
        dep = dependency(manifest='factory/uv.lock', distribution='redistributed', delivery_context=CONTEXT,
                         delivery_kind='factory-offline-archive',
                         artifact_filename=filename)
        payload = wheel(expression=expression, extra_files={
            'example-1.0.0.dist-info/licenses/NOTICE': NOTICE, 'example/__init__.py': b'VALUE=1\n'})
        dep['artifact_sha256'] = sha(payload)
        self.dep, self.inv = dep, inventory(dep)
        self.record = artifact(self.root, dep, payload, filename=filename)
        self.record['context'] = use_context(dep)
        repo = self.root / 'repo'
        source = repo / 'factory/src/getzilla_factory/__init__.py'
        source.parent.mkdir(parents=True)
        source.write_text("__version__='1.0.0'\n")
        filename = self.record['filename']
        lock = repo / 'factory/uv.lock'
        lock.write_text('version = 1\nrevision = 3\nrequires-python = ">=3.12,<3.13"\n'
                        '[[package]]\nname = "getzilla-factory"\nversion = "1.0.0"\n'
                        'dependencies = [{ name = "example" }]\n'
                        '[[package]]\nname = "example"\nversion = "1.0.0"\n'
                        f'wheels = [{{url="https://files.pythonhosted.org/packages/aa/{filename}", '
                        f'hash="sha256:{sha(payload)}"}}]\n')
        for args in (['init', '-q', '-b', 'fixture'], ['add', '.'],
                     ['-c', 'user.name=test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
        head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
        runtime = ROOT / 'factory/runtime'
        for name in ('setup_manager', 'build_offline_release'):
            if name not in sys.modules:
                spec = importlib.util.spec_from_file_location(name, runtime / f'{name}.py')
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
        builder = sys.modules['build_offline_release']
        wheelhouse = self.root / 'wheelhouse'
        wheelhouse.mkdir()
        (wheelhouse / filename).write_bytes(payload)
        wheel_inventory = self.root / 'wheel-inventory.json'
        wheel_inventory.write_text(json.dumps(builder.derive_inventory(lock)))
        result = builder.build_release(repository=repo, expected_head=head, wheelhouse=wheelhouse,
                                       inventory=wheel_inventory, output=self.root / 'release',
                                       product_version='1.0.0', enforce_host=False)
        self.delivery = {'context': CONTEXT, 'kind': 'factory-offline-archive', 'profile': PROFILE,
                         'path': 'release.zip', 'sha256': result['archive_sha256'],
                         'manifest_path': 'release.manifest.json', 'manifest_sha256': result['manifest_sha256'],
                         'sidecar_path': 'release.sha256',
                         'components': [{'artifact_id': component_id(self.record), 'prefix': 'site-packages/'}]}
        self.save()

    def save(self, *, records=None, deliveries=None):
        manifest(self.root, self.inv, records or [self.record])
        path = self.root / 'manifest.json'
        bundle = json.loads(path.read_bytes())
        bundle['deliveries'] = [self.delivery] if deliveries is None else deliveries
        path.write_text(json.dumps(bundle))

    def evaluate(self):
        return licenses.evaluate_artifacts(self.inv, self.root, POLICY, now=NOW)

    def rewrite_release(self, *, remove=None, change=None, add=None):
        path = self.root / 'release.zip'
        with zipfile.ZipFile(path) as archive:
            files = {member.filename: archive.read(member) for member in archive.infolist()}
        if remove:
            files.pop(remove)
        if change:
            files[change] += b'changed'
        files.update(add or {})
        with zipfile.ZipFile(path, 'w') as archive:
            for name, body in sorted(files.items()):
                archive.writestr(name, body)
        detached = json.loads((self.root / 'release.manifest.json').read_bytes())
        detached['files'] = [{'path': name, 'size': len(body), 'sha256': sha(body), 'mode': 420}
                             for name, body in sorted(files.items())]
        body = json.dumps(detached, sort_keys=True, separators=(',', ':')).encode()
        (self.root / 'release.manifest.json').write_bytes(body)
        self.delivery.update(sha256=sha(path.read_bytes()), manifest_sha256=sha(body))
        (self.root / 'release.sha256').write_text(
            f"{self.delivery['sha256']}  release.zip\n{self.delivery['manifest_sha256']}  release.manifest.json\n")
        self.save()

    def test_real_builder_output_binds_extracted_license_notice_and_detached_identity(self):
        self.prepare()
        result = self.evaluate()
        self.assertEqual(result['status'], 'pass', result)
        custody = result['details'][0]['delivery']
        self.assertEqual(custody['archive_sha256'], self.delivery['sha256'])
        self.assertEqual(custody['context'], CONTEXT)
        self.assertEqual(custody['retained_members'], [
            'site-packages/example-1.0.0.dist-info/licenses/LICENSE',
            'site-packages/example-1.0.0.dist-info/licenses/NOTICE'])
        before = licenses.artifact_catalog_source(self.inv, self.root, POLICY, now=NOW)
        self.assertTrue(before['content_sha256'])
        with (self.root / 'release.zip').open('ab') as output:
            output.write(b'changed')
        with self.assertRaises(licenses.ArtifactError):
            licenses.artifact_catalog_source(self.inv, self.root, POLICY, now=NOW)

    def test_wheel_cache_alone_cannot_qualify_named_archive_delivery(self):
        self.prepare()
        self.record['redistributed_path'] = self.record['path']
        self.save(deliveries=[])
        self.assertEqual(self.evaluate()['status'], 'fail')

    def test_real_native_profile_with_multiple_manylinux_tags_is_accepted(self):
        self.prepare(filename='example-1.0.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl')
        self.assertEqual(self.evaluate()['status'], 'pass', self.evaluate())

    def test_wrong_source_abi_fails_after_all_archive_identities_are_rebound(self):
        self.prepare()
        filename = 'example-1.0.0-cp313-cp313-manylinux_2_17_x86_64.whl'
        self.dep['artifact_filename'] = filename
        self.inv = inventory(self.dep)
        payload = (self.root / self.record['path']).read_bytes()
        self.record = artifact(self.root, self.dep, payload, filename=filename)
        self.record['context'] = use_context(self.dep)
        self.delivery['components'][0]['artifact_id'] = component_id(self.record)
        self.save()
        result = self.evaluate()
        self.assertIn('license-delivery-target', {gap['code'] for gap in result['gaps']}, result)

    def test_output_evidence_keeps_the_inclusive_72_hour_limit(self):
        self.prepare()
        result = licenses.evaluate_artifacts(self.inv, self.root, POLICY, now=NOW + timedelta(hours=72))
        self.assertEqual(result['status'], 'pass', result)
        result = licenses.evaluate_artifacts(self.inv, self.root, POLICY, now=NOW + timedelta(hours=72, seconds=1))
        self.assertIn('artifact-stale', {gap['code'] for gap in result['gaps']})

    def test_missing_or_altered_notices_fail_even_with_rebound_archive_checksums(self):
        for mutation in ('remove', 'change'):
            with self.subTest(mutation=mutation):
                # Each negative control has a fresh valid builder output.
                with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                    original = self.root
                    self.root = Path(temporary)
                    self.prepare()
                    self.rewrite_release(**{mutation: 'site-packages/example-1.0.0.dist-info/licenses/NOTICE'})
                    self.assertEqual(self.evaluate()['status'], 'fail')
                    self.root = original

    def test_absent_composition_wrong_digest_or_profile_and_detached_bytes_fail(self):
        self.prepare()
        original = copy.deepcopy(self.delivery)
        changes = [{'components': []}, {'sha256': '0' * 64}, {'profile': 'ubuntu-cpython313'},
                   {'manifest_sha256': '0' * 64}, {'components': [{'artifact_id': '0'*64, 'prefix':'site-packages/'}]}]
        for change in changes:
            with self.subTest(change=change):
                self.delivery = {**original, **change}
                self.save()
                self.assertEqual(self.evaluate()['status'], 'fail')
        self.delivery = original
        self.save()
        (self.root / 'release.sha256').write_text('0' * 64 + '  release.zip\n')
        self.assertEqual(self.evaluate()['status'], 'fail')

    def test_unlisted_archive_component_and_unsupported_license_fail(self):
        self.prepare()
        self.rewrite_release(add={'site-packages/foreign/LICENSE': b'unknown'})
        self.assertEqual(self.evaluate()['status'], 'fail')
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            self.root = Path(temporary)
            self.prepare(expression='MPL-2.0')
            result = self.evaluate()
            self.assertIn('license-policy-review', {gap['code'] for gap in result['gaps']})

    def test_mixed_use_cannot_downgrade_archive_scope_or_use_ci_record(self):
        self.prepare()
        ci = {**self.dep, 'manifest': 'trust-ci/requirements.txt', 'distribution': 'internal',
              'delivery_context': 'trust-ci', 'delivery_kind': 'installed-package'}
        ci_record = {**self.record, 'context': use_context(ci)}
        self.inv = inventory(self.dep, ci)
        self.save(records=[self.record, ci_record])
        self.assertEqual(self.evaluate()['status'], 'pass', self.evaluate())
        self.save(records=[ci_record])
        self.assertEqual(self.evaluate()['status'], 'fail')
        self.inv = inventory({**self.dep, 'distribution': 'internal'}, ci)
        self.save(records=[self.record, ci_record])
        self.assertEqual(self.evaluate()['status'], 'fail')
