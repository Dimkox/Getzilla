"""Fixed original-source payload bytes and delivery joins; no installation claim."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_CUSTODY = hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class FixedSourceDeliveryTests(unittest.TestCase):
    def test_exact_expected_members_match_actual_fixed_builder(self):
        from getzilla.security_source_delivery import fixed_delivery
        from getzilla.security_corresponding_source import CATALOG
        from tests.test_security_license_deliveries import factory_builder
        wheels = [{'name': name, 'version': row[0], 'filename': name + '-' + row[0] + '-py3-none-any.whl',
                   'sha256': row[3]} for name, row in CATALOG.items()]
        proof = fixed_delivery(ROOT, wheels)
        bodies = factory_builder()._legal_files(ROOT, wheels)
        bodies['legal/project/LICENSE'] = (ROOT / 'LICENSE').read_bytes()
        expected = [{'path': path, 'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'mode': 0o644}
                    for path, body in sorted(bodies.items())]
        self.assertEqual(proof['members'], expected)
        self.assertEqual({'certifi', 'psycopg'}, {p['name'] for p in proof['packages']})

    def test_actual_source_legal_member_join_and_tamper_controls(self):
        """Real source payloads; wheel tuples are metadata, not observed installations."""
        import copy
        from getzilla.security_source_delivery import fixed_delivery, verify_members
        from getzilla.security_corresponding_source import CATALOG
        from tests.test_security_license_deliveries import factory_builder
        wheels = [{'name': name, 'version': row[0], 'filename': name + '-' + row[0] + '-py3-none-any.whl',
                   'sha256': row[3]} for name, row in CATALOG.items()]
        proof = fixed_delivery(ROOT, wheels)
        bodies = factory_builder()._legal_files(ROOT, wheels)
        bodies['legal/project/LICENSE'] = (ROOT / 'LICENSE').read_bytes()
        members = {path: {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()} for path, body in bodies.items()}
        modes = {path: 0o644 for path in bodies}
        self.assertEqual(verify_members(proof, wheels, members, modes, modes, checker=ROOT), members)
        for path in bodies:
            for action in ('missing', 'bytes', 'mode', 'declared-mode'):
                actual, actual_modes, declared_modes = copy.deepcopy(members), dict(modes), dict(modes)
                with self.subTest(path=path, action=action):
                    if action == 'missing':
                        actual.pop(path)
                    elif action == 'bytes':
                        actual[path]['sha256'] = '0' * 64
                    elif action == 'mode':
                        actual_modes[path] = 0o755
                    else:
                        declared_modes[path] = 0o755
                    with self.assertRaises(ValueError):
                        verify_members(proof, wheels, actual, actual_modes, declared_modes, checker=ROOT)
        members['legal/undeclared.txt'] = {'size': 1, 'sha256': '0' * 64}
        with self.assertRaises(ValueError):
            verify_members(proof, wheels, members, modes, modes, checker=ROOT)

    def test_closed_proof_cannot_choose_wheels_members_or_surface(self):
        import copy
        from getzilla.security_source_delivery import fixed_delivery, validate_proof
        from getzilla.security_corresponding_source import CATALOG
        wheels = [{'name': name, 'version': row[0], 'filename': name + '-' + row[0] + '-py3-none-any.whl',
                   'sha256': row[3]} for name, row in CATALOG.items()]
        proof = fixed_delivery(ROOT, wheels)
        variants = [None, {}, {**proof, 'unknown': 'authority'}, {**proof, 'schema_version': True},
                    {**proof, 'source_surface_sha256': '0' * 64}, {**proof, 'members': []},
                    {**proof, 'packages': []}]
        for candidate in variants:
            with self.subTest(proof=candidate):
                with self.assertRaises(ValueError):
                    validate_proof(candidate, wheels, checker=ROOT)
        for key in ('name', 'version', 'filename', 'sha256'):
            changed = copy.deepcopy(wheels)
            changed[0][key] = 'wrong'
            with self.subTest(wheel_field=key):
                with self.assertRaises(ValueError):
                    validate_proof(proof, changed, checker=ROOT)
        with self.assertRaises(ValueError):
            validate_proof(proof, wheels[:1], checker=ROOT)
        self.assertIsNone(fixed_delivery(ROOT, [{'name': 'unrelated'}]))
        with self.assertRaises(ValueError):
            validate_proof(proof, [{'name': 'unrelated'}], checker=ROOT)

    def test_producer_rederives_source_admission_instead_of_accepting_caller_rows(self):
        from unittest.mock import patch
        from getzilla import security_source_delivery as delivery
        from getzilla import security_corresponding_source as source
        wheels = [{'name': 'certifi', 'version': source.CATALOG['certifi'][0],
                   'filename': 'certifi-2026.10.19-py3-none-any.whl', 'sha256': source.CATALOG['certifi'][3]}]
        with patch.object(source, 'classify', return_value=[]) as admission:
            with self.assertRaises(ValueError):
                delivery.admitted_delivery(ROOT, {'corresponding_sources': [{'package': 'certifi'}]}, wheels)
            admission.assert_called_once()
        with patch.object(source, 'classify', return_value=[{'package': 'psycopg'}]):
            with self.assertRaises(ValueError):
                delivery.admitted_delivery(ROOT, {'corresponding_sources': [{'package': 'certifi'}]}, wheels)
        with patch.object(source, 'classify', side_effect=ValueError('source changed')):
            with self.assertRaises(ValueError):
                delivery.admitted_delivery(ROOT, {}, wheels)


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class FactorySourceDeclarationTests(unittest.TestCase):
    """Real committed target metadata; these tests do not observe installed wheels."""
    @classmethod
    def setUpClass(cls):
        import json
        import tomllib
        from getzilla import security_factory_inputs as factory
        from getzilla.security_inventory import collect_inventory
        from getzilla.security_licenses import load_policy
        from getzilla.security_source_delivery import fixed_delivery
        cls.factory = factory
        cls.policy = load_policy(ROOT)
        from tests.test_security_corresponding_source import reviewed_fixture_surface
        with reviewed_fixture_surface(ROOT):
            cls.source_inventory = collect_inventory(ROOT)
        wheels = json.loads((ROOT / 'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json').read_text())['wheels']
        lock = tomllib.loads((ROOT / 'factory/uv.lock').read_text())
        dependencies = []
        for wheel in wheels:
            package = next(p for p in lock['package'] if p['name'] == wheel['name'] and p['version'] == wheel['version'])
            artifact = next(w for w in package['wheels'] if w['hash'] == 'sha256:' + wheel['sha256'])
            uses = [d for d in cls.source_inventory['dependencies'] if d['name'] == wheel['name']
                    and d['version'] == wheel['version'] and d['manifest'] == 'factory/uv.lock']
            dependencies.append({'ecosystem': 'PyPI', 'name': wheel['name'], 'version': wheel['version'],
                                 'manifest': 'factory/uv.lock', 'usage': 'runtime', 'extras': [],
                                 'artifact_filename': wheel['filename'], 'artifact_sha256': wheel['sha256'],
                                 'artifact_source': artifact['url'], 'distribution': 'redistributed',
                                 'delivery_kind': 'factory-offline-archive',
                                 'source_use_sha256': sorted(factory.digest(d) for d in uses)})
        cls.declared = {'schema_version': 1, 'profile': factory.PROFILE,
                        'policy_profile': cls.policy['factory_offline_profile'],
                        'inventory_sha256': cls.source_inventory['digest'], 'dependencies': dependencies,
                        'app_members_sha256': 'a' * 64, 'product_version': '0.1.0',
                        'corresponding_source_delivery': fixed_delivery(ROOT, wheels)}

    def test_closed_source_proof_survives_existing_declaration_and_output_digest(self):
        from getzilla.security_python_target import digest
        declared = self.factory.validate_declaration(self.declared)
        # Owned binding fixture selects no native or external authority.
        binding = {'source': {'owned_source': 'metadata-control'}, 'run': {'owned_run': 'metadata-control'}}
        result = self.factory.output_inventory(declared, binding)
        self.assertEqual(result['corresponding_source_delivery'], declared['corresponding_source_delivery'])
        self.assertEqual(result['digest'], digest({k: v for k, v in result.items() if k != 'digest'}))
        self.assertEqual(len(result['dependencies']), len(declared['dependencies']))
        self.assertEqual({p['name'] for p in result['corresponding_source_delivery']['packages']}, {'certifi', 'psycopg'})

    def test_missing_or_caller_changed_proof_refuses_before_output_inventory(self):
        import copy
        from getzilla.security_artifacts import ArtifactError
        for action in ('missing', 'empty-members', 'wrong-surface', 'extra-field', 'wrong-wheel'):
            value = copy.deepcopy(self.declared)
            with self.subTest(action=action):
                if action == 'missing':
                    value.pop('corresponding_source_delivery')
                elif action == 'empty-members':
                    value['corresponding_source_delivery']['members'] = []
                elif action == 'wrong-surface':
                    value['corresponding_source_delivery']['source_surface_sha256'] = '0' * 64
                elif action == 'extra-field':
                    value['corresponding_source_delivery']['permit'] = 'legal/anything'
                else:
                    next(d for d in value['dependencies'] if d['name'] == 'certifi')['artifact_sha256'] = '0' * 64
                with self.assertRaises(ArtifactError):
                    self.factory.validate_declaration(value)

    def test_producer_cannot_create_delivery_field_when_source_admission_refuses(self):
        import tempfile
        from unittest.mock import patch
        from getzilla.security_artifacts import ArtifactError
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as scratch:
            with patch('getzilla.security_source_delivery.admitted_delivery', side_effect=ValueError('role unverified')) as admission:
                with self.assertRaises(ArtifactError) as caught:
                    self.factory.declaration(ROOT, self.source_inventory, self.policy, scratch=Path(scratch))
                self.assertEqual(caught.exception.code, 'artifact-factory-source-delivery')
                admission.assert_called_once()


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class RetainedWheelDeliveryControl(unittest.TestCase):
    def test_actual_retained_wheels_and_source_legal_bytes_have_complete_custody(self):
        """Optional local byte control; no fresh acquisition or installation claim."""
        import copy
        import json
        import os
        import shutil
        import subprocess
        import tempfile
        from getzilla import security_factory_inputs as factory
        from getzilla.security_artifacts import MAX_ARTIFACT_BYTES, MAX_INDEX_BYTES, artifact_identity, read_file, verify_origin
        from getzilla.security_deliveries import verify_deliveries
        from getzilla.security_source_delivery import fixed_delivery
        from tests.test_security_license_deliveries import factory_builder
        selected = os.environ.get('GETZILLA_SOURCE_DELIVERY_ARTIFACTS')
        if not selected:
            self.skipTest('exact retained wheel/index cache was not selected; no artifact acquisition')
        cache = Path(selected)
        old_bundle = json.loads(read_file(cache, 'manifest.json', MAX_INDEX_BYTES))
        wheels = json.loads((ROOT / 'factory/runtime/runtime-wheels-linux-x86_64-cpython312.json').read_text())['wheels']
        runtime = ROOT / '.getzilla/runtime'
        with tempfile.TemporaryDirectory(prefix='source-delivery-custody-', dir=runtime) as directory:
            owned = Path(directory)
            owned.chmod(0o700)
            repo, artifacts, wheelhouse = owned / 'repo', owned / 'artifacts', owned / 'wheelhouse'
            for target in (repo, artifacts, wheelhouse):
                target.mkdir(mode=0o700)
            tracked_app = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z',
                                                   'factory/src/getzilla_factory']).decode().split('\0')
            for relative in filter(None, tracked_app):
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            shutil.copytree(ROOT / '.getzilla/config/license-exception-inputs/factory-source-delivery-v1',
                            repo / '.getzilla/config/license-exception-inputs/factory-source-delivery-v1')
            shutil.copy2(ROOT / 'factory/uv.lock', repo / 'factory/uv.lock')
            shutil.copy2(ROOT / 'LICENSE', repo / 'LICENSE')
            records, dependencies = [], []
            context = 'owned-real-retained-wheel-source-custody'
            for wheel in wheels:
                matches = [r for r in old_bundle['records'] if r['name'] == wheel['name']
                           and r['version'] == wheel['version'] and r['filename'] == wheel['filename']
                           and r['sha256'] == wheel['sha256']]
                self.assertEqual(len(matches), 1)
                record = copy.deepcopy(matches[0])
                raw = read_file(cache, record['path'], MAX_ARTIFACT_BYTES)
                self.assertEqual(hashlib.sha256(raw).hexdigest(), wheel['sha256'])
                verify_origin(cache, record, raw)
                dep = {'ecosystem': 'PyPI', 'name': wheel['name'], 'version': wheel['version'],
                       'manifest': 'factory/uv.lock', 'usage': 'runtime', 'extras': [],
                       'distribution': 'redistributed', 'delivery_kind': 'factory-offline-archive',
                       'delivery_context': context, 'artifact_filename': wheel['filename'],
                       'artifact_sha256': wheel['sha256']}
                factory.verify_wheel(dep, raw)
                record['context'] = {k: dep[k] for k in ('manifest', 'usage', 'distribution', 'delivery_context', 'delivery_kind')}
                index = read_file(cache, record['origin']['index_path'], MAX_INDEX_BYTES)
                for relative, body in ((record['path'], raw), (record['origin']['index_path'], index)):
                    target = artifacts / relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(body)
                    target.chmod(0o600)
                (wheelhouse / wheel['filename']).write_bytes(raw)
                records.append(record)
                dependencies.append(dep)
            for args in (['init', '-q'], ['add', '-f', '.'],
                         ['-c', 'user.name=Local byte control', '-c', 'user.email=control@example.invalid',
                          'commit', '-qm', 'Owned exact source and artifact control']):
                subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
            head = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
            builder = factory_builder()
            observed_target = builder._host_environment()
            self.assertIsNotNone(observed_target, 'retained-byte control needs the actual supported Factory build host')
            wheel_inventory = owned / 'wheel-inventory.json'
            wheel_inventory.write_text(json.dumps(builder.derive_inventory(repo / 'factory/uv.lock',
                                                        target_environment=observed_target)))
            built = builder.build_release(repository=repo, expected_head=head, wheelhouse=wheelhouse,
                                          inventory=wheel_inventory, output=artifacts / 'release',
                                          product_version='0.1.0', enforce_host=True,
                                          target_environment=observed_target)
            self.assertTrue(built['host_enforced'])
            self.assertEqual(built['target_environment'], observed_target)
            delivery = {'context': context, 'kind': 'factory-offline-archive', 'profile': factory.PROFILE,
                        'path': 'release.zip', 'sha256': built['archive_sha256'],
                        'manifest_path': 'release.manifest.json', 'manifest_sha256': built['manifest_sha256'],
                        'sidecar_path': 'release.sha256',
                        'components': [{'artifact_id': artifact_identity(r), 'prefix': 'site-packages/'} for r in records]}
            proof = fixed_delivery(ROOT, wheels)
            verified = verify_deliveries(artifacts, [delivery], records, dependencies,
                                        corresponding_source_delivery=proof)
            expected_ids = {artifact_identity(r) for r in records if r['name'] in {'certifi', 'psycopg'}}
            observed = verified[context]['corresponding_source_delivery']
            self.assertEqual(set(observed['components']), expected_ids)
            self.assertEqual(set(observed['members']), {m['path'] for m in proof['members']})
            # The final catalog projection has its own delivery-consumer callsite.
            # Use an explicit historical unit-test clock only to exercise that
            # path; current-clock rejection remains mandatory below.
            from datetime import datetime
            from getzilla import security_licenses as catalog
            from tests.test_security_licenses import POLICY
            catalog_inventory = {'complete': True, 'gaps': [], 'dependencies': dependencies, 'images': [], 'tools': [],
                                 'corresponding_source_delivery': proof, 'marker_environment': observed_target}
            catalog_inventory['digest'] = factory.digest(catalog_inventory)
            catalog_bundle = {**old_bundle, 'inventory_digest': catalog_inventory['digest'],
                              'records': records, 'deliveries': [delivery]}
            (artifacts / 'manifest.json').write_text(json.dumps(catalog_bundle))
            historical_clock = datetime.fromisoformat(old_bundle['last_verified_sync_utc'])
            projection = catalog.artifact_catalog_source(catalog_inventory, artifacts, POLICY, now=historical_clock)
            self.assertEqual(projection['acquisition']['last_verified_sync_utc'], old_bundle['last_verified_sync_utc'])
            self.assertEqual(projection['coverage']['record_count'], len(records))
            from getzilla.security_artifacts import ArtifactError
            for action in ('omit', 'rebind', 'free-bundle-field'):
                changed_inventory, changed_bundle = copy.deepcopy(catalog_inventory), copy.deepcopy(catalog_bundle)
                if action == 'rebind':
                    changed_inventory['corresponding_source_delivery']['members'][0]['sha256'] = '0' * 64
                else:
                    changed_inventory.pop('corresponding_source_delivery')
                    if action == 'free-bundle-field':
                        changed_bundle['corresponding_source_delivery'] = proof
                # Keep the old outer digest deliberately: the inner source-proof
                # join must refuse rather than silently trusting that digest.
                (artifacts / 'manifest.json').write_text(json.dumps(changed_bundle))
                with self.subTest(catalog_proof=action), self.assertRaises(ArtifactError) as refused:
                    catalog.artifact_catalog_source(changed_inventory, artifacts, POLICY, now=historical_clock)
                self.assertEqual(refused.exception.code, 'license-source-delivery')
            (artifacts / 'manifest.json').write_text(json.dumps(catalog_bundle))
            with self.assertRaises(ArtifactError) as current_clock:
                catalog.artifact_catalog_source(catalog_inventory, artifacts, POLICY)
            self.assertEqual(current_clock.exception.code, 'artifact-stale')
            alias_records = copy.deepcopy(records)
            for record in alias_records:
                if record['name'] in {'certifi', 'psycopg'}:
                    record['name'] = record['name'].upper()
            alias_delivery = {**delivery, 'components': [{'artifact_id': artifact_identity(r), 'prefix': 'site-packages/'}
                                                       for r in alias_records]}
            alias_result = verify_deliveries(artifacts, [alias_delivery], alias_records, dependencies,
                                            corresponding_source_delivery=proof)
            self.assertEqual(set(alias_result[context]['corresponding_source_delivery']['components']),
                             {artifact_identity(r) for r in alias_records if r['name'] in {'CERTIFI', 'PSYCOPG'}})
            with self.assertRaises(ArtifactError):
                verify_deliveries(artifacts, [alias_delivery], alias_records, dependencies)
            import io
            import stat
            import zipfile
            from getzilla.security_artifacts import ArtifactError
            from getzilla import security_licenses as licenses
            from tests.test_security_licenses import POLICY
            archive_path = artifacts / delivery['path']
            detached_path = artifacts / delivery['manifest_path']
            sidecar_path = artifacts / delivery['sidecar_path']
            original_archive, original_detached, original_sidecar = archive_path.read_bytes(), detached_path.read_bytes(), sidecar_path.read_bytes()
            original_delivery = copy.deepcopy(delivery)
            with zipfile.ZipFile(io.BytesIO(original_archive)) as archive:
                original_entries = [(copy.copy(info), archive.read(info)) for info in archive.infolist()]
            def rewrite(*, remove=None, change=None, mode=None, extra=None):
                output, declared = io.BytesIO(), []
                with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
                    entries = [(copy.copy(info), raw) for info, raw in original_entries]
                    if extra:
                        is_directory = extra == 'directory'
                        info = zipfile.ZipInfo('legal/undeclared/' if is_directory else 'legal/undeclared.txt')
                        info.create_system = 3
                        info.external_attr = ((stat.S_IFDIR | 0o755) if is_directory else (stat.S_IFREG | 0o644)) << 16
                        entries.append((info, b'' if is_directory else b'undeclared'))
                    for info, raw in entries:
                        if info.filename == remove:
                            continue
                        if info.filename == change:
                            raw += b'changed'
                        if info.filename == mode:
                            info.external_attr = (stat.S_IFREG | 0o755) << 16
                        archive.writestr(info, raw)
                        if not info.is_dir():
                            declared.append({'path': info.filename, 'size': len(raw),
                                             'sha256': hashlib.sha256(raw).hexdigest(),
                                             'mode': stat.S_IMODE(info.external_attr >> 16)})
                archive_path.write_bytes(output.getvalue())
                detached = json.loads(original_detached)
                detached['files'] = sorted(declared, key=lambda row: row['path'])
                detached_raw = json.dumps(detached, sort_keys=True, separators=(',', ':')).encode()
                detached_path.write_bytes(detached_raw)
                delivery['sha256'] = hashlib.sha256(output.getvalue()).hexdigest()
                delivery['manifest_sha256'] = hashlib.sha256(detached_raw).hexdigest()
                sidecar_path.write_text(delivery['sha256'] + '  release.zip\n' + delivery['manifest_sha256'] + '  release.manifest.json\n')
            controls = [{'remove': row['path']} for row in proof['members']]
            controls += [{'change': 'legal/source-map.json'}, {'change': 'legal/sources/certifi-2026.10.19.tar.gz'},
                         {'mode': 'legal/source-map.json'}, {'extra': True}, {'extra': 'directory'}]
            for control in controls:
                with self.subTest(rebound_archive=control):
                    rewrite(**control)
                    with self.assertRaises(ArtifactError):
                        verify_deliveries(artifacts, [delivery], records, dependencies, corresponding_source_delivery=proof)
            archive_path.write_bytes(original_archive)
            detached_path.write_bytes(original_detached)
            sidecar_path.write_bytes(original_sidecar)
            delivery.clear()
            delivery.update(original_delivery)
            with self.assertRaises(ArtifactError):
                verify_deliveries(artifacts, [delivery], records, dependencies)
            wrong = copy.deepcopy(delivery)
            wrong['components'][0]['artifact_id'] = wrong['components'][1]['artifact_id']
            with self.assertRaises(ArtifactError):
                verify_deliveries(artifacts, [wrong], records, dependencies, corresponding_source_delivery=proof)
            # Preserve the original historical freshness. A physical-custody
            # positive cannot turn these retained artifacts into fresh evidence.
            stale_inventory = {'complete': True, 'gaps': [], 'dependencies': dependencies, 'images': [], 'tools': [],
                               'corresponding_source_delivery': proof, 'marker_environment': observed_target}
            stale_inventory['digest'] = factory.digest(stale_inventory)
            stale_bundle = {**old_bundle, 'inventory_digest': stale_inventory['digest'], 'records': records,
                            'deliveries': [delivery]}
            (artifacts / 'manifest.json').write_text(json.dumps(stale_bundle))
            outcome = licenses.evaluate_artifacts(stale_inventory, artifacts, POLICY)
            self.assertEqual(outcome['status'], 'fail')
            self.assertIn('artifact-stale', {gap['code'] for gap in outcome['gaps']})
            self.assertEqual(old_bundle['last_verified_sync_utc'], json.loads(read_file(cache, 'manifest.json', MAX_INDEX_BYTES))['last_verified_sync_utc'])


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class FixedSourceInputTamperTests(unittest.TestCase):
    def test_original_inputs_cannot_change_expected_delivered_bodies(self):
        import shutil
        import tempfile
        from getzilla import security_corresponding_source as source
        from getzilla.security_source_delivery import fixed_delivery
        wheels = [{'name': name, 'version': row[0], 'filename': name + '-' + row[0] + '-py3-none-any.whl',
                   'sha256': row[3]} for name, row in source.CATALOG.items()]
        with tempfile.TemporaryDirectory(prefix='source-delivery-input-', dir=ROOT / '.getzilla/runtime') as directory:
            owned = Path(directory)
            owned.chmod(0o700)
            shutil.copytree(ROOT / source.LEGAL, owned / source.LEGAL)
            shutil.copy2(ROOT / 'LICENSE', owned / 'LICENSE')
            self.assertEqual(fixed_delivery(owned, wheels), fixed_delivery(ROOT, wheels))
            for relative in ('certifi-2026.10.19-source-map.json', 'psycopg-3.3.4-snapshot.json',
                             'certifi-2026.10.19-index.json', 'certifi-2026.10.19-notice.txt',
                             'MPL-2.0.txt', 'vendor/psycopg-3.3.4/pyproject.toml'):
                target = owned / source.LEGAL / relative
                original, mode = target.read_bytes(), target.stat().st_mode & 0o777
                for action in ('change', 'remove'):
                    with self.subTest(path=relative, action=action):
                        try:
                            if action == 'remove':
                                target.unlink()
                            else:
                                target.write_bytes(original + b'changed')
                            with self.assertRaises((OSError, ValueError)):
                                fixed_delivery(owned, wheels)
                        finally:
                            target.write_bytes(original)
                            target.chmod(mode)
            extra = owned / source.ROOTS[0] / 'unexpected-empty-directory'
            extra.mkdir()
            with self.assertRaises(ValueError):
                fixed_delivery(owned, wheels)


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class SourceSubjectIdentityTests(unittest.TestCase):
    def test_pypi_name_alias_cannot_remove_required_corresponding_source(self):
        from getzilla.security_corresponding_source import CATALOG
        from getzilla.security_source_delivery import fixed_delivery, validate_proof
        wheel = {'name': 'CERTIFI', 'version': CATALOG['certifi'][0],
                 'filename': 'certifi-2026.10.19-py3-none-any.whl', 'sha256': CATALOG['certifi'][3]}
        with self.assertRaises(ValueError):
            validate_proof(None, [wheel], checker=ROOT)
        canonical = {**wheel, 'name': 'certifi'}
        self.assertEqual(fixed_delivery(ROOT, [wheel]), fixed_delivery(ROOT, [canonical]))


class SourceAdapterSdkImportTests(unittest.TestCase):
    def test_fresh_lean_sdkzip_reads_actual_adapter_without_activating_classifier(self):
        import json
        import subprocess
        import sys
        import tempfile
        import zipfile
        package = ROOT / '.getzilla/getzilla'
        script = '''import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import getzilla.security_corresponding_source as source
assert 'getzilla.zip/getzilla/security_corresponding_source.py' in source.__file__.replace('\\\\','/')
body=source._trusted_adapter_bytes()
assert hashlib.sha256(body).hexdigest()==source.TRUSTED_ADAPTER_SHA256==sys.argv[2]
assert source.classify(Path(sys.argv[1]),[])==[]
assert 'getzilla.verification_policy_source' not in sys.modules
assert 'getzilla.live_evidence' not in sys.modules
assert 'getzilla.verification' not in sys.modules
assert 'getzilla.security_inventory' not in sys.modules
print(json.dumps({'sha256':source.TRUSTED_ADAPTER_SHA256,'loader':type(source.__loader__).__name__}))
'''
        observed = []
        with tempfile.TemporaryDirectory(prefix='source-sdkzip-', dir=ROOT / '.getzilla/runtime') as directory:
            for suffix in (b'', b'\n# owned source-byte mutation\n'):
                stack = Path(directory) / str(len(observed))
                (stack / 'getzilla').mkdir(parents=True)
                (stack / 'getzilla/__init__.py').write_bytes((package / '__init__.py').read_bytes())
                body = (package / 'security_corresponding_source.py').read_bytes() + suffix
                with zipfile.ZipFile(stack / 'getzilla.zip', 'w') as archive:
                    archive.writestr('getzilla/security_corresponding_source.py', body)
                    archive.writestr('getzilla/closed_loader_source.py', (package / 'closed_loader_source.py').read_bytes())
                completed = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script,
                                            str(stack), hashlib.sha256(body).hexdigest()],
                                           capture_output=True, text=True, timeout=15)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                observed.append(json.loads(completed.stdout))
        self.assertNotEqual(observed[0]['sha256'], observed[1]['sha256'])
        self.assertEqual({row['loader'] for row in observed}, {'zipimporter'})

    def test_trusted_body_reader_refuses_unknown_loader_or_source_identity(self):
        from unittest.mock import patch
        from getzilla import security_corresponding_source as source
        self.assertEqual(hashlib.sha256(source._trusted_adapter_bytes()).hexdigest(), source.TRUSTED_ADAPTER_SHA256)
        with patch.object(source, '__loader__', object()):
            with self.assertRaises(ValueError):
                source._trusted_adapter_bytes()
        with patch.object(source, '__file__', source.__file__ + '.different'):
            with self.assertRaises(ValueError):
                source._trusted_adapter_bytes()

    def test_source_policy_binds_closed_loader_helper_actual_body(self):
        from unittest.mock import patch
        from getzilla import verification_policy_source as policy
        from getzilla import closed_loader_source as helper
        self.assertIs(policy._module_source, helper.module_source)
        self.assertIs(policy.zipimport, helper.zipimport)
        before = policy.implementation_source_binding()
        self.assertIn('closed_loader_source.py', before)
        original = policy._module_source
        def changed(module):
            body = original(module)
            return body + b'\n# owned helper mutation\n' if module.__name__ == 'getzilla.closed_loader_source' else body
        with patch.object(policy, '_module_source', side_effect=changed):
            after = policy.implementation_source_binding()
        self.assertEqual(set(before), set(after))
        self.assertEqual({name for name in before if before[name] != after[name]}, {'closed_loader_source.py'})

    def test_source_policy_binds_each_new_actual_authority_owner(self):
        from unittest.mock import patch
        from getzilla import verification_policy_source as policy
        before = policy.implementation_source_binding()
        expected = {'security_corresponding_source.py', 'security_source_delivery.py', 'security_deliveries.py'}
        self.assertTrue(expected.issubset(before))
        original = policy._module_source
        def changed(module):
            body = original(module)
            return body + b'\n# owned policy-source mutation\n' if module.__name__ == 'getzilla.security_source_delivery' else body
        with patch.object(policy, '_module_source', side_effect=changed):
            after = policy.implementation_source_binding()
        self.assertEqual(set(before), set(after))
        self.assertEqual({name for name in before if before[name] != after[name]}, {'security_source_delivery.py'})


@unittest.skipUnless(SOURCE_CUSTODY, 'named Linux source delivery requires no-follow custody')
class SourceDeliveryBudgetTests(unittest.TestCase):
    def test_original_budget_includes_final_payload_serialization(self):
        from unittest.mock import patch
        from getzilla import security_source_delivery as delivery
        from getzilla import security_corresponding_source as source
        wheel = {'name': 'certifi', 'version': source.CATALOG['certifi'][0],
                 'filename': 'certifi-2026.10.19-py3-none-any.whl', 'sha256': source.CATALOG['certifi'][3]}
        elapsed = [0]
        original = delivery.json.dumps
        def late_serialization(*args, **kwargs):
            body = original(*args, **kwargs)
            elapsed[0] = source.MAX_SECONDS + 1
            return body
        with patch.object(delivery, 'monotonic', return_value=0), \
             patch.object(source, 'monotonic', side_effect=lambda: elapsed[0]), \
             patch.object(delivery.json, 'dumps', side_effect=late_serialization):
            with self.assertRaisesRegex(ValueError, 'original time budget'):
                delivery.fixed_delivery(ROOT, [wheel])


class QualifiedFactoryZipClosureTests(unittest.TestCase):
    def test_explicit_directories_cannot_disappear_from_legal_member_closure(self):
        import io
        import stat
        import zipfile
        from getzilla.security_deliveries import _legal_modes
        def payload(directory):
            result = io.BytesIO()
            with zipfile.ZipFile(result, 'w') as archive:
                info = zipfile.ZipInfo('legal/source-map.json')
                info.create_system, info.external_attr = 3, (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, b'{}')
                if directory:
                    info = zipfile.ZipInfo('legal/undeclared/')
                    info.create_system, info.external_attr = 3, (stat.S_IFDIR | 0o755) << 16
                    archive.writestr(info, b'')
            return result.getvalue()
        self.assertEqual(_legal_modes(payload(False)), {'legal/source-map.json': 0o644})
        with self.assertRaises(ValueError):
            _legal_modes(payload(True))
