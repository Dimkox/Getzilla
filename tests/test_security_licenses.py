from __future__ import annotations

import copy
import hashlib
import io
import json
import re
import base64
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_licenses as licenses  # noqa: E402

NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
POLICY = {'schema_version': 1, 'project_repository': 'github.com/Dimkox/Getzilla',
          'auto_allow': ['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', '0BSD'],
          'usage_distribution': {}}
LICENSES = json.loads((ROOT / 'tests/fixtures/security-license-texts.json').read_text())
LICENSE_TEXT = LICENSES['MIT']['text']


def inventory(*dependencies: dict, **extra) -> dict:
    result = {'dependencies': list(dependencies), 'tools': [], 'images': [], 'complete': True, 'gaps': [], **extra}
    result['digest'] = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    return result


def dependency(name='example', version='1.0.0', **extra) -> dict:
    return {'ecosystem': 'PyPI', 'name': name, 'version': version, 'manifest': 'requirements.txt',
            'usage': 'runtime', 'extras': [], 'distribution': 'internal', **extra}


def wheel(*, name='example', version='1.0.0', expression='MIT', requires=(), license_text=LICENSE_TEXT,
          headers='', extra_files=None, declared_license=True, metadata_version='2.4') -> bytes:
    metadata = f'Metadata-Version: {metadata_version}\nName: {name}\nVersion: {version}\n'
    if expression is not None:
        metadata += f'License-Expression: {expression}\n'
    if declared_license:
        metadata += 'License-File: LICENSE\n'
    metadata += ''.join(f'Requires-Dist: {item}\n' for item in requires) + headers + '\n'
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr(f'{name}-{version}.dist-info/METADATA', metadata)
        if license_text is not None:
            archive.writestr(f'{name}-{version}.dist-info/licenses/LICENSE', license_text)
        for path, contents in (extra_files or {}).items():
            archive.writestr(path, contents)
    return output.getvalue()


def tar_archive(files: dict[str, bytes | str], *, link=False) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, body in files.items():
            body = body.encode() if isinstance(body, str) else body
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
        if link:
            member = tarfile.TarInfo('package/link')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            archive.addfile(member)
    return output.getvalue()


def artifact(root: Path, dep: dict, payload: bytes, *, filename=None, index_license=None) -> dict:
    digest = hashlib.sha256(payload).hexdigest()
    filename = filename or f"{dep['name']}-{dep['version']}-py3-none-any.whl"
    url = f'https://files.pythonhosted.org/packages/aa/bb/{filename}'
    index = {'info': {'name': dep['name'], 'version': dep['version'], 'license_expression': index_license},
             'urls': [{'filename': filename, 'url': url, 'digests': {'sha256': digest},
                       'packagetype': 'bdist_wheel' if filename.endswith('.whl') else 'sdist', 'yanked': False}]}
    index_bytes = json.dumps(index).encode()
    index_digest = hashlib.sha256(index_bytes).hexdigest()
    for relative, content in ((f'objects/{digest}', payload), (f'indexes/{index_digest}.json', index_bytes)):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return {'ecosystem': dep['ecosystem'], 'name': dep['name'], 'version': dep['version'],
            'filename': filename, 'path': f'objects/{digest}', 'sha256': digest,
            'origin': {'index_url': f"https://pypi.org/pypi/{dep['name']}/{dep['version']}/json",
                       'index_path': f'indexes/{index_digest}.json', 'index_sha256': index_digest,
                       'artifact_url': url}}


def manifest(root: Path, inv: dict, records: list[dict], *, acquired=NOW) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / 'manifest.json').write_text(json.dumps({'schema_version': 1, 'inventory_digest': inv['digest'],
        'last_verified_sync_utc': acquired.isoformat(), 'records': records, 'gaps': []}))


class ArtifactLicenseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def evaluate(self, dep=None, payload=None, *, policy=None, acquired=NOW, inv=None, change=None) -> dict:
        dep = dep or dependency()
        inv = inv or inventory(dep)
        record = artifact(self.root, dep, payload if payload is not None else wheel())
        if change:
            change(record)
        manifest(self.root, inv, [record], acquired=acquired)
        return licenses.evaluate_artifacts(inv, self.root, POLICY if policy is None else policy, now=NOW)

    def test_exact_trust_ci_test_scope_does_not_classify_mixed_locks(self) -> None:
        policy = json.loads((ROOT / '.getzilla/config/license-policy.json').read_text(encoding='utf-8'))
        for path, usage, expected in (
            ('trust-ci/requirements-test.txt', 'runtime-and-development', 'pass'),
            ('trust-ci/requirements.txt', 'runtime-and-development', 'fail'),
            ('factory/uv.lock', 'runtime-and-development', 'fail'),
            ('factory/uv.lock', 'manifest:trust-ci/requirements-test.txt#runtime-and-development', 'fail'),
            ('trust-ci/requirements-test.txt', 'other', 'fail'),
            ('.getzilla/config/python-test-requirements.txt', 'build-ci', 'pass'),
        ):
            with self.subTest(path=path, usage=usage):
                dep = dependency(manifest=path, usage=usage)
                del dep['distribution']
                result = self.evaluate(dep=dep, policy=policy)
                self.assertEqual(result['status'], expected, result)
                if expected == 'pass':
                    self.assertEqual(result['details'][0]['distribution'], 'internal')
                else:
                    self.assertIn('license-scope-unknown', {item['code'] for item in result['gaps']})

    def test_exact_redistributed_scope_requires_delivery_and_rejects_downgrade(self) -> None:
        policy = {**POLICY, 'usage_distribution': {'runtime': 'internal',
                  'manifest:fixture/requirements.txt#runtime': 'redistributed'}}
        dep = dependency(manifest='fixture/requirements.txt')
        conflict = self.evaluate(dep=dep, policy=policy)
        self.assertIn('license-scope-conflict', {item['code'] for item in conflict['gaps']})
        del dep['distribution']
        missing = self.evaluate(dep=dep, policy=policy)
        self.assertIn('license-obligation-missing', {item['code'] for item in missing['gaps']})

    def test_ci_scope_is_not_approval_for_a_non_allowed_license(self) -> None:
        policy = json.loads((ROOT / '.getzilla/config/license-policy.json').read_text(encoding='utf-8'))
        dep = dependency(manifest='trust-ci/requirements-test.txt', usage='runtime-and-development')
        del dep['distribution']
        result = self.evaluate(dep=dep, policy=policy, payload=wheel(expression='MPL-2.0'))
        self.assertEqual(result['status'], 'fail')
        self.assertIn('license-policy-review', {gap['code'] for gap in result['gaps']})

    def test_known_license_with_exact_artifact_and_scope_has_local_integrity_pass(self) -> None:
        result = self.evaluate()
        self.assertEqual(result['status'], 'pass', result)
        self.assertEqual(result['assurance'], 'artifact-integrity-only')
        self.assertEqual(result['details'][0]['selected_expression'], 'MIT')
        self.assertTrue(result['details'][0]['license_files'][0]['sha256'])

    def test_allowed_label_without_license_file_is_not_an_obligation_pass(self) -> None:
        result = self.evaluate(payload=wheel(license_text=None))
        self.assertEqual(result['status'], 'fail')
        self.assertIn('license-obligation-missing', {item['code'] for item in result['gaps']})

    def test_expression_all_choice_and_unknown_cases(self) -> None:
        cases = [('MIT AND Apache-2.0', 'pass', 'MIT AND Apache-2.0'),
                 ('GPL-3.0-only OR MIT', 'pass', 'MIT'),
                 ('MIT AND GPL-3.0-only', 'fail', None),
                 ('MIT OR Apache-2.0', 'pass', 'MIT'),
                 ('MIT WITH Custom-exception', 'fail', None),
                 ('LicenseRef-special OR MIT', 'fail', None),
                 ('licenseref-special OR MIT', 'fail', None),
                 ('Unrecognized-Custom-License OR MIT', 'fail', None),
                 ('(MIT OR Apache-2.0) AND BSD-2-Clause', 'pass', 'MIT AND BSD-2-Clause'),
                 ('MIT OR', 'fail', None)]
        for expression, status, selected in cases:
            extra_files = {f'example-1.0.0.dist-info/licenses/LICENSE.{name}': value['text']
                           for name, value in LICENSES.items() if name != 'MIT' and name in expression}
            with self.subTest(expression=expression):
                result = self.evaluate(payload=wheel(expression=expression, extra_files=extra_files))
                self.assertEqual(result['status'], status, result)
                if selected:
                    self.assertEqual(result['details'][0]['selected_expression'], selected)

    def test_missing_distribution_is_human_scope_gap_even_for_build_dependency(self) -> None:
        dep = dependency(usage='build')
        del dep['distribution']
        result = self.evaluate(dep=dep)
        self.assertEqual(result['status'], 'fail')
        self.assertIn('license-scope-unknown', {item['code'] for item in result['gaps']})
        result = self.evaluate(dep=dep, payload=wheel(expression='LicenseRef-unknown'))
        self.assertTrue({'license-scope-unknown', 'license-policy-review'} <= {item['code'] for item in result['gaps']})

    def test_conflicting_metadata_or_license_file_never_uses_project_license(self) -> None:
        for payload in (wheel(headers='License: GPL-3.0-only\n'),
                        wheel(license_text='SPDX-License-Identifier: GPL-3.0-only\n'),
                        wheel(expression=None)):
            with self.subTest(payload=payload[:30]):
                result = self.evaluate(payload=payload)
                self.assertEqual(result['status'], 'fail')
                self.assertTrue({'license-conflict', 'license-unknown'} & {item['code'] for item in result['gaps']})

    def test_registry_page_license_cannot_override_the_selected_artifact(self) -> None:
        dep = dependency()
        inv = inventory(dep)
        record = artifact(self.root, dep, wheel(expression='GPL-3.0-only'), index_license='MIT')
        manifest(self.root, inv, [record])
        result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
        self.assertEqual(result['status'], 'fail')

    def test_name_version_hash_and_inventory_binding_are_required(self) -> None:
        cases = [(wheel(name='other'), None), (wheel(version='2.0.0'), None),
                 (wheel(), lambda record: record.update(sha256='0' * 64)),
                 (wheel(), lambda record: record['origin'].update(index_sha256='0' * 64)),
                 (wheel(), lambda record: record['origin'].update(artifact_url='https://evil.invalid/x'))]
        for payload, change in cases:
            with self.subTest(change=change):
                self.assertEqual(self.evaluate(payload=payload, change=change)['status'], 'fail')
        dep = dependency()
        inv = inventory(dep)
        record = artifact(self.root, dep, wheel())
        manifest(self.root, {**inv, 'digest': '0' * 64}, [record])
        self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'fail')

    def test_snapshot_age_boundary_and_future_clock(self) -> None:
        self.assertEqual(self.evaluate(acquired=NOW - timedelta(hours=72))['status'], 'pass')
        for acquired in (NOW - timedelta(seconds=259201), NOW + timedelta(seconds=1), NOW.replace(tzinfo=None)):
            with self.subTest(acquired=acquired):
                self.assertEqual(self.evaluate(acquired=acquired)['status'], 'fail')

    def test_arbitrary_paths_and_symlink_records_are_refused(self) -> None:
        for path in ('../escape', '/etc/passwd', 'objects/../escape', 'C:\\outside'):
            with self.subTest(path=path):
                self.assertEqual(self.evaluate(change=lambda record: record.update(path=path))['status'], 'fail')
        dep = dependency()
        inv = inventory(dep)
        record = artifact(self.root, dep, wheel())
        target = self.root / record['path']
        elsewhere = self.root / 'elsewhere.whl'
        target.rename(elsewhere)
        target.symlink_to(elsewhere)
        manifest(self.root, inv, [record])
        self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'fail')

    def test_archive_traversal_and_links_are_refused_without_extraction(self) -> None:
        payloads = [wheel(extra_files={'../outside': b'bad'})]
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            info = zipfile.ZipInfo('link')
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, 'outside')
        payloads.append(output.getvalue())
        for payload in payloads:
            with self.subTest(payload=payload[:16]):
                self.assertEqual(self.evaluate(payload=payload)['status'], 'fail')
        self.assertFalse((self.root.parent / 'outside').exists())

    def test_transitive_dependency_requires_exact_covered_version(self) -> None:
        result = self.evaluate(payload=wheel(requires=['missing>=2']))
        self.assertEqual(result['status'], 'fail')
        self.assertIn('license-transitive-coverage', {item['code'] for item in result['gaps']})
        deps = [dependency(), dependency('child', '2.0.0')]
        inv = inventory(*deps)
        records = [artifact(self.root, deps[0], wheel(requires=['child>=2,<3'])),
                   artifact(self.root, deps[1], wheel(name='child', version='2.0.0'))]
        manifest(self.root, inv, records)
        self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'pass')

    def test_unresolved_markers_and_nonpackage_inventory_remain_gaps(self) -> None:
        result = self.evaluate(payload=wheel(requires=['child; python_version < "3.12"']))
        self.assertEqual(result['status'], 'fail')
        inv = inventory(dependency(), tools=[{'kind': 'github-action', 'reference': 'owner/action@sha'}],
                        images=[{'reference': 'postgres@sha256:' + '1' * 64}])
        result = self.evaluate(inv=inv)
        self.assertEqual(result['status'], 'fail')
        self.assertTrue({'license-tool-coverage', 'license-image-coverage'} <= {item['code'] for item in result['gaps']})

    def test_redistribution_requires_exact_unchanged_deliverable_and_notice(self) -> None:
        dep = dependency(distribution='redistributed')
        payload = wheel(expression='Apache-2.0', license_text=LICENSES['Apache-2.0']['text'],
                        extra_files={'example-1.0.0.dist-info/licenses/NOTICE': 'Publisher attribution'})
        self.assertEqual(self.evaluate(dep=dep, payload=payload)['status'], 'fail')

        def delivered(record):
            target = self.root / 'distribution' / record['filename']
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(payload)
            record['redistributed_path'] = target.relative_to(self.root).as_posix()

        result = self.evaluate(dep=dep, payload=payload, change=delivered)
        self.assertEqual(result['status'], 'pass', result)
        self.assertTrue(result['details'][0]['notice_files'])

    def test_no_policy_or_incomplete_inventory_never_passes_applicable_dependencies(self) -> None:
        self.assertEqual(self.evaluate(policy={})['status'], 'fail')
        self.assertEqual(self.evaluate(inv=inventory(dependency(), complete=False, gaps=['unresolved']))['status'], 'fail')
        self.assertEqual(licenses.evaluate_artifacts(inventory(), self.root, {}, now=NOW)['status'], 'skip')

    def test_evaluator_cannot_contact_network_or_execute_artifact_code(self) -> None:
        payload = wheel(extra_files={'setup.py': 'raise RuntimeError("must never execute")'})
        with mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                mock.patch('subprocess.run', side_effect=AssertionError('artifact execution forbidden')):
            self.assertEqual(self.evaluate(payload=payload)['status'], 'pass')

    def test_sdist_declared_license_file_is_read_even_when_named_copyright(self) -> None:
        dep = dependency(artifact_filename='example-1.0.0.tar.gz')
        inv = inventory(dep)
        payload = tar_archive({'example-1.0.0/PKG-INFO': 'Metadata-Version: 2.4\nName: example\nVersion: 1.0.0\nLicense-Expression: MIT\nLicense-File: legal/TERMS\n\n',
                               'example-1.0.0/legal/TERMS': LICENSE_TEXT})
        record = artifact(self.root, dep, payload, filename=dep['artifact_filename'])
        manifest(self.root, inv, [record])
        result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
        self.assertEqual(result['status'], 'pass', result)
        self.assertEqual(result['details'][0]['license_files'][0]['path'], 'example-1.0.0/legal/TERMS')

    def test_npm_tarball_has_registry_integrity_and_explicit_artifact_license(self) -> None:
        dep = dependency(name='example', version='1.0.0', ecosystem='npm')
        inv = inventory(dep)
        for link, expected in ((False, 'pass'), (True, 'fail')):
            payload = tar_archive({'package/package.json': json.dumps({'name': 'example', 'version': '1.0.0', 'license': 'MIT'}),
                                   'package/LICENSE': LICENSE_TEXT}, link=link)
            digest = hashlib.sha256(payload).hexdigest()
            artifact_path = self.root / 'objects' / digest
            artifact_path.parent.mkdir(exist_ok=True)
            artifact_path.write_bytes(payload)
            index = {'name': 'example', 'version': '1.0.0', 'dist': {'tarball': 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
                     'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(payload).digest()).decode()}}
            raw = json.dumps(index).encode()
            index_digest = hashlib.sha256(raw).hexdigest()
            index_path = self.root / 'indexes' / (index_digest + '.json')
            index_path.parent.mkdir(exist_ok=True)
            index_path.write_bytes(raw)
            record = {'ecosystem': 'npm', 'name': 'example', 'version': '1.0.0', 'filename': 'example-1.0.0.tgz',
                      'path': f'objects/{digest}', 'sha256': digest, 'origin': {'index_url': 'https://registry.npmjs.org/example/1.0.0',
                      'index_path': f'indexes/{index_digest}.json', 'index_sha256': index_digest, 'artifact_url': index['dist']['tarball']}}
            manifest(self.root, inv, [record])
            self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], expected)

    def test_archive_budget_covers_stream_overhead_and_unselected_member_crc(self) -> None:
        from getzilla.security_artifacts import ArtifactError, archive_files
        payload = tar_archive({'package/LICENSE': LICENSE_TEXT})
        with mock.patch('getzilla.security_artifacts.MAX_ARCHIVE_BYTES', 1024):
            with self.assertRaises(ArtifactError):
                archive_files(payload, 'example.tgz')
        payload = wheel(extra_files={'example.py': b'unselected-member-bytes'})
        corrupted = payload.replace(b'unselected-member-bytes', b'unselected-member-bytEs', 1)
        self.assertEqual(self.evaluate(payload=corrupted)['status'], 'fail')

    def test_corrupt_deflate_stream_returns_structured_gap(self) -> None:
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(wheel())) as source, zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as target:
            for name in source.namelist():
                target.writestr(name, source.read(name))
        payload = bytearray(output.getvalue())
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            member = archive.infolist()[0]
            offset = member.header_offset + 30 + len(member.filename.encode()) + len(member.extra)
        payload[offset] = 0x07  # Invalid DEFLATE block type, while central directory stays parseable.
        result = self.evaluate(payload=bytes(payload))
        self.assertEqual(result['status'], 'fail')
        self.assertIn('artifact-archive', {item['code'] for item in result['gaps']})

    def test_malformed_registry_field_returns_gap_and_never_throws(self) -> None:
        dep = dependency()
        inv = inventory(dep)
        record = artifact(self.root, dep, wheel())
        path = self.root / record['origin']['index_path']
        index = json.loads(path.read_bytes())
        index['urls'][0]['digests'] = []
        raw = json.dumps(index).encode()
        path.write_bytes(raw)
        record['origin']['index_sha256'] = hashlib.sha256(raw).hexdigest()
        manifest(self.root, inv, [record])
        self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'fail')

    def test_dynamic_license_or_conflicting_classifier_requires_review(self) -> None:
        for headers in ('Dynamic: License-Expression\n', 'Classifier: License :: OSI Approved :: GNU General Public License v3 (GPLv3)\n'):
            with self.subTest(headers=headers):
                self.assertEqual(self.evaluate(payload=wheel(headers=headers))['status'], 'fail')

    def test_observed_marker_environment_is_used_instead_of_runtime(self) -> None:
        dep = dependency()
        payload = wheel(requires=['child; python_version < "3.12"'])
        self.assertEqual(self.evaluate(payload=payload, inv=inventory(dep, marker_environment={'python_version': '3.13'}))['status'], 'pass')
        self.assertEqual(self.evaluate(payload=payload, inv=inventory(dep, marker_environment={'python_version': '3.11'}))['status'], 'fail')
        self.assertEqual(self.evaluate(payload=payload, inv=inventory(dep, marker_environment=[]))['status'], 'fail')

    def test_pep685_extra_comparisons_activate_the_same_missing_child(self) -> None:
        equivalent = ('speed-up', 'speed_up', 'SPEED-UP', 'speed.up', 'Speed__..---UP')
        for selected in equivalent:
            for expected in equivalent:
                for operator, status in (('==', 'fail'), ('!=', 'pass')):
                    with self.subTest(selected=selected, expected=expected, operator=operator):
                        dep = dependency(extras=[selected])
                        payload = wheel(headers='Provides-Extra: speed-up\n',
                                        requires=[f'missing-child>=1; extra {operator} "{expected}"'])
                        result = self.evaluate(dep=dep, payload=payload)
                        self.assertEqual(result['status'], status, result)
                        if status == 'fail':
                            self.assertIn('license-transitive-coverage', {item['code'] for item in result['gaps']})
        for operator, status in (('==', 'pass'), ('!=', 'fail')):
            payload = wheel(headers='Provides-Extra: genuinely-different\n',
                            requires=[f'missing-child>=1; extra {operator} "speed-up"'])
            self.assertEqual(self.evaluate(dep=dependency(extras=['genuinely-different']), payload=payload)['status'], status)

    def test_selected_extras_must_be_declared_before_policy(self) -> None:
        headers = 'Provides-Extra: public-known\nProvides-Extra: public-other\n'
        payload = wheel(headers=headers, requires=['missing-child==1; extra == "public-known"'])
        for extras, expected in ((['public-known'], 'fail'), (['PUBLIC__OTHER'], 'pass'),
                                 (['public-unknown'], 'fail'), ([], 'pass')):
            with self.subTest(extras=extras):
                result = self.evaluate(dep=dependency(extras=extras), payload=payload)
                self.assertEqual(result['status'], expected, result)
                if extras == ['public-unknown']:
                    self.assertIn('license-transitive-coverage', {g['code'] for g in result['gaps']})
                    self.assertEqual(result['details'], [])
        for headers in ('', 'Provides-Extra: public-other\n'):
            with self.subTest(headers=headers), mock.patch.object(licenses, '_select_expression', wraps=licenses._select_expression) as policy:
                result = self.evaluate(dep=dependency(extras=['public-unknown']), payload=wheel(headers=headers))
                self.assertEqual(result['status'], 'fail', result)
                policy.assert_not_called()
        self.assertEqual(self.evaluate(payload=wheel())['status'], 'pass')

    def test_declared_extras_follow_metadata_version_and_reject_collisions(self) -> None:
        for version in ('2.1', '2.2', '2.3', '2.4', '2.5', '2.6'):
            for declared in ('speed-up', 'SPEED_UP', 'speed.up', 'speed--up'):
                with self.subTest(version=version, declared=declared):
                    payload = wheel(metadata_version=version, headers=f'Provides-Extra: {declared}\n')
                    result = self.evaluate(dep=dependency(extras=['SPEED__UP']), payload=payload)
                    expected = 'pass' if version in {'2.1', '2.2'} or declared == 'speed-up' else 'fail'
                    self.assertEqual(result['status'], expected, result)
        for version, headers in (
            ('2.2', 'Provides-Extra: speed-up\nProvides-Extra: SPEED_UP\n'),
            ('2.4', 'Provides-Extra: speed-up\nProvides-Extra: speed-up\n'),
            ('1.2', 'Provides-Extra: speed-up\n'),
            ('2.4', 'Provides-Extra: \n'),
            ('2.2', 'Provides-Extra: speed/up\n'),
            ('2.4', 'Provides-Extra: speed-up\n continuation\n'),
        ):
            with self.subTest(version=version, headers=headers):
                result = self.evaluate(dep=dependency(extras=['speed-up']),
                                       payload=wheel(metadata_version=version, headers=headers))
                self.assertEqual(result['status'], 'fail', result)

    def test_metadata_retains_and_bounds_raw_extra_declarations(self) -> None:
        from getzilla.security_artifacts import ArtifactError, archive_files, package_metadata
        filename = 'example-1.0.0-py3-none-any.whl'
        headers = 'Provides-Extra: Speed_Up\nProvides-Extra: public-other\n'
        metadata = package_metadata(archive_files(wheel(metadata_version='2.2', headers=headers), filename), 'PyPI', filename)
        self.assertEqual(metadata['provides_extra'], ['Speed_Up', 'public-other'])
        self.assertEqual(metadata['metadata_version'], '2.2')
        for headers, count in ((''.join(f'Provides-Extra: x{i}\n' for i in range(256)), 256),
                               ('Provides-Extra: ' + 'x' * 512 + '\n', 1)):
            bounded = package_metadata(archive_files(wheel(headers=headers), filename), 'PyPI', filename)
            self.assertEqual(len(bounded['provides_extra']), count)
        for headers in ('Provides-Extra: x\n' * 257, 'Provides-Extra: ' + 'x' * 513 + '\n'):
            with self.subTest(length=len(headers)), self.assertRaises(ArtifactError):
                package_metadata(archive_files(wheel(headers=headers), filename), 'PyPI', filename)

    def test_pep685_transitive_extras_are_normalized_and_still_require_child_artifacts(self) -> None:
        for required, observed in (('speed_up', 'SPEED-UP'), ('SPEED.UP', 'speed-up'), ('Speed__..--UP', 'speed.up')):
            for has_grandchild in (False, True):
                with self.subTest(required=required, observed=observed, has_grandchild=has_grandchild):
                    deps = [dependency(), dependency('child', extras=[observed])]
                    records = [artifact(self.root, deps[0], wheel(requires=[f'child[{required}]>=1'])),
                               artifact(self.root, deps[1], wheel(name='child', headers='Provides-Extra: speed-up\n',
                                   requires=['grandchild>=1; extra == "speed-up"']))]
                    if has_grandchild:
                        deps.append(dependency('grandchild'))
                        records.append(artifact(self.root, deps[-1], wheel(name='grandchild')))
                    inv = inventory(*deps)
                    manifest(self.root, inv, records)
                    result = licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)
                    self.assertEqual(result['status'], 'pass' if has_grandchild else 'fail', result)
        deps = [dependency(), dependency('child', extras=['different'])]
        inv = inventory(*deps)
        manifest(self.root, inv, [artifact(self.root, deps[0], wheel(requires=['child[speed-up]>=1'])),
                                  artifact(self.root, deps[1], wheel(name='child'))])
        self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'fail')

    def test_malformed_extra_names_are_not_ignored_even_without_markers(self) -> None:
        for extras in (None, 'speed-up', [''], [' speed-up'], ['speed/up'], ['-speed'], ['speed.'], ['spéed'], [True]):
            with self.subTest(extras=extras):
                self.assertEqual(self.evaluate(dep=dependency(extras=extras))['status'], 'fail')
        for marker in ('invalid/name', ' speed-up', 'speed-', 'spéed'):
            with self.subTest(marker=marker):
                self.assertEqual(self.evaluate(payload=wheel(requires=[f'child; extra == "{marker}"']))['status'], 'fail')
        for required in ('-speed', 'speed.', 'speed,,up'):
            deps = [dependency(), dependency('child', extras=[required])]
            inv = inventory(*deps)
            manifest(self.root, inv, [artifact(self.root, deps[0], wheel(requires=[f'child[{required}]'])),
                                      artifact(self.root, deps[1], wheel(name='child'))])
            with self.subTest(required=required):
                self.assertEqual(licenses.evaluate_artifacts(inv, self.root, POLICY, now=NOW)['status'], 'fail')

    def test_all_six_allowed_licenses_need_recognized_complete_text(self) -> None:
        for identifier, fixture in LICENSES.items():
            with self.subTest(identifier=identifier):
                result = self.evaluate(payload=wheel(expression=identifier, license_text=fixture['text']))
                self.assertEqual(result['status'], 'pass', result)
                self.assertEqual(result['details'][0]['selected_expression'], identifier)

    def test_spdx_label_partial_or_additional_terms_are_human_gaps(self) -> None:
        cases = ['SPDX-License-Identifier: MIT\n', LICENSE_TEXT[:250],
                 LICENSE_TEXT + '\nRedistribution is prohibited.\n',
                 re.sub(r'The above copyright.*?Software\.\s*', '', LICENSE_TEXT, flags=re.DOTALL)]
        for text in cases:
            with self.subTest(text=text[:50]):
                self.assertNotEqual(text, LICENSE_TEXT)
                self.assertEqual(self.evaluate(payload=wheel(license_text=text))['status'], 'fail')

    def test_standard_bsd_bullets_and_retained_copyright_markdown_are_recognized(self) -> None:
        text = LICENSES['BSD-3-Clause']['text'].replace('Copyright (c) 2026 Test Publisher.',
            'Copyright © 2019, [Test Publisher](https://example.invalid/).\nAll rights reserved.')
        text = re.sub(r'(?m)^[123]\. ', '* ', text)
        result = self.evaluate(payload=wheel(expression='BSD-3-Clause', license_text=text))
        self.assertEqual(result['status'], 'pass', result)

    def test_project_license_full_text_is_a_fixture_only_not_dependency_fallback(self) -> None:
        self.assertEqual(self.evaluate(payload=wheel(license_text=(ROOT / 'LICENSE').read_text()))['status'], 'pass')
        self.assertEqual(self.evaluate(payload=wheel(license_text=None))['status'], 'fail')


class PolicyTests(unittest.TestCase):
    def test_nonstandard_project_origin_is_not_silently_equated_with_github(self) -> None:
        for url in ('https://github.com:8443/Dimkox/Getzilla.git', 'https://github.com/Dimkox/Getzilla.git?source=other'):
            with self.subTest(url=url):
                self.assertIsNone(licenses._repository_identity(url))

    def test_copied_getzilla_policy_does_not_apply_to_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'https://github.com/customer/app.git'], check=True)
            target = root / '.getzilla/config/license-policy.json'
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / '.getzilla/config/license-policy.json').read_bytes())
            result = licenses.load_policy(root)
            self.assertIn('project', result.get('error', ''))

    def test_consumer_can_select_its_own_explicit_policy_with_canonical_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin', 'git@github.com:customer/app.git'], check=True)
            target = root / '.getzilla/config/license-policy.json'
            target.parent.mkdir(parents=True)
            policy = copy.deepcopy(POLICY)
            policy['project_repository'] = 'github.com/customer/app'
            target.write_text(json.dumps(policy))
            first = licenses.load_policy(root)
            self.assertRegex(first['digest'], r'^[0-9a-f]{64}$')
            target.write_text(json.dumps(dict(reversed(list(policy.items()))), indent=2))
            self.assertEqual(licenses.load_policy(root)['digest'], first['digest'])


class CatalogEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.dep = dependency()
        self.inv = inventory(self.dep)
        self.record = artifact(self.root, self.dep, wheel())
        manifest(self.root, self.inv, [self.record])

    def source(self, **options):
        return licenses.artifact_catalog_source(self.inv, self.root, POLICY, now=options.get('now', NOW))

    def test_descriptor_binds_original_clock_and_actual_bytes_without_requiring_policy_pass(self):
        del self.dep['distribution']
        self.inv = inventory(self.dep)
        self.record = artifact(self.root, self.dep, wheel(expression='LicenseRef-unknown'))
        manifest(self.root, self.inv, [self.record])
        self.assertEqual(licenses.evaluate_artifacts(self.inv, self.root, POLICY, now=NOW)['status'], 'fail')
        first = self.source()
        self.assertEqual(first['source_id'], 'artifact-license-catalog')
        self.assertEqual(first['source_url'], 'urn:getzilla:artifact-license-catalog:1')
        self.assertEqual(first['database'], str(self.root.absolute()))
        self.assertEqual(first['coverage'], {'schema': 'artifact-license-catalog-1', 'scopes': ['catalog'],
                                              'record_count': 1, 'complete': True})
        self.assertEqual(first['acquisition']['last_verified_sync_utc'], NOW.isoformat())
        self.assertEqual(self.source(now=NOW + timedelta(hours=1)), first)
        self.assertGreater(first['payload_size'], len((self.root / self.record['path']).read_bytes()))

    def test_replaced_artifact_or_index_and_missing_manifest_are_unavailable(self):
        from getzilla.security_artifacts import ArtifactError
        for relative in (self.record['path'], self.record['origin']['index_path'], 'manifest.json'):
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b' changed')
            with self.subTest(relative=relative), self.assertRaises((ArtifactError, ValueError)):
                self.source()
            path.write_bytes(original)
        (self.root / 'manifest.json').unlink()
        with self.assertRaises(ArtifactError):
            self.source()

    def test_coherent_replacement_or_policy_or_inventory_edit_changes_frozen_binding(self):
        first = self.source()
        updated_policy = {**POLICY, 'auto_allow': ['MIT']}
        self.assertNotEqual(licenses.artifact_catalog_source(self.inv, self.root, updated_policy, now=NOW)['content_sha256'], first['content_sha256'])
        self.inv['dependencies'][0]['usage'] = 'different-observed-use'
        self.assertNotEqual(self.source()['content_sha256'], first['content_sha256'])
        self.inv['dependencies'][0]['usage'] = 'runtime'
        second = artifact(self.root, self.dep, wheel(extra_files={'example.py': b'# exact new bytes'}))
        manifest(self.root, self.inv, [second])
        self.assertNotEqual(self.source()['content_sha256'], first['content_sha256'])

    def test_catalog_age_limit_is_inclusive_and_rechecked_on_each_consumption(self):
        from getzilla.security_artifacts import ArtifactError
        from getzilla.security_data import SecurityDataError
        self.source(now=NOW + timedelta(hours=72))
        for now in (NOW + timedelta(seconds=259201), NOW - timedelta(seconds=1), NOW.replace(tzinfo=None)):
            with self.subTest(now=now), self.assertRaises((ArtifactError, SecurityDataError)):
                self.source(now=now)

    def test_redistributed_bytes_are_bound_and_never_treated_as_trusted_approval(self):
        from getzilla.security_artifacts import ArtifactError
        target = self.root / 'delivery.whl'
        target.write_bytes((self.root / self.record['path']).read_bytes())
        self.record['redistributed_path'] = 'delivery.whl'
        self.record['approved'] = True  # This input never supplies authority or forgives changed bytes.
        manifest(self.root, self.inv, [self.record])
        with mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                mock.patch('subprocess.run', side_effect=AssertionError('execution forbidden')):
            descriptor = self.source()
        self.assertRegex(descriptor['content_sha256'], r'^[0-9a-f]{64}$')
        target.write_bytes(b'changed')
        with self.assertRaises(ArtifactError):
            self.source()


if __name__ == '__main__':
    unittest.main()
